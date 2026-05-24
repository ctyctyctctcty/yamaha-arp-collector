#!/usr/bin/env python3
"""
Collect ARP table data from multiple Yamaha RTX830 routers via SSH and
aggregate device presence over time.

Runtime behavior:
- Polls every INTERVAL seconds with optional +/- JITTER_SECONDS variance
- Connects to each router via SSH using paramiko
- Executes "show arp"
- Parses IP/MAC pairs and updates an in-memory device inventory
- Saves aggregate results to JSON after every polling cycle

Configuration:
- Preferred: edit routers.local.json (kept out of Git by .gitignore)
- Fallback: fill the ROUTERS list below directly if you prefer
"""

from __future__ import annotations

import json
import random
import re
import sys
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ImportError as exc:  # pragma: no cover - import failure is environment-specific
    print(
        "[FATAL] paramiko is required. Install it with: pip install paramiko",
        file=sys.stderr,
    )
    raise SystemExit(1) from exc


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "routers.local.json"
OUTPUT_PATH = BASE_DIR / "devices_usage.json"

# Fallback inline configuration. Prefer routers.local.json for real credentials.
ROUTERS: list[dict[str, str]] = []

INTERVAL = 15 * 60
JITTER_SECONDS = 120
SSH_TIMEOUT = 5
SSH_RETRIES = 1
COMMAND = "show arp"

MAC_RE = re.compile(
    r"(?P<mac>(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})"
)
IP_RE = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")


def log(message: str) -> None:
    """Print a timestamped log line."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", flush=True)


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def normalize_mac(raw_mac: str) -> str:
    """Normalize MAC address formats to aa:bb:cc:dd:ee:ff."""
    mac = raw_mac.strip().lower().replace("-", ":")
    if "." in mac:
        compact = mac.replace(".", "")
        if len(compact) != 12:
            return ""
        mac = ":".join(compact[i : i + 2] for i in range(0, 12, 2))

    parts = mac.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return ""

    try:
        int("".join(parts), 16)
    except ValueError:
        return ""
    return mac


def is_valid_ipv4(ip: str) -> bool:
    """Validate IPv4 text extracted from command output."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def load_router_config() -> list[dict[str, str]]:
    """Load router definitions from local JSON config or inline fallback."""
    if CONFIG_PATH.exists():
        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log(f"Failed to read config file {CONFIG_PATH.name}: {exc}")
            raise SystemExit(1) from exc

        if not isinstance(data, dict) or not isinstance(data.get("routers"), list):
            log(f"Invalid config format in {CONFIG_PATH.name}; expected {{\"routers\": [...]}}")
            raise SystemExit(1)

        routers = data["routers"]
    else:
        routers = ROUTERS

    valid_routers: list[dict[str, str]] = []
    for index, router in enumerate(routers, start=1):
        if not isinstance(router, dict):
            log(f"Skipping router config #{index}: expected an object")
            continue

        ip = str(router.get("ip", "")).strip()
        username = str(router.get("username", "")).strip()
        password = str(router.get("password", ""))
        if not ip or not username or not password:
            log(f"Skipping router config #{index}: missing ip/username/password")
            continue

        valid_routers.append({"ip": ip, "username": username, "password": password})

    return valid_routers


def connect_and_get_arp(router: dict[str, str]) -> str:
    """Connect to one router, run 'show arp', and return raw output."""
    last_error: Exception | None = None

    for attempt in range(1, SSH_RETRIES + 2):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            log(f"Connecting to router {router['ip']} (attempt {attempt})")
            client.connect(
                hostname=router["ip"],
                username=router["username"],
                password=router["password"],
                timeout=SSH_TIMEOUT,
                banner_timeout=SSH_TIMEOUT,
                auth_timeout=SSH_TIMEOUT,
                look_for_keys=False,
                allow_agent=False,
            )
            _, stdout, stderr = client.exec_command(COMMAND, timeout=SSH_TIMEOUT)
            output = stdout.read().decode("utf-8", errors="ignore")
            error_output = stderr.read().decode("utf-8", errors="ignore").strip()
            if error_output:
                log(f"Router {router['ip']} returned stderr: {error_output}")
            return output
        except Exception as exc:  # pragma: no cover - depends on network/device state
            last_error = exc
            log(f"SSH failed for router {router['ip']} on attempt {attempt}: {exc}")
            if attempt <= SSH_RETRIES:
                time.sleep(1)
        finally:
            client.close()

    raise RuntimeError(f"Unable to collect ARP from {router['ip']}: {last_error}")


def parse_arp(output: str) -> list[dict[str, str]]:
    """Extract IP/MAC pairs from Yamaha show arp output."""
    entries: list[dict[str, str]] = []
    seen_pairs: set[tuple[str, str]] = set()

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        ip_match = IP_RE.search(line)
        mac_match = MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue

        ip = ip_match.group("ip")
        mac = normalize_mac(mac_match.group("mac"))
        if not is_valid_ipv4(ip) or not mac:
            continue

        pair = (ip, mac)
        if pair in seen_pairs:
            continue

        seen_pairs.add(pair)
        entries.append({"ip": ip, "mac": mac})

    return entries


def update_devices(
    devices: dict[str, dict[str, Any]],
    arp_entries: Iterable[dict[str, Any]],
    checked_times: int,
    seen_at: str,
) -> None:
    """Merge one polling cycle's ARP data into the global device state."""
    for entry in arp_entries:
        mac = entry["mac"]
        ips = sorted(set(entry["ips"]))

        if mac not in devices:
            devices[mac] = {
                "mac": mac,
                "seen_times": 0,
                "checked_times": checked_times,
                "ips": [],
                "first_seen": seen_at,
                "last_seen": seen_at,
            }

        device = devices[mac]
        device["seen_times"] += 1
        device["checked_times"] = checked_times
        for ip in ips:
            if ip not in device["ips"]:
                device["ips"].append(ip)
        device["ips"].sort()
        if not device.get("first_seen"):
            device["first_seen"] = seen_at
        device["last_seen"] = seen_at

    # Ensure every known device reflects the current total polling count.
    for device in devices.values():
        device["checked_times"] = checked_times


def save_json(devices: dict[str, dict[str, Any]], output_path: Path) -> None:
    """Persist aggregate data after each polling cycle."""
    output = sorted(devices.values(), key=lambda item: item["mac"])
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2, ensure_ascii=False)


def load_existing_devices(output_path: Path) -> dict[str, dict[str, Any]]:
    """Resume from an existing JSON snapshot when available."""
    if not output_path.exists():
        return {}

    try:
        with output_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log(f"Could not load existing data file {output_path.name}: {exc}")
        return {}

    if not isinstance(data, list):
        log(f"Ignoring malformed existing data in {output_path.name}: expected a list")
        return {}

    devices: dict[str, dict[str, Any]] = {}
    for item in data:
        if not isinstance(item, dict):
            continue

        mac = normalize_mac(str(item.get("mac", "")))
        if not mac:
            continue

        ips = [
            ip
            for ip in item.get("ips", [])
            if isinstance(ip, str) and is_valid_ipv4(ip)
        ]
        devices[mac] = {
            "mac": mac,
            "seen_times": int(item.get("seen_times", 0)),
            "checked_times": int(item.get("checked_times", 0)),
            "ips": sorted(set(ips)),
            "first_seen": item.get("first_seen") or "",
            "last_seen": item.get("last_seen") or "",
        }

    return devices


def collect_cycle(routers: list[dict[str, str]], devices: dict[str, dict[str, Any]], cycle: int) -> None:
    """Collect ARP data from all routers and update aggregate state."""
    seen_at = utc_now_iso()
    cycle_entries: dict[str, set[str]] = {}

    for router in routers:
        try:
            raw_output = connect_and_get_arp(router)
            parsed_entries = parse_arp(raw_output)
            for entry in parsed_entries:
                cycle_entries.setdefault(entry["mac"], set()).add(entry["ip"])
            log(f"Collected {len(parsed_entries)} ARP entries from {router['ip']}")
        except Exception as exc:  # pragma: no cover - depends on network/device state
            log(f"Skipping router {router['ip']} due to error: {exc}")

    deduplicated_entries = [
        {"mac": mac, "ips": sorted(ips)}
        for mac, ips in sorted(cycle_entries.items(), key=lambda item: item[0])
    ]
    update_devices(devices, deduplicated_entries, checked_times=cycle, seen_at=seen_at)
    save_json(devices, OUTPUT_PATH)
    log(
        "Cycle completed: "
        f"{len(deduplicated_entries)} unique MACs seen this round, "
        f"{len(devices)} total MACs tracked"
    )


def get_sleep_seconds(base_interval: int, jitter_seconds: int) -> int:
    """Return the next sleep interval with optional random jitter."""
    if jitter_seconds <= 0:
        return base_interval
    return max(1, base_interval + random.randint(-jitter_seconds, jitter_seconds))


def main() -> None:
    routers = load_router_config()
    if not routers:
        log(
            "No valid routers configured. Fill routers.local.json or edit the ROUTERS list in the script."
        )
        raise SystemExit(1)

    devices = load_existing_devices(OUTPUT_PATH)
    checked_times = max((device.get("checked_times", 0) for device in devices.values()), default=0)

    log(f"Loaded {len(routers)} router definitions")
    log(f"Resumed with {len(devices)} previously tracked devices")
    log(f"Output file: {OUTPUT_PATH}")

    while True:
        checked_times += 1
        log(f"Starting polling cycle #{checked_times}")
        collect_cycle(routers, devices, checked_times)
        sleep_seconds = get_sleep_seconds(INTERVAL, JITTER_SECONDS)
        log(f"Sleeping for {sleep_seconds} seconds before next cycle")
        time.sleep(sleep_seconds)


if __name__ == "__main__":
    main()
