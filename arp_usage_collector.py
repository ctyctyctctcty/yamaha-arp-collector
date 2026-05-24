#!/usr/bin/env python3
"""
Collect ARP table data from multiple Yamaha RTX830 routers via SSH and
aggregate device presence over time.
"""

from __future__ import annotations

import argparse
import json
import logging
from logging.handlers import RotatingFileHandler
import random
import re
import signal
import socket
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
DEFAULT_CONFIG_PATH = BASE_DIR / "routers.local.json"
OUTPUT_PATH = BASE_DIR / "devices_usage.json"
LOG_PATH = BASE_DIR / "arp_collector.log"

# Fallback inline configuration. Prefer routers.local.json for real credentials.
ROUTERS: list[dict[str, Any]] = []

INTERVAL = 15 * 60
JITTER_SECONDS = 120
SSH_CONNECT_TIMEOUT = 10
SSH_COMMAND_TIMEOUT = 15
SSH_RETRIES = 1
SHELL_SETTLE_SECONDS = 0.5
SHELL_IDLE_SECONDS = 1.0
SHELL_READ_TIMEOUT = 15
COMMAND = "show arp"

MAC_RE = re.compile(
    r"(?P<mac>(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})"
)
IP_RE = re.compile(r"(?P<ip>\b(?:\d{1,3}\.){3}\d{1,3}\b)")
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")

logger = logging.getLogger(__name__)
shutdown_requested = False


def setup_logging() -> None:
    """Configure stdout and rotating file logging once."""
    if logger.handlers:
        return

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S")

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    file_handler = RotatingFileHandler(
        LOG_PATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    logger.propagate = False


def log(message: str) -> None:
    """Route timestamped messages through the configured logger."""
    logger.info(message)


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


def handle_shutdown_signal(signum: int, _frame: Any) -> None:
    """Record a shutdown request and let the current cycle finish cleanly."""
    global shutdown_requested
    shutdown_requested = True
    signal_name = signal.Signals(signum).name
    log(f"Received {signal_name}; shutdown will occur after the current cycle")


def register_signal_handlers() -> None:
    """Register signal handlers supported by the current platform."""
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_shutdown_signal)


def wait_with_shutdown(seconds: int) -> None:
    """Sleep in short steps so shutdown can interrupt the wait."""
    end_time = time.time() + max(0, seconds)
    while not shutdown_requested and time.time() < end_time:
        remaining = end_time - time.time()
        time.sleep(min(1.0, remaining))


def parse_args() -> argparse.Namespace:
    """Parse command-line flags."""
    parser = argparse.ArgumentParser(
        description="Collect Yamaha RTX830 ARP data over SSH and aggregate device presence."
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to the router config JSON file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run exactly one collection cycle without writing output.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run exactly one collection cycle, write output, then exit.",
    )
    return parser.parse_args()


def load_router_config(config_path: Path) -> list[dict[str, Any]]:
    """Load router definitions from local JSON config or inline fallback."""
    if config_path.exists():
        try:
            with config_path.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            log(f"Failed to read config file {config_path.name}: {exc}")
            raise SystemExit(1) from exc

        if not isinstance(data, dict) or not isinstance(data.get("routers"), list):
            log(f"Invalid config format in {config_path.name}; expected {{\"routers\": [...]}}")
            raise SystemExit(1)

        routers = data["routers"]
    else:
        routers = ROUTERS

    valid_routers: list[dict[str, Any]] = []
    for index, router in enumerate(routers, start=1):
        if not isinstance(router, dict):
            log(f"Skipping router config #{index}: expected an object")
            continue

        ip = str(router.get("ip", "")).strip()
        username = str(router.get("username", "")).strip()
        password = router.get("password")
        admin_password = router.get("admin_password")
        key_filename = str(router.get("key_filename", "")).strip()
        port = router.get("port", 22)

        if not ip or not username:
            log(f"Skipping router config #{index}: missing ip/username")
            continue

        if not password and not key_filename:
            log(f"Skipping router config #{index}: provide password or key_filename")
            continue

        try:
            port = int(port)
        except (TypeError, ValueError):
            log(f"Skipping router config #{index}: invalid port")
            continue

        valid_routers.append(
            {
                "ip": ip,
                "username": username,
                "password": str(password) if password else "",
                "admin_password": str(admin_password) if admin_password else "",
                "key_filename": key_filename,
                "port": port,
            }
        )

    return valid_routers


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from shell output."""
    return ANSI_RE.sub("", text)


def _recv_available(channel: paramiko.Channel, timeout_seconds: float) -> str:
    """Read from a shell channel until it stays idle or timeout is reached."""
    deadline = time.time() + timeout_seconds
    last_data_time = time.time()
    chunks: list[str] = []

    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="ignore")
            if chunk:
                chunks.append(chunk)
                last_data_time = time.time()
                continue
        elif time.time() - last_data_time >= SHELL_IDLE_SECONDS:
            break

        time.sleep(0.1)

    return "".join(chunks)


def _read_until(channel: paramiko.Channel, markers: tuple[str, ...], timeout_seconds: float) -> str:
    """Read until one of the markers appears or timeout expires."""
    deadline = time.time() + timeout_seconds
    chunks: list[str] = []

    while time.time() < deadline:
        if channel.recv_ready():
            chunk = channel.recv(65535).decode("utf-8", errors="ignore")
            if chunk:
                chunks.append(chunk)
                joined = "".join(chunks)
                if any(marker in joined for marker in markers):
                    return joined
        time.sleep(0.1)

    return "".join(chunks)


def _clean_command_output(raw_output: str, command: str) -> str:
    """Strip ANSI noise, echoed commands, and prompt-only lines."""
    cleaned = strip_ansi(raw_output).replace("\r", "")
    lines: list[str] = []

    for raw_line in cleaned.splitlines():
        line = raw_line.strip()
        if not line or line == command:
            continue
        if line.lower() == "console lines infinity":
            continue
        if line.lower() == "administrator":
            continue
        if line.lower() == "exit":
            continue
        if line.endswith(">") or line.endswith("#"):
            continue
        if line == "Password:":
            continue
        lines.append(raw_line)

    return "\n".join(lines).strip()


def connect_and_get_arp(router: dict[str, Any]) -> str:
    """Connect to one router, run 'show arp' through an interactive shell, and return raw output."""
    last_error: Exception | None = None
    transient_errors = (socket.timeout, paramiko.SSHException, OSError)

    for attempt in range(1, SSH_RETRIES + 2):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        channel: paramiko.Channel | None = None
        try:
            log(f"Connecting to router {router['ip']} (attempt {attempt})")
            client.connect(
                hostname=router["ip"],
                port=router["port"],
                username=router["username"],
                password=router["password"] or None,
                key_filename=router["key_filename"] or None,
                timeout=SSH_CONNECT_TIMEOUT,
                banner_timeout=SSH_CONNECT_TIMEOUT,
                auth_timeout=SSH_CONNECT_TIMEOUT,
                look_for_keys=not bool(router["key_filename"]),
                allow_agent=False,
            )

            channel = client.invoke_shell()
            channel.settimeout(0.2)
            time.sleep(SHELL_SETTLE_SECONDS)
            _recv_available(channel, SHELL_SETTLE_SECONDS)

            if router.get("admin_password"):
                channel.send("administrator\n")
                prompt_output = _read_until(channel, ("Password:", "#", ">"), SSH_COMMAND_TIMEOUT)
                if "Password:" in prompt_output:
                    channel.send(f"{router['admin_password']}\n")
                    _read_until(channel, ("#", ">"), SSH_COMMAND_TIMEOUT)

            channel.send("console lines infinity\n")
            _read_until(channel, ("#", ">"), SSH_COMMAND_TIMEOUT)

            channel.send(f"{COMMAND}\n")
            raw_output = _recv_available(channel, SHELL_READ_TIMEOUT)

            channel.send("exit\n")
            time.sleep(0.2)
            _recv_available(channel, 0.5)
            return _clean_command_output(raw_output, COMMAND)
        except paramiko.AuthenticationException as exc:  # pragma: no cover - network/device specific
            log(f"Authentication failed for router {router['ip']}: {exc}")
            raise
        except transient_errors as exc:  # pragma: no cover - network/device specific
            last_error = exc
            log(f"SSH failed for router {router['ip']} on attempt {attempt}: {exc}")
            if attempt <= SSH_RETRIES:
                time.sleep(1)
        finally:
            if channel is not None:
                channel.close()
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
    total_cycles: int,
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
                "total_cycles": total_cycles,
                "ips": [],
                "first_seen": seen_at,
                "last_seen": seen_at,
            }

        device = devices[mac]
        device["seen_times"] += 1
        device["total_cycles"] = total_cycles
        for ip in ips:
            if ip not in device["ips"]:
                device["ips"].append(ip)
        device["ips"].sort()
        if not device.get("first_seen"):
            device["first_seen"] = seen_at
        device["last_seen"] = seen_at

    for device in devices.values():
        device["total_cycles"] = total_cycles


def save_json(
    devices: dict[str, dict[str, Any]],
    output_path: Path,
    total_cycles: int | None = None,
) -> None:
    """Persist aggregate data after each polling cycle."""
    if total_cycles is None:
        total_cycles = max(
            (int(device.get("total_cycles", 0)) for device in devices.values()),
            default=0,
        )
    payload = {
        "total_cycles": total_cycles,
        "generated_at": utc_now_iso(),
        "devices": sorted(devices.values(), key=lambda item: item["mac"]),
    }
    with output_path.open("w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def load_existing_devices(output_path: Path) -> tuple[dict[str, dict[str, Any]], int]:
    """Resume from an existing JSON snapshot when available."""
    if not output_path.exists():
        return {}, 0

    try:
        with output_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError) as exc:
        log(f"Could not load existing data file {output_path.name}: {exc}")
        return {}, 0

    total_cycles = 0
    raw_devices: list[Any]
    if isinstance(data, list):
        raw_devices = data
        total_cycles = max(
            (
                int(item.get("checked_times", 0))
                for item in data
                if isinstance(item, dict)
            ),
            default=0,
        )
    elif isinstance(data, dict) and isinstance(data.get("devices"), list):
        raw_devices = data["devices"]
        total_cycles = int(data.get("total_cycles", 0))
    else:
        log(f"Ignoring malformed existing data in {output_path.name}")
        return {}, 0

    devices: dict[str, dict[str, Any]] = {}
    for item in raw_devices:
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
        device_total_cycles = int(item.get("total_cycles", item.get("checked_times", total_cycles)))
        devices[mac] = {
            "mac": mac,
            "seen_times": int(item.get("seen_times", 0)),
            "total_cycles": device_total_cycles,
            "ips": sorted(set(ips)),
            "first_seen": item.get("first_seen") or "",
            "last_seen": item.get("last_seen") or "",
        }

    if not total_cycles:
        total_cycles = max(
            (int(device.get("total_cycles", 0)) for device in devices.values()),
            default=0,
        )

    return devices, total_cycles


def collect_cycle(
    routers: list[dict[str, Any]],
    devices: dict[str, dict[str, Any]],
    cycle: int,
    *,
    write_output: bool,
) -> None:
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
    update_devices(devices, deduplicated_entries, total_cycles=cycle, seen_at=seen_at)
    if write_output:
        save_json(devices, OUTPUT_PATH, cycle)
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
    setup_logging()
    register_signal_handlers()
    args = parse_args()

    config_path = Path(args.config).expanduser()
    routers = load_router_config(config_path)
    if not routers:
        log(
            "No valid routers configured. Fill routers.local.json or edit the ROUTERS list in the script."
        )
        raise SystemExit(1)

    devices, total_cycles = load_existing_devices(OUTPUT_PATH)

    log(f"Loaded {len(routers)} router definitions")
    log(f"Resumed with {len(devices)} previously tracked devices")
    log(f"Output file: {OUTPUT_PATH}")
    log(f"Log file: {LOG_PATH}")

    while not shutdown_requested:
        total_cycles += 1
        log(f"Starting polling cycle #{total_cycles}")
        collect_cycle(routers, devices, total_cycles, write_output=not args.dry_run)

        if args.dry_run:
            log("Dry run completed; output file was not written")
            break

        if args.once:
            log("Single-cycle run completed")
            break

        if shutdown_requested:
            break

        sleep_seconds = get_sleep_seconds(INTERVAL, JITTER_SECONDS)
        log(f"Sleeping for {sleep_seconds} seconds before next cycle")
        wait_with_shutdown(sleep_seconds)

    if not args.dry_run:
        save_json(devices, OUTPUT_PATH, total_cycles)
        log("Final device snapshot saved")


if __name__ == "__main__":
    main()
