# Yamaha ARP Collector

Collect ARP tables from multiple Yamaha RTX830 routers over SSH and aggregate MAC/IP presence over time.

## Files

- `arp_usage_collector.py`: main collector script
- `routers.example.json`: example router config
- `routers.local.json`: local real config (create this yourself, ignored by Git)
- `devices_usage.json`: output file written after each polling cycle
- `arp_collector.log`: rotating runtime log file next to the script

## Quick Start

1. Install dependency:

   ```powershell
   pip install paramiko
   ```

2. Create `routers.local.json` based on `routers.example.json`
3. Fill in the real router IPs and credentials
4. Run:

   ```powershell
   python arp_usage_collector.py
   ```

## Router Config

Each router entry supports:

- `ip`: router IP address
- `username`: SSH username
- `password`: SSH password, optional when `key_filename` is provided
- `admin_password`: optional password for entering Yamaha `administrator` mode
- `key_filename`: optional path to a private SSH key; preferred over password auth when available
- `port`: optional SSH port, default `22`

Example:

```json
{
  "routers": [
    {
      "ip": "192.168.1.1",
      "username": "admin",
      "password": "replace_me",
      "admin_password": "replace_me_if_needed",
      "key_filename": "",
      "port": 22
    }
  ]
}
```

## CLI Flags

- `--config PATH`: use a different router config file instead of `routers.local.json`
- `--dry-run`: run exactly one cycle and exit without writing `devices_usage.json`
- `--once`: run exactly one cycle, write output, then exit

## Output JSON

The collector writes:

```json
{
  "total_cycles": 1234,
  "generated_at": "2026-05-24T12:34:56+00:00",
  "devices": [
    {
      "mac": "aa:bb:cc:dd:ee:ff",
      "seen_times": 120,
      "total_cycles": 1234,
      "ips": [
        "192.168.1.10",
        "192.168.1.15"
      ],
      "first_seen": "2026-05-24T00:00:00+00:00",
      "last_seen": "2026-05-24T12:00:00+00:00"
    }
  ]
}
```

Older list-only output files are loaded and migrated automatically on the next save.

## Notes

- The script uses an interactive SSH shell because Yamaha RTX devices are often more reliable that way than `exec_command`
- Paging is disabled with `console lines infinity`
- Poll interval defaults to 15 minutes with random jitter of up to 2 minutes
- SSH key authentication is preferred over password authentication when available
- The script retries transient SSH failures once, but authentication failures are not retried
- Logs go to stdout and to `arp_collector.log` with rotation enabled
