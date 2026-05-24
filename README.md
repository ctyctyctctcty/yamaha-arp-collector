# Yamaha ARP Collector

Collect ARP tables from multiple Yamaha RTX830 routers over SSH and aggregate MAC/IP presence over time.

## Files

- `arp_usage_collector.py`: main collector script
- `routers.example.json`: example router config
- `routers.local.json`: local real config (create this yourself, ignored by Git)
- `devices_usage.json`: output file written after each polling cycle

## Quick Start

1. Install dependency:

   ```powershell
   pip install paramiko
   ```

2. Copy `routers.example.json` to `routers.local.json`
3. Fill in the real router IPs and credentials
4. Run:

   ```powershell
   python arp_usage_collector.py
   ```

## Notes

- Poll interval defaults to 15 minutes
- SSH timeout is 5 seconds
- The script retries failed SSH collection once
- MAC addresses are normalized to lowercase colon format
- Existing `devices_usage.json` data is resumed automatically on restart
