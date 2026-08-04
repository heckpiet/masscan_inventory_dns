# masscan_inventory_dns has moved

This project has been incorporated into
[heckpiet/masscan_inventory](https://github.com/heckpiet/masscan_inventory) and is no longer
maintained as a separate application.

The unified scanner provides the original inventory functionality and optional, parallel
reverse-DNS enrichment from one tested package and command-line interface.

## Migration

Install the main project with optional DNS support:

```bash
python -m pip install "masscan-inventory[dns]"
```

Run a scan with DNS enrichment:

```bash
masscan-inventory \
  --targets-file targets.txt \
  --dns-servers dns_servers.txt \
  --dns-concurrency 20 \
  --dns-timeout 1.0
```

The DNS server file still accepts one IPv4 or IPv6 resolver address per line. The unified version
continues to produce `inventory_hosts_dns.csv` and `inventory_hosts_dns.json`.

See the [main project documentation](https://github.com/heckpiet/masscan_inventory#optional-dns-enrichment)
and the [v3.3.0 release](https://github.com/heckpiet/masscan_inventory/releases/tag/v3.3.0) for
installation, usage, security guidance, and release artifacts.

## Repository status

This repository is retained as a read-only archive so existing links and commit history remain
available. Report issues and submit changes in
[heckpiet/masscan_inventory](https://github.com/heckpiet/masscan_inventory).
