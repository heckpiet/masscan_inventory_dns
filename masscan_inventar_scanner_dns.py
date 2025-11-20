
---

## `masscan_inventar_scanner.py`

> Das ist deine aktuelle, erweiterte Version 3.2.0 inkl. nachgelagerter DNS-Auflösung (basierend auf `inventory_hosts.json`). Ich habe nur minimal korrigiert (Regex in `sanitize_filename` wieder wie im Original).

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Masscan Inventar Scanner
Version: 3.2.0
Author: heckpiet (überarbeitet)
License: MIT

Purpose:
    Fast network inventory scanner based on masscan, with optional
    post-scan DNS resolution for discovered hosts.

Features:
    - Reads target networks/hosts from a text file:
        * one entry per line
        * lines starting with '#' are treated as comments
    - Parallel masscan scans across all targets (IPv4 & IPv6).
    - Optional IPv6 splitting:
        * large IPv6 CIDRs are split into smaller subnets to avoid huge scans.
    - Uses masscan JSON output and parses it into normalized structures.
    - Keeps a structured output directory per run:

        Masscan_Inventar_Scanner_YYYYMMDD_HHMMSS/
        ├── logs/
        │   ├── masscan.log            # raw masscan stdout/stderr
        │   └── errors.log             # worker errors, non-zero exits, parse issues
        ├── output/
        │   ├── <target>_masscan_output.json
        │   ├── <target>_parsed.csv
        │   ├── <target>_parsed.json
        │   ├── <target>_summary.txt
        │   ├── inventory_hosts.csv           # aggregated inventory (all hosts)
        │   ├── inventory_hosts.json          # aggregated inventory (JSON)
        │   ├── inventory_hosts_report.txt    # human-readable report
        │   ├── inventory_hosts_dns.csv       # DNS resolution results
        │   └── inventory_hosts_dns.json      # DNS resolution results (JSON)
        └── html/
            └── (currently unused placeholder for future HTML/screenshot features)

UI language:
    - All console messages are in German (user-facing).
    - Code comments and docstrings are in English (developer-facing).

Notes:
    - masscan typically requires root or CAP_NET_RAW to send raw packets.
      For stable high-speed scans, run this script with sudo or assign
      capabilities to the masscan binary.
    - DNS resolution step uses "dig" and a list of DNS servers from a text file,
      if -d/--dns-file is provided on the command line.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

# ---------------------------
# Global configuration
# ---------------------------

SCRIPT_VERSION = "3.2.0"

# Typical ports for a general inventory scan when none are explicitly set
DEFAULT_PORTS = [
    "21", "22", "23", "53", "67-69", "80", "88", "135", "139", "161", "162",
    "389", "443", "445", "500", "514", "631", "1433", "1521", "3306", "3389",
    "5060", "5900", "8000-8080", "1900", "5353"
]

# Maximum prefix length for IPv6 subnet splitting:
# Example: 2001:db8::/32 with max_prefix 48 will be split into /48 chunks.
DEFAULT_IPV6_MAX_SUBNET_PREFIX = 48

# Default number of concurrent masscan workers
DEFAULT_CONCURRENCY = 6


# ---------------------------
# Generic helpers
# ---------------------------

def german_print(msg: str) -> None:
    """Print user-facing messages in German."""
    print(msg)


def timestamp(fmt: str = "%Y%m%d_%H%M%S") -> str:
    """Return current timestamp string in given format."""
    return datetime.now().strftime(fmt)


def ensure_dir(path: Path) -> None:
    """Ensure directory exists (like mkdir -p)."""
    path.mkdir(parents=True, exist_ok=True)


def check_dependency(cmd: str) -> bool:
    """Return True if the given command is available in PATH."""
    return shutil.which(cmd) is not None


def sanitize_filename(s: str) -> str:
    """
    Make a string safe for file names by replacing unwanted characters.
    This is used for target-based output file names.
    """
    return re.sub(r"[^A-Za-z0-9._\-]", "_", s)


# ---------------------------
# Target handling & IPv6 splitting
# ---------------------------

def read_targets_file(path: Path) -> List[str]:
    """
    Read target networks/hosts from a text file.

    Rules:
        - One entry per line.
        - Lines starting with '#' are treated as comments.
        - Empty lines are ignored.
    """
    if not path.exists():
        raise FileNotFoundError(f"Targets-Datei nicht gefunden: {path}")

    targets: List[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def split_ipv6_to_prefixes(cidr: str, max_prefix: int) -> List[str]:
    """
    Split an IPv6 network into smaller subnets with given max_prefix.
    Example:
        - Input:  2001:db8::/32
        - Result: list of /48 CIDRs if max_prefix == 48
    """
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 6:
        return [cidr]
    if net.prefixlen >= max_prefix:
        return [cidr]
    return [str(sn) for sn in net.subnets(new_prefix=max_prefix)]


def expand_targets(targets: Iterable[str], ipv6_max_prefix: int) -> List[str]:
    """
    Normalize and expand targets:
        - IPv4 networks or hosts: keep as-is.
        - IPv6 networks:
            * if prefix < ipv6_max_prefix, split into smaller networks.
            * otherwise, keep as-is.
        - Non-CIDR entries are treated as hostnames/IPs and passed through.
    """
    out: List[str] = []
    for t in targets:
        try:
            net = ipaddress.ip_network(t, strict=False)
            if net.version == 6 and net.prefixlen < ipv6_max_prefix:
                out.extend(split_ipv6_to_prefixes(t, ipv6_max_prefix))
            else:
                out.append(t)
        except ValueError:
            # Not a valid CIDR - treat as host/IP and let masscan handle it
            out.append(t)
    return out


# ---------------------------
# Masscan execution & JSON parsing
# ---------------------------

def build_masscan_cmd(
    target: str,
    ports: str,
    rate: int,
    out_path: Path,
    format_flag: str,
    extra: str
) -> List[str]:
    """
    Build a masscan command.

    Args:
        target: target network or host (e.g. "192.168.0.0/24").
        ports: port specification (e.g. "22,80,443" or "1-1000").
        rate: packets per second for masscan.
        out_path: output file path for masscan.
        format_flag: masscan output flag, e.g. "-oJ" (JSON).
        extra: additional masscan arguments (string).

    Returns:
        List suitable for subprocess.run([...]).
    """
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), format_flag, str(out_path)]
    if extra:
        cmd += extra.split()
    return cmd


def run_masscan_single(
    target: str,
    ports: str,
    rate: int,
    out_file: Path,
    log_file: Path,
    extra_args: str,
    format_flag: str
) -> int:
    """
    Run masscan for a single target and append stdout/stderr to log_file.

    Returns:
        masscan exit code (0 on success).
    """
    cmd = build_masscan_cmd(target, ports, rate, out_file, format_flag, extra_args)
    german_print(f"[INF] Starte masscan für {target}")
    with log_file.open("a", encoding="utf-8") as logfh:
        logfh.write(f"\n=== masscan {timestamp()} target={target} ===\n")
        logfh.write(f"CMD: {' '.join(cmd)}\n")
        try:
            proc = subprocess.run(cmd, stdout=logfh, stderr=logfh)
            return proc.returncode
        except Exception as e:
            logfh.write(f"[ERR] Exception bei masscan für {target}: {e}\n")
            return 255


def parse_masscan_jsonfile(json_path: Path) -> List[Dict]:
    """
    Parse a masscan JSON output file into a normalized list of dicts.

    Normalized record structure:
        {
            "ip": "x.x.x.x",
            "port": "443",
            "proto": "tcp",
            "status": "open",
            "timestamp": <unix_timestamp or None>
        }

    The function is tolerant regarding:
        - multiple JSON objects per line
        - trailing commas in arrays
    """
    if not json_path.exists():
        return []

    raw = json_path.read_text(encoding="utf-8", errors="ignore").strip()
    if not raw:
        return []

    try:
        # Scenario: one JSON object per line
        if raw.startswith("{") and "\n" in raw:
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            data = json.loads("[" + ",".join(lines) + "]")
        else:
            data = json.loads(raw)
    except json.JSONDecodeError:
        # Simple repair: remove trailing commas before closing brackets/braces
        repaired = re.sub(r",\s*([\]\}])", r"\1", raw)
        try:
            data = json.loads(repaired)
        except Exception:
            return []

    results: List[Dict] = []
    for entry in data:
        ip = entry.get("ip") or entry.get("address")
        ts = entry.get("timestamp")
        ports = entry.get("ports", [])
        for p in ports:
            results.append({
                "ip": ip,
                "port": str(p.get("port")),
                "proto": p.get("proto"),
                "status": p.get("status"),
                "timestamp": ts
            })
    return results


# ---------------------------
# Per-target output & summaries
# ---------------------------

def write_summary_file(parsed: List[Dict], summary_path: Path) -> None:
    """
    Write a simple human-readable summary for a single target.

    Example:
        192.168.0.10:
          Open ports: 22, 80, 443
    """
    ensure_dir(summary_path.parent)
    with summary_path.open("w", encoding="utf-8") as fh:
        fh.write(f"Masscan Summary - {timestamp()}\n")
        fh.write(f"Total entries: {len(parsed)}\n\n")

        by_ip: Dict[str, List[Dict]] = {}
        for r in parsed:
            ip = r.get("ip")
            if not ip:
                continue
            by_ip.setdefault(ip, []).append(r)

        for ip, entries in sorted(by_ip.items()):
            fh.write(f"{ip}:\n")
            ports = sorted({e["port"] for e in entries if e.get("port")}, key=lambda x: int(x))
            fh.write(f"  Offene Ports: {', '.join(ports) if ports else '-'}\n\n")


def write_csv(parsed: List[Dict], csv_path: Path) -> None:
    """Write a per-target CSV file containing all normalized records."""
    ensure_dir(csv_path.parent)
    if not parsed:
        return
    fieldnames = ["ip", "port", "proto", "status", "timestamp"]
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in parsed:
            writer.writerow(r)


# ---------------------------
# Aggregated inventory handling
# ---------------------------

def append_to_inventory(parsed: List[Dict], inventory: Dict[str, Dict]) -> None:
    """
    Merge parsed records into an in-memory inventory structure.

    inventory[ip] = {
        "ip": ip,
        "ports": set([...]),
        "protocols": set([...]),
        "count": int    # number of matching records for this IP
    }
    """
    for r in parsed:
        ip = r.get("ip")
        if not ip:
            continue
        port = r.get("port")
        proto = r.get("proto") or "unknown"

        if ip not in inventory:
            inventory[ip] = {
                "ip": ip,
                "ports": set(),
                "protocols": set(),
                "count": 0
            }
        inventory[ip]["count"] += 1
        if port:
            inventory[ip]["ports"].add(port)
        if proto:
            inventory[ip]["protocols"].add(proto)


def write_inventory_report_text(inventory: Dict[str, Dict], out_dir: Path) -> None:
    """
    Write a human-readable text report listing all hosts with open ports.

    File:
        inventory_hosts_report.txt
    """
    ensure_dir(out_dir)
    report_path = out_dir / "inventory_hosts_report.txt"

    with report_path.open("w", encoding="utf-8") as fh:
        fh.write(f"Inventar-Gesamtübersicht - {timestamp()}\n")
        fh.write(f"Anzahl Hosts: {len(inventory)}\n\n")

        for ip, info in sorted(inventory.items()):
            ports_sorted = sorted(info["ports"], key=lambda x: int(x))
            protos_sorted = sorted(info["protocols"])
            fh.write(f"{ip}\n")
            fh.write(f"  Offene Ports: {', '.join(ports_sorted) if ports_sorted else '-'}\n")
            fh.write(f"  Protokolle: {', '.join(protos_sorted) if protos_sorted else '-'}\n")
            fh.write("\n")

    german_print(f"[INF] Text-Report geschrieben: {report_path}")


def write_inventory_files(inventory: Dict[str, Dict], out_dir: Path) -> None:
    """
    Write all aggregated inventory files:

        - inventory_hosts.csv     (for Excel / import)
        - inventory_hosts.json    (machine-readable)
        - inventory_hosts_report.txt (human-readable text report)
    """
    ensure_dir(out_dir)
    csv_path = out_dir / "inventory_hosts.csv"
    json_path = out_dir / "inventory_hosts.json"

    # Flatten in-memory structure for CSV/JSON
    records: List[Dict] = []
    for ip, info in sorted(inventory.items()):
        ports_sorted = sorted(info["ports"], key=lambda x: int(x)) if info["ports"] else []
        protos_sorted = sorted(info["protocols"]) if info["protocols"] else []
        records.append({
            "ip": ip,
            "ports": ",".join(ports_sorted),
            "protocols": ",".join(protos_sorted),
            "entry_count": info["count"],
        })

    # CSV
    if records:
        fieldnames = ["ip", "ports", "protocols", "entry_count"]
        with csv_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for r in records:
                writer.writerow(r)

    # JSON
    with json_path.open("w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2, ensure_ascii=False)

    german_print(f"[INF] Gesamtinventar (CSV/JSON) geschrieben: {csv_path}, {json_path}")

    # Additional human-readable text report
    write_inventory_report_text(inventory, out_dir)


# ---------------------------
# DNS resolution (post-scan step)
# ---------------------------

def read_dns_servers(dns_file: Path) -> List[str]:
    """
    Read DNS servers from a text file.

    Rules:
        - one entry per line
        - '#' starts a comment
        - empty lines are ignored
    """
    if not dns_file.exists():
        raise FileNotFoundError(f"DNS-Datei nicht gefunden: {dns_file}")

    servers: List[str] = []
    for raw in dns_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        servers.append(line)

    return servers


def resolve_ip_with_dns(
    ip: str,
    dns_servers: List[str],
    max_total_seconds: float = 1.0
) -> Tuple[str, str]:
    """
    Resolve a single IP via reverse DNS using a list of DNS servers.

    Args:
        ip: IP address to resolve.
        dns_servers: list of DNS servers (IP strings).
        max_total_seconds: maximum total time budget per IP across all DNS tries.

    Returns:
        (hostname, status)
        status in {"OK", "TIMEOUT", "NO_RECORD", "ERROR", "NO_DNS_SERVERS"}

    Notes:
        - Uses 'dig +short -x' with a per-call timeout.
        - Stops when a hostname is found or time budget is exhausted.
    """
    if not dns_servers:
        return ip, "NO_DNS_SERVERS"

    start = time.monotonic()
    for dns in dns_servers:
        elapsed = time.monotonic() - start
        if elapsed >= max_total_seconds:
            return ip, "TIMEOUT"

        cmd = ["dig", "+short", "-x", ip, f"@{dns}"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=max(0.1, max_total_seconds - elapsed),
            )
        except subprocess.TimeoutExpired:
            # Try next DNS if time allows
            continue
        except Exception:
            # Some other error, try next DNS
            continue

        if proc.returncode != 0:
            # DNS server returned error, try next one
            continue

        out = proc.stdout.strip()
        if out:
            hostname = out.splitlines()[0].rstrip(".")
            return hostname, "OK"

    # If we reach here, no hostname found
    elapsed = time.monotonic() - start
    if elapsed >= max_total_seconds:
        return ip, "TIMEOUT"
    return ip, "NO_RECORD"


def run_dns_inventory_resolution(output_dir: Path, dns_file: Path) -> None:
    """
    Post-scan step:
        - read all IPs from output/inventory_hosts.json
        - resolve each IP using DNS servers from dns_file
        - write inventory_hosts_dns.csv and inventory_hosts_dns.json
    """
    inv_json = output_dir / "inventory_hosts.json"
    if not inv_json.exists():
        german_print("[WARN] inventory_hosts.json nicht gefunden – DNS-Auflösung wird übersprungen.")
        return

    try:
        dns_servers = read_dns_servers(dns_file)
    except FileNotFoundError as e:
        german_print(f"[FEHLER] {e}")
        return

    if not dns_servers:
        german_print("[WARN] DNS-Datei enthält keine gültigen Server – DNS-Auflösung wird übersprungen.")
        return

    if not check_dependency("dig"):
        german_print("[FEHLER] 'dig' wurde nicht gefunden. Bitte dnsutils/bind-utils installieren.")
        return

    german_print(f"[INF] Starte DNS-Auflösung für Inventar-Hosts mit {len(dns_servers)} DNS-Server(n).")

    data = json.loads(inv_json.read_text(encoding="utf-8", errors="ignore") or "[]")
    ips = sorted({str(entry.get("ip")) for entry in data if entry.get("ip")})
    if not ips:
        german_print("[INF] Keine IP-Adressen im Inventar gefunden – DNS-Auflösung entfällt.")
        return

    dns_results: List[Dict] = []
    total = len(ips)
    german_print(f"[INF] Anzahl zu resolvender IP-Adressen: {total}")

    for idx, ip in enumerate(ips, start=1):
        hostname, status = resolve_ip_with_dns(ip, dns_servers, max_total_seconds=1.0)
        dns_results.append(
            {
                "ip": ip,
                "hostname": hostname,
                "status": status,
            }
        )
        if idx % 20 == 0 or idx == total:
            german_print(f"[INF] DNS-Auflösung Fortschritt: {idx}/{total} IPs verarbeitet")

    # Write CSV + JSON
    dns_csv = output_dir / "inventory_hosts_dns.csv"
    dns_json = output_dir / "inventory_hosts_dns.json"

    fieldnames = ["ip", "hostname", "status"]
    with dns_csv.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for r in dns_results:
            writer.writerow(r)

    with dns_json.open("w", encoding="utf-8") as fh:
        json.dump(dns_results, fh, indent=2, ensure_ascii=False)

    german_print(f"[INF] DNS-Inventar geschrieben: {dns_csv}, {dns_json}")


# ---------------------------
# Worker for a single target
# ---------------------------

def process_target_worker(
    target: str,
    ports: str,
    rate: int,
    logs_dir: Path,
    output_dir: Path,
    extra_args: str,
    format_flag: str,
    inventory: Dict[str, Dict],
    inventory_lock,
) -> None:
    """
    Worker executed in a thread pool:
        - runs masscan for one target
        - parses JSON output
        - writes per-target summary/csv/json
        - updates global inventory under lock
    """
    safe_target = sanitize_filename(target)
    out_file = output_dir / f"{safe_target}_masscan_output.json"

    rc = run_masscan_single(
        target=target,
        ports=ports,
        rate=rate,
        out_file=out_file,
        log_file=logs_dir / "masscan.log",
        extra_args=extra_args,
        format_flag=format_flag,
    )

    if rc != 0:
        with (logs_dir / "errors.log").open("a", encoding="utf-8") as eh:
            eh.write(f"{timestamp()} - masscan exit {rc} für {target}\n")
        german_print(f"[WARN] masscan für {target} endete mit Code {rc} (siehe logs/errors.log)")

    parsed: List[Dict] = []
    if out_file.exists() and format_flag == "-oJ":
        parsed = parse_masscan_jsonfile(out_file)

    summary_path = output_dir / f"{safe_target}_summary.txt"
    csv_path = output_dir / f"{safe_target}_parsed.csv"
    parsed_json_path = output_dir / f"{safe_target}_parsed.json"

    write_summary_file(parsed, summary_path)
    write_csv(parsed, csv_path)
    parsed_json_path.write_text(
        json.dumps(parsed, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    german_print(f"[INF] Ergebnisse für {target} geschrieben: {summary_path.name}, {csv_path.name}")

    # Update global inventory (thread-safe)
    with inventory_lock:
        append_to_inventory(parsed, inventory)


# ---------------------------
# CLI / main
# ---------------------------

def build_argparser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    p = argparse.ArgumentParser(
        prog="Masscan Inventar Scanner",
        description="Inventarscanner: Zielnetze aus Datei, Masscan parallel, Gesamtinventar als CSV/JSON/Report."
    )
    p.add_argument(
        "-f", "--targets-file", required=True,
        help="Pfad zur Datei mit Zielnetzen/Hosts (eine Zeile pro Eintrag, '#' = Kommentar)."
    )
    p.add_argument(
        "-p", "--ports",
        help="Ports (z.B. 22,80,443 oder 1-1000). Wenn leer, werden typische Standardports genutzt."
    )
    p.add_argument(
        "-r", "--rate", type=int, default=1000,
        help="Masscan Rate (Pakete/Sekunde). Default: 1000."
    )
    p.add_argument(
        "--format", default="json",
        help="Masscan Output-Format (intern json empfohlen). Default: json."
    )
    p.add_argument(
        "--outdir",
        help="Basis-Ausgabepfad (Default: aktuelles Verzeichnis)."
    )
    p.add_argument(
        "--concurrency", type=int, default=DEFAULT_CONCURRENCY,
        help=f"Maximale parallele Masscan-Jobs. Default: {DEFAULT_CONCURRENCY}."
    )
    p.add_argument(
        "--ipv6-max-prefix", type=int, default=DEFAULT_IPV6_MAX_SUBNET_PREFIX,
        help=f"Maximaler Prefix für IPv6-Subnets nach Split. Default: {DEFAULT_IPV6_MAX_SUBNET_PREFIX}."
    )
    p.add_argument(
        "--masscan-extra", default="",
        help="Zusätzliche Parameter für masscan als String (z.B. '--router-ip 10.0.0.1')."
    )
    p.add_argument(
        "-d", "--dns-file",
        help="Datei mit DNS-Servern für nachgelagerte DNS-Auflösung des Inventars "
             "(eine IP pro Zeile, '#' = Kommentar)."
    )
    p.add_argument(
        "--version", action="version",
        version=f"%(prog)s {SCRIPT_VERSION}"
    )
    return p


def main():
    parser = build_argparser()
    args = parser.parse_args()

    german_print("=== Masscan Inventar Scanner ===")
    german_print(f"Version: {SCRIPT_VERSION}")

    # Check for masscan binary
    if not check_dependency("masscan"):
        german_print("[FEHLER] masscan wurde nicht gefunden. Bitte installieren und PATH prüfen.")
        sys.exit(2)
    else:
        german_print("[INF] masscan gefunden.")

    # Read targets
    targets_file = Path(args.targets_file)
    try:
        targets_raw = read_targets_file(targets_file)
    except FileNotFoundError as e:
        german_print(f"[FEHLER] {e}")
        sys.exit(2)

    if not targets_raw:
        german_print("[FEHLER] Targets-Datei enthält keine gültigen Einträge.")
        sys.exit(2)

    # Ports (either CLI or default list)
    ports = args.ports if args.ports else ",".join(DEFAULT_PORTS)

    # Output base directory
    base_out = Path(args.outdir) if args.outdir else Path.cwd()
    session_dir = base_out / f"Masscan_Inventar_Scanner_{timestamp()}"
    logs_dir = session_dir / "logs"
    output_dir = session_dir / "output"
    html_dir = session_dir / "html"   # placeholder for future HTML/screenshot features
    ensure_dir(session_dir)
    ensure_dir(logs_dir)
    ensure_dir(output_dir)
    ensure_dir(html_dir)

    german_print(f"[INF] Session-Verzeichnis: {session_dir}")

    # Masscan output format handling
    fmt = args.format.lower()
    if fmt not in ("json", "list", "xml", "grepable"):
        german_print(f"[WARN] Unbekanntes Format '{args.format}', verwende json.")
        fmt = "json"
    format_flag_map = {"json": "-oJ", "list": "-oL", "xml": "-oX", "grepable": "-oG"}
    format_flag = format_flag_map[fmt]

    # Expand/split IPv6 targets if needed
    expanded_targets = expand_targets(targets_raw, args.ipv6_max_prefix)
    german_print(f"[INF] Targets nach Expand/Split: {len(expanded_targets)} (aus {len(targets_raw)})")

    # Concurrency
    concurrency = max(1, args.concurrency)

    # Initialize logs
    (logs_dir / "masscan.log").write_text(
        f"Masscan log gestartet: {timestamp()}\n",
        encoding="utf-8"
    )
    (logs_dir / "errors.log").write_text(
        f"Errors log gestartet: {timestamp()}\n",
        encoding="utf-8"
    )

    # In-memory inventory with a lock for thread-safe updates
    inventory: Dict[str, Dict] = {}
    from threading import Lock
    inventory_lock = Lock()

    german_print(f"[INF] Starte parallele Scans (Concurrency={concurrency}) ...")

    # Parallel scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for t in expanded_targets:
            futures.append(
                executor.submit(
                    process_target_worker,
                    t,
                    ports,
                    args.rate,
                    logs_dir,
                    output_dir,
                    args.masscan_extra,
                    format_flag,
                    inventory,
                    inventory_lock,
                )
            )
        # Collect worker exceptions
        for fut in concurrent.futures.as_completed(futures):
            try:
                fut.result()
            except Exception as e:
                with (logs_dir / "errors.log").open("a", encoding="utf-8") as eh:
                    eh.write(f"{timestamp()} - Worker-Exception: {e}\n")

    # Write aggregated inventory files
    write_inventory_files(inventory, output_dir)

    # Optional DNS resolution step, if dns-file parameter is present
    if args.dns_file:
        german_print("[INF] DNS-Datei angegeben – starte nachgelagerte DNS-Auflösung des Inventars ...")
        run_dns_inventory_resolution(output_dir, Path(args.dns_file))
    else:
        german_print("[INF] Keine DNS-Datei angegeben – DNS-Auflösung wird übersprungen.")

    german_print("=== Scan-Durchläufe abgeschlossen ===")
    german_print(f"Ergebnisse liegen unter: {session_dir}")

    # Root/capabilities hint only if not running as root (where supported)
    try:
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            german_print(
                "Hinweis: masscan benötigt für hohe Scan-Geschwindigkeiten meist Root- oder "
                "CAP_NET_RAW-Rechte. Prüfe bei Problemen Berechtigungen und Netzlast."
            )
    except Exception:
        # On platforms without geteuid (e.g. Windows), silently ignore.
        pass


if __name__ == "__main__":
    main()
