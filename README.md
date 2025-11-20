# Masscan Inventar Scanner (mit DNS-Auflösung)

**Version:** 3.2.0  
**Autor:** heckpiet  
**Lizenz:** MIT  

Ein schneller, parallelisierter Inventarscanner auf Basis von `masscan`, erweitert um eine **optionale DNS-Nachbearbeitung** der gefundenen Hosts.

Der Scanner liest Zielnetze aus einer Textdatei, führt parallele Scans aus, parst Masscan-Ergebnisse, erzeugt eine vollständige Inventarübersicht **und kann anschließend alle gefundenen IP-Adressen per Reverse-DNS auflösen**.

---

## ✨ Features

- Liest Zielnetze und Hosts aus einer Textdatei
- Unterstützt IPv4 und IPv6
- IPv6-Netze können automatisch gesplittet werden (z. B. /32 → /48), um Masscan-Limits zu umgehen
- Masscan läuft parallel für maximale Geschwindigkeit
- Ergebnisse je Ziel:
  - JSON-Rohdaten (`<target>_masscan_output.json`)
  - CSV (`<target>_parsed.csv`)
  - JSON (parsed, `<target>_parsed.json`)
  - menschlich lesbare Zusammenfassung (`<target>_summary.txt`)
- Gesamtinventar für alle gefundenen Hosts:
  - `inventory_hosts.csv`
  - `inventory_hosts.json`
  - `inventory_hosts_report.txt` (menschenlesbarer Textreport)
- **Neu: DNS-Nachbearbeitung**
  - Liest IPs aus `inventory_hosts.json`
  - Führt Reverse-DNS-Lookups über eine konfigurierbare Liste von DNS-Servern durch
  - Maximal ca. 1 Sekunde pro IP (Zeitbudget über alle DNS-Server hinweg)
  - Ergebnisse:
    - `inventory_hosts_dns.csv`
    - `inventory_hosts_dns.json`
  - Markiert Status pro IP (`OK`, `TIMEOUT`, `NO_RECORD`, `NO_DNS_SERVERS`, …)

---

## 📂 Output-Struktur

```text
Masscan_Inventar_Scanner_YYYYMMDD_HHMMSS/
├── logs/
│   ├── masscan.log                # raw masscan stdout/stderr
│   └── errors.log                 # Worker-Fehler, non-zero exits, Parse-Issues
├── output/
│   ├── <target>_masscan_output.json
│   ├── <target>_parsed.csv
│   ├── <target>_parsed.json
│   ├── <target>_summary.txt
│   ├── inventory_hosts.csv        # Aggregiertes Inventar (alle Hosts)
│   ├── inventory_hosts.json       # Aggregiertes Inventar (JSON)
│   ├── inventory_hosts_report.txt # menschenlesbarer Report
│   ├── inventory_hosts_dns.csv    # DNS-Ergebnisse (IP, Hostname, Status)
│   └── inventory_hosts_dns.json   # DNS-Ergebnisse (JSON)
└── html/
    └── (Reserviert für spätere HTML-/Screenshot-Features)

---

## 🚀 Nutzung
1. Targets-Datei vorbereiten

Beispiel: targets.txt (siehe auch targets.example.txt):

192.168.0.0/24
192.168.0.10
2001:db8::/64
example.local

2. DNS-Server-Datei vorbereiten (optional)

Beispiel: dns_servers.txt (siehe auch dns_servers.example.txt):

192.168.0.10
192.168.0.11
8.8.8.8

3. Einfacher Scan ohne DNS
sudo ./masscan_inventar_scanner.py \
  -f targets.txt \
  -r 2000 \
  --outdir /var/scans

4. Scan mit nachgelagerter DNS-Auflösung
sudo ./masscan_inventar_scanner.py \
  -f targets.txt \
  -r 2000 \
  --outdir /var/scans \
  -d dns_servers.txt


Ergebnis:

Scan & Inventar wie gewohnt (inventory_hosts.*)

Danach zusätzliche DNS-Files:

inventory_hosts_dns.csv

inventory_hosts_dns.json

5. Wichtige Parameter

-f / --targets-file
Pfad zur Datei mit Zielnetzen/Hosts (Pflichtparameter).

-p / --ports
Portliste wie bei masscan (22,80,443 oder 1-1000).
Wenn nicht gesetzt, wird eine Standard-Portliste für Inventarscans verwendet
(z. B. 22, 80, 443, 3389, 8000–8080, …).

-r / --rate
Masscan-Rate (Pakete/Sekunde), Default: 1000.

--concurrency
Maximale Anzahl paralleler Masscan-Jobs, Default: 6.

--ipv6-max-prefix
Maximaler Prefix für IPv6-Splitting (Default: /48).

--masscan-extra
Zusätzliche Parameter, z. B. --router-ip 10.0.0.1.

-d / --dns-file
Aktiviert die DNS-Nachbearbeitung und zeigt auf die Datei mit DNS-Servern.

📝 Hinweis zu Rechten und Performance

Für große Scans und hohe --rate-Werte:

Script als root ausführen (z. B. sudo) oder

CAP_NET_RAW auf die masscan-Binary setzen.

Die DNS-Auflösung ist bewusst limitiert:

max. ~1 Sekunde pro IP über alle DNS-Server

so blockiert ein defekter DNS nicht den gesamten Job.
