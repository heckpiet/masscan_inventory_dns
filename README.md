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
