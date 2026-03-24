# SOC CVE Monitor

Outil Python de Threat Intelligence pour SOC / CERT permettant de :

- Récupérer les CVE récents depuis la NVD

- Filtrer les CVSS critiques (>=7)

- Générer CSV et JSON pour SIEM (Splunk, QRADAR, Wazuh, ELK,  Sentinel....)

- Afficher tableau lisible dans la console

- Historiser les logs d’exécution



## Installation


git clone https://github.com/zabikissa/soc-cve-monitor.git

cd soc-cve-monitor

pip3 install -r requirements.txt





## Utilisation

python3 soc_cve.py

Le script génère automatiquement :

output/soc_cves.csv
output/soc_cves.json
logs/soc_cve.log




## A noter que  : 

Les rapports seront générés automatiquement dans le dossier output/.
Les logs détaillés seront disponibles dans le dossier logs/.


##Sorties 

output/
Contient les fichiers CSV ou JSON générés par le script, par exemple :

output/
├── cve_report_2026-03-24.csv
└── cve_report_2026-03-24.json


## logs/
Contient les fichiers de logs pour le suivi et le debug.



##Cron job exemple
crontab -e
*/30 * * * * /usr/bin/python3 /opt/soc/soc_cve.py







---

## `soc_cve.py` (script SOC complet)

#!/usr/bin/env python3

import requests
import csv
import json
import logging
from datetime import datetime, timedelta
import os

# -----------------------------
# Configuration
# -----------------------------
RESULTS = 200
LIMIT = 30
DAYS_BACK = 1
CVSS_MIN = 7

# Fichiers de sortie
os.makedirs("output", exist_ok=True)
os.makedirs("logs", exist_ok=True)
CSV_FILE = "output/soc_cves.csv"
JSON_FILE = "output/soc_cves.json"
LOG_FILE = "logs/soc_cve.log"

# Logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

# -----------------------------
# Récupération CVE depuis NVD
# -----------------------------
def get_recent_cves():
    now = datetime.utcnow()
    past = now - timedelta(days=DAYS_BACK)

    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"pubStartDate={past.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        f"&pubEndDate={now.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        f"&resultsPerPage={RESULTS}"
    )

    logging.info("Request NVD API")
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        logging.error(f"Error fetching CVE: {e}")
        return []

    out = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cid = cve.get("id", "")
        date = cve.get("published", "")[:10]
        desc = cve.get("descriptions", [{}])[0].get("value", "")[:80]

        score = 0
        try:
            score = cve["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"]
        except:
            try:
                score = cve["metrics"]["cvssMetricV30"][0]["cvssData"]["baseScore"]
            except:
                pass

        if score < CVSS_MIN:
            continue

        out.append({
            "CVE": cid,
            "CVSS": score,
            "DATE": date,
            "SOURCE": "NVD",
            "DESCRIPTION": desc
        })

    out.sort(key=lambda x: x["DATE"], reverse=True)
    return out[:LIMIT]

# -----------------------------
# Affichage console
# -----------------------------
def print_table(cves):
    line = "-" * 110
    print(line)
    print(f"| {'CVE':18} | {'CVSS':4} | {'DATE':10} | {'SRC':4} | {'DESCRIPTION':60} |")
    print(line)
    for c in cves:
        print(f"| {c['CVE']:18} | {str(c['CVSS'])[:4]:4} | {c['DATE']:10} | {c['SOURCE']:4} | {c['DESCRIPTION'][:60]:60} |")
    print(line)

# -----------------------------
# Export CSV
# -----------------------------
def export_csv(cves):
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["CVE","CVSS","DATE","SOURCE","DESCRIPTION"])
        writer.writeheader()
        for c in cves:
            writer.writerow(c)
    logging.info("CSV exported")

# -----------------------------
# Export JSON
# -----------------------------
def export_json(cves):
    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2)
    logging.info("JSON exported")

# -----------------------------
# Main
# -----------------------------
def main():
    logging.info("Start CVE script")
    cves = get_recent_cves()
    if not cves:
        print("No CVEs found or API error.")
        logging.warning("No CVEs retrieved")
        return
    print_table(cves)
    export_csv(cves)
    export_json(cves)
    logging.info("Done")

if __name__ == "__main__":
    main()




