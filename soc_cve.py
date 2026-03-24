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
# Couleurs console pour CVSS
# -----------------------------
def color_cvss(score):
    try:
        s = float(score)
    except:
        return ""
    if s >= 9:
        return "\033[91m"  # rouge
    elif s >= 7:
        return "\033[93m"  # orange
    else:
        return "\033[92m"  # vert

RESET = "\033[0m"

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
    print("\n\033[1m=== Voici les 30 derniers CVE identifiés avec leur score CVSS depuis la source NVD ===\033[0m\n")
    line = "-" * 120
    print(line)
    print(f"| {'CVE':18} | {'CVSS':5} | {'DATE':10} | {'SRC':6} | {'DESCRIPTION':70} |")
    print(line)
    for c in cves:
        color = color_cvss(c['CVSS'])
        print(f"| {c['CVE']:18} | {color}{str(c['CVSS'])[:5]:5}{RESET} | {c['DATE']:10} | {c['SOURCE']:6} | {c['DESCRIPTION'][:70]:70} |")
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
