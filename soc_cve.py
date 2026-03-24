#!/usr/bin/env python3

import requests
import csv
import json
import logging
from datetime import datetime, timedelta

RESULTS = 200
LIMIT = 30
DAYS_BACK = 1
CVSS_MIN = 7

CSV_FILE = "soc_cves.csv"
JSON_FILE = "soc_cves.json"
LOG_FILE = "soc_cve.log"


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)


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

    r = requests.get(url, timeout=30)
    data = r.json()

    out = []

    for v in data.get("vulnerabilities", []):

        cve = v["cve"]

        cid = cve.get("id", "")
        date = cve.get("published", "")[:10]
        desc = cve["descriptions"][0]["value"][:80]

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

        out.append(
            {
                "CVE": cid,
                "CVSS": score,
                "DATE": date,
                "SOURCE": "NVD",
                "DESCRIPTION": desc,
            }
        )

    out.sort(key=lambda x: x["DATE"], reverse=True)

    return out[:LIMIT]


def print_table(cves):

    line = "-" * 110

    print(line)
    print(
        f"| {'CVE':18} | {'CVSS':4} | {'DATE':10} | {'SRC':4} | {'DESCRIPTION':60} |"
    )
    print(line)

    for c in cves:

        print(
            f"| {c['CVE']:18} "
            f"| {str(c['CVSS']):4} "
            f"| {c['DATE']:10} "
            f"| {c['SOURCE']:4} "
            f"| {c['DESCRIPTION'][:60]:60} |"
        )

    print(line)


def export_csv(cves):

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:

        writer = csv.DictWriter(
            f,
            fieldnames=["CVE", "CVSS", "DATE", "SOURCE", "DESCRIPTION"],
        )

        writer.writeheader()

        for c in cves:
            writer.writerow(c)

    logging.info("CSV exported")


def export_json(cves):

    with open(JSON_FILE, "w", encoding="utf-8") as f:
        json.dump(cves, f, indent=2)

    logging.info("JSON exported")


def main():

    logging.info("Start CVE script")

    cves = get_recent_cves()

    print_table(cves)

    export_csv(cves)

    export_json(cves)

    logging.info("Done")


if __name__ == "__main__":
    main()
