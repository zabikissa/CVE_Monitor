# SOC CVE Monitor

Outil Python de Threat Intelligence pour SOC / CERT permettant de :

- Récupérer les CVE récents depuis la NVD

- Filtrer les CVSS critiques (>=7)

- Générer CSV et JSON pour SIEM (Splunk, QRADAR, Wazuh, ELK,  Sentinel....)

- Afficher tableau lisible dans la console

- Historiser les logs d’exécution



## Installation



git clone https://github.com/zabikissa/CVE_Monitor.git



cd CVE_Monitor



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









