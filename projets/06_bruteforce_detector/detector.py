import re
import argparse
from collections import Counter
from datetime import datetime

REGEX_FAILED = r'Failed password.*from (\d+\.\d+\.\d+\.\d+)'

def analyze_log(filepath):
    ips = []
    print(f"[*]analyse de {filepath}...")

    with open(filepath, 'r') as f:
        for line in f:
            match = re.search(REGEX_FAILED, line)
            if match:
                ip = match.group(1)
                ips.append(ip)

    counter = Counter(ips)     

    print("\n--- RAPPORT SOC ---")     
    report_data = []  
    for ip, count in counter.items():
        if count >= 5:
            level = "[CRITICAL] BRUTEFORCE"
            action = f"BLOQUE IP {ip}"
        elif count >= 3:
             level = "[SUSPICIOUS]"
             action = f"surveiller IP {ip}"
        else:
            level = "[SAFE]"
            action = "ignorer"

        msg = f"{level} | IP: {ip} | {count} echecs | -> {action}"
        print(msg)
        report_data.append(msg)

    with  open("reports/report.txt", "w") as out:
        out.write(f"Rapport BruteForce - {datetime.now()}\n")
        out.write("-"*40 + "\n")
        out.write("\n".join(report_data))
    
    print("\n[+] Rapport sauvegarde: reports/report.txt")

if __name__ =="__main__":
    parser = argparse.ArgumentParser(description="Detecteur BruteForce SSH")
    parser.add_argument("-f", "--file", required=True, help="chemin vers auth.log")
    args = parser.parse_args()
    analyze_log(args.file)