import re
import os
import argparse
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_PATTERN = r'(\d+\.\d+\.\d+\.\d+).*?\[(.*?)\].*?"(GET|POST|PUT|DELETE).*? (.*?) HTTP.*?" (\d{3})'
INJECTION_PATTERNS =["union select", "'or", "<script>", "../", "etc/passwd", "1=1"]

def parse_log_line(line):
    match = re.search(LOG_PATTERN, line, re.IGNORECASE)
    if not match:
        return None
    ip, date_str, method, url, status = match.groups()    
    try:
        dt = datetime.strptime(date_str.split()[0], "%d/%b/%Y:%H:%M:%S")
    except:
        dt = None 
    return {"ip": ip, "datetime": dt, "url": url.lower(), "status": int(status), "raw": line.strip()}   

def analyzer_file(filepath):
    logs = []    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed :
                    logs.append(parsed)
    except FileNotFoundError:
        print(f"[!] File not found:{filepath}") 
        return 
        
    print(f"[!] parsed {len(logs)} valid lines")               
    ip_counter = Counter([l['ip'] for l in logs])
    scan_ips = defaultdict(int)
    injection_alerts = []
    logs_by_ip = defaultdict(list)

    for log in logs:
        if log['status'] == 404:
            scan_ips[log['ip']] += 1
        for pat in INJECTION_PATTERNS:
            if pat in log['url']:
                injection_alerts.append(log)
                break
        if log['datetime']:
            logs_by_ip[log['ip']].append(log)

    flood_alerts = []  
    for ip, enties in logs_by_ip.items():
        enties.sort(key=lambda x: x['datetime'] or datetime.min)  
        for i in range(len(enties)):
            if not enties[i]['datetime']:continue
            windows_end = enties[i] ['datetime'] + timedelta(seconds=60)
            count = 0
            for e in enties[i:]:
                if e['datetime'] and e['datetime'] <= windows_end:
                    count += 1
                else:
                    break   
            if count >= 20:
                flood_alerts.append((ip, enties[i]['datetime'], count))
                break

    base_dir = os.path.dirname(os.path.abspath(__file__))
    report_path = os.path.join(base_dir, "reports", "report.txt")

    with open(report_path, 'w') as out:
        out.write("===LOG ANALYZER REPORT===\n")
        out.write(f"Top 10 IPs:\n")
        for ip, c in ip_counter.most_common(10):
            out.write(f" -{ip}: {c} requests\n")
        for ip, c in scan_ips.items():
            if c > 5:
                out.write(f"[ALERT] Scanning: {ip} -> {c} 404s\n")
        for log in injection_alerts:
            out.write(f"[CRITICAL] Injection: {log['ip']} -> {log['url']}\n")
        for ip, dt, c in flood_alerts:
            out.write(f"[ALERT] Flood: {ip} -> {c} reqs at {dt}\n")
   
    print(f"[+] Report: {report_path}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description= "Log Analyzer - labo-verin P04")
    parser.add_argument("-f", "--file", required=True, help="path to access.log")
    args = parser.parse_args()
    analyzer_file(args.file)

