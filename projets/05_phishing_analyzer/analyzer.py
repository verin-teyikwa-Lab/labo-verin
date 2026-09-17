import re
import argparse
import os

def analyze_url(url):
    score = 0
    reasons = []

    if re.search(r'https?://\d+\.\d+\.\d+\.d+', url):
        score += 40
        reasons.append("IP adress used instead of domain name")

    if "@" in url:
        score += 30
        reasons.append("contains '@' symbol (redirection trick)")

    try:
        domain = url.split('/')[2]
        if domain.count('-') >= 3:
            score += 20
            reasons.append(f"excessive hyphens in domain ({domain.count('-')})")
    except indexError:
        pass

    suspicious_keywords = ['secure', 'login', 'verify', 'update', 'account', 'confirm', 'webscr', 'ebayisapi']
    for kw in suspicious_keywords:
        if kw in url.lower() and len (url) > 30:
            score += 10
            reasons.append(f"suspicious keyword '{kw}' + long URL")
            break
    
    if len(url) > 75:
        score += 10
        reasons.append(f" abnormally long URL ({len(url)} chars)")

    if score >= 50:
        verdict = "PHISHING"
    elif score >= 20:
        verdict = "SUSPICIOUS"
    else: verdict = "SAFE"

    return score, verdict, reasons

def main():
    parser = argparse.ArgumentParser(description= "phishing URL analyzer -verinlab_socproject 05")
    parser.add_argument("-f", "--file", help="path to file containing URLs")
    parser.add_argument("-u", "--url", help="single URL to analyze")
    args = parser.parse_args()

    urls = []
    if args.file:
        try:
            with open (args.file, 'r', encoding='utf-8') as f:
                urls = [line.strip() for line in f if line.strip()]
        except FileNotFondError:
            print(f"[ERROR] File not found: {args.file}")
            return
    elif args.url:
        urls = [args.url]
    else:
        parser.print_help()
        return

    results = []
    print("\n=== verinlab phishing analyzer Report ===\n")

    for url in urls:
        score, verdict, reasons = analyze_url(url)
        results.append((url, score, verdict, reasons))
        print(f"[{verdict}] {url} -> {score}/100")
        for r in reasons:
            print (f" - {r}")
        print()

    os.makedirs("reports", exist_ok=True)

    with open ("reports/report.txt", "w", encoding="utf-8") as report:
        report.write("---verinlab phishing analysis reports ---\n\n")
        for url, score, verdict, reasons in results:
            report.write(f"{verdict} | {score}/100 | {url}\n")
            for r in reasons:
                report.write(f" - {r}\n")
            report.write("\n")

    print(f"[+] Report saved to reports/reports.txt")
    print(f"[+] Analyzed {len(results)} URLs")

if __name__ == "__main__":
    main() 