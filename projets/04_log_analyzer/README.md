analyse les access.log et detecte :
- Top IP
- Scanning 404
- Injection / ../../etc/passwd
-Flood 20 req/60s


lancer: python 04_log_analyzer/analyzer.py -f 04_log_analyzer/sample_logs/access.log