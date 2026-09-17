soc tool to analyze suspicious URLs from phishing emails without opening them.

- '-f /--file': analyze list of URLs
- '-u / --url' analyze single URL
- heuristic scoring engine (0-100)
- generates soc report in 'reports/report.txt'

|Rule |points |description|
| :---| :---| :---|
| IP in URL | 40 | http:?/192.168.1.1/login |
| @ symbol | 30 | https://google.com@evil.com |
| hyphens | 20 | secure-paypal-login.com|
| keywords +length |10 | secure, login,verify +>30 chars|
| Too Long | 10 | URL > 70 chars |

verdict: SAFE(<20), SUSPICIOUS (20-49), PHISHING (>=50)


''bash
phython analyzer.py -f samples/urls.txt
python analyzer.py -u "http:// mtn-cameroon-secure-login.com/verify-account"
