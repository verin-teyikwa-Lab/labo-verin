outils SOC qui detecte un malware sans lexecuter par comparaison SHA256
1. calcul le SHA256 du fichier suspect
2. compare avec la base threat intelligente 'malicious_hashes.txt'
3. verdict : SAIN OU MALVEILLANT

python hash_checker.py
> test_files/clean.exe -> SAIN 
> test_files/eicar.com -> MALVEILLANT

python, hashlib, os. lecture par block 8ko.