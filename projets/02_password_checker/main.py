import re

def check_password(password):
    score = 0
    conseils = []
    
    if len(password) >= 8:
        score += 1
    else:
        conseils.append(" au moins 8 caracteres")    

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        conseils.append(" au moins une majuscule")    

    if re.search(r"[a-z]", password):
        score += 1
    else:
        conseils.append(" au moins une minuscule")  

    if re.search(r"[0-9]", password):
        score += 1
    else:
        conseils.append(" au moins un chiffre")  

    if re.search(r"[@#$^&*!_\-]", password):
        score += 1
    else:
        conseils.append(" au moins un caractere special (@#$!*&)")

    if score == 5:
        return "MOT DE PASSE FORT",[]    
    elif score >= 3:
        return "MOT DE PASS MOYEN", conseils
    else:
        return "MOT DE PASSE FAIBLE", conseils

print(" password strength checker Labo verin ")
pwd = input("entre le mot de passe a tester: ")
result, conseils = check_password(pwd)
print(f"\nResultat: {result}")
if conseils:
    print("po