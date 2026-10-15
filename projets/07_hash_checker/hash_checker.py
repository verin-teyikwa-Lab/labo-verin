import hashlib
import os

def calculer_sha256(chemin_fichier):
    sha256 = hashlib.sha256()
    with open(chemin_fichier, "rb") as f:
        for bloc in iter(lambda: f.read(8192), b""):
            sha256.update(bloc)
    return sha256.hexdigest()     

def verifier_fichier(chemin_fichier):
    if not os.path.exists(chemin_fichier):
        print(f"[!] Fichier introuvable : {chemin_fichier}")
        return

    with open("malicious_hashes.txt", "r") as base:
        base_malveillante = {ligne.strip().lower() for ligne in base}

    empreinte = calculer_sha256(chemin_fichier)
    print(f"\n[*] Fichier : {chemin_fichier}")
    print(f"[*] SHA256 : {empreinte}")

    if empreinte.lower() in base_malveillante:
        print("[ALERTE] MALVEILLANT - CE FICHIER EST CONNU COMME UN VIRUS!")
    else:
        print("[OK] SAIN - FIVHIER NON REPERTORIE")

if __name__ == "__main__":
    fichier = input("entre le chemin a scanner").strip()
    verifier_fichier(fichier)
