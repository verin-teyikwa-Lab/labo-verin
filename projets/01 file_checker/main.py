import hashlib
import os

def calculer_hash(chemin_fichier):
    sha256 = hashlib.sha256()
    with open(chemin_fichier, "rb") as f:
        while True:
            morceau = f.read(4096)
            if not morceau:
                break
            sha256.update(morceau)
    return sha256.hexdigest()

fichier_a_verifier ="text.txt"

with open(fichier_a_verifier, "w") as f:
    f.write("ceci est un fichier important de verin")

hash1 = calculer_hash(fichier_a_verifier)
print(f"Hash initial : {hash1}")

print("\n[simulation] un hacker modifie le fichier....")
with open(fichier_a_verifier, "a") as f:
    f.write("-pirate")

hash2 = calculer_hash(fichier_a_verifier)   
print(f"nouveau Hash : {hash2}")

if hash1 != hash2:
    print("\n DANGER : Fichier modifier !")
else:
    print("\n Fichier intact")