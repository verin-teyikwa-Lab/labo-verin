le projet 03 nous permet de scanner de port en python. il verifie quels ports sont ouverts sur une machine.

le script tente de se connecter a chaque port dans un intervalle donne . si la connexion reussit, le port est considerer comme OUVERT.

```bash
python main.py

**test 1 : Scan local 127.0.0.1 (1-100)**
-commande: 'python main.py'
-resultat: Scan termine en 0:01:41.85 -aucun port ouvert detecte (pare-feu windows actif) -ok crash

**test 2 : Scan 80-85
- a faire 

Timeout de 1s par port rend le scan lent.