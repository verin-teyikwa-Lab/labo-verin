outil soc pour detecter les attaques SSH par force brute.
1. lit le 'auth.log'
2. extrait les IP avec regex 'Failed password'
3. compte les echecs avec Counter 'Counter'
4. gernere les alerte :
  - '>=5 echecs " -[CRITICAL] BREUTEFORCE -> BLOQUE IP
  - '3-4" echecs' - [SUSPICIOUS] -> Surveiller 
  - '<3echecs -> [SAFE] -> ignorer 