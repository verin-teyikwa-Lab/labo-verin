import socket
from datetime import datetime

def scan_port(ip, port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    socket.setdefaulttimeout(1)
    result = s.connect_ex((ip, port))
    s.close()

    return result == 0

def main():
    print(" scanner de ports-Labo-verin ")
    target = input("entre l`IP cible (ex:127.0.0.1) : ")
    try:
        start = int(input("port de debut : "))

        end = int(input("port de fin : "))

        print(f"\nScan de {target} de {start} a {end}...")
        debut = datetime.now()

        for port in range(start, end + 1):
            if scan_port(target, port):
                print(f"[+] port {port} OUVERT")

        fin = datetime.now()     
        print(f"\nScan terminer en {fin - debut}")   

    except keyboardInterrupt:
        print("\n[!]Scan interrompu par l`utilisateur")    
    except Exception as e:
        print(f"[!] Erreur : {e}")   
if __name__ == "__main__":
    main()       