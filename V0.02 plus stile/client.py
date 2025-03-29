import socket
import threading
import ssl
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad
import base64
import socket
import threading
import os

HOST = '127.0.0.1'
PORT = 54424

# Création du contexte SSL
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="SSL/server.crt")
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def aes_encrypt(texte, cle_utilisateur):
    try:
        """Chiffre le texte avec AES en utilisant une clé dérivée"""
        salt = get_random_bytes(16)
        key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2**14, r=8, p=1)

        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Appliquer un padding PKCS7
        texte_padded = pad(texte.encode(), AES.block_size)

        encrypted_text = cipher.encrypt(texte_padded)

        return base64.b64encode(salt + iv + encrypted_text).decode()
    except:
        print("Erreur lors du chiffrement.")
        return None


def aes_decrypt(texte_chiffre, cle_utilisateur):
    try: 
        """Déchiffre le texte avec AES"""
        data = base64.b64decode(texte_chiffre)
        salt, iv, encrypted_text = data[:16], data[16:32], data[32:]

        key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_text = cipher.decrypt(encrypted_text)

        # Retirer le padding PKCS7 proprement
        decrypted_text = unpad(decrypted_text, AES.block_size)

        return decrypted_text.decode()
    except:
        print("Erreur lors du déchiffrement.")
        return None

def receive_messages(client_socket, cle_session):
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode()
            if encrypted_message:
                try:
                    decrypted_message = aes_decrypt(encrypted_message, cle_session)
                    print(f"\n📥 Message reçu : {decrypted_message}\n> ", end="")
                except (ValueError, KeyError):
                    print("\n⚠️ Impossible de déchiffrer un message reçu. Ignoré.\n> ", end="")
        except:
            print("❌ Connexion au serveur perdue.")
            break


def env_msg():
    try:
        while True:
            message = input("> ")
            if message.lower() == "exit":
                    aff_menu()
            if secure_client.fileno() == -1:
                print("Connexion perdue.")
                break
            message = username + " : " + message  # Préfixer avec le nom d'utilisateur
            try:
                encrypted_message = aes_encrypt(message, cle_utilisateur)
                secure_client.send(encrypted_message.encode())
            except (ConnectionResetError, ssl.SSLError, ConnectionRefusedError) as e:
                print(f"Erreur de connexion: {e}")
                break
            except Exception as e:
                print(f"Erreur lors de l'envoi du message: {e}")
                secure_client.send(b"EXIT")  # Send exit signal before closing
                secure_client.shutdown(socket.SHUT_RDWR)
                secure_client.close()
                break
    except:
        print("Erreur avec la fonction d'envoie des message.")


# Fonction pour les menue
def clear_ecran():
    """Effacer le terminal en fonction de l'OS."""
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        print("Vous utiliser un os non compatible donc l'écran na pas pu être effacé.")


def aff_menu():
    clear_ecran()
    print("╔═════════════════════════════╗")
    print("║       Menu Principal        ║")
    print("╠═════════════════════════════╣")
    print("║ 1. Envoyez un message       ║")
    print("║ 2. Créer un groupe          ║")
    print("║ 3. Ajouter un ami           ║")
    print("║ 4. Bloquer un utilisateur   ║")
    print("║ 5. Signaler                 ║")
    print("║ 6. Quitter                  ║")
    print("╚═════════════════════════════╝")
    choix = input("  Choisissez une option: ")
    if choix == '1':
        print(f"Menue {choix} affiché")
        env_msg()
    elif choix == '2':
        print(f"Menue {choix} affiché")
        autre_menu()
    elif choix == '3':
        print(f"Menue {choix} affiché")
        autre_menu()
    elif choix == '4':
        print(f"Menue {choix} affiché")
        autre_menu()
    elif choix == '5':
        print(f"Menue {choix} affiché")
        autre_menu()
    elif choix == '6':
        print("Au revoir!")
        secure_client.send(b"EXIT") # Send an exit signal to the server
        secure_client.shutdown(socket.SHUT_RDWR) # Ensure both read and write are closed
        secure_client.close()
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        aff_menu()

def autre_menu():
    clear_ecran()
    print("╔══════════════════════════════════════════╗")
    print("║ Cette option n'est pas encore disponible ║")
    print("╠══════════════════════════════════════════╣")
    print("║ 1. HaycomChat est en cours de dev        ║")
    print("║ 2. Donc pas tout est encore disponible   ║")
    print("║ 3. Retour au menu principal              ║")
    print("╚══════════════════════════════════════════╝")
    choix = input("  Choisissez une option: ")
    if choix == '1':
        print("Option 1 sélectionnée.")
        input("Appuyez sur Entrée pour continuer...")
        autre_menu()
    elif choix == '2':
        print("Option 2 sélectionnée.")
        input("Appuyez sur Entrée pour continuer...")
        autre_menu()
    elif choix == '3':
        aff_menu()
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        autre_menu()


# Connexion au serveur avec gestion de la connexion SSL
try:
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client: #créé un sokcet en ipv4 en utilisant TCP
        client.connect((HOST, PORT)) # Ce connecter aux serveur
        print("🔐 Connexion au serveur en cours...")
        secure_client = context.wrap_socket(client, server_hostname=HOST) # Sécuriser la connection TCP avec SSL

        # Authentification (PLAIN TEXT)
        print(secure_client.recv(1024).decode(), end="") # Afficher le texte d'authtification reçus pas le serveur
        username = input()
        secure_client.send(username.encode()) #Envoyez l'ID

        print(secure_client.recv(1024).decode(), end="")
        password = getpass.getpass() #Faire que on voye pas le mdp qui est écrit pour la sécuriter
        secure_client.send(password.encode()) #Envoyez le mdp
        
        auth_response = secure_client.recv(1024).decode() # Afficher la réponse du serveur
        if auth_response == "AUTH_FAIL":
            print("❌ Authentification échouée !")
            secure_client.close()
            exit()

        print("✅ Authentification réussie ! Vous pouvez maintenant discuter.")

        # Demande de clé de chiffrement à l'utilisateur APRÈS l'authentification
        cle_utilisateur = getpass.getpass("🔑 Entrez votre clé de chiffrement : ") #Entrer le la clé de chiffrement 

        threading.Thread(target=receive_messages, args=(secure_client, cle_utilisateur), daemon=True).start() #Lancer le thread des message reçu
        
        aff_menu() #afficher le menu
              
except Exception as e:
    print(f"❌ Une erreur est survenue: ( {e} )")


print("❌ Connexion au serveur perdue.")
secure_client.close()
input("Appuyez sur Entrée pour quitter...")
exit()