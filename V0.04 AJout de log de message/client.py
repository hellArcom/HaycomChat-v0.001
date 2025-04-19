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

HOST = '127.0.0.1'  # ip du serveur
PORT = 54424

try:
    # Création du contexte SSL
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="SSL/server.crt")  # catfile=endroit/du/ssl
    context.check_hostname = False  # desactiver la verif
    context.verify_mode = ssl.CERT_NONE  # desactiver la verif
except:
    print("Erreur lors de la création du contexte SSL. (server.crt et surment manquant.)")

def login():
    # Utiliser return au lieu de exit() pour revenir au menu principal en cas d'erreur
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        try:
            client.connect((HOST, PORT))
            print("🔐 Connexion au serveur en cours...")
            global secure_client
            secure_client = context.wrap_socket(client, server_hostname=HOST)
        except ConnectionRefusedError:
             print("❌ Connexion refusée. Le serveur est-il démarré et accessible?")
             input("Appuyez sur Entrée pour continuer...") # Pause pour voir le message
             return # Retourne au menu
        except Exception as e:
             print(f"❌ Erreur de connexion initiale: {e}")
             input("Appuyez sur Entrée pour continuer...")
             return # Retourne au menu

        # Authentification
        try:
            # --- MODIFICATION START ---
            # 1. Demander l'identifiant D'ABORD
            username = input("Identifiant : ")
            # 2. Envoyer l'identifiant
            secure_client.send(username.encode())

            # 3. Attendre le prompt du mot de passe (ou un message d'erreur initial comme IP_LOCKED)
            response = secure_client.recv(1024).decode()

            # Gérer les erreurs potentielles reçues AVANT le prompt du mot de passe
            # Le serveur peut envoyer IP_LOCKED immédiatement s'il détecte un blocage
            if response == "IP_LOCKED":
                print("❌ Votre IP est bloquée. Réessayez plus tard.")
                secure_client.close()
                input("Appuyez sur Entrée pour continuer...")
                return # Retourne au menu
            elif response != "MOT DE PASSE : ":
                # Si on ne reçoit pas le prompt attendu, il y a un problème
                # Cela peut arriver si le serveur envoie AUTH_FAIL pour une autre raison
                # ou si le protocole est désynchronisé.
                print(f"❌ Réponse inattendue du serveur après l'envoi de l'identifiant: {response}")
                secure_client.close()
                input("Appuyez sur Entrée pour continuer...")
                return # Retourne au menu

            # 4. Afficher le prompt reçu et demander le mot de passe
            print(response, end="") # Affiche "MOT DE PASSE : "
            password = getpass.getpass()
            # 5. Envoyer le mot de passe
            secure_client.send(password.encode())

            # 6. Recevoir la réponse finale d'authentification
            auth_response = secure_client.recv(1024).decode()
            # --- MODIFICATION END ---

            if auth_response == "AUTH_FAIL":
                print("❌ Authentification échouée (Identifiant ou mot de passe incorrect)!")
            elif auth_response == "AUTH_SUCCESS":
                print("✅ Authentification réussie ! Vous pouvez maintenant discuter.")
                # Continuer vers le chat...
                cle_utilisateur = getpass.getpass("🔑 Entrez votre clé de chiffrement : ")
                threading.Thread(target=receive_messages, args=(secure_client, cle_utilisateur), daemon=True).start()
                aff_menu(secure_client, username, cle_utilisateur)
                # Si aff_menu se termine (déconnexion), la fonction login se termine aussi.
                return # Retourne au menu après déconnexion normale
            elif auth_response == "IP_LOCKED": # Peut aussi être reçu après échecs répétés
                 print("❌ Trop de tentatives échouées. Votre IP est bloquée.")
            else:
                # Gérer d'autres réponses possibles (AUTH_TIMEOUT, etc.)
                print(f"❌ Erreur d'authentification inattendue: {auth_response}")

        except ssl.SSLError as e:
             print(f"❌ Erreur SSL: {e}. Vérifiez les certificats ou la configuration SSL.")
        except ConnectionResetError:
             print("❌ La connexion a été réinitialisée par le serveur pendant l'authentification.")
        except Exception as e:
            print(f"❌ Erreur pendant l'authentification : {e}")
        finally:
            # Assurer la fermeture propre du socket si ce n'est pas déjà fait
            try:
                if secure_client.fileno() != -1: # Vérifie si le socket est encore ouvert
                    secure_client.close()
            except Exception:
                pass # Ignore les erreurs lors de la fermeture

        # Si on arrive ici, c'est qu'il y a eu une erreur ou échec d'authentification
        input("Appuyez sur Entrée pour continuer...")
        return # Retourne au menu principal

def aes_encrypt(texte, cle_utilisateur):
    try:
        """Chiffre le texte avec AES en utilisant une clé dérivée"""
        salt = get_random_bytes(16)
        key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2 ** 14, r=8, p=1)

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

        key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2 ** 14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        decrypted_text = cipher.decrypt(encrypted_text)

        # Retirer le padding PKCS7 proprement
        decrypted_text = unpad(decrypted_text, AES.block_size)

        return decrypted_text.decode()
    except:
        print("Erreur lors du déchiffrement.")
        return "⚠️ Impossible de déchiffrer le message reçu. Ignoré. "


def receive_messages(client_socket, cle_session):
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode()
            if encrypted_message:
                if encrypted_message.startswith("MESSAGE_FROM:"):
                    parts = encrypted_message.split(":", 2)
                    if len(parts) == 3:
                        sender, content = parts[1], parts[2]
                        try:
                            decrypted_message = aes_decrypt(content, cle_session)
                            print(f"\n📥 Message de {sender} : {decrypted_message}\n> ", end="")
                        except:
                            print(f"\n⚠️ Impossible de déchiffrer le message reçu de {sender}. Ignoré.\n> ", end="")
                    else:
                        print(f"\n⚠️ Message reçu dans un format invalide : {encrypted_message}\n> ", end="")
                else:
                    try:
                        decrypted_message = aes_decrypt(encrypted_message, cle_session)
                        print(f"\n📥 Message reçu : {decrypted_message}\n> ", end="")
                    except:
                        print(f"\n⚠️ Impossible de déchiffrer le message reçu. Ignoré.\n> ", end="")
        except:
            print("❌ Connexion au serveur perdue.")
            break



def env_msg(secure_client, cle_utilisateur, username):
    try:
        while True:
            print("Entrer exit en tant que message pour quitter.")
            recipient = input("Destinataire (ou 'all' pour tous) : ")
            message = input("Message : ")
            if message.lower() == "exit":
                aff_menu(secure_client, username, cle_utilisateur)
                return
            if secure_client.fileno() == -1:
                print("Connexion perdue.")
                break
            if recipient.lower() == "all":
                message_to_send = aes_encrypt(message, cle_utilisateur) # Chiffrer le message sans le nom d'utilisateur
            else:
                message_to_send = f"SEND_TO:{recipient}:{aes_encrypt(message, cle_utilisateur)}" # Chiffrer le message
            try:
                secure_client.send(message_to_send.encode())
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


def cree_compte():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((HOST, PORT))
        secure_client = context.wrap_socket(client, server_hostname=HOST)

        secure_client.send(b"CREATE_ACCOUNT")  # Indique au serveur qu'on veut créer un compte

        username = input("Nom d'utilisateur : ")
        secure_client.send(username.encode())

        password = getpass.getpass("Mot de passe : ")
        secure_client.send(password.encode())

        response = secure_client.recv(1024).decode() # Wait for the response from the server
        if response == "ACCOUNT_CREATED":
            print("✅ Compte créé avec succès !")
        elif response == "USERNAME_TAKEN":
            print("❌ Ce nom d'utilisateur est déjà pris.")
        else:
            print("❌ Erreur lors de la création du compte.")
        
        secure_client.close() # close the connection after receiving the response.
        input("Appuyez sur Entrée pour continuer...")
        Start_menu()

# Fonction pour les menue
def clear_ecran():
    """Effacer le terminal en fonction de l'OS."""
    try:
        os.system('cls' if os.name == 'nt' else 'clear')
    except:
        print("Vous utiliser un os non compatible donc l'écran na pas pu être effacé.")


def aff_menu(secure_client, username, cle_utilisateur):
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
    choix = input("Choisissez une option: ")
    if choix == '1':
        print(f"Vous avez choisit {choix} Le menue envoyez un message est affiché")
        env_msg(secure_client, cle_utilisateur, username)  # Pass secure_client, username and cle_utilisateur
    elif choix == '2':
        print(f"Vous avez choisit {choix} Pour créé un groupe (option non disponible)")
        autre_menu(secure_client, username, cle_utilisateur)
    elif choix == '3':
        print(f"Vous avvez choisit {choix} Pour Ajouter un ami (vous avez pas d'ami) (option non disponible)")
        autre_menu(secure_client, username, cle_utilisateur)
    elif choix == '4':
        print(f"Vous avvez choisit {choix} pour bloquer un utilisateur (option non disponible)")
        autre_menu(secure_client, username, cle_utilisateur)
    elif choix == '5':
        print(f"Menue {choix} affiché pour signaler (option non disponible)")
        autre_menu(secure_client, username, cle_utilisateur)
    elif choix == '6':
        print("Au revoir!")
        secure_client.send(b"EXIT")  # Envoyez les message de déconnection aux serveur
        secure_client.shutdown(socket.SHUT_RDWR)  # Fermer la connection en lecture seul
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        aff_menu(secure_client, username, cle_utilisateur)


def autre_menu(secure_client, username, cle_utilisateur):
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
        autre_menu(secure_client, username, cle_utilisateur)
    elif choix == '2':
        print("Option 2 sélectionnée.")
        input("Appuyez sur Entrée pour continuer...")
        autre_menu(secure_client, username, cle_utilisateur)
    elif choix == '3':
        aff_menu(secure_client, username, cle_utilisateur)
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        autre_menu(secure_client, username, cle_utilisateur)


def Start_menu():
    clear_ecran()
    print("╔══════════════════════════════════════════╗")
    print("║      Que voulais vous faire ?            ║")
    print("╠══════════════════════════════════════════╣")
    print("║ 1. Ce connecter                          ║")
    print("║ 2. Créé un compte                        ║")
    print("║ 3. Quitter                               ║")
    print("╚══════════════════════════════════════════╝")
    choix = input("  Choisissez une option: ")
    if choix == '1':
        print("Ce conencter")
        input("Appuyez sur Entrée pour continuer...")
        login()
    elif choix == '2':
        print("créé un compte.")
        input("Appuyez sur Entrée pour continuer...")
        cree_compte()
    elif choix == '3':
        print("Vous avez choisit de fermer le programme.")
        exit()
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        Start_menu()

# Connexion au serveur avec gestion de la connexion SSL
try:
    Start_menu()  # menu de départ
except Exception as e:
    print(f"❌ Une erreur est survenue: ( {e} )")

print("❌ Connexion au serveur perdue.")
try:
    secure_client.close()
except:
    pass
input("Appuyez sur Entrée pour quitter...")
exit()
