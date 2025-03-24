import asyncio
import hashlib
import os
import hmac
import ssl
import json
import time
import logging
from collections import defaultdict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 54424
clients = {}  # Dictionnaire des clients connectés
login_attempts = {}

# Configuration du journal
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

MAX_MESSAGE_SIZE = 4024  # Taille maximale des messages en octets

# --- DoS/DDoS Protection ---
CONNECTION_RATE_LIMIT = 10  # Max connections per second
CONNECTION_RATE_WINDOW = 1  # Time window for rate limiting (in seconds)
MAX_CONNECTIONS_PER_IP = 5  # Max connections from a single IP
MAX_MESSAGE_RATE = 50  # Max messages per second
MESSAGE_RATE_WINDOW = 1  # Time window for message rate limiting (in seconds)
IP_CONNECTION_HISTORY = defaultdict(list)
IP_MESSAGE_HISTORY = defaultdict(list)
# --- End DoS/DDoS Protection ---

# --- SYN Flood Protection ---
AUTHENTICATION_TIMEOUT = 10  # Seconds to wait for authentication
AUTHENTICATION_RATE_LIMIT = 5  # Max authentication per second
AUTHENTICATION_RATE_WINDOW = 1  # Time window for authentication rate limiting (in seconds)
IP_AUTHENTICATION_HISTORY = defaultdict(list)
# --- End SYN Flood Protection ---

# --- Brute-Force Protection ---
MAX_FAILED_LOGIN_ATTEMPTS = 3  # Max failed attempts before lockout
ACCOUNT_LOCKOUT_DURATION = 60  # Lockout duration in seconds
IP_LOCKOUT_DURATION = 120  # IP lockout duration in seconds
IP_FAILED_LOGIN_ATTEMPTS = defaultdict(int)  # Failed attempts per IP
IP_LOCKOUT_UNTIL = defaultdict(float)  # IP lockout expiration time
ACCOUNT_LOCKOUT_UNTIL = defaultdict(float)  # Account lockout expiration time
# --- End Brute-Force Protection ---

# Fonction pour charger les utilisateurs à la volée à partir du fichier JSON
def load_user(username, json_filename="users.json"):
    """Charge les informations d'un utilisateur depuis un fichier JSON."""

    if os.path.exists(json_filename):  # Vérifier si le fichier existe
        try:
            with open(json_filename, "r") as file:
                users_data = json.load(file)  # Charger les données JSON
                return users_data.get(username)  # Retourne l'utilisateur ou None

        except json.JSONDecodeError:
            logging.error(f"Erreur lors du décodage du fichier JSON [{json_filename}]")
            return None

    return None  # Retourner None si le fichier n'existe pas

def add_user_to_json(username, password, json_filename="users.json"):
    # Charger les utilisateurs existants
    if os.path.exists(json_filename):
        with open(json_filename, "r") as file:
            users_data = json.load(file)
    else:
        users_data = {}

    # Créer un salt unique
    salt = os.urandom(16)
    
    # Hacher le mot de passe avec PBKDF2
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    # Ajouter l'utilisateur au dictionnaire
    users_data[username] = {
        "password_hash": password_hash.hex(),
        "salt": salt.hex()
    }

    # Sauvegarder le fichier JSON
    with open(json_filename, "w") as file:
        json.dump(users_data, file, indent=4)

    print(f"✅ Utilisateur {username} ajouté avec succès au fichier JSON !")


# Vérifier les informations d'identification de l'utilisateur
def verify_user(username, password, json_filename="users.json"):
    if username.startswith("/create"):
        new_username = username[7:].strip()  # Extraire le nom d'utilisateur après "/create"
        if new_username:
            if load_user(new_username, json_filename):
                return "USERNAME_EXISTS" #Nom d'utilisateur déjà existant
            else:
                add_user_to_json(new_username, password)
                return "USER_CREATED" #remplacer par failled_auth
        else:
            return "INVALID_USERNAME" #Nom d'utilisateur invalide
    else:
        user_data = load_user(username, json_filename)
        if user_data:
            stored_hash = bytes.fromhex(user_data["password_hash"])
            salt = bytes.fromhex(user_data["salt"])
            received_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
            return hmac.compare_digest(stored_hash, received_hash)
        return False


# Authentifier l'utilisateur
async def authenticate(reader, writer, ip_address):
    current_time = time.time()

    # --- IP Lockout Check ---
    if IP_LOCKOUT_UNTIL[ip_address] > current_time:
        logging.warning(f"Tentative de connexion bloquée pour l'IP {ip_address} (bloquée).")
        writer.write(b"IP_LOCKED")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        return None

    # --- Authentication Rate Limiting ---
    IP_AUTHENTICATION_HISTORY[ip_address].append(current_time)
    IP_AUTHENTICATION_HISTORY[ip_address] = [t for t in IP_AUTHENTICATION_HISTORY[ip_address] if
                                             current_time - t < AUTHENTICATION_RATE_WINDOW]
    if len(IP_AUTHENTICATION_HISTORY[ip_address]) > AUTHENTICATION_RATE_LIMIT:
        logging.warning(f"Trop de tentatives d'authentification de l'IP {ip_address} dans un court laps de temps.")
        writer.close()
        await writer.wait_closed()
        return None
    # --- End Authentication Rate Limiting ---

    try:
  
        writer.write(b"IDENTIFIANT : ")
        await writer.drain()
        username_future = reader.read(1024)
        username = (await asyncio.wait_for(username_future, timeout=AUTHENTICATION_TIMEOUT)).decode().strip()

        writer.write(b"MOT DE PASSE : ")
        await writer.drain()
        password_future = reader.read(1024)
        password = (await asyncio.wait_for(password_future, timeout=AUTHENTICATION_TIMEOUT)).decode().strip()

        auth_result = verify_user(username, password)

        if auth_result == True:
            writer.write(b"AUTH_SUCCESS")
            await writer.drain()
            login_attempts[username] = 0
            IP_FAILED_LOGIN_ATTEMPTS[ip_address] = 0
            logging.info(f"Utilisateur {username} authentifié avec succès depuis {ip_address}.")
            return username
        elif auth_result == "USER_CREATED":
            writer.write(b"USER_CREATED")
            await writer.drain()
            logging.info(f"Utilisateur {username[7:]} créé avec succès.")
            return username[7:] # Retourner le nom d'utilisateur créé sans le préfixe "/create"
        elif auth_result == "USERNAME_EXISTS":
            writer.write(b"USERNAME_EXISTS")
            await writer.drain()
            logging.warning(f"Nom d'utilisateur déjà existant.")
            return None
        elif auth_result == "INVALID_USERNAME":
            writer.write(b"INVALID_USERNAME")
            await writer.drain()
            logging.warning(f"Nom d'utilisateur invalide.")
            return None
        else:
            # --- Account Lockout Check ---
            if ACCOUNT_LOCKOUT_UNTIL[username] > current_time:
                logging.warning(f"Tentative de connexion bloquée pour l'utilisateur {username} (compte bloqué).")
                writer.write(b"AUTH_FAIL")
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return None

        writer.write(b"MOT DE PASSE : ")
        await writer.drain()
        password_future = reader.read(1024)
        password = (await asyncio.wait_for(password_future, timeout=AUTHENTICATION_TIMEOUT)).decode().strip()

        if verify_user(username, password):
            writer.write(b"AUTH_SUCCESS")
            await writer.drain()
            login_attempts[username] = 0
            IP_FAILED_LOGIN_ATTEMPTS[ip_address] = 0  # Reset failed attempts on success
            logging.info(f"Utilisateur {username} authentifié avec succès depuis {ip_address}.")
            return username
        else:
            # Augmenter les tentatives de connexion
            login_attempts[username] = login_attempts.get(username, 0) + 1
            IP_FAILED_LOGIN_ATTEMPTS[ip_address] += 1
            writer.write(b"AUTH_FAIL")
            await writer.drain()
            logging.warning(f"Tentative d'authentification échouée pour {username} depuis {ip_address} ({login_attempts[username]}/{MAX_FAILED_LOGIN_ATTEMPTS}).")

            # --- Account Lockout ---
            if login_attempts[username] >= MAX_FAILED_LOGIN_ATTEMPTS:
                ACCOUNT_LOCKOUT_UNTIL[username] = time.time() + ACCOUNT_LOCKOUT_DURATION
                logging.warning(f"Compte {username} bloqué pour {ACCOUNT_LOCKOUT_DURATION} secondes.")

            # --- IP Lockout ---
            if IP_FAILED_LOGIN_ATTEMPTS[ip_address] >= MAX_FAILED_LOGIN_ATTEMPTS:
                IP_LOCKOUT_UNTIL[ip_address] = time.time() + IP_LOCKOUT_DURATION
                logging.warning(f"IP {ip_address} bloquée pour {IP_LOCKOUT_DURATION} secondes.")

            writer.close()
            await writer.wait_closed()

    except asyncio.TimeoutError:
        logging.warning(f"Délai d'authentification dépassé pour {ip_address}.")
        writer.close()
        await writer.wait_closed()
        return None
    except Exception as e:
        logging.error(f"Erreur lors de l'authentification: {e}")
        writer.close()
        await writer.wait_closed()
        return None
    except (asyncio.TimeoutError, ssl.SSLError, Exception) as e:  # Gérer plus d'exceptions
        logging.error(f"Erreur lors de l'authentification: {e}")
    finally:
        writer.close()  # Fermer le writer dans le bloc finally
        await writer.wait_closed()

    return None

# Gérer les messages des clients (envoyer immédiatement sans stocker en mémoire)
async def handle_client(reader, writer, username, ip_address):
    clients[username] = writer
    try:
        while True:
            try:
                message = await reader.read(MAX_MESSAGE_SIZE + 100) # Add 100 for the encryption
            except ConnectionResetError:
                logging.warning(f"Connexion réinitialisée par {username} ({ip_address}).")
                break
            except Exception as e:
                logging.error(f"Erreur de lecture de {username} ({ip_address}): {e}")
                break
            
            if not message:
                break

            # --- Message Size Check ---
            if len(message) > MAX_MESSAGE_SIZE + 100:
                logging.warning(f"Message trop volumineux reçu de {username} ({ip_address}).")
                break
            # --- End Message Size Check ---

            # --- Message Rate Limiting ---
            current_time = time.time()
            IP_MESSAGE_HISTORY[ip_address].append(current_time)
            IP_MESSAGE_HISTORY[ip_address] = [t for t in IP_MESSAGE_HISTORY[ip_address] if
                                              current_time - t < MESSAGE_RATE_WINDOW]
            if len(IP_MESSAGE_HISTORY[ip_address]) > MAX_MESSAGE_RATE:
                logging.warning(f"{username} ({ip_address}) a dépassé la limite de messages.")
                break
            # --- End Message Rate Limiting ---
            
            logging.debug(f"Message reçu de {username} ({ip_address}) : {len(message)} octets")

            # Envoyer directement les messages aux autres utilisateurs sans les stocker en mémoire
            for user, client_writer in clients.items():
                if client_writer != writer:
                    try:
                        client_writer.write(message)
                        await client_writer.drain()
                    except ConnectionResetError:
                        logging.warning(f"Connexion réinitialisée lors de l'envoi à {user}.")
                        break
                    except Exception as e:
                        logging.error(f"Erreur lors de l'envoi du message à {user}: {e}")
    except asyncio.CancelledError:
        pass  # Gestion propre de la déconnexion
    except Exception as e:
        logging.error(f"Erreur dans handle_client: {e}")
    finally:
        logging.info(f"Client {username} déconnecté.")
        del clients[username]
        try:
            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logging.error(f"Erreur lors de la fermeture de la connexion de {username}: {e}")

# Fonction principale de gestion du serveur
async def main():
    # Charger les certificats SSL pour sécuriser la connexion
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # A changer si les certificat SSL et valide 
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # -----------------------------------------

    # Créer le serveur avec SSL
    server = await asyncio.start_server(
        handle_client_wrapper,
        HOST, PORT,
        ssl=context  # Appliquer SSL ici
    )

    logging.info(f"Serveur en écoute sur {HOST}:{PORT}")
    await server.serve_forever()

# Wrapper pour gérer la connexion et l'authentification
async def handle_client_wrapper(reader, writer):
    # --- Limitation du débit de connexion ---
    peername = writer.get_extra_info('peername')
    if peername is None:
        logging.warning("Impossible de récupérer l'adresse IP du client.")
        writer.close()
        await writer.wait_closed()
        return
    ip_address = peername[0]
    current_time = time.time()
    IP_CONNECTION_HISTORY[ip_address].append(current_time)
    IP_CONNECTION_HISTORY[ip_address] = [t for t in IP_CONNECTION_HISTORY[ip_address] if
                                         current_time - t < CONNECTION_RATE_WINDOW]

    if len(IP_CONNECTION_HISTORY[ip_address]) > CONNECTION_RATE_LIMIT:
        logging.warning(f"Trop de connexions de {ip_address} dans un court laps de temps.")
        writer.close()
        await writer.wait_closed()
        return

    # --- NB max de co par ip ---
    ip_connection_count = sum(
        1 for client_peername in [w.get_extra_info('peername') for w in clients.values()] if
        client_peername and client_peername[0] == ip_address)
    if ip_connection_count >= MAX_CONNECTIONS_PER_IP:
        logging.warning(f"Trop de connexions de {ip_address} simultanées.")
        writer.close()
        await writer.wait_closed()
        return
    # ----------------------------

    username = await authenticate(reader, writer, ip_address)
    if username:
        await handle_client(reader, writer, username, ip_address)

# Exécuter l'app
if __name__ == "__main__":
    asyncio.run(main())