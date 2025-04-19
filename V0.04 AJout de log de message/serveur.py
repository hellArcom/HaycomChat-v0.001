import asyncio
import hashlib
import os
import hmac
import ssl
import json
import time
import logging
from collections import defaultdict

##############################
# Variables de configuration

# --- Configuration générale ---
HOST = '127.0.0.1'
PORT = 54424

MAX_MESSAGE_SIZE = 4024  # Taille max des messages (octets)

# --- Configuration des limites et sécurité ---
CONNECTION_RATE_LIMIT = 10  # Connexions max/sec
MAX_CONNECTIONS_PER_IP = 5  # Connexions max/IP
MAX_MESSAGE_RATE = 10  # Messages max/sec
AUTH_TIMEOUT = 20  # Temps max pour l'authentification (s)
MAX_FAILED_LOGIN_ATTEMPTS = 3  # Essais avant blocage
ACCOUNT_LOCKOUT_DURATION = 60  # Durée de blocage du compte (s)
IP_LOCKOUT_DURATION = 120  # Durée de blocage de l'IP (s)

# --- Logs et gestion des connexions ---
clients = {}
IP_CONNECTION_HISTORY = defaultdict(list)
IP_MESSAGE_HISTORY = defaultdict(list)
IP_FAILED_LOGIN_ATTEMPTS = defaultdict(int)
ACCOUNT_LOCKOUT_UNTIL = defaultdict(float)
IP_LOCKOUT_UNTIL = defaultdict(float)

## fin des vraibles de configuration
##############################

# --- Configuration des logs ---
try:
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
except:
    print("Erreur lors de la configuration des logs.")


# --- Gestion des utilisateurs ---
# Charger les utilisateur de la DB
def load_users_data(filename="Data/user.json"):
    """Charge les données des utilisateurs depuis un fichier JSON."""
    if os.path.exists(filename):
        try:
            with open(filename, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            logging.error(f"Erreur de lecture du fichier {filename}")
    return {"utilisateurs": {}, "groupes": {}, "demandes_amis": []}


def load_user(username, filename="Data/user.json"):
    """Charge un utilisateur depuis un fichier JSON."""
    users_data = load_users_data(filename)
    return users_data["utilisateurs"].get(username)


# Ajouter un utilisateur a la base de donner
def add_user(username, password, filename="Data/user.json"):
    """Ajoute un nouvel utilisateur avec hashage sécurisé."""
    try:
        users_data = load_users_data(filename)
        users = users_data["utilisateurs"]

        if username in users:
            return False

        # Générer un salt aléatoire
        salt = os.urandom(16)

        # Hasher le mot de passe avec le salt
        password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

        users[username] = {
            "mot_de_passe": password_hash.hex(),  # Stocker le hash en hexadécimal
            "salt": salt.hex(),  # Stocker le salt en hexadécimal
            "amis": [],
            "bloques": [],
            "sessions": [],
            "derniere_connexion": time.strftime("%Y-%m-%dT%H:%M:%S")
        }

        with open(filename, "w") as file:
            json.dump(users_data, file, indent=4)

        logging.info(f"Utilisateur {username} ajouté avec succès.")
        return True

    except Exception as e:
        logging.error(f"Erreur lors de l'ajout de l'utilisateur {username}: {e}")
        return False


async def create_account(reader, writer, ip_address):
    """Gère la création d'un nouveau compte."""
    try:
        username = (await asyncio.wait_for(reader.read(1024), timeout=AUTH_TIMEOUT)).decode().strip()
        password = (await asyncio.wait_for(reader.read(1024), timeout=AUTH_TIMEOUT)).decode().strip()

        if add_user(username, password):
            writer.write(b"ACCOUNT_CREATED")
            await writer.drain()
            logging.info(f"Nouveau compte créé : {username} ({ip_address})")
        else:
            writer.write(b"USERNAME_TAKEN")
            await writer.drain()
            logging.warning(
                f"Tentative de création de compte avec un nom d'utilisateur déjà pris : {username} ({ip_address})")
    except asyncio.TimeoutError:
        logging.warning(f"Temps dépassé pour la création de compte {ip_address}")
        writer.write(b"AUTH_FAIL")
        await writer.drain()
    except Exception as e:
        logging.error(f"Erreur lors de la création du compte : {e}")
        writer.write(b"AUTH_FAIL")
        await writer.drain()

async def authenticate(reader, writer, ip_address):
    """Gère l'authentification et la création de compte."""
    current_time = time.time()
    try:
        # --- Vérification du blocage IP (inchangée) ---
        if IP_LOCKOUT_UNTIL[ip_address] > current_time:
            logging.warning(f"Connexion refusée (IP bloquée) : {ip_address}")
            writer.write(b"IP_LOCKED")
            await writer.drain()
            return None
    except Exception as e:
        logging.error(f"Erreur lors de la vérification du blocage IP pour {ip_address}: {e}")
        try:
            if not writer.is_closing():
                writer.write(b"AUTH_FAIL") # Ou un code d'erreur serveur interne
                await writer.drain()
        except Exception: pass
        return None

    try:
        # --- MODIFICATION START ---
        # 1. Lire la TOUTE PREMIERE chose envoyée par le client
        #    Ce sera soit "CREATE_ACCOUNT", soit le nom d'utilisateur pour une connexion.
        first_input_bytes = await asyncio.wait_for(reader.read(1024), timeout=AUTH_TIMEOUT)
        first_input = first_input_bytes.decode().strip()

        # 2. Vérifier si c'est une demande de création de compte
        if first_input == "CREATE_ACCOUNT":
            # 3a. Si oui, appeler create_account qui lira username/password et enverra la réponse
            #    PAS D'ENVOI DE PROMPT ICI.
            logging.debug(f"Requête CREATE_ACCOUNT reçue de {ip_address}")
            await create_account(reader, writer, ip_address)
            # create_account gère l'envoi de ACCOUNT_CREATED/USERNAME_TAKEN/AUTH_FAIL
            return None # La création de compte gère sa propre fin de communication

        # 3b. Si non, c'était une tentative de connexion, first_input est le username
        else:
            username = first_input
            logging.debug(f"Tentative de connexion pour: {username} ({ip_address})")

            # 4. Envoyer le prompt pour le mot de passe SEULEMENT MAINTENANT
            writer.write(b"MOT DE PASSE : ")
            await writer.drain()

            # 5. Lire le mot de passe
            password = (await asyncio.wait_for(reader.read(1024), timeout=AUTH_TIMEOUT)).decode().strip()

            # 6. Vérifier les identifiants (logique existante)
            if verify_user(username, password):
                IP_FAILED_LOGIN_ATTEMPTS[ip_address] = 0 # Reset on success
                logging.info(f"Connexion réussie : {username} ({ip_address})")
                writer.write(b"AUTH_SUCCESS")
                await writer.drain()
                update_last_login(username)
                return username # Retourner le nom d'utilisateur pour handle_client
            else: # verify_user returned False
                logging.warning(f"Échec de connexion : {username} ({ip_address})")
                IP_FAILED_LOGIN_ATTEMPTS[ip_address] += 1
                if IP_FAILED_LOGIN_ATTEMPTS[ip_address] >= MAX_FAILED_LOGIN_ATTEMPTS:
                    IP_LOCKOUT_UNTIL[ip_address] = current_time + IP_LOCKOUT_DURATION
                    logging.warning(f"IP bloquée : {ip_address} ({IP_LOCKOUT_DURATION}s)")
                    writer.write(b"IP_LOCKED")
                    await writer.drain()
                else:
                    writer.write(b"AUTH_FAIL")
                    await writer.drain()
                return None # Échec de l'authentification
        # --- MODIFICATION END ---

    except asyncio.TimeoutError:
        logging.warning(f"Temps dépassé pendant l'authentification/création de compte pour {ip_address}")
        try:
            if not writer.is_closing():
                writer.write(b"AUTH_TIMEOUT") # Ou b"AUTH_FAIL"
                await writer.drain()
        except Exception: pass
        return None
    except ConnectionResetError:
        logging.warning(f"Connexion réinitialisée par {ip_address} pendant l'authentification/création.")
        return None
    except Exception as e:
        logging.error(f"Erreur inattendue pendant l'authentification/création pour {ip_address}: {e}")
        try:
            if not writer.is_closing():
                writer.write(b"AUTH_FAIL")
                await writer.drain()
        except Exception: pass
        return None


    except asyncio.TimeoutError:
        logging.warning(f"Temps dépassé pour l'authentification de {ip_address}")
        try:
            if not writer.is_closing():
                # Envoyer AUTH_TIMEOUT si possible, sinon AUTH_FAIL pourrait être plus générique
                writer.write(b"AUTH_TIMEOUT") # Ou b"AUTH_FAIL"
                await writer.drain()
        except Exception: pass
        return None
    except ConnectionResetError:
        logging.warning(f"Connexion réinitialisée par {ip_address} pendant l'authentification.")
        return None
    except Exception as e:
        logging.error(f"Erreur d'authentification inattendue pour {ip_address}: {e}")
        try:
            if not writer.is_closing():
                writer.write(b"AUTH_FAIL")
                await writer.drain()
        except Exception: pass
        return None


# Vérifier les identifiants de l'utilisateur
def verify_user(username, password, filename="Data/user.json"):
    """Vérifie les identifiants de l'utilisateur."""
    try:
        user_data = load_user(username, filename)
        if user_data:
            # Récupérer le salt et le hash stocké
            salt = bytes.fromhex(user_data["salt"])
            stored_hash = bytes.fromhex(user_data["mot_de_passe"])

            # Hasher le mot de passe avec le salt récupéré
            received_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

            # Comparer les hashs
            logging.debug(f"Hash stocké: {stored_hash.hex()}")
            logging.debug(f"Hash reçu: {received_hash.hex()}")
            return hmac.compare_digest(stored_hash, received_hash)
        return False
    except Exception as e:
        logging.error(f"Erreur lors de la vérification de l'utilisateur {username}: {e}")
        return False

def update_last_login(username, filename="Data/user.json"):
    """Met à jour la date de dernière connexion de l'utilisateur."""
    try:
        users_data = load_users_data(filename)
        user = users_data["utilisateurs"].get(username)
        if user:
            user["derniere_connexion"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            with open(filename, "w") as file:
                json.dump(users_data, file, indent=4)
    except Exception as e:
        logging.error(f"Erreur lors de la mise à jour de la dernière connexion de {username}: {e}")

# --- Gestion des messages ---
def load_messages_data(filename="Data/msg.json"):
    """Charge les données des messages depuis un fichier JSON."""
    if os.path.exists(filename):
        try:
            with open(filename, "r") as file:
                return json.load(file)
        except json.JSONDecodeError:
            logging.error(f"Erreur de lecture du fichier {filename}")
    return {"messages": [], "signalements": [], "archives": {"messages": []}}

def save_message(sender, recipient, content, filename="Data/msg.json"):
    """Enregistre un message dans le fichier JSON."""
    try:
        messages_data = load_messages_data(filename)
        messages_data["messages"].append({
            "envoyeur": sender,
            "destinataire": recipient,
            "contenu": content,
            "horodatage": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "statut": "non_lu"
        })
        with open(filename, "w") as file:
            json.dump(messages_data, file, indent=4)
    except Exception as e:
        logging.error(f"Erreur lors de l'enregistrement du message: {e}")

# --- Gestion des clients ---
async def handle_client(reader, writer, username, ip_address):
    """Gère la communication avec un client connecté."""
    clients[username] = writer
    try:
        while True:
            message = await reader.read(MAX_MESSAGE_SIZE)
            if not message:
                break
            if message == b"EXIT":
                break

            # Protection contre le flood
            current_time = time.time()
            IP_MESSAGE_HISTORY[ip_address].append(current_time)
            IP_MESSAGE_HISTORY[ip_address] = [t for t in IP_MESSAGE_HISTORY[ip_address] if current_time - t < 1]
            if len(IP_MESSAGE_HISTORY[ip_address]) > MAX_MESSAGE_RATE:
                logging.warning(f"Trop de messages de {username} ({ip_address})")
                break

            try:
                decoded_message = message.decode()
                if decoded_message.startswith("SEND_TO:"):
                    parts = decoded_message.split(":", 2)
                    if len(parts) == 3:
                        recipient, content = parts[1], parts[2]
                        save_message(username, recipient, content)
                        if recipient in clients:
                            try:
                                # Le serveur envoie le message tel quel (chiffré)
                                clients[recipient].write(f"MESSAGE_FROM:{username}:{content}".encode())
                                await clients[recipient].drain()
                            except Exception as e:
                                logging.error(f"Erreur d'envoi à {recipient}: {e}")
                        else:
                            logging.warning(f"Utilisateur {recipient} non connecté.")
                    else:
                        logging.warning(f"Format de message invalide : {decoded_message}")
                    continue
                else:
                    # Répercuter le message aux autres clients
                    for user, client_writer in clients.items():
                        if user != username:
                            try:
                                # Le serveur envoie le message tel quel (chiffré)
                                client_writer.write(f"{username} : {decoded_message}".encode())
                                await client_writer.drain()
                            except Exception as e:
                                logging.error(f"Erreur d'envoi à {user}: {e}")
            except UnicodeDecodeError:
                logging.error(f"Erreur de décodage du message reçu de {username}")

    except asyncio.CancelledError:
        pass  # Already handled
    except ConnectionResetError:
        logging.warning(f"Connexion interrompue par {username} ({ip_address})")
    except asyncio.TimeoutError:
        # Client hasn't sent anything in a while, assume disconnect
        logging.warning(f"Client {username} ({ip_address}) timed out.")
    except asyncio.CancelledError:
        pass
    except OSError as e:
        logging.error(
            f"Erreur (OSError) pour {username}: {e} (un client s'est déconnecté brutalement en fermant le terminal (le plus probable) ?)")
    except Exception as e:
        logging.error(f"Erreur dans handle_client pour {username}: {e}")
    finally:
        logging.info(f"Déconnexion de {username}")
        del clients[username]
        if not writer.is_closing():
            writer.close()
        await writer.wait_closed()


async def handle_client_wrapper(reader, writer):
    """Gère la connexion, applique les limites et démarre la session client."""
    try:
        peername = writer.get_extra_info('peername')
        if peername is None:
            logging.warning("Impossible d'obtenir l'IP du client.")
            writer.close()
            await writer.wait_closed()
            return

        ip_address = peername[0]
        current_time = time.time()

        # Protection contre les connexions excessives
        IP_CONNECTION_HISTORY[ip_address].append(current_time)
        IP_CONNECTION_HISTORY[ip_address] = [t for t in IP_CONNECTION_HISTORY[ip_address] if current_time - t < 1]
        if len(IP_CONNECTION_HISTORY[ip_address]) > CONNECTION_RATE_LIMIT:
            logging.warning(f"Trop de connexions depuis {ip_address}")
            writer.close()
            await writer.wait_closed()
            return

        # Vérification du nombre max de connexions par IP
        ip_connection_count = sum(
            1 for w in clients.values() if w.get_extra_info('peername')[0] == ip_address
        )
        if ip_connection_count >= MAX_CONNECTIONS_PER_IP:
            logging.warning(f"Limite de connexions atteinte pour {ip_address}")
            writer.close()
            await writer.wait_closed()
            return

        # Authentification et gestion du client
        username = await authenticate(reader, writer, ip_address)
        if username:
            await handle_client(reader, writer, username, ip_address)

    except Exception as e:
        print(f"Erreur dans handle_client_wrapper {e}")

async def main():
    try:
        """Démarre le serveur sécurisé."""
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="SSL/server.crt", keyfile="SSL/server.key")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE  # /!\ À modifier en production !

        server = await asyncio.start_server(handle_client_wrapper, HOST, PORT, ssl=context)
        logging.info(f"Serveur en écoute sur {HOST}:{PORT}")
        await server.serve_forever()
    except Exception as e:
        print(f"Erreur lors du démarrage du serveur. (Dans async def main) erreur : {e}")
        logging.error(f"Erreur lors du démarrage du serveur : {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        print("Erreur dans main {e} pour la partie if __name__ == __main__")
        logging.error(f"Erreur dans main : {e}")
