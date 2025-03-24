import asyncio
import hashlib
import os
import hmac
import ssl
import json
import time
import logging
from collections import defaultdict

# --- Configuration générale ---
HOST = '127.0.0.1'
PORT = 54424
MAX_MESSAGE_SIZE = 4024  # Taille max des messages (octets)

# --- Configuration des limites et sécurité ---
CONNECTION_RATE_LIMIT = 10  # Connexions max/sec
MAX_CONNECTIONS_PER_IP = 5   # Connexions max/IP
MAX_MESSAGE_RATE = 50        # Messages max/sec
AUTH_TIMEOUT = 10            # Temps max pour l'authentification (s)
MAX_FAILED_LOGIN_ATTEMPTS = 3  # Essais avant blocage
ACCOUNT_LOCKOUT_DURATION = 60  # Durée de blocage du compte (s)
IP_LOCKOUT_DURATION = 120      # Durée de blocage de l'IP (s)

# --- Logs et gestion des connexions ---
clients = {}
IP_CONNECTION_HISTORY = defaultdict(list)
IP_MESSAGE_HISTORY = defaultdict(list)
IP_FAILED_LOGIN_ATTEMPTS = defaultdict(int)
ACCOUNT_LOCKOUT_UNTIL = defaultdict(float)
IP_LOCKOUT_UNTIL = defaultdict(float)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- Gestion des utilisateurs ---
def load_user(username, filename="data/users.json"):
    """Charge un utilisateur depuis un fichier JSON."""
    if os.path.exists(filename):
        try:
            with open(filename, "r") as file:
                users = json.load(file)
                return users.get(username)
        except json.JSONDecodeError:
            logging.error(f"Erreur de lecture du fichier {filename}")
    return None

def add_user(username, password, filename="data/users.json"):
    """Ajoute un nouvel utilisateur avec hashage sécurisé."""
    users = {}
    if os.path.exists(filename):
        with open(filename, "r") as file:
            users = json.load(file)

    salt = os.urandom(16)
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    users[username] = {"password_hash": password_hash.hex(), "salt": salt.hex()}

    with open(filename, "w") as file:
        json.dump(users, file, indent=4)

    logging.info(f"Utilisateur {username} ajouté avec succès.")

def verify_user(username, password, filename="data/users.json"):
    """Vérifie les identifiants de l'utilisateur."""
    user_data = load_user(username, filename)
    if user_data:
        stored_hash = bytes.fromhex(user_data["password_hash"])
        salt = bytes.fromhex(user_data["salt"])
        received_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(stored_hash, received_hash)
    return False

# --- Authentification ---
async def authenticate(reader, writer, ip_address):
    """Gère l'authentification des utilisateurs."""
    current_time = time.time()

    if IP_LOCKOUT_UNTIL[ip_address] > current_time:
        logging.warning(f"Connexion refusée (IP bloquée) : {ip_address}")
        writer.write(b"IP_LOCKED")
        await writer.drain()
        return None

    try:
        writer.write(b"IDENTIFIANT : ")
        await writer.drain()
        username = (await asyncio.wait_for(reader.read(1024), timeout=AUTH_TIMEOUT)).decode().strip()

        writer.write(b"MOT DE PASSE : ")
        await writer.drain()
        password = (await asyncio.wait_for(reader.read(1024), timeout=AUTH_TIMEOUT)).decode().strip()

        if verify_user(username, password):
            logging.info(f"Connexion réussie : {username} ({ip_address})")
            writer.write(b"AUTH_SUCCESS") # Explicit success message
            await writer.drain()
            return username

        logging.warning(f"Échec de connexion : {username} ({ip_address})")
        IP_FAILED_LOGIN_ATTEMPTS[ip_address] += 1
        if IP_FAILED_LOGIN_ATTEMPTS[ip_address] >= MAX_FAILED_LOGIN_ATTEMPTS:
            IP_LOCKOUT_UNTIL[ip_address] = current_time + IP_LOCKOUT_DURATION
            logging.warning(f"IP bloquée : {ip_address} ({IP_LOCKOUT_DURATION}s)")
        
    except asyncio.TimeoutError:
        logging.warning(f"Temps dépassé pour {ip_address}")
    except Exception as e:
        logging.error(f"Erreur d'authentification : {e}")

    writer.write(b"AUTH_FAIL")
    await writer.drain()
    return None

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

            # Répercuter le message aux autres clients
            for user, client_writer in clients.items():
                if user != username:
                    try:
                        client_writer.write(message)
                        await client_writer.drain()
                    except Exception as e:
                        logging.error(f"Erreur d'envoi à {user}: {e}")

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
        logging.error(f"Erreur (OSError) pour {username}: {e} (un client s'est déconnecté brutalement en fermant le terminal (le plus probable) ?)")
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

async def main():
    """Démarre le serveur sécurisé."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="SSL/server.crt", keyfile="SSL/server.key")
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # ⚠ À modifier en production !

    server = await asyncio.start_server(handle_client_wrapper, HOST, PORT, ssl=context)
    logging.info(f"Serveur en écoute sur {HOST}:{PORT}")
    await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())