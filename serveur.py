import socket
import threading
import json
import hashlib
import os
import hmac
import ssl

HOST = '127.0.0.1'
PORT = 54424
clients = {}
login_attempts = {}

def load_users(json_filename="users.json"):
    if os.path.exists(json_filename):
        with open(json_filename, "r") as file:
            return json.load(file)
    return {}

def verify_user(username, password, json_filename="users.json"):
    users_data = load_users(json_filename)
    if username in users_data:
        stored_hash = bytes.fromhex(users_data[username]["password_hash"])
        salt = bytes.fromhex(users_data[username]["salt"])
        received_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return hmac.compare_digest(stored_hash, received_hash)
    return False


def authenticate(client_socket):
    client_socket.send(b"IDENTIFIANT : ")
    username = client_socket.recv(1024).decode().strip()

    if login_attempts.get(username, 0) >= 3:
        client_socket.send(b"ACCOUNT_LOCKED")
        print(f"🚫 {username} est bloqué après plusieurs tentatives.")
        return None

    client_socket.send(b"MOT DE PASSE : ")
    password = client_socket.recv(1024).decode().strip()

    if verify_user(username, password):
        client_socket.send(b"AUTH_SUCCESS")
        login_attempts[username] = 0
        print(f"✅ {username} authentifié !")
        return username
    else:
        login_attempts[username] = login_attempts.get(username, 0) + 1
        client_socket.send(b"AUTH_FAIL")
        print(f"❌ Tentative échouée pour {username} ({login_attempts[username]}/3)")

    return None

def handle_client(client_socket, username):
    clients[username] = client_socket
    try:
        while True:
            message = client_socket.recv(1024)
            if not message:
                break
            for user, client in clients.items():
                if client != client_socket:
                    client.sendall(message)
    except:
        pass
    finally:
        print(f"❌ {username} déconnecté.")
        del clients[username]
        client_socket.close()

if __name__ == "__main__":  # Ajoutez ce bloc
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind((HOST, PORT))
        server.listen()
        print(f"🚀 Serveur en écoute sur {HOST}:{PORT}")
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server.crt", keyfile="server.key")

        while True:
            client_socket, _ = server.accept()
            secure_socket = context.wrap_socket(client_socket, server_side=True)
            username = authenticate(secure_socket)
            
            if username:
                threading.Thread(target=handle_client, args=(secure_socket, username), daemon=True).start()
            else:
                client_socket.close()
