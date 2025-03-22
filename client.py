import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os
import getpass
import ssl

CRYP_KEY = b'0123456789abcdef0123456789abcdef'
HOST = '127.0.0.1'
PORT = 54424

#certificat
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="server.crt")
context.check_hostname = False  # désactiver la vérification
context.verify_mode = ssl.CERT_NONE  # désactiver la vérification

def encrypt_message(message):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()
    cipher = Cipher(algorithms.AES(CRYP_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_message

def decrypt_message(encrypted_message):
    iv = encrypted_message[:16]
    encrypted_data = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(CRYP_KEY), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted_message

def receive_messages(client_socket):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                decrypted_message = decrypt_message(encrypted_message)
                print(f"\n📥 Message reçu : {decrypted_message.decode()}\n> ", end="")
        except:
            print("❌ Connexion au serveur perdue.")
            break

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    secure_client = context.wrap_socket(client, server_hostname=HOST)
    secure_client.connect((HOST, PORT))

    print(secure_client.recv(1024).decode(), end="")
    nom_user = input()
    secure_client.send(nom_user.encode())

    print(secure_client.recv(1024).decode(), end="")
    mdp = getpass.getpass()
    secure_client.send(mdp.encode())

    auth_response = secure_client.recv(1024).decode()
    if auth_response == "AUTH_FAIL":
        print("❌ Authentification échouée !")
        secure_client.close()
        exit()
    
    print("✅ Authentification réussie ! Vous pouvez maintenant discuter.")

    threading.Thread(target=receive_messages, args=(secure_client,), daemon=True).start()

    while True:
        message = input("> ")
        if message.lower() == "exit":
            break
        message = nom_user + " : " + message
        encrypted_message = encrypt_message(message.encode('utf-8'))
        secure_client.sendall(encrypted_message)

    print("❌ Déconnexion...")
