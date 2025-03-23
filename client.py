import socket
import threading
import ssl
import getpass
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad, unpad  # Ajouté pour la gestion propre du padding
import base64

HOST = '127.0.0.1'
PORT = 54424

# Création du contexte SSL
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile="server.crt")
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def aes_encrypt(texte, cle_utilisateur):
    """Chiffre le texte avec AES en utilisant une clé dérivée"""
    salt = get_random_bytes(16)
    key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2**14, r=8, p=1)

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Appliquer un padding PKCS7
    texte_padded = pad(texte.encode(), AES.block_size)

    encrypted_text = cipher.encrypt(texte_padded)

    return base64.b64encode(salt + iv + encrypted_text).decode()

def aes_decrypt(texte_chiffre, cle_utilisateur):
    """Déchiffre le texte avec AES"""
    data = base64.b64decode(texte_chiffre)
    salt, iv, encrypted_text = data[:16], data[16:32], data[32:]

    key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_text = cipher.decrypt(encrypted_text)

    # Retirer le padding PKCS7 proprement
    decrypted_text = unpad(decrypted_text, AES.block_size)

    return decrypted_text.decode()

def receive_messages(client_socket, cle_utilisateur):
    while True:
        try:
            encrypted_message = client_socket.recv(1024).decode()
            if encrypted_message:
                decrypted_message = aes_decrypt(encrypted_message, cle_utilisateur)
                print(f"\n📥 Message reçu : {decrypted_message}\n> ", end="")
        except:
            print("❌ Connexion au serveur perdue.")
            break

# Connexion au serveur
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.connect((HOST, PORT))
    secure_client = context.wrap_socket(client, server_hostname=HOST)

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

    # Demande de clé de chiffrement à l'utilisateur
    cle_utilisateur = getpass.getpass("🔑 Entrez votre clé de chiffrement : ")

    threading.Thread(target=receive_messages, args=(secure_client, cle_utilisateur), daemon=True).start()

    while True:
        message = input("> ")
        if message.lower() == "exit":
            break
        message = nom_user + " : " + message
        encrypted_message = aes_encrypt(message, cle_utilisateur)
        secure_client.sendall(encrypted_message.encode())

    print("❌ Déconnexion...")
    secure_client.close()
    exit()