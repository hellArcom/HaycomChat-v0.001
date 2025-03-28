from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64

def aes_encrypt(texte, cle_utilisateur):
    """Chiffre le texte avec AES en utilisant une clé dérivée"""
    # Générer un sel aléatoire pour le hachage
    salt = get_random_bytes(16)
    # Dériver une clé de 32 octets à partir de la clé utilisateur
    # Remplacer dklen par keylen
    key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2**14, r=8, p=1)

    # Initialiser AES en mode CBC avec un vecteur d'initialisation (IV) aléatoire
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Ajouter un padding pour que le texte soit un multiple de 16 octets
    padding_length = 16 - len(texte) % 16
    texte_padded = texte + chr(padding_length) * padding_length
    
    # Chiffrement du texte
    encrypted_text = cipher.encrypt(texte_padded.encode())
    
    # Retourner le texte chiffré avec le salt et l'IV
    return base64.b64encode(salt + iv + encrypted_text).decode()

def aes_decrypt(texte_chiffre, cle_utilisateur):
    """Déchiffre le texte avec AES en utilisant la même clé"""
    # Décoder le texte chiffré
    data = base64.b64decode(texte_chiffre)
    
    # Extraire le salt et l'IV du texte chiffré
    salt = data[:16]
    iv = data[16:32]
    encrypted_text = data[32:]
    
    # Dériver la clé à partir du salt
    key = scrypt(cle_utilisateur.encode(), salt, key_len=32, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Déchiffrer le texte
    decrypted_text = cipher.decrypt(encrypted_text)
    
    # Retirer le padding
    padding_length = decrypted_text[-1]
    decrypted_text = decrypted_text[:-padding_length]
    
    return decrypted_text.decode()

# Interface utilisateur
mode = input("Voulez-vous (1) Chiffrer ou (2) Déchiffrer ? ")

if mode == "1":
    cle_utilisateur = input("Entrez votre clé : ")
    texte = input("Entrez le texte à chiffrer : ")
    
    # Chiffrement avec AES
    encrypted_text = aes_encrypt(texte, cle_utilisateur)
    
    # Affichage du résultat
    print("\n🔑 Texte chiffré (base64) :", encrypted_text)

elif mode == "2":
    cle_utilisateur = input("Entrez votre clé pour déchiffrer : ")
    texte_chiffre = input("Collez le texte chiffré (base64) : ")
    
    # Déchiffrement avec AES
    decrypted_text = aes_decrypt(texte_chiffre, cle_utilisateur)
    
    print("\n✅ Texte déchiffré :", decrypted_text)

else:
    print("❌ Option invalide !")
