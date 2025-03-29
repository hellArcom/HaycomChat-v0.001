import hashlib
import os
import json

# Fonction pour ajouter un utilisateur au fichier JSON
def add_user_to_json(username, password, json_filename="users.json"):
    # Charger les user existants
    if os.path.exists(json_filename):
        with open(json_filename, "r") as file:
            users_data = json.load(file)
    else:
        users_data = {}

    # Créer un salt unique pour le cryptage
    salt = os.urandom(16)
    
    # Hacher le mot de passe avec PBKDF2
    password_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)

    # Ajouter l'utilisateur au "dictionnaire" ou la "liste" ou un truc comme ça je sait plus je confond toujours
    users_data[username] = {
        "password_hash": password_hash.hex(),
        "salt": salt.hex()
    }

    # Sauvegarder le fichier JSON
    with open(json_filename, "w") as file:
        json.dump(users_data, file, indent=4)

    print(f"✅ Utilisateur {username} ajouté avec succès au fichier JSON !")

# Exemple pour add un user au fichier JSON mais ne pas faire plusieur foit la commande avec le même info /!\
add_user_to_json("user", "user1234")