import hashlib
import os
import json

# Fonction pour ajouter un utilisateur au fichier JSON
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

# Exemple : Ajouter des utilisateurs (ne faire cela qu'une seule fois)
add_user_to_json("user", "user1234")
