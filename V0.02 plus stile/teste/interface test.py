import os
import time

def clear_screen():
    """Clears the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def show_contextual_menu():
    """Displays the contextual menu with a stylized look."""
    clear_screen()
    print("╔═════════════════════════════╗")
    print("║   Menu Contextuel           ║")
    print("╠═════════════════════════════╣")
    print("║ 1. Option 1 (Exemple)       ║")
    print("║ 2. Option 2 (Exemple)       ║")
    print("║ 3. Retour au menu principal ║")
    print("╚═════════════════════════════╝")
    choice = input("  Choisissez une option: ")
    if choice == '1':
        print("Option 1 sélectionnée.")
        input("Appuyez sur Entrée pour continuer...")
        show_contextual_menu()
    elif choice == '2':
        print("Option 2 sélectionnée.")
        input("Appuyez sur Entrée pour continuer...")
        show_contextual_menu()
    elif choice == '3':
        show_main_menu()
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        show_contextual_menu()

def create_group():
    """Simulates creating a group with a stylized look."""
    clear_screen()
    print("╔═════════════════════════════╗")
    print("║     Créer un groupe         ║")
    print("╚═════════════════════════════╝")
    print("Fonctionnalité de création de groupe appelée.")
    input("Appuyez sur Entrée pour continuer...")
    show_main_menu()

def add_friend():
    """Simulates adding a friend with a stylized look."""
    clear_screen()
    print("╔═════════════════════════════╗")
    print("║     Ajouter un ami          ║")
    print("╚═════════════════════════════╝")
    print("Fonctionnalité d'ajout d'ami appelée.")
    input("Appuyez sur Entrée pour continuer...")
    show_main_menu()

def block_user():
    """Simulates blocking a user with a stylized look."""
    clear_screen()
    print("╔═════════════════════════════╗")
    print("║   Bloquer un utilisateur    ║")
    print("╚═════════════════════════════╝")
    print("Fonctionnalité de blocage d'utilisateur appelée.")
    input("Appuyez sur Entrée pour continuer...")
    show_main_menu()

def report_user():
    """Simulates reporting a user with a stylized look."""
    clear_screen()
    print("╔═════════════════════════════╗")
    print("║          Signaler           ║")
    print("╚═════════════════════════════╝")
    print("Fonctionnalité de signalement appelée.")
    input("Appuyez sur Entrée pour continuer...")
    show_main_menu()

def show_main_menu():
    """Displays the main menu with a stylized look."""
    clear_screen()
    print("╔═════════════════════════════╗")
    print("║       Menu Principal        ║")
    print("╠═════════════════════════════╣")
    print("║ 1. Menu Contextuel          ║")
    print("║ 2. Créer un groupe          ║")
    print("║ 3. Ajouter un ami           ║")
    print("║ 4. Bloquer un utilisateur   ║")
    print("║ 5. Signaler                 ║")
    print("║ 6. Quitter                  ║")
    print("╚═════════════════════════════╝")
    choice = input("  Choisissez une option: ")
    if choice == '1':
        show_contextual_menu()
    elif choice == '2':
        create_group()
    elif choice == '3':
        add_friend()
    elif choice == '4':
        block_user()
    elif choice == '5':
        report_user()
    elif choice == '6':
        print("Au revoir!")
        exit()
    else:
        print("Option invalide.")
        input("Appuyez sur Entrée pour continuer...")
        show_main_menu()

if __name__ == "__main__":
    show_main_menu()
