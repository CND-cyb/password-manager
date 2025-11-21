import base64, os, json, getpass, secrets, string, pyperclip, threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import hashlib, requests
from pyfiglet import Figlet

class PasswordManager:
    def __init__(self, filename):
        self.filename = filename
        self.key = None
        self.salt = None
        self.data = {}
    
    def derive_key(self, password:str, salt:bytes):
        """
        Dérive une clé à partir du mot de passe maître et du sel
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(password.encode())
    
    def unlock(self, master_password:str):
        """
        Retourne l'état du déverouillage du coffre-fort
            - False: Mot de passe maître invalide
            - True: Coffre-fort dévérouillé
        """
        if not os.path.exists(self.filename):
            self.salt = os.urandom(16)
            self.key = self.derive_key(master_password, self.salt)
            return True
        try:
            with open(self.filename, "r") as f:
                lines = f.read().splitlines()
                if not lines: 
                    self.salt = os.urandom(16)
                    self.key = self.derive_key(master_password, self.salt)
                    return True
                
                salt_from_file = bytes.fromhex(lines[0])
                token_from_file = lines[1].encode()

                key = self.derive_key(master_password, salt_from_file)
                f_read = Fernet(base64.urlsafe_b64encode(key))
                text = f_read.decrypt(token_from_file)
                self.data = json.loads(text.decode())
                self.key = key
                self.salt = salt_from_file
                return True
        except Exception:
            return False   
        
    def save(self):
        """
        Sauvegarde les données dans le fichier utilisé
            - Erreur : clé utilisé invalide
        """
        if self.key is None:
            print("Clé invalide")
            return False
        f = Fernet(base64.urlsafe_b64encode(self.key))
        passwords_json = json.dumps(self.data)
        token = f.encrypt(passwords_json.encode())
        tempfile = self.filename + ".tmp"
        with open(tempfile, "w") as f:
            f.write(self.salt.hex() + "\n")
            f.write(token.decode())
        os.replace(tempfile, self.filename)
        return True

    def add_password(self, site:str, password:str):
        """
        Ajoute le mot de passe donné par l'utilisateur pour un site
        """
        self.data[site] = password
        self.save()

    def delete_password(self, site:str):
        """
        Supprime le mot de passe du site sélectionné
        """
        if site in self.data:
            del self.data[site]
            self.save()

    def get_password(self, site:str):
        """
        Retourne le mot de passe du site sélectionné
        """
        return self.data.get(site)
    
    def list_sites(self):
        """
        Retourne la liste des sites enregistrés
        """
        return list(self.data.keys())
    
    def check_pwned(self, password:str):
        """
        Vérifie si le mot de passe a été compromis avec l'API "Have I Been Pwned"
        """
        n_matches = 0
        sha1pwd = hashlib.sha1(password.encode()).hexdigest().upper()
        try:
            PWNED_API_URL = "https://api.pwnedpasswords.com/range/"
            response = requests.get(PWNED_API_URL + sha1pwd[:5], timeout=2)
            if response.status_code == 200:
                hashes = (line.split(":") for line in response.text.splitlines())
                for h, count in hashes:
                    if h == sha1pwd[5:]:
                        n_matches = int(count)
                        return n_matches
                return 0
            else:
                print("Erreur API")
                return 0
        except Exception as e:
            print(f"Erreur: {e}")
            return 0
        
    def search(self, query:str):
        """
        Recherche les sites correspondant à la requête
        """
        results = []
        for site in self.data.keys():
            if query.lower() in site.lower():
                results.append(site)
        return results


def generate_password(length=16):
    """
    Génération d'un mot de passe avec lettres + chiffres + symboles
    """
    characters = string.ascii_letters + string.digits + string.punctuation
    message = ""
    for i in range(length):
        message += secrets.choice(characters)
    return message

def copy_to_clipboard(password:str):
    """
    Insère le mot de passe dans le presse-papier
        - Utilisation d'un thread pour vider le presse-papier 10 secondes après
    """
    pyperclip.copy(password)
    t = threading.Timer(10.0, clear_clipboard)
    t.daemon = True 
    t.start()

def clear_clipboard():
    """
    Vide le presse-papier
    """
    pyperclip.copy("")

if __name__ == "__main__":
    manager = PasswordManager("data.txt")
    f = Figlet(font="standard", width=200)
    print(f.renderText("PyPass"))
    master_password = getpass.getpass("Mot de passe maître: ")
    if manager.unlock(master_password):
        os.system('cls' if os.name == 'nt' else 'clear')
        del master_password
        while True:
            sites = manager.list_sites()
            if not sites:
                print("Le coffre est vide")
            else:
                print("\nSites disponibles :")
                for site in manager.list_sites():
                    print(f"[*] {site}")
            print()
            choice = input("Menu : [a]jouter / [s]upprimer / [v]oir / [q]uitter : ").lower()
            
            match choice:
                case "q":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    break
                case "a" | "ajouter":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    site = input("Nom du site: ")
                    pwd = input("Mot de passe: ")
                    if pwd == "":
                        pwd = generate_password()
                        print(f"Mot de passe généré.")
                    else:
                        count = manager.check_pwned(pwd)
                        if count > 0:
                            print(f"Ce mot de passe apparait {count} fois dans des fuites de données.")
                            confirm = input("Voulez-vous vraiment l'utiliser ? (o/n) : ").lower()
                            if confirm != "o":
                                continue

                    manager.add_password(site, pwd)
                    os.system('cls' if os.name == 'nt' else 'clear')
                    print(f"Mot de passe ajouté pour le site {site}.\n")
                case "s" | "supprimer":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    sites = manager.list_sites()
                    if not sites:
                        print("Le coffre est vide")
                    else:
                        print("Sites disponibles :")
                        for site in manager.list_sites():
                            print(f"- {site}")
                        site = input("Nom du site à supprimer: ")
                        manager.delete_password(site)
                        os.system('cls' if os.name == 'nt' else 'clear')
                        print(f"Mot de passe pour le site {site} supprimé.")
                case "v" | "voir":
                    os.system('cls' if os.name == 'nt' else 'clear')
                    query = input("Rechercher un site: ")
                    if not query:
                        continue  
                    results = manager.search(query)
                    if not results:
                        print("Aucun site trouvé")
                    elif len(results) == 1:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        site_found = results[0]
                        print(f"Site trouvé : {site_found}")
                        pwd = manager.get_password(site_found)
                        copy_to_clipboard(pwd)
                        print("Mot de passe copié pendant 10 secondes")
                    else:
                        os.system('cls' if os.name == 'nt' else 'clear')
                        print(f"Plusieurs sites trouvés ({len(results)}) :")
                        for i, s in enumerate(results):
                            print(f" {i+1}. {s}")
                        try:
                            choice_idx = int(input("Entrez le numéro du site: ")) - 1
                            if 0 <= choice_idx < len(results):
                                site_found = results[choice_idx]
                                pwd = manager.get_password(site_found)
                                copy_to_clipboard(pwd)
                                os.system('cls' if os.name == 'nt' else 'clear')
                                print(f"Mot de passe pour {site_found} copié pendant 10 secondes")
                            else:
                                print("Numéro invalide.")
                        except ValueError:
                            print("Entrée invalide.")
                case _:
                    print("Choix invalide.")
    else:
        print("Mot de passe incorrect.")