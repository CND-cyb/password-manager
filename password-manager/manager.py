import base64, os, json, getpass, secrets, string, pyperclip, time, threading
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

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
            return True
        try:
            with open(self.filename, "r") as f:
                lines = f.read().splitlines()
                if not lines: 
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
            return 0
        f = Fernet(base64.urlsafe_b64encode(self.key))
        passwords_json = json.dumps(self.data)
        token = f.encrypt(passwords_json.encode())
        tempfile = self.filename + ".tmp"
        with open(tempfile, "w") as f:
            f.write(self.salt.hex() + "\n")
            f.write(token.decode())
        os.replace(tempfile, self.filename)

    def add_password(self, site:str, password:str):
        """
        Ajoute le mot de passe donné par l'utilisateur pour un site
        """
        self.data[site] = password
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
    master_password = getpass.getpass("Mot de passe maître: ")
    
    if manager.unlock(master_password):
        del master_password
        while True:
            choice = input("\nMenu : [a]jouter / [v]oir / [q]uitter : ").lower()
            
            if choice == "q":
                break
                
            elif choice == "a" or choice == "ajouter":
                site = input("Nom du site: ")
                pwd = input("Mot de passe: ")
                if pwd == "":
                    pwd = generate_password()
                    print(f"Mot de passe généré.")
                
                manager.add_password(site, pwd)
                
            elif choice == "v" or choice == "voir":
                sites = manager.list_sites()
                if not sites:
                    print("Le coffre est vide")
                else:
                    print("Sites disponibles :")
                    for site in manager.list_sites():
                        print(f"- {site}")
                    site = input("Nom du site: ")
                    found_pwd = manager.get_password(site)
                    
                    if found_pwd:
                        copy_to_clipboard(found_pwd)
                        print("Mot de passe copié")
                    else:
                        print("Aucun mot de passe trouvé.")
    else:
        print("Mot de passe incorrect.")