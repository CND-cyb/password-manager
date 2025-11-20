import base64, os, json, getpass, secrets, string, pyperclip, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class PasswordManager:
    def __init__(self, filename):
        self.filename = filename
        self.data = {}
    
    def derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(password.encode())
    
    def unlock(self, master_password):
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
                return True
        except Exception:
            return False
        
    def save(self, master_password):
        salt = os.urandom(16)
        
        key = self.derive_key(master_password, salt)
        f = Fernet(base64.urlsafe_b64encode(key))
        
        passwords_json = json.dumps(self.data)
        token = f.encrypt(passwords_json.encode())
        with open(self.filename, "w") as f:
            f.write(salt.hex() + "\n")
            f.write(token.decode())

    def add_password(self, site, password, master_password):
        self.data[site] = password
        self.save(master_password)

    def get_password(self, site):
        return self.data.get(site)
    
def generate_password(length=16):
    characters = string.ascii_letters + string.digits + string.punctuation
    message = ""
    for i in range(length):
        message += secrets.choice(characters)
    return message

def copy_to_clipboard(password):
    pyperclip.copy(password)
    print("Mot de passe copié dans le presse-papiers pendant 10 secondes.")
    time.sleep(10)
    pyperclip.copy("")

if __name__ == "__main__":
    print("#### COFFRE-FORT PYTHON ####")

    manager = PasswordManager("data.txt")
    master_password = getpass.getpass("Entrez le mot de passe maître : ")
    
    if manager.unlock(master_password):
        print(f"Coffre ouvert ! {len(manager.data)} mot(s) de passe chargé(s).")
        while True:
            choice = input("\nMenu : [a]jouter / [v]oir / [q]uitter : ").lower()
            
            if choice == "q":
                print("Fermeture du coffre...")
                break
                
            elif choice == "a" or choice == "ajouter":
                site = input("Nom du site : ")
                pwd = input("Mot de passe : ")
                if pwd == "":
                    pwd = generate_password()
                    print(f"Mot de passe généré.")
                
                manager.add_password(site, pwd, master_password)
                print(f"Mot de passe pour {site} sauvegardé !")
                
            elif choice == "v" or choice == "voir":
                site = input("Quel site cherchez-vous ? : ")
                found_pwd = manager.get_password(site)
                
                if found_pwd:
                    copy_to_clipboard(found_pwd)
                else:
                    print("Aucun mot de passe trouvé pour ce site.")
    else:
        print("Mot de passe maître incorrect.")