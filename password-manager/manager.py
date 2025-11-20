import base64, os, json, getpass, secrets, string, pyperclip, time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

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

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password.encode())

def load_data(filename, master_password):
    if not os.path.exists(filename):
        return {}

    try:
        with open(filename, "r") as f:
            lines = f.read().splitlines()
            if not lines: 
                return {}
            
            salt_from_file = bytes.fromhex(lines[0])
            token_from_file = lines[1].encode()

        key = derive_key(master_password, salt_from_file)
        f_read = Fernet(base64.urlsafe_b64encode(key))
        text = f_read.decrypt(token_from_file)
        return json.loads(text.decode())
    except Exception:
        return None 

def save_data(filename, master_password, data_dict):
    salt = os.urandom(16)
    
    key = derive_key(master_password, salt)
    f = Fernet(base64.urlsafe_b64encode(key))
    
    passwords_json = json.dumps(data_dict)
    token = f.encrypt(passwords_json.encode())
    with open(filename, "w") as f:
        f.write(salt.hex() + "\n")
        f.write(token.decode())

if __name__ == "__main__":
    print("#### COFFRE-FORT PYTHON ####")
    master_password = getpass.getpass("Entrez le mot de passe maître : ")
    
    data = load_data("data.txt", master_password)
    if data is None:
        print("Mot de passe incorrect ou fichier corrompu.")
        exit()
    
    print(f"Coffre ouvert ! {len(data)} mot(s) de passe chargé(s).")
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
            
            data[site] = pwd
            save_data("data.txt", master_password, data)
            print(f"Mot de passe pour {site} sauvegardé !")
            
        elif choice == "v" or choice == "voir":
            site = input("Quel site cherchez-vous ? : ")
            found_pwd = data.get(site)
            
            if found_pwd:
                copy_to_clipboard(found_pwd)
            else:
                print("Aucun mot de passe trouvé pour ce site.")