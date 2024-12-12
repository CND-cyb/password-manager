import os

class PasswordManager:
    def __init__(self):
        self.data = None

    def create_file(self, file_name):
        """Créer un nouveau fichier"""
        try:
            data = f"C^^->N - {file_name} - Version 0.1"
            data_bytes = data.encode('utf-8')
            with open(file_name + ".cndb","wb") as file:
                file.write(data_bytes)
            return "Fichier crée avec succès!"
        except Exception as e:
            raise Exception(f"Erreur lors de la création du fichier : {str(e)}")
        
    def load_file(self, file_path):
        """Importer un fichier"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Le fichier {file_path} n'existe pas.")
        try:
            with open(file_path, "rb") as file:
                encrypted_data = file.read()
            self.data = encrypted_data.decode("utf-8")
            return self.data
        except Exception as e:
            raise Exception(f"Erreur lors du chargement du fichier : {str(e)}")
        


