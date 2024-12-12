import customtkinter
import tkinter.filedialog as fd
import os
from password_manager import *


class CreateFile_Window(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.PWDM = PasswordManager()
        self.title("Create File Window")
        window_width, window_height = 500, 300
        screen_width, screen_height = self.winfo_screenwidth(), self.winfo_screenheight()
        position_x, position_y = (screen_width - window_width) // 2, (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

        self.grid_columnconfigure((0, 1, 2), weight=1)
        self.grid_rowconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.label_name = customtkinter.CTkLabel(self, text="Nom du fichier")
        self.label_name.grid(row=0, column=0, padx=20, pady=10, sticky="w")
        self.file_entry = customtkinter.CTkEntry(self, placeholder_text="")
        self.file_entry.grid(row=0, column=1, padx=20, pady=10, sticky="ew", columnspan=1)

        self.label_error = customtkinter.CTkLabel(self, text="")
        self.label_error.grid(row=3, column=1, padx=20, pady=10, sticky="ew", columnspan=1)

        self.button_quit = customtkinter.CTkButton(self, text="Retour", command=self.quit)
        self.button_quit.grid(row=5, column=0, padx=20, pady=10, sticky="e")
        self.button_create = customtkinter.CTkButton(self, text="Ok", command=self.create_file)
        self.button_create.grid(row=5, column=1, padx=20, pady=10, sticky="w")

    def create_file(self):
        file_name = self.file_entry.get()
        self.PWDM.create_file(file_name)
        self.destroy()
        file_name = file_name + ".cndb"
        Main_Window(file_name).mainloop()

    def quit(self):
        self.destroy()
        from main import Menu_Window
        Menu_Window().mainloop()




class Main_Window(customtkinter.CTk):
    def __init__(self, file):
        super().__init__()


        self.file = file
        self.title("Main Window")
        window_width, window_height = 700, 500
        screen_width, screen_height = self.winfo_screenwidth(), self.winfo_screenheight()
        position_x, position_y = (screen_width - window_width) // 2, (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

        self.grid_columnconfigure((0, 1, 2), weight=1)
        self.grid_rowconfigure(0, weight=1)

        with open(file, "rb") as file:
            data = file.read().strip()

        self.textbox = customtkinter.CTkTextbox(self, width=500, height=300)
        self.textbox.grid(row=1, column=0, padx=20, pady=10, sticky="ew", columnspan=2)

        self.button_import = customtkinter.CTkButton(self, text="Créer une Entrée", command=self.createEntry)
        self.button_import.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.button_quit = customtkinter.CTkButton(self, text="Quitter", command=self.quit)
        self.button_quit.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        self.textbox.insert("0.0", data)

    def createEntry(self):
        pass

    def quit(self):
        self.destroy()
        from main import Menu_Window
        Menu_Window().mainloop()