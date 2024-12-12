from gui import *


class Menu_Window(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        self.title("Menu Windows")
        window_width, window_height = 500, 300
        screen_width, screen_height = self.winfo_screenwidth(), self.winfo_screenheight()
        position_x, position_y = (screen_width - window_width) // 2, (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{position_x}+{position_y}")

        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.button_creation = customtkinter.CTkButton(self, text="Créer une DB", command=self.open_creation_window)
        self.button_creation.grid(row=0, column=0, padx=10, pady=10, sticky="ew")

        self.button_import = customtkinter.CTkButton(self, text="Ouvrir une DB", command=self.open_import_window)
        self.button_import.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

    def open_creation_window(self):
        self.destroy()
        CreateFile_Window().mainloop()

    def open_import_window(self):
        file_path = fd.askopenfilename(
            title="Choisir un fichier",
            filetypes=(("Fichiers chiffrés", "*.cndb"), ("Tous les fichiers", "*.*"))
        )
        if file_path:
            if not file_path.lower().endswith(".cndb"):
                return
            self.quit()
            self.destroy()
            Main_Window(file_path).mainloop()


if __name__ == "__main__":
    app = Menu_Window()
    app.mainloop()