import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad

class KeyGenerator:
    """
    @brief Klasa do generowania pary kluczy RSA oraz szyfrowania klucza prywatnego z użyciem AES.
    """
    def __init__(self):
        """
        @brief Inicjalizuje komponenty GUI i zmienne do przechowywania hasła oraz statusu.
        """
        self.root = tk.Tk()
        self.aes_pin = tk.StringVar()
        self.label_text = tk.StringVar()

    def generate_keys(self):
        """
        @brief Generuje parę kluczy RSA. Klucz prywatny szyfruje za pomocą AES na podstawie hasła użytkownika.
        @details
        - Hasło jest używane do wyprowadzenia klucza AES za pomocą algorytmu scrypt.
        - Szyfrowany klucz prywatny zapisywany jest do pliku "encrypted_private_key.txt".
        - Klucz publiczny zapisywany jest do pliku "public_key.txt".
        - W przypadku braku hasła, operacja zostaje przerwana.
        """
        if self.aes_pin.get() == "":
            self.label_text.set('Provide a valid password')
            return None
        
        self.label_text.set('Generating a key pair')
        self.generate_button.config(state=tk.DISABLED)
        self.root.update_idletasks()

        # Generowanie pary kluczy RSA
        key = RSA.generate(4096)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Generowanie soli i klucza AES z hasła
        salt = get_random_bytes(16)
        aes_key = scrypt(self.aes_pin.get(), salt, key_len=32, N=2**20, r=8, p=1)

        # Generowanie wektora inicjalizującego
        iv = get_random_bytes(16)

        # Szyfrowanie klucza prywatnego
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_private_key = cipher.encrypt(pad(private_key, AES.block_size))
        
        # Zapis zaszyfrowanego klucza prywatnego do pliku
        with open("encrypted_private_key.txt", "wb") as priv_file:
            priv_file.write(salt + iv + encrypted_private_key)

        # Zapis klucza publicznego do pliku
        with open("public_key.txt", "wb") as pub_file:
            pub_file.write(public_key)

        self.label_text.set('Key pair successfully generated')
        self.generate_button.config(state=tk.NORMAL)

    def main(self):
        """
        @brief Uruchamia główne okno aplikacji GUI do generowania kluczy.
        @details Tworzy widżety GUI i wyświetla je użytkownikowi.
        """
        self.root.geometry('360x240')
        self.root.title('Key pair generator')

        tk.Label(self.root, text="Enter your password below").pack(side='top', pady=20)
        tk.Entry(self.root, textvariable=self.aes_pin).pack(side='top', pady=20)
        self.generate_button = tk.Button(self.root, text='Generate keys', command=self.generate_keys)
        self.generate_button.pack(side='top', pady=20)
        self.status_label = tk.Label(self.root, textvariable=self.label_text, width=40, anchor='center')
        self.status_label.pack(side='top')
        self.root.mainloop()

if __name__ == "__main__":
    keyGenerator = KeyGenerator()
    keyGenerator.main()