import os
from tkinter.filedialog import askopenfilename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PyPDF2 import PdfReader, PdfWriter
import binascii
import tkinter as tk

class App:
    """
    @brief Główna klasa aplikacji GUI do podpisywania i weryfikowania plików PDF.
    """

    def __init__(self):
        """
        @brief Inicjalizuje aplikację, zmienne GUI oraz konfigurację dysku USB.
        """
        self.PAD_BLOCK_SIZE = 16
        self.DRIVE_LETTER = "E"

        self.root = tk.Tk()
        self.warning_label = tk.StringVar()
        self.drive_found_label = tk.StringVar()
        self.pdf_signed_label = tk.StringVar()
        self.verify_label = tk.StringVar()
        self.aes_pin = tk.StringVar()

    def pad(self, data):
        """
        @brief Dodaje padding do danych zgodnie z rozmiarem bloku AES.
        @param data Dane do wypadowania jako bajty.
        @return Wypadowane dane jako bajty.
        """
        padding_length = self.PAD_BLOCK_SIZE - len(data) % self.PAD_BLOCK_SIZE
        padding = chr(padding_length) * padding_length
        return data + padding.encode()

    def unpad(self, data):
        """
        @brief Usuwa padding z danych odszyfrowanych.
        @param data Dane z paddingiem jako bajty.
        @return Dane bez paddingu jako bajty.
        """
        padding_length = data[-1]
        return data[:-padding_length]

    def read_encrypted_key_from_drive(self, drive_letter, key_filename):
        """
        @brief Odczytuje zaszyfrowany klucz prywatny z określonego napędu USB.
        @param drive_letter Litera napędu, np. "E".
        @param key_filename Nazwa pliku z zaszyfrowanym kluczem.
        @return Zawartość pliku jako bajty lub None jeśli plik nie istnieje.
        """
        key_path = f"{drive_letter}:\\{key_filename}"
        if not os.path.exists(key_path):
            self.warning_label.set(f"Encrypted key file not found at {key_path}")
            return None
        with open(key_path, 'rb') as file:
            return file.read()

    def decrypt_private_key(self, encrypted_key_data, aes_pin):
        """
        @brief Odszyfrowuje klucz prywatny z użyciem hasła użytkownika i algorytmu AES.
        @param encrypted_key_data Dane zaszyfrowanego klucza jako bajty.
        @param aes_pin Hasło AES wprowadzone przez użytkownika.
        @return Klucz RSA lub None jeśli odszyfrowanie się nie powiodło.
        """
        try:
            salt = encrypted_key_data[:16]
            iv = encrypted_key_data[16:32]
            encrypted_private_key = encrypted_key_data[32:]
            key = scrypt(aes_pin, salt, key_len=32, N=2**20, r=8, p=1)
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted_key = self.unpad(cipher.decrypt(encrypted_private_key))
            self.warning_label.set("")
            return RSA.import_key(decrypted_key)
        except ValueError:
            self.warning_label.set("Incorrect password")
            return None

    def sign_pdf(self):
        """
        @brief Podpisuje wybrany plik PDF przy użyciu klucza prywatnego.
        """
        self.verify_label.set("")
        encrypted_key_data = self.read_encrypted_key_from_drive(self.DRIVE_LETTER, "encrypted_private_key.txt")
        if encrypted_key_data is None:
            return None

        private_key = self.decrypt_private_key(encrypted_key_data, self.aes_pin.get())
        if private_key is None:
            return None

        pdf_path = askopenfilename(title="Select a pdf file to sign", filetypes=[("PDF Files", "*.pdf")])
        if not os.path.exists(pdf_path):
            return None

        with open(pdf_path, 'rb') as file:
            pdf_reader = PdfReader(file)
            pdf_writer = PdfWriter()
            hash_value = SHA256.new()

            for page in pdf_reader.pages:
                pdf_writer.add_page(page)
                page_text = page.extract_text()
                if page_text:
                    hash_value.update(page_text.encode('utf-8'))

            signature = pkcs1_15.new(private_key).sign(hash_value)
            pdf_writer.add_metadata({'/Signature': signature.hex()})

            signed_pdf_path = pdf_path.replace('.pdf', '_signed.pdf')
            with open(signed_pdf_path, 'wb') as signed_file:
                pdf_writer.write(signed_file)

        self.pdf_signed_label.set(f"PDF signed")

    def verify_pdf_signature(self):
        """
        @brief Weryfikuje podpis w wybranym pliku PDF za pomocą klucza publicznego.
        @return True jeśli podpis jest poprawny, False w przeciwnym wypadku.
        """
        self.pdf_signed_label.set("")
        self.warning_label.set("")
        public_key_path = askopenfilename(title="Select the public key", filetypes=[("Text Files", "*.txt")])
        if not os.path.exists(public_key_path):
            self.warning_label.set(f"Public key file not found at {public_key_path}")
            return None

        public_key = RSA.import_key(open(public_key_path).read())
        pdf_path = askopenfilename(title="Select a pdf file to verify signature", filetypes=[("PDF Files", "*.pdf")])
        if not os.path.exists(pdf_path):
            return None

        with open(pdf_path, 'rb') as file:
            pdf_reader = PdfReader(file)
            signature_hex = pdf_reader.metadata.get('/Signature')
            if not signature_hex:
                self.verify_label.set("No signature found.")
                return False

            try:
                signature = binascii.unhexlify(signature_hex)
            except binascii.Error:
                self.verify_label.set("Invalid signature format.")
                return False

            hash_value = SHA256.new()
            for page in pdf_reader.pages:
                page_text = page.extract_text()
                if page_text:
                    hash_value.update(page_text.encode('utf-8'))

            try:
                pkcs1_15.new(public_key).verify(hash_value, signature)
                self.verify_label.set("Signature is valid.")
                return True
            except (ValueError, TypeError):
                self.verify_label.set("Signature verification failed.")
                return False

    def update_drive_found_label(self):
        """
        @brief Sprawdza obecność dysku USB i aktualizuje komunikat na GUI.
        """
        if not os.path.exists(f"{self.DRIVE_LETTER}:\\"):
            self.drive_found_label.set(f"Drive {self.DRIVE_LETTER}:\\ not found. Please insert the pendrive.")
        else:
            self.drive_found_label.set(f"Drive {self.DRIVE_LETTER}:\\ detected.")

        self.root.after(500, self.update_drive_found_label)

    def run(self):
        """
        @brief Uruchamia główną pętlę GUI i konfiguruje interfejs użytkownika.
        """
        self.root.geometry('720x480')
        self.root.title('PDF Signer')

        for i in range(8):    
            self.root.rowconfigure(i, weight=1)

        for i in range(3):    
            self.root.columnconfigure(i, weight=1)

        self.update_drive_found_label()
        tk.Label(self.root, textvariable=self.drive_found_label).grid(column=1, row=0)
        tk.Label(self.root, textvariable=self.warning_label).grid(column=1, row=1)
        tk.Label(self.root, text="Enter your password below").grid(column=1, row=2)
        tk.Entry(self.root, textvariable=self.aes_pin).grid(column=1, row=3)
        generate_button = tk.Button(self.root, text='Sign a PDF document', command=self.sign_pdf)
        generate_button.grid(column=0, row=5)
        tk.Label(self.root, textvariable=self.pdf_signed_label).grid(column=0, row=4)
        generate_button = tk.Button(self.root, text='Verify a signature', command=self.verify_pdf_signature)
        generate_button.grid(column=2, row=5)
        tk.Label(self.root, textvariable=self.verify_label).grid(column=2, row=4)
        tk.mainloop()


if __name__ == "__main__":
    """
    @brief Punkt wejścia aplikacji.
    """
    app = App()
    app.run()