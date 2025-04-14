import tkinter as tk
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.Padding import pad

class KeyGenerator:
    def __init__(self):
        self.root = tk.Tk()
        self.aes_pin = tk.StringVar()
        self.label_text = tk.StringVar()

    def generate_keys(self):
        if self.aes_pin.get() == "":
            self.label_text.set('Provide a valid password')
            return None
        
        self.label_text.set('Generating a key pair')
        self.generate_button.config(state=tk.DISABLED)
        self.root.update_idletasks()

        # generate a key pair
        key = RSA.generate(4096)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # generate a random salt for key derivation
        salt = get_random_bytes(16)
        aes_key = scrypt(self.aes_pin.get(), salt, key_len=32, N=2**20, r=8, p=1)

        # generate a random initialization vector (IV) for AES
        iv = get_random_bytes(16)

        # encrypt the private key using AES in CBC mode
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        encrypted_private_key = cipher.encrypt(pad(private_key, AES.block_size))
        
        # save the private key, salt, and IV together
        with open("encrypted_private_key.txt", "wb") as priv_file:
            priv_file.write(salt + iv + encrypted_private_key)

        # save the public key
        with open("public_key.txt", "wb") as pub_file:
            pub_file.write(public_key)

        self.label_text.set('Key pair successfully generated')
        self.generate_button.config(state=tk.NORMAL)

    def main(self):
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