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

PAD_BLOCK_SIZE = 16
DRIVE_LETTER = "E"

root = tk.Tk()
warning_label = tk.StringVar()
drive_found_label = tk.StringVar()
pdf_signed_label = tk.StringVar()
verify_label = tk.StringVar()
aes_pin = tk.StringVar()

# pad the plaintext
def pad(data):
    padding_length = PAD_BLOCK_SIZE - len(data) % PAD_BLOCK_SIZE
    padding = chr(padding_length) * padding_length
    return data + padding.encode()

# unpad the plaintext
def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def read_encrypted_key_from_drive(drive_letter, key_filename):
    key_path = f"{drive_letter}:\\{key_filename}"
    if not os.path.exists(key_path):
        warning_label.set(f"Encrypted key file not found at {key_path}")
        return None
    with open(key_path, 'rb') as file:
        return file.read()

def decrypt_private_key(encrypted_key_data, aes_pin):
    try:
        salt = encrypted_key_data[:16]
        iv = encrypted_key_data[16:32]
        encrypted_private_key = encrypted_key_data[32:]

        # derive the encryption key
        key = scrypt(aes_pin, salt, key_len=32, N=2**20, r=8, p=1)

        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_key = unpad(cipher.decrypt(encrypted_private_key))

        warning_label.set("")
        return RSA.import_key(decrypted_key)
    except (ValueError) as e:
        warning_label.set("Incorrect password")
        return None
    
def sign_pdf():
    verify_label.set("")
    encrypted_key_data = read_encrypted_key_from_drive(DRIVE_LETTER, "encrypted_private_key.txt")
    if encrypted_key_data is None:
        return None
    
    private_key = decrypt_private_key(encrypted_key_data, aes_pin.get())
    if private_key is None:
        return None

    pdf_path = askopenfilename(title="Select a pdf file to sign", filetypes=[("PDF Files", "*.pdf")])
    # check if user chose any file
    if not os.path.exists(pdf_path):
        return None

    # open the PDF file
    with open(pdf_path, 'rb') as file:
        pdf_reader = PdfReader(file)
        pdf_writer = PdfWriter()
        hash_value = SHA256.new()

        # iterate through each page to extract text and update the hash
        for page in pdf_reader.pages:
            pdf_writer.add_page(page)
            page_text = page.extract_text()
            if page_text:
                hash_value.update(page_text.encode('utf-8'))

        # sign the hash and add the signature to the metadata
        signature = pkcs1_15.new(private_key).sign(hash_value)
        pdf_writer.add_metadata({'/Signature': signature.hex()})

        signed_pdf_path = pdf_path.replace('.pdf', '_signed.pdf')
        with open(signed_pdf_path, 'wb') as signed_file:
            pdf_writer.write(signed_file)
    
    pdf_signed_label.set(f"PDF signed")

def verify_pdf_signature():
    pdf_signed_label.set("")
    warning_label.set("")
    public_key_path = askopenfilename(title="Select the public key", filetypes=[("Text Files", "*.txt")])
    if not os.path.exists(public_key_path):
        warning_label.set(f"Encrypted key file not found at {public_key_path}")
        return None
    public_key = RSA.import_key(open(public_key_path).read())
    pdf_path = askopenfilename(title="Select a pdf file to verify signature", filetypes=[("PDF Files", "*.pdf")])
    # check if user chose any file
    if not os.path.exists(pdf_path):
        return None

    # open the PDF file
    with open(pdf_path, 'rb') as file:
        pdf_reader = PdfReader(file)

        # extract the signature
        signature_hex = pdf_reader.metadata.get('/Signature')
        if not signature_hex:
            verify_label.set("No signature found.")
            return False

        # convert the hexadecimal signature back to bytes
        try:
            signature = binascii.unhexlify(signature_hex)
        except binascii.Error:
            verify_label.set("Invalid signature format.")
            return False

        hash_value = SHA256.new()

        # iterate through each page to extract text and update the hash
        for page in pdf_reader.pages:
            page_text = page.extract_text()
            if page_text:
                hash_value.update(page_text.encode('utf-8'))

        # verify the signature using the public key
        try:
            pkcs1_15.new(public_key).verify(hash_value, signature)
            verify_label.set("Signature is valid.")
            return True
        except (ValueError, TypeError):
            verify_label.set("Signature verification failed.")
            return False

def update_drive_found_label():
    if not os.path.exists(f"{DRIVE_LETTER}:\\"):
        drive_found_label.set(f"Drive {DRIVE_LETTER}:\\ not found. Please insert the pendrive.")
    else:
        drive_found_label.set(f"Drive {DRIVE_LETTER}:\\ detected.")

    root.after(500, update_drive_found_label)

if __name__ == "__main__":
    root.geometry('720x480')
    root.title('PDF Signer')

    for i in range(8):    
        root.rowconfigure(i, weight=1)

    for i in range(3):    
        root.columnconfigure(i, weight=1)

    update_drive_found_label()
    tk.Label(root, textvariable=drive_found_label).grid(column=1, row=0)
    tk.Label(root, textvariable=warning_label).grid(column=1, row=1)
    tk.Label(root, text="Enter your password below").grid(column=1, row=2)
    tk.Entry(root, textvariable=aes_pin).grid(column=1, row=3)
    generate_button = tk.Button(root, text='Sign a PDF document', command=sign_pdf)
    generate_button.grid(column=0, row=5)
    tk.Label(root, textvariable=pdf_signed_label).grid(column=0, row=4)
    generate_button = tk.Button(root, text='Verify a signature', command=verify_pdf_signature)
    generate_button.grid(column=2, row=5)
    tk.Label(root, textvariable=verify_label).grid(column=2, row=4)
    tk.mainloop()
