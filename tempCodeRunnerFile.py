    def sign_pdf(self):
        self.verify_label.set("")
        encrypted_key_data = self.read_encrypted_key_from_drive(self.DRIVE_LETTER, "encrypted_private_key.txt")
        if encrypted_key_data is None:
            return None
        
        private_key = self.decrypt_private_key(encrypted_key_data, self.aes_pin.get())
        if private_key is None:
            return None

        pdf_path = askopenfilename(title="Select a PDF file to sign", filetypes=[("PDF Files", "*.pdf")])
        if not pdf_path or not os.path.exists(pdf_path):
            return None

        with open(pdf_path, 'rb') as file:
            pdf_reader = PdfReader(file)
            pdf_writer = PdfWriter()
            hash_value = SHA256.new()

            # Dodajemy strony do nowego dokumentu i liczymy hash tekstu
            for page in pdf_reader.pages:
                pdf_writer.add_page(page)
                text = page.extract_text()
                if text:
                    hash_value.update(text.encode('utf-8'))

            # Podpisujemy hash
            signature = pkcs1_15.new(private_key).sign(hash_value)

            # Zapisujemy podpis jako metadane w heksie
            pdf_writer.add_metadata({"/Signature": signature.hex()})

            signed_pdf_path = pdf_path.replace('.pdf', '_signed.pdf')
            with open(signed_pdf_path, 'wb') as signed_file:
                pdf_writer.write(signed_file)

        self.pdf_signed_label.set(f"PDF signed successfully.")

    def verify_pdf_signature(self):
        self.pdf_signed_label.set("")
        self.warning_label.set("")

        public_key_path = askopenfilename(title="Select the public key", filetypes=[("Text Files", "*.txt")])
        if not public_key_path or not os.path.exists(public_key_path):
            self.warning_label.set(f"Public key file not found at {public_key_path}")
            return None

        with open(public_key_path, 'r') as pk_file:
            public_key = RSA.import_key(pk_file.read())

        pdf_path = askopenfilename(title="Select a PDF file to verify signature", filetypes=[("PDF Files", "*.pdf")])
        if not pdf_path or not os.path.exists(pdf_path):
            return None

        with open(pdf_path, 'rb') as file:
            pdf_reader = PdfReader(file)

            signature_hex = pdf_reader.metadata.get('/Signature')
            if not signature_hex:
                self.verify_label.set("No signature found in PDF.")
                return False

            try:
                signature = binascii.unhexlify(signature_hex)
            except binascii.Error:
                self.verify_label.set("Invalid signature format.")
                return False

            hash_value = SHA256.new()
            for page in pdf_reader.pages:
                text = page.extract_text()
                if text:
                    hash_value.update(text.encode('utf-8'))

            try:
                pkcs1_15.new(public_key).verify(hash_value, signature)
                self.verify_label.set("Signature is valid.")
                return True
            except (ValueError, TypeError):
                self.verify_label.set("Signature verification failed.")
                return False