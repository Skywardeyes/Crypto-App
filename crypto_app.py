import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from hashlib import md5, sha1, sha256, sha512
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import os
import datetime

class CryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Application")
        self.root.geometry("800x600")
        
        # Create notebook for different sections
        self.notebook = ttk.Notebook(root)
        
        # Message Digest Tab
        self.digest_tab = ttk.Frame(self.notebook)
        self.create_digest_ui()
        
        # Symmetric Encryption Tab
        self.sym_tab = ttk.Frame(self.notebook)
        self.create_symmetric_ui()
        
        # Asymmetric Encryption Tab
        self.asym_tab = ttk.Frame(self.notebook)
        self.create_asymmetric_ui()
        
        # Digital Signature Tab
        self.sig_tab = ttk.Frame(self.notebook)
        self.create_signature_ui()
        
        self.notebook.add(self.digest_tab, text="Message Digest")
        self.notebook.add(self.sym_tab, text="Symmetric Encryption")
        self.notebook.add(self.asym_tab, text="Asymmetric Encryption")
        self.notebook.add(self.sig_tab, text="Digital Signature")
        self.notebook.pack(expand=True, fill="both")
        
    def create_digest_ui(self):
        frame = ttk.Frame(self.digest_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Input Section
        input_frame = ttk.LabelFrame(frame, text="Input Text")
        input_frame.pack(fill="x", pady=(0, 10))
        
        self.digest_input = tk.Text(input_frame, height=5)
        self.digest_input.pack(fill="x", padx=5, pady=5)
        
        # Algorithm Selection
        algo_frame = ttk.LabelFrame(frame, text="Select Algorithm")
        algo_frame.pack(fill="x", pady=(0, 10))
        
        self.digest_algo = tk.StringVar(value="MD5")
        ttk.Radiobutton(algo_frame, text="MD5", variable=self.digest_algo, value="MD5").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="SHA-1", variable=self.digest_algo, value="SHA1").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="SHA-256", variable=self.digest_algo, value="SHA256").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="SHA-512", variable=self.digest_algo, value="SHA512").pack(side="left", padx=5)
        
        # Calculate Button
        ttk.Button(frame, text="Calculate Digest", command=self.calculate_digest).pack(pady=10)
        
        # Output Section
        output_frame = ttk.LabelFrame(frame, text="Message Digest")
        output_frame.pack(fill="both", expand=True)
        
        self.digest_output = tk.Text(output_frame, height=5, state="disabled")
        self.digest_output.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_symmetric_ui(self):
        frame = ttk.Frame(self.sym_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Input Section
        input_frame = ttk.LabelFrame(frame, text="Input Text")
        input_frame.pack(fill="x", pady=(0, 10))
        
        self.sym_input = tk.Text(input_frame, height=5)
        self.sym_input.pack(fill="x", padx=5, pady=5)
        
        # Algorithm and Key Section
        algo_key_frame = ttk.Frame(frame)
        algo_key_frame.pack(fill="x", pady=(0, 10))
        
        # Algorithm Selection
        algo_frame = ttk.LabelFrame(algo_key_frame, text="Algorithm")
        algo_frame.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.sym_algo = tk.StringVar(value="AES")
        ttk.Radiobutton(algo_frame, text="AES", variable=self.sym_algo, value="AES").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="DES", variable=self.sym_algo, value="DES").pack(side="left", padx=5)
        
        # Key Input
        key_frame = ttk.LabelFrame(algo_key_frame, text="Encryption Key")
        key_frame.pack(side="left", fill="x", expand=True, padx=(5, 0))
        
        self.sym_key = ttk.Entry(key_frame)
        self.sym_key.pack(fill="x", padx=5, pady=5)
        
        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_symmetric).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_symmetric).pack(side="left", padx=5)
        
        # Output Section
        output_frame = ttk.LabelFrame(frame, text="Output")
        output_frame.pack(fill="both", expand=True)
        
        self.sym_output = tk.Text(output_frame, height=5, state="disabled")
        self.sym_output.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_asymmetric_ui(self):
        frame = ttk.Frame(self.asym_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Key Generation Section
        key_frame = ttk.LabelFrame(frame, text="RSA Key Pair")
        key_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(key_frame, text="Generate RSA Keys", command=self.generate_rsa_keys).pack(pady=5)
        
        # Input Section
        input_frame = ttk.LabelFrame(frame, text="Input Text")
        input_frame.pack(fill="x", pady=(0, 10))
        
        self.asym_input = tk.Text(input_frame, height=5)
        self.asym_input.pack(fill="x", padx=5, pady=5)
        
        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(btn_frame, text="Encrypt", command=self.encrypt_asymmetric).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Decrypt", command=self.decrypt_asymmetric).pack(side="left", padx=5)
        
        # Output Section
        output_frame = ttk.LabelFrame(frame, text="Output")
        output_frame.pack(fill="both", expand=True)
        
        self.asym_output = tk.Text(output_frame, height=5, state="disabled")
        self.asym_output.pack(fill="both", expand=True, padx=5, pady=5)
        
    def create_signature_ui(self):
        frame = ttk.Frame(self.sig_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)
        
        # Certificate Section
        cert_frame = ttk.LabelFrame(frame, text="Certificate")
        cert_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(cert_frame, text="Generate Certificate", command=self.generate_certificate).pack(pady=5)
        
        # Input Section
        input_frame = ttk.LabelFrame(frame, text="Input Text")
        input_frame.pack(fill="x", pady=(0, 10))
        
        self.sig_input = tk.Text(input_frame, height=5)
        self.sig_input.pack(fill="x", padx=5, pady=5)
        
        # Action Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(btn_frame, text="Sign", command=self.create_signature).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Verify", command=self.verify_signature).pack(side="left", padx=5)
        
        # Output Section
        output_frame = ttk.LabelFrame(frame, text="Output")
        output_frame.pack(fill="both", expand=True)
        
        self.sig_output = tk.Text(output_frame, height=5, state="disabled")
        self.sig_output.pack(fill="both", expand=True, padx=5, pady=5)
        
    # Message Digest Functions
    def calculate_md5(self, data):
        return md5(data.encode()).hexdigest()
        
    def calculate_sha1(self, data):
        return sha1(data.encode()).hexdigest()
        
    def calculate_sha256(self, data):
        return sha256(data.encode()).hexdigest()
        
    def calculate_sha512(self, data):
        return sha512(data.encode()).hexdigest()
        
    def calculate_digest(self):
        data = self.digest_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to hash")
            return
            
        algo = self.digest_algo.get()
        if algo == "MD5":
            result = self.calculate_md5(data)
        elif algo == "SHA1":
            result = self.calculate_sha1(data)
        elif algo == "SHA256":
            result = self.calculate_sha256(data)
        elif algo == "SHA512":
            result = self.calculate_sha512(data)
            
        self.digest_output.config(state="normal")
        self.digest_output.delete("1.0", "end")
        self.digest_output.insert("1.0", result)
        self.digest_output.config(state="disabled")
        
    # Symmetric Encryption Functions
    def des_encrypt(self, plaintext, key):
        # Pad data to be multiple of 8 bytes
        length = 8 - len(plaintext) % 8
        plaintext += chr(length) * length
        
        # Generate IV and create cipher
        iv = Random.get_random_bytes(8)
        cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
        
        # Encrypt and return base64 encoded result
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(iv + ciphertext).decode()
        
    def des_decrypt(self, ciphertext, key):
        try:
            # Decode base64 and extract IV
            data = base64.b64decode(ciphertext.encode())
            iv = data[:8]
            ciphertext = data[8:]
            
            # Create cipher and decrypt
            cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext).decode()
            
            # Remove padding
            pad_length = ord(plaintext[-1])
            return plaintext[:-pad_length]
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return None
        
    def aes_encrypt(self, plaintext, key):
        # Pad data to be multiple of 16 bytes
        length = 16 - len(plaintext) % 16
        plaintext += chr(length) * length
        
        # Generate IV and create cipher
        iv = Random.get_random_bytes(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
        
        # Encrypt and return base64 encoded result
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(iv + ciphertext).decode()
        
    def aes_decrypt(self, ciphertext, key):
        try:
            # Decode base64 and extract IV
            data = base64.b64decode(ciphertext.encode())
            iv = data[:16]
            ciphertext = data[16:]
            
            # Create cipher and decrypt
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext).decode()
            
            # Remove padding
            pad_length = ord(plaintext[-1])
            return plaintext[:-pad_length]
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return None
            
    def encrypt_symmetric(self):
        data = self.sym_input.get("1.0", "end-1c")
        key = self.sym_key.get()
        
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to encrypt")
            return
            
        if not key:
            messagebox.showwarning("Key Error", "Please enter an encryption key")
            return
            
        algo = self.sym_algo.get()
        try:
            if algo == "AES":
                if len(key) not in [16, 24, 32]:
                    messagebox.showwarning("Key Error", "AES key must be 16, 24, or 32 bytes long")
                    return
                result = self.aes_encrypt(data, key)
            else:
                if len(key) != 8:
                    messagebox.showwarning("Key Error", "DES key must be exactly 8 bytes long")
                    return
                result = self.des_encrypt(data, key)
                
            self.sym_output.config(state="normal")
            self.sym_output.delete("1.0", "end")
            self.sym_output.insert("1.0", result)
            self.sym_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            
    def decrypt_symmetric(self):
        data = self.sym_input.get("1.0", "end-1c")
        key = self.sym_key.get()
        
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to decrypt")
            return
            
        if not key:
            messagebox.showwarning("Key Error", "Please enter an encryption key")
            return
            
        algo = self.sym_algo.get()
        try:
            if algo == "AES":
                if len(key) not in [16, 24, 32]:
                    messagebox.showwarning("Key Error", "AES key must be 16, 24, or 32 bytes long")
                    return
                result = self.aes_decrypt(data, key)
            else:
                if len(key) != 8:
                    messagebox.showwarning("Key Error", "DES key must be exactly 8 bytes long")
                    return
                result = self.des_decrypt(data, key)
                
            if result is not None:
                self.sym_output.config(state="normal")
                self.sym_output.delete("1.0", "end")
                self.sym_output.insert("1.0", result)
                self.sym_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
        
    # Asymmetric Encryption Functions
    def generate_rsa_keys(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            # Save keys to files
            with open("private.pem", "wb") as f:
                f.write(private_key)
            with open("public.pem", "wb") as f:
                f.write(public_key)
                
            messagebox.showinfo("Success", "RSA keys generated and saved as private.pem and public.pem")
        except Exception as e:
            messagebox.showerror("Key Generation Error", str(e))
        
    def rsa_encrypt(self, plaintext, public_key):
        try:
            key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = cipher.encrypt(plaintext.encode())
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            return None
        
    def rsa_decrypt(self, ciphertext, private_key):
        try:
            key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = base64.b64decode(ciphertext.encode())
            plaintext = cipher.decrypt(ciphertext).decode()
            return plaintext
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            return None
            
    def encrypt_asymmetric(self):
        data = self.asym_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to encrypt")
            return
            
        try:
            with open("public.pem", "rb") as f:
                public_key = f.read()
                
            result = self.rsa_encrypt(data, public_key)
            if result:
                self.asym_output.config(state="normal")
                self.asym_output.delete("1.0", "end")
                self.asym_output.insert("1.0", result)
                self.asym_output.config(state="disabled")
        except FileNotFoundError:
            messagebox.showwarning("Key Error", "Please generate RSA keys first")
        except Exception as e:
            messagebox.showerror("Encryption Error", str(e))
            
    def decrypt_asymmetric(self):
        data = self.asym_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to decrypt")
            return
            
        try:
            with open("private.pem", "rb") as f:
                private_key = f.read()
                
            result = self.rsa_decrypt(data, private_key)
            if result:
                self.asym_output.config(state="normal")
                self.asym_output.delete("1.0", "end")
                self.asym_output.insert("1.0", result)
                self.asym_output.config(state="disabled")
        except FileNotFoundError:
            messagebox.showwarning("Key Error", "Please generate RSA keys first")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))
            
    # Digital Signature Functions
    def generate_certificate(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            
            # Create self-signed certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Beijing"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "Beijing"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CryptoApp"),
                x509.NameAttribute(NameOID.COMMON_NAME, "cryptoapp.com"),
            ])
            
            cert = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.datetime.utcnow()
            ).not_valid_after(
                datetime.datetime.utcnow() + datetime.timedelta(days=365)
            ).sign(key, hashes.SHA256())
            
            with open("certificate.pem", "wb") as f:
                f.write(cert.public_bytes(serialization.Encoding.PEM))
                
            messagebox.showinfo("Success", "Certificate generated and saved as certificate.pem")
        except Exception as e:
            messagebox.showerror("Certificate Error", str(e))
        
    def _sign_data(self, data, private_key):
        try:
            key = RSA.import_key(private_key)
            h = SHA256.new(data.encode())
            signature = pkcs1_15.new(key).sign(h)
            return base64.b64encode(signature).decode()
        except Exception as e:
            messagebox.showerror("Signing Error", str(e))
            return None
            
    def _verify_data(self, data, signature, public_key):
        try:
            key = RSA.import_key(public_key)
            h = SHA256.new(data.encode())
            signature = base64.b64decode(signature.encode())
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            return False
        except Exception as e:
            messagebox.showerror("Verification Error", str(e))
            return False
            
    def create_signature(self):
        data = self.sig_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to sign")
            return
            
        try:
            with open("private.pem", "rb") as f:
                private_key = f.read()
                
            result = self._sign_data(data, private_key)
            if result:
                self.sig_output.config(state="normal")
                self.sig_output.delete("1.0", "end")
                self.sig_output.insert("1.0", result)
                self.sig_output.config(state="disabled")
        except FileNotFoundError:
            messagebox.showwarning("Key Error", "Please generate RSA keys first")
        except Exception as e:
            messagebox.showerror("Signing Error", str(e))
            
    def verify_signature(self):
        data = self.sig_input.get("1.0", "end-1c")
        signature = self.sig_output.get("1.0", "end-1c")
        
        if not data:
            messagebox.showwarning("Input Error", "Please enter some text to verify")
            return
            
        if not signature:
            messagebox.showwarning("Signature Error", "Please create a signature first")
            return
            
        try:
            with open("public.pem", "rb") as f:
                public_key = f.read()
                
            if self._verify_signature(data, signature, public_key):
                messagebox.showinfo("Success", "Signature is valid")
            else:
                messagebox.showwarning("Warning", "Signature is invalid")
        except FileNotFoundError:
            messagebox.showwarning("Key Error", "Please generate RSA keys first")
        except Exception as e:
            messagebox.showerror("Verification Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()
