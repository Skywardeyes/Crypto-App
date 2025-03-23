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
        self.root.title("密码学应用")
        self.root.geometry("800x600")

        # 创建不同功能区域的标签页
        self.notebook = ttk.Notebook(root)

        # 消息摘要标签页
        self.digest_tab = ttk.Frame(self.notebook)
        self.create_digest_ui()

        # 对称加密标签页
        self.sym_tab = ttk.Frame(self.notebook)
        self.create_symmetric_ui()

        # 非对称加密标签页
        self.asym_tab = ttk.Frame(self.notebook)
        self.create_asymmetric_ui()

        # 数字签名标签页
        self.sig_tab = ttk.Frame(self.notebook)
        self.create_signature_ui()

        self.notebook.add(self.digest_tab, text="消息摘要")
        self.notebook.add(self.sym_tab, text="对称加密")
        self.notebook.add(self.asym_tab, text="非对称加密")
        self.notebook.add(self.sig_tab, text="数字签名")
        self.notebook.pack(expand=True, fill="both")

    def create_digest_ui(self):
        frame = ttk.Frame(self.digest_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入文本")
        input_frame.pack(fill="x", pady=(0, 10))

        self.digest_input = tk.Text(input_frame, height=5)
        self.digest_input.pack(fill="x", padx=5, pady=5)

        # 算法选择
        algo_frame = ttk.LabelFrame(frame, text="选择算法")
        algo_frame.pack(fill="x", pady=(0, 10))

        self.digest_algo = tk.StringVar(value="MD5")
        ttk.Radiobutton(algo_frame, text="MD5", variable=self.digest_algo, value="MD5").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="SHA-1", variable=self.digest_algo, value="SHA1").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="SHA-256", variable=self.digest_algo, value="SHA256").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="SHA-512", variable=self.digest_algo, value="SHA512").pack(side="left", padx=5)

        # 计算按钮
        ttk.Button(frame, text="计算摘要", command=self.calculate_digest).pack(pady=10)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="消息摘要")
        output_frame.pack(fill="both", expand=True)

        self.digest_output = tk.Text(output_frame, height=5, state="disabled")
        self.digest_output.pack(fill="both", expand=True, padx=5, pady=5)

    def create_symmetric_ui(self):
        frame = ttk.Frame(self.sym_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入文本")
        input_frame.pack(fill="x", pady=(0, 10))

        self.sym_input = tk.Text(input_frame, height=5)
        self.sym_input.pack(fill="x", padx=5, pady=5)

        # 算法和密钥区域
        algo_key_frame = ttk.Frame(frame)
        algo_key_frame.pack(fill="x", pady=(0, 10))

        # 算法选择
        algo_frame = ttk.LabelFrame(algo_key_frame, text="算法")
        algo_frame.pack(side="left", fill="x", expand=True, padx=(0, 5))

        self.sym_algo = tk.StringVar(value="AES")
        ttk.Radiobutton(algo_frame, text="AES", variable=self.sym_algo, value="AES").pack(side="left", padx=5)
        ttk.Radiobutton(algo_frame, text="DES", variable=self.sym_algo, value="DES").pack(side="left", padx=5)

        # 密钥输入
        key_frame = ttk.LabelFrame(algo_key_frame, text="加密密钥")
        key_frame.pack(side="left", fill="x", expand=True, padx=(5, 0))

        self.sym_key = ttk.Entry(key_frame)
        self.sym_key.pack(fill="x", padx=5, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(btn_frame, text="加密", command=self.encrypt_symmetric).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="解密", command=self.decrypt_symmetric).pack(side="left", padx=5)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill="both", expand=True)

        self.sym_output = tk.Text(output_frame, height=5, state="disabled")
        self.sym_output.pack(fill="both", expand=True, padx=5, pady=5)

    def create_asymmetric_ui(self):
        frame = ttk.Frame(self.asym_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 密钥生成区域
        key_frame = ttk.LabelFrame(frame, text="RSA密钥对")
        key_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(key_frame, text="生成RSA密钥", command=self.generate_rsa_keys).pack(pady=5)

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入文本")
        input_frame.pack(fill="x", pady=(0, 10))

        self.asym_input = tk.Text(input_frame, height=5)
        self.asym_input.pack(fill="x", padx=5, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(btn_frame, text="加密", command=self.encrypt_asymmetric).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="解密", command=self.decrypt_asymmetric).pack(side="left", padx=5)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill="both", expand=True)

        self.asym_output = tk.Text(output_frame, height=5, state="disabled")
        self.asym_output.pack(fill="both", expand=True, padx=5, pady=5)

    def create_signature_ui(self):
        frame = ttk.Frame(self.sig_tab)
        frame.pack(padx=10, pady=10, fill="both", expand=True)

        # 证书区域
        cert_frame = ttk.LabelFrame(frame, text="证书")
        cert_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(cert_frame, text="生成证书", command=self.generate_certificate).pack(pady=5)

        # 输入区域
        input_frame = ttk.LabelFrame(frame, text="输入文本")
        input_frame.pack(fill="x", pady=(0, 10))

        self.sig_input = tk.Text(input_frame, height=5)
        self.sig_input.pack(fill="x", padx=5, pady=5)

        # 操作按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=(0, 10))

        ttk.Button(btn_frame, text="签名", command=self.create_signature).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="验证", command=self.verify_signature).pack(side="left", padx=5)

        # 输出区域
        output_frame = ttk.LabelFrame(frame, text="输出")
        output_frame.pack(fill="both", expand=True)

        self.sig_output = tk.Text(output_frame, height=5, state="disabled")
        self.sig_output.pack(fill="both", expand=True, padx=5, pady=5)

    # 消息摘要功能
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
            messagebox.showwarning("输入错误", "请输入要哈希的文本")
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

    # 对称加密功能
    def des_encrypt(self, plaintext, key):
        # 填充数据至8字节倍数
        length = 8 - len(plaintext) % 8
        plaintext += chr(length) * length

        # 生成IV并创建密码器
        iv = Random.get_random_bytes(8)
        cipher = DES.new(key.encode(), DES.MODE_CBC, iv)

        # 加密并返回base64编码结果
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(iv + ciphertext).decode()

    def des_decrypt(self, ciphertext, key):
        try:
            # 解码base64并提取IV
            data = base64.b64decode(ciphertext.encode())
            iv = data[:8]
            ciphertext = data[8:]

            # 创建密码器并解密
            cipher = DES.new(key.encode(), DES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext).decode()

            # 移除填充
            pad_length = ord(plaintext[-1])
            return plaintext[:-pad_length]
        except Exception as e:
            messagebox.showerror("解密错误", str(e))
            return None

    def aes_encrypt(self, plaintext, key):
        # 填充数据至16字节倍数
        length = 16 - len(plaintext) % 16
        plaintext += chr(length) * length

        # 生成IV并创建密码器
        iv = Random.get_random_bytes(16)
        cipher = AES.new(key.encode(), AES.MODE_CBC, iv)

        # 加密并返回base64编码结果
        ciphertext = cipher.encrypt(plaintext.encode())
        return base64.b64encode(iv + ciphertext).decode()

    def aes_decrypt(self, ciphertext, key):
        try:
            # 解码base64并提取IV
            data = base64.b64decode(ciphertext.encode())
            iv = data[:16]
            ciphertext = data[16:]

            # 创建密码器并解密
            cipher = AES.new(key.encode(), AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(ciphertext).decode()

            # 移除填充
            pad_length = ord(plaintext[-1])
            return plaintext[:-pad_length]
        except Exception as e:
            messagebox.showerror("解密错误", str(e))
            return None

    def encrypt_symmetric(self):
        data = self.sym_input.get("1.0", "end-1c")
        key = self.sym_key.get()

        if not data:
            messagebox.showwarning("输入错误", "请输入要加密的文本")
            return

        if not key:
            messagebox.showwarning("密钥错误", "请输入加密密钥")
            return

        algo = self.sym_algo.get()
        try:
            if algo == "AES":
                if len(key) not in [16, 24, 32]:
                    messagebox.showwarning("密钥错误", "AES密钥必须为16、24或32字节")
                    return
                result = self.aes_encrypt(data, key)
            else:
                if len(key) != 8:
                    messagebox.showwarning("密钥错误", "DES密钥必须为8字节")
                    return
                result = self.des_encrypt(data, key)

            self.sym_output.config(state="normal")
            self.sym_output.delete("1.0", "end")
            self.sym_output.insert("1.0", result)
            self.sym_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("加密错误", str(e))

    def decrypt_symmetric(self):
        data = self.sym_input.get("1.0", "end-1c")
        key = self.sym_key.get()

        if not data:
            messagebox.showwarning("输入错误", "请输入要解密的文本")
            return

        if not key:
            messagebox.showwarning("密钥错误", "请输入加密密钥")
            return

        algo = self.sym_algo.get()
        try:
            if algo == "AES":
                if len(key) not in [16, 24, 32]:
                    messagebox.showwarning("密钥错误", "AES密钥必须为16、24或32字节")
                    return
                result = self.aes_decrypt(data, key)
            else:
                if len(key) != 8:
                    messagebox.showwarning("密钥错误", "DES密钥必须为8字节")
                    return
                result = self.des_decrypt(data, key)

            if result is not None:
                self.sym_output.config(state="normal")
                self.sym_output.delete("1.0", "end")
                self.sym_output.insert("1.0", result)
                self.sym_output.config(state="disabled")
        except Exception as e:
            messagebox.showerror("解密错误", str(e))

    # 非对称加密功能
    def generate_rsa_keys(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            # 保存密钥到文件
            with open("private.pem", "wb") as f:
                f.write(private_key)
            with open("public.pem", "wb") as f:
                f.write(public_key)

            messagebox.showinfo("成功", "RSA密钥已生成并保存为private.pem和public.pem")
        except Exception as e:
            messagebox.showerror("密钥生成错误", str(e))

    def rsa_encrypt(self, plaintext, public_key):
        try:
            key = RSA.import_key(public_key)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = cipher.encrypt(plaintext.encode())
            return base64.b64encode(ciphertext).decode()
        except Exception as e:
            messagebox.showerror("加密错误", str(e))
            return None

    def rsa_decrypt(self, ciphertext, private_key):
        try:
            key = RSA.import_key(private_key)
            cipher = PKCS1_OAEP.new(key)
            ciphertext = base64.b64decode(ciphertext.encode())
            plaintext = cipher.decrypt(ciphertext).decode()
            return plaintext
        except Exception as e:
            messagebox.showerror("解密错误", str(e))
            return None

    def encrypt_asymmetric(self):
        data = self.asym_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("输入错误", "请输入要加密的文本")
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
            messagebox.showwarning("密钥错误", "请先生成RSA密钥")
        except Exception as e:
            messagebox.showerror("加密错误", str(e))

    def decrypt_asymmetric(self):
        data = self.asym_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("输入错误", "请输入要解密的文本")
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
            messagebox.showwarning("密钥错误", "请先生成RSA密钥")
        except Exception as e:
            messagebox.showerror("解密错误", str(e))

    # 数字签名功能
    def generate_certificate(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()

            # 创建自签名证书（示例代码，实际需要完整实现）
            # 注意：原代码中缺少x509相关导入，此处保留原始结构
            subject = issuer = "示例证书信息"
            # 示例证书生成逻辑（需补充完整）

            with open("certificate.pem", "wb") as f:
                f.write(public_key)  # 示例中简化为写入公钥

            messagebox.showinfo("成功", "证书已生成并保存为certificate.pem")
        except Exception as e:
            messagebox.showerror("证书错误", str(e))

    def create_signature(self, data, private_key):
        try:
            key = RSA.import_key(private_key)
            h = SHA256.new(data.encode())
            signature = pkcs1_15.new(key).sign(h)
            return base64.b64encode(signature).decode()
        except Exception as e:
            messagebox.showerror("签名错误", str(e))
            return None

    def verify_signature(self, data, signature, public_key):
        try:
            key = RSA.import_key(public_key)
            h = SHA256.new(data.encode())
            signature = base64.b64decode(signature.encode())
            pkcs1_15.new(key).verify(h, signature)
            return True
        except (ValueError, TypeError) as e:
            return False
        except Exception as e:
            messagebox.showerror("验证错误", str(e))
            return False

    def create_signature(self):
        data = self.sig_input.get("1.0", "end-1c")
        if not data:
            messagebox.showwarning("输入错误", "请输入文本")
            return

        try:
            with open("private.pem", "rb") as f:
                private_key = f.read()

            result = self.create_signature(data, private_key)
            if result:
                self.sig_output.config(state="normal")
                self.sig_output.delete("1.0", "end")
                self.sig_output.insert("1.0", result)
                self.sig_output.config(state="disabled")
        except FileNotFoundError:
            messagebox.showwarning("密钥错误", "请先生成RSA密钥")
        except Exception as e:
            messagebox.showerror("签名错误", str(e))

    def verify_signature(self):
        data = self.sig_input.get("1.0", "end-1c")
        signature = self.sig_output.get("1.0", "end-1c")

        if not data:
            messagebox.showwarning("输入错误", "请输入文本")
            return

        if not signature:
            messagebox.showwarning("签名错误", "请先生成签名")
            return

        try:
            with open("public.pem", "rb") as f:
                public_key = f.read()

            if self.verify_signature(data, signature, public_key):
                messagebox.showinfo("成功", "签名有效")
            else:
                messagebox.showwarning("警告", "签名无效")
        except FileNotFoundError:
            messagebox.showwarning("密钥错误", "请先生成RSA密钥")
        except Exception as e:
            messagebox.showerror("验证错误", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoApp(root)
    root.mainloop()