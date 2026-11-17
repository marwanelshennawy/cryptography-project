import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import requests
import string
import struct
import json
import base64
import hashlib
import random
import math
import threading
from sympy import randprime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

BASE_URL = "http://4.149.142.212/"
client_session = requests.Session()
MAX_STORAGE_BYTES = 200 * 1024 * 1024

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


def AESEncrypt(data, key):
    iv = os.urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv + ciphertext


def AESDecrypt(ciphertext, key):
    iv = ciphertext[:16]
    encrypted = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()

    padded = decryptor.update(encrypted) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded) + unpadder.finalize()

    return data


def hash_password_SHA256(password: bytes):
    password = password.encode()

    h0, h1, h2, h3, h4, h5, h6, h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

    mask = 0xffffffff

    password_length = len(password) * 8
    password += b'\x80'

    while (len(password) * 8) % 512 != 448:
        password += b'\x00'

    password += struct.pack('>Q', password_length)

    for i in range(0, len(password), 64):
        chunk = password[i:i + 64]
        w = list(struct.unpack('>16I', chunk)) + [0] * 48

        for t in range(16, 64):
            w15 = w[t - 15]
            w2 = w[t - 2]

            s0 = ((w15 >> 7) | (w15 << 25)) ^ ((w15 >> 18) | (w15 << 14)) ^ (w15 >> 3)
            s1 = ((w2 >> 17) | (w2 << 15)) ^ ((w2 >> 19) | (w2 << 13)) ^ (w2 >> 10)

            w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & mask

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for t in range(64):
            S1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[t] + w[t]) & mask

            S0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & mask

            h = g
            g = f
            f = e
            e = (d + temp1) & mask
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & mask

        h0 = (h0 + a) & mask
        h1 = (h1 + b) & mask
        h2 = (h2 + c) & mask
        h3 = (h3 + d) & mask
        h4 = (h4 + e) & mask
        h5 = (h5 + f) & mask
        h6 = (h6 + g) & mask
        h7 = (h7 + h) & mask

    return ''.join(f'{x:08x}' for x in [h0, h1, h2, h3, h4, h5, h6, h7])


def RSAKeyGeneration():
    p = randprime(1000, 10000)
    q = randprime(1000, 10000)

    n = p * q
    phi = (p - 1) * (q - 1)

    while True:
        e = random.randint(2, phi - 1)
        if math.gcd(e, phi) == 1:
            break

    d = pow(e, -1, phi)
    if d == e:
        d += phi

    return e, d, n


def RSAEncryption(file_content, password):
    e, d, n = RSAKeyGeneration()

    encrypted_bytes = bytearray()

    for char in file_content:
        m = ord(char)
        c = pow(m, e, n)
        block_size = (n.bit_length() + 7) // 8

        encrypted_bytes.extend(c.to_bytes(block_size, byteorder="big"))

    ciphertext = base64.b64encode(encrypted_bytes).decode()

    fdk = json.dumps({
        "d": d,
        "n": n
    }).encode()

    salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000,
        dklen=32
    )

    encrypted_fdk = AESEncrypt(fdk, key)

    header = {
        "algorithm": "RSA",
        "fdk": base64.b64encode(encrypted_fdk).decode(),
        "salt": base64.b64encode(salt).decode()
    }

    return {
        "header": header,
        "ciphertext": ciphertext
    }


def RSADecryption(file_content, password):
    header = file_content["header"]
    ciphertext = file_content["ciphertext"]

    salt = base64.b64decode(header["salt"])

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000,
        dklen=32
    )

    encrypted_fdk = base64.b64decode(header["fdk"])
    fdk = AESDecrypt(encrypted_fdk, key)

    private_key = json.loads(fdk.decode())

    d = private_key["d"]
    n = private_key["n"]

    encrypted_bytes = base64.b64decode(ciphertext)

    decryptedMessage = ""
    block_size = (n.bit_length() + 7) // 8

    for i in range(0, len(encrypted_bytes), block_size):
        chunk = encrypted_bytes[i:i + block_size]
        c = int.from_bytes(chunk, byteorder="big")
        m = pow(c, d, n)
        decryptedMessage += chr(m)

    return decryptedMessage


def ElGamalKeyGeneration():
    p = randprime(1000, 10000)

    while True:
        D = random.randint(2, p - 2)
        if math.gcd(D, p) == 1:
            break

    K = []
    for i in range(1, p - 1):
        if (p - 1) % i == 0:
            K.append(i)

    E1 = 2
    while True:
        flag = True
        for k in K:
            if pow(E1, k, p) == 1:
                flag = 0
                break
        if flag:
            break
        E1 += 1

    E2 = pow(E1, D, p)

    return E1, E2, p, D


def ElGamalEncryption(file_content, password):
    E1, E2, P, D = ElGamalKeyGeneration()
    r = random.randint(1, P - 2)
    c1 = pow(E1, r, P)

    encrypted_bytes = bytearray()

    shared_secret = pow(E2, r, P)

    block_size = (P.bit_length() + 7) // 8

    for char in file_content:
        m = ord(char)
        c = (m * shared_secret) % P
        encrypted_bytes.extend(c.to_bytes(block_size, byteorder="big"))

    c2 = base64.b64encode(encrypted_bytes).decode()

    metadata = json.dumps({
        "c1": c1,
        "D": D,
        "P": P
    }).encode()

    salt = os.urandom(16)

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000,
        dklen=32
    )

    encrypted_metadata = AESEncrypt(metadata, key)

    header = {
        "algorithm": "ElGamal",
        "metadata": base64.b64encode(encrypted_metadata).decode(),
        "salt": base64.b64encode(salt).decode()
    }

    return {
        "header": header,
        "c2": c2
    }


def ElGamalDecryption(file_content, password):
    header = file_content["header"]
    encrypted_metadata = base64.b64decode(header["metadata"])

    salt = base64.b64decode(header["salt"])

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        100000,
        dklen=32
    )

    metadata = json.loads(AESDecrypt(encrypted_metadata, key).decode())

    c1 = metadata["c1"]
    D = metadata["D"]
    P = metadata["P"]

    encrypted_bytes = base64.b64decode(file_content["c2"])

    decryptedMessage = ""

    block_size = (P.bit_length() + 7) // 8

    shared_secret = pow(c1, D, P)

    inverse_secret = pow(shared_secret, -1, P)

    for i in range(0, len(encrypted_bytes), block_size):
        chunk = encrypted_bytes[i:i + block_size]
        c = int.from_bytes(chunk, byteorder="big")
        m = (c * inverse_secret) % P
        decryptedMessage += chr(m)

    return decryptedMessage


def hybridEncryption(file_content, password):
    rsa_result = RSAEncryption(file_content, password)

    rsa_ciphertext = rsa_result["ciphertext"]

    rsa_fdk = rsa_result["header"]["fdk"]
    rsa_salt = rsa_result["header"]["salt"]

    elgamal_result = ElGamalEncryption(rsa_ciphertext, password)

    elgamal_ciphertext = elgamal_result["c2"]

    elgamal_metadata = elgamal_result["header"]["metadata"]
    elgamal_salt = elgamal_result["header"]["salt"]

    return {
        "header": {
            "algorithm": "Hybrid",
            "fdk": rsa_fdk,
            "metadata": elgamal_metadata,
            "RSA-salt": rsa_salt,
            "ElGamal_salt": elgamal_salt
        },
        "ciphertext": elgamal_ciphertext
    }


def hybridDecryption(file_content, password):
    header = file_content["header"]

    elgamal_structure = {
        "header": {
            "algorithm": "ElGamal",
            "metadata": header["metadata"],
            "salt": header["ElGamal_salt"]
        },
        "c2": file_content["ciphertext"]
    }

    rsa_ciphertext = ElGamalDecryption(elgamal_structure, password)

    rsa_structure = {
        "header": {
            "algorithm": "RSA",
            "fdk": header["fdk"],
            "salt": header["RSA-salt"]
        },
        "ciphertext": rsa_ciphertext
    }

    plaintext = RSADecryption(rsa_structure, password)

    return plaintext


class ToastManager:
    def __init__(self, parent):
        self.parent = parent
        self.frame = ctk.CTkFrame(parent, height=15, corner_radius=10)
        self.label = ctk.CTkLabel(self.frame, text="", font=("Arial", 13, "bold"))
        self.label.pack(padx=30, pady=2)

    def show(self, message, duration=5000):
        self.frame.configure(fg_color="#8B1E1E")
        self.label.configure(text=message)
        self.frame.place(relx=0.5, y=15, anchor="n")
        self.parent.after(duration, self.hide)

    def hide(self):
        self.frame.place_forget()


class LoginFrame(ctk.CTkFrame):
    def __init__(self, master, switch_to_signup, switch_to_dashboard, toast):
        super().__init__(master)

        self.switch_to_signup = switch_to_signup
        self.switch_to_dashboard = switch_to_dashboard
        self.toast = toast

        ctk.CTkLabel(self, text="LOGIN", font=("Arial", 28, "bold")).pack(pady=25)

        self.username = ctk.CTkEntry(self, placeholder_text="Username", width=280)
        self.username.pack(pady=10)

        self.password = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=280)
        self.password.pack(pady=10)

        ctk.CTkButton(self, text="Login", width=220, command=self.login).pack(pady=15)

        ctk.CTkButton(self, text="Go to Sign Up", fg_color="transparent", hover_color="#333333",
                      command=self.switch_to_signup).pack(pady=10)

    def login(self):
        username = self.username.get()
        password = self.password.get()

        if not username or not password:
            self.toast.show("All fields are required")
            return

        try:
            hashed_password = hash_password_SHA256(password)
            response = client_session.post(f"{BASE_URL}/login", json={"username": username,
                                                                      "password": hashed_password})

            if response.json() is True:
                self.switch_to_dashboard(password)
            else:
                self.toast.show("Invalid username or password")

        except Exception as e:
            self.toast.show(str(e))


class SignupFrame(ctk.CTkFrame):
    def __init__(self, master, switch_to_dashboard, toast):
        super().__init__(master)

        self.switch_to_dashboard = switch_to_dashboard
        self.toast = toast

        ctk.CTkLabel(self, text="SIGN UP", font=("Arial", 28, "bold")).pack(pady=25)

        self.username = ctk.CTkEntry(self, placeholder_text="Username", width=280)
        self.username.pack(pady=10)

        self.password = ctk.CTkEntry(self, placeholder_text="Password", show="*", width=280)
        self.password.pack(pady=10)

        self.confirm = ctk.CTkEntry(self, placeholder_text="Confirm Password", show="*", width=280)
        self.confirm.pack(pady=10)

        ctk.CTkButton(self, text="Sign Up", width=220, command=self.signup).pack(pady=15)

    def signup(self):
        username = self.username.get()
        password = self.password.get()
        confirm = self.confirm.get()

        if not username or not password or not confirm:
            self.toast.show("All fields are required")
            return

        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        special_chars = string.punctuation
        has_special = any(c in special_chars for c in password)

        if not len(password) > 6 or not has_upper or not has_lower or not has_digit or not has_special:
            self.toast.show("Passwords must be at least 7 chars, combination of capital and small letters, digits"
                            " and special chars")
            return

        if password != confirm:
            self.toast.show("Passwords do not match")
            self.confirm.delete(0, "end")
            return

        try:
            password = hash_password_SHA256(password)
            response = client_session.post(f"{BASE_URL}/sign-up", json={"username": username, "password": password})

            if response.status_code == 201:
                self.switch_to_dashboard(password)
            else:
                self.toast.show(response.json().get("message", "Signup failed"))

        except Exception as e:
            self.toast.show(str(e))


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, toast, password):
        super().__init__(master)

        self.algorithm = ctk.StringVar(value="RSA")

        self.user_password = password
        self.file_content = ""
        self.encrypted_file_content = {}
        self.active_uploads = set()
        self.active_downloads = set()

        self.toast = toast
        self.retrieve_files_response = self.retrieve_files()
        self.files = self.retrieve_files_response["files"]
        self.files_sizes = self.retrieve_files_response["corresponding-sizes"]

        self.top_bar = ctk.CTkFrame(self, height=60, corner_radius=0)
        self.top_bar.pack(fill="x", side="top")

        ctk.CTkButton(self.top_bar, text="⬆ Upload", width=120, command=self.upload_file).pack(side="right", padx=10,
                                                                                               pady=10)

        ctk.CTkButton(self.top_bar, text="Delete account", width=120, command=self.delete_account).pack(side="left",
                                                                                                        padx=10,
                                                                                                        pady=10)

        self.progress_bar = ctk.CTkProgressBar(self.top_bar, width=185)
        self.progress_bar.pack(side="left", padx=10, pady=10)

        self.storage_label = ctk.CTkLabel(self.top_bar, text="")
        self.storage_label.pack(side="left", padx=10)

        self.update_progress()

        ctk.CTkSegmentedButton(self.top_bar, values=["ElGamal", "RSA", "Hybrid"], width=180, variable=self.algorithm)\
            .pack(side="right", padx=10, pady=10)

        self.file_area = ctk.CTkScrollableFrame(self, scrollbar_button_color="White",
                                                scrollbar_button_hover_color="White")
        self.file_area.pack(fill="both", expand=True, padx=10, pady=10)
        self.render_files()

    def update_progress(self):
        used_bytes = sum(self.files_sizes)
        max_bytes = MAX_STORAGE_BYTES

        if max_bytes <= 0:
            ratio = 0.0
        else:
            ratio = used_bytes / max_bytes

        ratio = min(max(ratio, 0.0), 1.0)

        self.progress_bar.set(ratio)

        used_mb = used_bytes / (1024 * 1024)
        max_mb = max_bytes / (1024 * 1024)

        self.storage_label.configure(text=f"{used_mb:.1f} MB / {max_mb:.1f} MB")

        if ratio < 0.7:
            color = "white"
        elif ratio < 0.9:
            color = "orange"
        else:
            color = "red"

        self.storage_label.configure(text_color=color)

    def delete_account(self):
        result = messagebox.askyesno("Confirmation",
                                     "Are you sure you want to delete your account?\nThis action cannot be undone.")

        if not result:
            return

        try:
            response = client_session.post(f"{BASE_URL}/delete-account")

            if response.status_code == 200:
                self.master.master.show_login_frame()
            else:
                self.toast.show(response.json().get("error", "Failed to delete account"))

        except Exception as e:
            self.toast.show(str(e))

    def retrieve_files(self):
        try:
            response = client_session.get(f"{BASE_URL}/retrieve-files-names")

            if response.status_code == 200:
                return response.json()
            else:
                self.toast.show("Failed to retrieve files")
                return []

        except Exception as e:
            self.toast.show(str(e))
            return {"files": [], "total_storage": 0}

    def render_files(self):
        for widget in self.file_area.winfo_children():
            widget.destroy()

        cols, row, col = 4, 0, 0

        for filename, file_size in zip(self.files, self.files_sizes):
            card = self.create_file_card(self.file_area, filename, file_size)
            card.grid(row=row, column=col, padx=20, pady=15)

            col += 1
            if col == cols:
                col = 0
                row += 1

    def create_file_card(self, parent, filename, file_size):
        frame = ctk.CTkFrame(parent, width=150, height=150, corner_radius=10, fg_color="Black")
        frame.grid_propagate(False)
        frame.pack_propagate(False)

        ctk.CTkLabel(frame, text=filename, wraplength=130, text_color="White", font=("Arial", 15, "bold")).pack(pady=10)

        btn_frame = ctk.CTkFrame(frame, fg_color="transparent")
        btn_frame.pack(pady=15)

        if file_size < (1024 * 1024):
            ctk.CTkLabel(frame, text=str((round(file_size/1024, 2)))+" KB", wraplength=130,
                         text_color="#B0B0B0").pack(side="right", padx=10)
        else:
            ctk.CTkLabel(frame, text=str(round(file_size / (1024 * 1024), 2)) + " MB", text_color="#B0B0B0",
                         wraplength=130).pack(side="right", padx=10)

        ctk.CTkButton(btn_frame, text="⬇", width=40, command=lambda f=filename: self.download_file(f)).pack(side="left",
                                                                                                            padx=5)

        ctk.CTkButton(btn_frame, text="🗑", width=40, fg_color="red", command=lambda f=filename: self.delete_file(f)) \
            .pack(side="left", padx=5)

        return frame

    def upload_file_thread(self, file_path):
        filename = os.path.basename(file_path)

        try:
            file_size = os.path.getsize(file_path)
            algorithm = self.algorithm.get()

            with open(file_path, "r", encoding="utf-8") as file:
                self.file_content = file.read()

            if algorithm == "ElGamal":
                self.encrypted_file_content = ElGamalEncryption(self.file_content, self.user_password)

            elif algorithm == "RSA":
                self.encrypted_file_content = RSAEncryption(self.file_content, self.user_password)

            else:
                self.encrypted_file_content = hybridEncryption(self.file_content, self.user_password)

            response = client_session.post(
                f"{BASE_URL}/upload",
                json={
                    "filename": filename,
                    "data": self.encrypted_file_content,
                    "size": str(file_size)
                }
            )

            self.after(0, lambda: self.handle_upload_response(response, filename, file_size))

        except Exception as e:
            self.after(0, lambda: self.toast.show(str(e)))

        finally:
            self.active_uploads.discard(filename)

    def handle_upload_response(self, response, filename, file_size):
        try:
            if response.status_code == 200:
                if filename not in self.files:
                    self.files.append(filename)
                    self.files_sizes.append(file_size)
                else:
                    self.files_sizes[self.files.index(filename)] = file_size

                self.render_files()
                self.update_progress()

            else:
                try:
                    data = response.json()
                    error_message = data.get("error") or data.get("message") or "Upload failed"
                except:
                    error_message = response.text

                self.toast.show(error_message)

        except Exception as e:
            self.toast.show(str(e))

    def upload_file(self):
        file_path = filedialog.askopenfilename()

        if not file_path:
            return

        _, ext = os.path.splitext(file_path)

        if ext.lower() != ".txt":
            self.toast.show("Only .txt files allowed")
            return

        filename = os.path.basename(file_path)

        if filename in self.active_uploads:
            self.toast.show("This file is already being uploaded")
            return

        if filename in self.files:
            result = messagebox.askyesno(
                "confirmation message",
                "there is file with this name, do you want to overwrite it?"
            )

            if not result:
                return

        self.active_uploads.add(filename)

        threading.Thread(target=self.upload_file_thread, args=(file_path,), daemon=True).start()

    def delete_file(self, filename):
        try:
            response = client_session.post(f"{BASE_URL}/delete", json={"filename": filename})

            if response.status_code == 200:
                index = self.files.index(filename)
                self.files_sizes.pop(index)
                self.files.remove(filename)
                self.render_files()
                self.update_progress()
            else:
                self.toast.show("Delete failed")

        except Exception as e:
            self.toast.show(str(e))

    def download_file_thread(self, filename):
        try:
            response = client_session.get(
                f"{BASE_URL}/retrieve",
                params={"filename": filename},
                stream=True
            )

            if response.status_code != 200:
                self.after(0, lambda: self.toast.show("Download failed"))
                return

            save_path = filedialog.asksaveasfilename(initialfile=filename, defaultextension=".txt",
                                                     filetypes=[("Text Files", "*.txt")])

            if not save_path:
                return

            encrypted_data = b""

            for chunk in response.iter_content(8192):
                if chunk:
                    encrypted_data += chunk

            encrypted_json = json.loads(encrypted_data.decode())

            algorithm = encrypted_json["header"]["algorithm"]

            if algorithm == "ElGamal":
                plaintext = ElGamalDecryption(encrypted_json, self.user_password)

            elif algorithm == "RSA":
                plaintext = RSADecryption(encrypted_json, self.user_password)

            elif algorithm == "Hybrid":
                plaintext = hybridDecryption(encrypted_json, self.user_password)

            else:
                raise Exception("Unsupported algorithm")

            with open(save_path, "w", encoding="utf-8") as file:
                file.write(plaintext)

        except Exception as e:
            self.after(0, lambda e=e: self.toast.show(str(e)))

        finally:
            self.active_downloads.discard(filename)

    def download_file(self, filename):
        if filename in self.active_downloads:
            self.toast.show("This file is already being downloaded")
            return

        self.active_downloads.add(filename)

        threading.Thread(target=self.download_file_thread, args=(filename,), daemon=True).start()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Secure Storage")
        self.geometry("800x500")
        self.resizable(False, False)

        self.container = ctk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        self.toast = ToastManager(self)

        self.current_frame = None
        self.show_login_frame()

    def clear(self):
        if self.current_frame:
            self.current_frame.destroy()

    def show_login_frame(self):
        self.clear()
        self.current_frame = LoginFrame(self.container, self.show_signup_frame, self.show_dashboard_frame, self.toast)
        self.current_frame.pack(expand=True)

    def show_signup_frame(self):
        self.clear()
        self.current_frame = SignupFrame(self.container, self.show_dashboard_frame, self.toast)
        self.current_frame.pack(expand=True)

    def show_dashboard_frame(self, password):
        self.clear()
        self.current_frame = DashboardFrame(self.container, self.toast, password)
        self.current_frame.pack(fill="both", expand=True)


app = App()
app.mainloop()