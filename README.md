"""
Cryptography Project
Demonstration of Symmetric Encryption with AES

NOTE:
AES.MODE_ECB is used for educational purposes only.
In real-world applications, more secure modes such as CBC or GCM should be used.
"""

from tkinter import Tk, Label, Entry, Button, Text, END
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib


# =========================
# Encryption / Decryption
# =========================

def encrypt(message: str, password: str) -> str:
    """
    Encrypts text using AES symmetric encryption.
    Key is generated from password using SHA-256.
    """
    key = hashlib.sha256(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    encrypted_bytes = cipher.encrypt(padded_message)
    return base64.b64encode(encrypted_bytes).decode()


def decrypt(encrypted_message: str, password: str) -> str:
    """
    Decrypts AES-encrypted text.
    """
    try:
        key = hashlib.sha256(password.encode()).digest()
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted_bytes = base64.b64decode(encrypted_message)
        decrypted_message = unpad(
            cipher.decrypt(encrypted_bytes),
            AES.block_size
        )
        return decrypted_message.decode()
    except (ValueError, TypeError) as error:
        raise ValueError(
            "Decryption error. Check the password or encrypted text format."
        ) from error


# =========================
# GUI logic
# =========================

def encrypt_message():
    message = input_text.get("1.0", END).strip()
    password = password_entry.get()

    if not message or not password:
        output_text.delete("1.0", END)
        output_text.insert(END, "Enter text and password.")
        return

    encrypted = encrypt(message, password)
    output_text.delete("1.0", END)
    output_text.insert(END, encrypted)


def decrypt_message():
    encrypted_message = input_text.get("1.0", END).strip()
    password = password_entry.get()

    if not encrypted_message or not password:
        output_text.delete("1.0", END)
        output_text.insert(END, "Enter encrypted text and password.")
        return

    try:
        decrypted = decrypt(encrypted_message, password)
        output_text.delete("1.0", END)
        output_text.insert(END, decrypted)
    except ValueError as error:
        output_text.delete("1.0", END)
        output_text.insert(END, str(error))


# =========================
# Application UI
# =========================

app = Tk()
app.title("AES Encryption and Decryption")
app.geometry("600x400")

Label(app, text="Enter text to encrypt/decrypt:").pack(pady=5)
input_text = Text(app, height=5, width=60)
input_text.pack(pady=5)

Label(app, text="Enter password:").pack(pady=5)
password_entry = Entry(app, show="*", width=30)
password_entry.pack(pady=5)

Button(app, text="Encrypt", command=encrypt_message).pack(pady=5)
Button(app, text="Decrypt", command=decrypt_message).pack(pady=5)

Label(app, text="Result:").pack(pady=5)
output_text = Text(app, height=5, width=60)
output_text.pack(pady=5)

app.mainloop()
