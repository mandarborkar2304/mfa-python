import base64
import hashlib
import hmac
import os
import random
import string
import tkinter as tk
from time import time
from tkinter import messagebox
from typing import Tuple
import qrcode


def generate_secret_key(length: int = 16) -> str:
    """Generate a secure random base32 secret key"""
    return base64.b32encode(os.urandom(length)).decode('utf-8')


def get_hotp_token(secret: str, intervals_no: int) -> int:
    """Generate a HMAC-based One-Time Password (HOTP)"""
    key = base64.b32decode(secret, True)
    msg = int.to_bytes(intervals_no, 8, 'big') 
    hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
    ob = hmac_digest[19] & 15
    otp = (int.from_bytes(hmac_digest[ob:ob + 4], 'big') & 0x7fffffff) % 1000000
    return otp


def get_totp_token(secret: str) -> int:
    """Generate a Time-based One-Time Password (TOTP)"""
    return get_hotp_token(secret, intervals_no=int(time()) // 30)


def verify_totp(token: int, secret: str, window: int = 1) -> bool:
    """Verify a TOTP given a specific window"""
    for error in range(-window, window + 1):
        if get_hotp_token(secret, intervals_no=int(time()) // 30 + error) == token:
            return True
    return False

class MFAApp:
    def __init__(self, master):
        self.master = master
        self.master.title("MFA App")
        self.secret_key = generate_secret_key()
        self.totp_token = get_totp_token(self.secret_key)

        self.secret_key_label = tk.Label(master, text="Secret Key:")
        self.secret_key_label.pack()

        self.secret_key_entry = tk.Entry(master, width=40, show="*")
        self.secret_key_entry.insert(0, self.secret_key)
        self.secret_key_entry.pack()

        self.qr_code_image_label = tk.Label(master, image="")

        self.generate_qr_code()

        self.token_label = tk.Label(master, text="Enter the TOTP token:")
        self.token_label.pack()

        self.token_entry = tk.Entry(master, width=40)
        self.token_entry.pack()

        self.verify_button = tk.Button(master, text="Verify", command=self.verify_token)
        self.verify_button.pack()

        print(f"Secret Key: {self.secret_key}")
        print(f"TOTP Token: {self.totp_token}")

    def verify_token(self):
        user_provided_token = int(self.token_entry.get())
        if verify_totp(user_provided_token, self.secret_key):
            messagebox.showinfo("Authentication Result", "Authentication successful!")
            self.secret_key_label.pack_forget()
            self.secret_key_entry.pack_forget()
            self.token_label.pack_forget()
            self.token_entry.pack_forget()
            self.verify_button.pack_forget()
            self.generate_qr_code()
            self.token_label = tk.Label(self.master, text="Enter the Google Authenticator code:")
            self.token_label.pack()
            self.token_entry = tk.Entry(self.master, width=40)
            self.token_entry.pack()
            self.verify_button = tk.Button(self.master, text="Verify", command=self.verify_google_code)
            self.verify_button.pack()
        else:
            messagebox.showinfo("Authentication Result", "Authentication failed. Please try again.")
            print(f"User-provided token: {user_provided_token}")

    def generate_qr_code(self):
        uri = f"otpauth://totp/MyApp:{self.secret_key}?secret={self.secret_key}&issuer=MyApp"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save("qr_code.png")
        self.qr_code_image_label.config(image=tk.PhotoImage(file="qr_code.png"))
        self.qr_code_image_label.image = tk.PhotoImage(file="qr_code.png")
        self.qr_code_image_label.pack()

    def verify_google_code(self):
        user_provided_google_code = int(self.token_entry.get())
        if verify_totp(user_provided_google_code, self.secret_key):
            messagebox.showinfo("Authentication Result", "Authentication successful!")
        else:
            messagebox.showinfo("Authentication Result", "Authentication failed. Please try again.")
            print(f"User-provided Google Authenticator code: {user_provided_google_code}")


if __name__ == '__main__':
    root = tk.Tk()
    app = MFAApp(root)
    root.mainloop()
