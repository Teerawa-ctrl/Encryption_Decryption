import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode
import os
import cv2
import numpy as np
from PIL import Image, ImageTk

# ฟังก์ชันเข้ารหัส AES
def encrypt_AES(data, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return salt + iv + encrypted_data

# ฟังก์ชันถอดรหัส AES
def decrypt_AES(encrypted_data, password):
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data

# ฟังก์ชันเปิดไฟล์ภาพ
def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        return file_path
    return None

# ฟังก์ชันสำหรับการเข้ารหัสภาพ
def encrypt_image():
    file_path = open_file()
    if file_path:
        image = cv2.imread(file_path)
        image_data = cv2.imencode('.png', image)[1].tobytes()
        password = password_entry.get()
        encrypted_data = encrypt_AES(image_data, password)
        with open(file_path + ".enc", "wb") as f:
            f.write(encrypted_data)
        messagebox.showinfo("Success", "Image encrypted successfully!")

# ฟังก์ชันสำหรับการถอดรหัสภาพ
def decrypt_image():
    file_path = open_file()
    if file_path:
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        password = password_entry.get()
        decrypted_data = decrypt_AES(encrypted_data, password)
        image_np = np.frombuffer(decrypted_data, np.uint8)
        image = cv2.imdecode(image_np, cv2.IMREAD_COLOR)
        cv2.imshow("Decrypted Image", image)
        cv2.waitKey(0)
        cv2.destroyAllWindows()

# ฟังก์ชันสำหรับการสร้าง GUI
def create_gui():
    root = tk.Tk()
    root.title("AES Image Encryptor/Decryptor")

    global password_entry
    password_label = tk.Label(root, text="Enter Password:")
    password_label.pack(pady=10)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=10)

    encrypt_button = tk.Button(root, text="Encrypt Image", command=encrypt_image)
    encrypt_button.pack(pady=10)

    decrypt_button = tk.Button(root, text="Decrypt Image", command=decrypt_image)
    decrypt_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
