# gui.py
import tkinter as tk
from tkinter import messagebox
from App.test_utils import open_file
from App.test_encrypt import encrypt_AES, decrypt_AES
import cv2
import numpy as np

def encrypt_image():
    file_path = open_file()
    if file_path:
        image = cv2.imread(file_path)
        image_data = cv2.imencode('.png', image)[1].tobytes()
        password = password_entry.get()
        encrypted_data = encrypt_AES(image_data, password)
        save_file(encrypted_data, file_path + ".enc")
        messagebox.showinfo("Success", "Image encrypted successfully!")

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
