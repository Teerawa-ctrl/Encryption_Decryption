# gui.py
import tkinter as tk
from tkinter import messagebox
from test_utils import open_file, save_file
from test_encrypt import encrypt_AES, decrypt_AES
from video_encrypt import encrypt_video, decrypt_video

def encrypt_image():
    file_path = open_file()
    if file_path:
        with open(file_path, "rb") as f:
            image_data = f.read()
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
        save_file(decrypted_data, file_path.replace(".enc", "_decrypted"))
        messagebox.showinfo("Success", "Image decrypted successfully!")

def encrypt_video_file():
    file_path = open_file()
    if file_path:
        output_path = file_path + ".enc"
        password = password_entry.get()
        encrypt_video(file_path, output_path, password)
        messagebox.showinfo("Success", "Video encrypted successfully!")

def decrypt_video_file():
    file_path = open_file()
    if file_path:
        if file_path.endswith(".enc"):
            output_path = file_path.replace(".enc", "_decrypted.mp4")
        else:
            output_path = file_path + "_decrypted.mp4"
        password = password_entry.get()
        decrypt_video(file_path, output_path, password)
        messagebox.showinfo("Success", "Video decrypted successfully!")

def create_gui():
    root = tk.Tk()
    root.title("AES Encryptor_Decryptor")

    global password_entry
    password_label = tk.Label(root, text="Enter Password:")
    password_label.pack(pady=10)
    password_entry = tk.Entry(root, show="*")
    password_entry.pack(pady=10)

    encrypt_image_button = tk.Button(root, text="Encrypt Image", command=encrypt_image)
    encrypt_image_button.pack(pady=10)

    decrypt_image_button = tk.Button(root, text="Decrypt Image", command=decrypt_image)
    decrypt_image_button.pack(pady=10)

    encrypt_video_button = tk.Button(root, text="Encrypt Video", command=encrypt_video_file)
    encrypt_video_button.pack(pady=10)

    decrypt_video_button = tk.Button(root, text="Decrypt Video", command=decrypt_video_file)
    decrypt_video_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
