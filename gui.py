# gui.py
import tkinter as tk
from tkinter import messagebox , ttk
from utils import open_file, save_file
from encrypt import encrypt_AES, decrypt_AES
from video_encrypt import encrypt_video, decrypt_video
import re

def check_password_strength(password):
    if len(password) < 8:
        return "Weak: Password too short"
    if not re.search(r"[A-Za-z]", password) or not re.search(r"[0-9]", password):
        return "Weak: Must contain letters and numbers"
    if not re.search(r"[A-Z]", password):
        return "Moderate: Add uppercase letters for strength"
    if not re.search(r"[@$!%*?&]", password):
        return "Moderate: Add special characters for strength"
    return "Strong"

def on_password_entry_change(event):
    password = password_entry.get()
    strength_label.config(text=check_password_strength(password)) # type: ignore

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
    
    #Dark Mode
    dark_bg = "#2e2e2e"
    dark_fg = "#ffffff"
    dark_button_bg = "#444444"
    dark_button_active_bg = "#666666"
    dark_entry_bg = "#3e3e3e"

    root.configure(bg=dark_bg)
    
    global password_entry, strength_label, progress_bar

    # ใช้ Frame เพื่อจัด layout แบบ horizontal
    top_frame = tk.Frame(root, bg=dark_bg)
    top_frame.grid(row=0, column=0, sticky="ew", padx=20, pady=10)

    middle_frame = tk.Frame(root, bg=dark_bg)
    middle_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=10)

    bottom_frame = tk.Frame(root, bg=dark_bg)
    bottom_frame.grid(row=2, column=0, sticky="ew", padx=20, pady=10)

    # การตั้งค่าให้ Frame ขยายตามหน้าต่าง
    for i in range(3):
        root.grid_rowconfigure(i, weight=1)
    root.grid_columnconfigure(0, weight=1)

    password_label = tk.Label(top_frame, text="Enter Password:", bg=dark_bg, fg=dark_fg)
    password_label.pack(side=tk.LEFT, padx=10)

    password_entry = tk.Entry(top_frame, show="*", bg=dark_entry_bg, fg=dark_fg, insertbackground=dark_fg)
    password_entry.pack(side=tk.LEFT, padx=10, fill=tk.X, expand=True)
    password_entry.bind('<KeyRelease>', on_password_entry_change)

    strength_label = tk.Label(top_frame, text="", bg=dark_bg, fg=dark_fg)
    strength_label.pack(side=tk.LEFT, padx=10)

    encrypt_image_button = tk.Button(middle_frame, text="Encrypt Image", command=encrypt_image,
                                     bg=dark_button_bg, fg=dark_fg, activebackground=dark_button_active_bg)
    encrypt_image_button.pack(side=tk.LEFT, padx=10)

    decrypt_image_button = tk.Button(middle_frame, text="Decrypt Image", command=decrypt_image,
                                     bg=dark_button_bg, fg=dark_fg, activebackground=dark_button_active_bg)
    decrypt_image_button.pack(side=tk.LEFT, padx=10)

    encrypt_video_button = tk.Button(middle_frame, text="Encrypt Video", command=encrypt_video_file,
                                     bg=dark_button_bg, fg=dark_fg, activebackground=dark_button_active_bg)
    encrypt_video_button.pack(side=tk.LEFT, padx=10)

    decrypt_video_button = tk.Button(middle_frame, text="Decrypt Video", command=decrypt_video_file,
                                     bg=dark_button_bg, fg=dark_fg, activebackground=dark_button_active_bg)
    decrypt_video_button.pack(side=tk.LEFT, padx=10)

    progress_bar = ttk.Progressbar(bottom_frame, orient="horizontal", length=400, mode="determinate")
    progress_bar.pack(padx=10, pady=20, fill=tk.X, expand=True)

    root.mainloop()

