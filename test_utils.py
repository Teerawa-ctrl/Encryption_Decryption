# file_utils.py
from tkinter import filedialog

def open_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        return file_path
    return None

def save_file(data, file_path):
    with open(file_path, "wb") as f:
        f.write(data)
