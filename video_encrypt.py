# video_encryption.py
import cv2
from encrypt import encrypt_AES, decrypt_AES
import numpy as np

def encrypt_video(input_file_path, output_file_path, password):
    with open(input_file_path, 'rb') as f:
        data = f.read()
    encrypted_data = encrypt_AES(data, password)
    with open(output_file_path, 'wb') as f:
        f.write(encrypted_data)

def decrypt_video(input_file_path, output_file_path, password):
    with open(input_file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_AES(encrypted_data, password)
    with open(output_file_path, 'wb') as f:
        f.write(decrypted_data)