# encryption_utils.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

def encrypt_AES(data, password):
    
    """
    เข้ารหัสข้อมูลด้วย AES
    :param data: ข้อมูลที่ต้องการเข้ารหัส
    :param password: รหัสผ่านที่ใช้ในการเข้ารหัส
    :return: ข้อมูลที่เข้ารหัสแล้ว
    """
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

def decrypt_AES(encrypted_data, password):
    
    """
    ถอดรหัสข้อมูลด้วย AES
    :param encrypted_data: ข้อมูลที่เข้ารหัสแล้ว
    :param password: รหัสผ่านที่ใช้ในการถอดรหัส
    :return: ข้อมูลที่ถอดรหัสแล้ว
    """
    
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
