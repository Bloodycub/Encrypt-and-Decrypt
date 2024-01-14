from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import main
import os

def encrypt_file(file_path, password, salt):
    # Derive a key from the password and salt
    key = main.derive_key(password, salt)

    # Generate a random initialization vector (IV)
    iv = os.urandom(16)

    with open(file_path, "rb") as file:
        plaintext = file.read()

    # Print debug information
    print("Key:", key)
    print("IV:", iv)
    print("Plaintext:", plaintext)

    # Encrypt the plaintext
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Save the salt, IV, and ciphertext to a new file
    with open(file_path + ".enc", "wb") as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext)
        print("Salt:", salt)

# Rest of your code remains unchanged
