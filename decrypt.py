from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import main

def decrypt_file(encrypted_file_path, password):
    with open(encrypted_file_path, "rb") as encrypted_file:
        # Read the salt, IV, and ciphertext from the file
        salt = encrypted_file.read(16)
        iv = encrypted_file.read(16)
        ciphertext = encrypted_file.read()

    # Derive the key from the password and salt
    key = main.derive_key(password, salt)

    # Print some information for debugging
    #print("Salt:", salt)
    #print("IV:", iv)
    #print("Ciphertext:", ciphertext)

    # Decrypt the ciphertext using CFB mode
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Save the decrypted data to a new file
    with open(encrypted_file_path[:-8] + "_decrypted.txt", "wb") as decrypted_file:
        decrypted_file.write(decrypted_data)
