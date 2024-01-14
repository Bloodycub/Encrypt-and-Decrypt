from cryptography.fernet import Fernet
import encrypt
import decrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
from getpass import getpass
import hashlib
from cryptography.hazmat.primitives import hashes

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Output key length
        salt=salt,
        iterations=100000,  # Adjust the number of iterations as needed
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def check_password(entered_password_bytes, stored_password_hash, salt):
    # Hash the entered password with the stored salt
    entered_password_hash = hashlib.sha256(entered_password_bytes + salt).hexdigest()

    # Compare the stored hash with the hash of the entered password
    return entered_password_hash == stored_password_hash

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename="key.key"):
    with open(filename, "wb") as key_file:
        key_file.write(key)

def load_key(filename="key.key"):
    try:
        with open(filename, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        return None

def checkfile(file_name):
    if not os.path.exists(file_name):
        with open(file_name, "w") as file:
            file.write("")
            print(f"File '{file_name}' created successfully.")
    else:
        print(f"File '{file_name}' already exists.")

def checkkey(key):
    if key is None:
        key = generate_key()
        save_key(key)
        print("New key generated and saved.")
    else:
        print("Using an existing key.")

def main():
    input_file = "a.txt"
    checkfile(input_file)

    key = load_key()
    checkkey(key)
    salt = os.urandom(16)


    while True:
        try:
            operation = int(input("Enter 1 for 'encrypt' or 2 for 'decrypt': "))
            if operation == 1:
                password = input("Enter Password For Encrypt. ")
                encrypt.encrypt_file(input_file, password, salt)
                print("File encrypted successfully!")
                break

            elif operation == 2:
                entered_password = getpass("Enter the password to decrypt with: ")

                if entered_password is None:
                    print("Please encrypt the file first before attempting to decrypt.")
                    continue

                # Convert the password to bytes
                entered_password_bytes = entered_password.encode()
                stored_password_hash = hashlib.sha256(bytes(entered_password_bytes) + salt).hexdigest()

                if check_password(entered_password_bytes, stored_password_hash, salt):
                    print("Password correct. Proceeding...")
                    decrypt.decrypt_file(input_file + ".enc", entered_password)
                    print("File decrypted successfully!")
                    break
                else:
                    print("Incorrect password. Please try again.")
            else:
                 print("Invalid operation. Please enter '1' or '2'.")
        except ValueError:
            print("Invalid operation. Please enter '1' or '2'.")

if __name__ == "__main__":
    main()
