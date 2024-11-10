# encryption.py
import asyncio
import json
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(data, key):
    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Initialize AES cipher with 32-byte key and 16-byte IV in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to AES block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return {"ciphertext": ciphertext, "iv": iv}  # Return both the ciphertext and the IV


def decrypt(ciphertext, key, iv):
    # Initialize AES cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return {"decrypted_data": decrypted_data}


def main():
    input_data = json.loads(sys.stdin.read())
    data = input_data["data"]
    key = input_data["key"]
    iv = input_data.get("iv")
    operation = input_data["operation"]

    if operation == "encrypt":
        result = encrypt(data, key)
    elif operation == "decrypt":
        result = decrypt(data, key, iv)
    else:
        result = "Invalid operation"

    # Output the result as JSON
    print(json.dumps({"result": result}))


if __name__ == "__main__":
    main()
