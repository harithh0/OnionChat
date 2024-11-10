# encryption.py
import ast
import asyncio
import base64
import json
import os
import sys

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(data, key_dict):
    byte_list = [int(x.strip()) for x in data.split(",")]

    # Convert the list of integers into a bytes object
    byte_data = bytes(byte_list)

    # Decode the Base64 string to bytes
    # data = base64.b64decode(data_base64)

    # Rebuild the key from the dictionary (assuming the key_dict has the key as a sequence of 32 integers)
    key = bytes([key_dict[str(i)] for i in range(len(key_dict))])

    # Generate a random 16-byte IV
    iv = os.urandom(16)

    # Initialize AES cipher with 32-byte key and 16-byte IV in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad data to AES block size (16 bytes)
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(byte_data) + padder.finalize()

    # Encrypt the data
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Encode the ciphertext and IV as Base64 strings
    ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")
    iv_base64 = base64.b64encode(iv).decode("utf-8")

    decrypted_data = decrypt(ciphertext_base64, key_dict, iv_base64)

    return {
        "ciphertext": ciphertext_base64,
        "iv": iv_base64,
    }  # Return Base64-encoded ciphertext and IV


def decrypt(ciphertext_base64, key_dict, iv_base64):

    ciphertext = base64.b64decode(ciphertext_base64)
    iv = base64.b64decode(iv_base64)
    key = bytes([key_dict[str(i)] for i in range(len(key_dict))])
    # Initialize AES cipher for decryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the decrypted data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
    decrypted_data = decrypted_data.decode()
    return {"decrypted_data": str(decrypted_data)}


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
