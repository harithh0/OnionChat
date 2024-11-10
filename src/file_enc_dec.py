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

    byte_data = bytes(byte_list)

    key = bytes([key_dict[str(i)] for i in range(len(key_dict))])

    iv = os.urandom(16)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(byte_data) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    ciphertext_base64 = base64.b64encode(ciphertext).decode("utf-8")
    iv_base64 = base64.b64encode(iv).decode("utf-8")

    return {
        "ciphertext": ciphertext_base64,
        "iv": iv_base64,
    }


def decrypt(ciphertext_base64, key_dict, iv_base64):

    ciphertext = base64.b64decode(ciphertext_base64)
    iv = base64.b64decode(iv_base64)
    key = bytes([key_dict[str(i)] for i in range(len(key_dict))])

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    decrypted_data_base64 = base64.b64encode(decrypted_data).decode("utf-8")

    return {"decrypted_data": (decrypted_data_base64)}


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

    print(json.dumps({"result": result}))


if __name__ == "__main__":
    main()
