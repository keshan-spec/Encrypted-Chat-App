from Crypto.Cipher import AES
from base64 import b64encode, b64decode
import json


class AES:
    def __init__(self, key):
        self.key = key

    def encrypt(self, msg) -> str:
        # Initialize AES object for encryption, parameters: [key], [counter feedback mode]
        cipher = AES.new(self.key, AES.MODE_CFB)
        # The message what will be sent, containing the username and the user input
        # Byte encode it, because AES input must be byte encoded and Encrypt the message
        encrypted_message = cipher.encrypt(msg.encode())
        # Generate the initialization vector and b64 encode it along with the ciphered text
        iv = b64encode(cipher.iv).decode("utf-8")
        message = b64encode(encrypted_message).decode("utf-8")
        # Create a json formatted message
        return json.dumps({"iv": iv, "ciphertext": message})

    def decrypt_message(self, message):
        # Take out the initialization vector and the ciphered text and b64 decode it
        iv, cipherText = b64decode(message["iv"]), b64decode(message["ciphertext"])
        # Create and AES object, parameters: [secret_key], [counter feedback mode], [initialization vector]
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
        # Use the object to decrypt the ciphertext
        return cipher.decrypt(cipherText)
