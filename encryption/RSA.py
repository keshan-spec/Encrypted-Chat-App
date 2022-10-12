from socket import socket
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode


class RSA:
    def __init__(self) -> None:
        self.pub_key = self.generate_keys()

    # Generate the public and private key pair
    @staticmethod
    def generate_keys():
        try:
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            private_key_pem = private_key.exportKey().decode()
            public_key_pem = public_key.exportKey().decode()

            with open("server_private_key.pem", "w") as priv:
                priv.write(private_key_pem)
            with open("server_public_key.pem", "w") as pub:
                pub.write(public_key_pem)

            return public_key
        except Exception as e:
            print(e)

    # Encrypt the secret with the client public key
    @staticmethod
    def encrypt_secret(client_pub_key, secret_key):
        try:
            cpKey = RSA.importKey(client_pub_key)
            cipher = PKCS1_OAEP.new(cpKey)
            encrypted_secret = cipher.encrypt(secret_key)
            return encrypted_secret
        except Exception as e:
            print(e)

    @staticmethod
    def send_secret(c: socket, secret_key):
        try:
            c.send(secret_key)
            print(" Secret key had been sent to the client ")

        except Exception as e:
            print(e)

    # Exchanging the public key with the client
    @staticmethod
    def send_pub_key(c: socket):
        try:
            public_key = RSA.importKey(open("server_public_key.pem", "r").read())
            c.send(public_key.exportKey())
            client_pub_key = c.recv(1024)
            print(" Client public key had been received")
            return client_pub_key
        except Exception as e:
            print(f"Error exchanging public key with client: {e}")

    def exchange_keys(self, c):
        client_pub_key = self.send_pub_key(c)
        secret_key = get_random_bytes(16)
        encrypted_secret = self.encrypt_secret(client_pub_key, secret_key)
        self.send_secret(c, encrypted_secret)
