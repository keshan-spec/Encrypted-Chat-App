import socket, threading, argparse
import os, datetime
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes


class Server:
    def __init__(self, port):
        self.host = "127.0.0.1"
        self.port = port

    def start_server(self):
        # Generate the public and private keys to share
        # And a random secret key for AES
        self.generate_keys()
        secret_key = get_random_bytes(16)

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.clients = []

        self.s.bind((self.host, self.port))
        self.s.listen(100)

        print(f"[+] Server started on {self.host}:{self.port}")

        self.username_lookup = {}

        """
        The server will wait for a client to connect
        Once a client connects, the key exchange will start
        Once its done the server will start to listen for messages on a new thread
        """
        while True:
            c, addr = self.s.accept()
            username = c.recv(1024).decode()
            print(f"[+] {username} connected from {addr[0]}:{addr[1]}")

            # Add the client to the list of clients
            self.username_lookup[c] = username
            self.clients.append(c)

            # Exchange the public key with the client
            client_pub_key = self.send_pub_key(c)
            # Encrypt the secret with the client public key
            encrypted_secret = self.encrypt_secret(client_pub_key, secret_key)
            # send the encrypted secret to the client
            self.send_secret(c, encrypted_secret)

            # Broadcast the new user to all the clients
            self.broadcast(f"{username} has joined the server.", c)

            # Start listening for messages on a new thread
            threading.Thread(
                target=self.handle_client,
                args=(
                    c,
                    addr,
                ),
            ).start()

    # Sending broadcast messages
    def broadcast(self, msg, c):
        print(f"[+] Broadcasting: {msg}")
        for connection in self.clients:
            if connection == c:
                continue
            connection.send(msg.encode())

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
    def send_secret(c, secret_key):
        try:
            c.send(secret_key)
            print(" Secret key had been sent to the client ")

        except Exception as e:
            print(e)

    # Exchanging the public key with the client
    @staticmethod
    def send_pub_key(c):
        try:
            public_key = RSA.importKey(open("server_public_key.pem", "r").read())
            c.send(public_key.exportKey())
            client_pub_key = c.recv(1024)
            print(" Client public key had been received")
            return client_pub_key
        except Exception as e:
            print(f"Error exchanging public key with client: {e}")

    def handle_client(self, c, _):
        while True:
            try:
                msg = c.recv(1024)
            except:
                c.shutdown(socket.SHUT_RDWR)
                self.clients.remove(c)
                self.broadcast(f"{self.username_lookup[c]} has left.", c)
                break

            if msg.decode() != "":
                current_time = datetime.datetime.now()
                print(
                    f"[*] {current_time.strftime('%Y-%m-%d %H:%M:%S')}: Message exchanged"
                )
                for connection in self.clients:
                    if connection == c:
                        continue
                    connection.send(msg)
            else:
                print(f"[-] {self.username_lookup[c]} has left.")
                for conn in self.clients:
                    if conn == c:
                        self.clients.remove(c)
                break


def terminate(Server):
    while True:
        command = input("")
        if command == "TERMINATE":
            for conn in Server.clients:
                conn.shutdown(socket.SHUT_RDWR)
            print(" All connections had been terminated")
        break
    print(" Server is shut down")
    os._exit(0)


if __name__ == "__main__":
    # Port needed as argument whihc will be used to open the socket
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument(
        "-p", "--port", type=int, required=True, help="port to run the server"
    )
    args = arg_parse.parse_args()

    server = Server(args.port)
    terminate = threading.Thread(target=terminate, args=(server,))
    terminate.start()
    server.start_server()
