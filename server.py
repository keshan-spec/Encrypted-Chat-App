import socket, threading, argparse
import os, datetime
from encryption.RSA import RSAEncryptionServer


class Server:
    def __init__(self, port):
        self.host = "127.0.0.1"
        self.port = port

    def start_server(self):
        # Generate the public and private keys to share
        rsa = RSAEncryptionServer()

        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.s.bind((self.host, self.port))
        self.s.listen(100)

        print(f"[+] Server started on {self.host}:{self.port}")

        self.clients = []
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
            rsa.exchange_keys(c)

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
        if command.lower() == "terminate":
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
        "-p",
        "--port",
        type=int,
        required=True,
        help="port to run the server",
    )
    arg_parse.add_argument(
        "-e",
        "--encrypt",
        type=str,
        required=True,
        help="encryption type to use (AES or RSA)",
    )
    args = arg_parse.parse_args()

    server = Server(args.port)
    terminate = threading.Thread(target=terminate, args=(server,))
    terminate.start()
    server.start_server()
