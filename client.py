import json, socket, threading, argparse, os, datetime

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode


class Client:
    def __init__(self, server, port, username):
        self.server = server
        self.port = port
        self.username = username

    # Create the connection to the server
    def create_connection(self):
        # Setting up the socket, takes the serverIP and portNumber arguments to set up the connection to the server
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server, self.port))
        except Exception as e:
            print(f"[!] {e}")

        # Initial message exchanges for the communication
        # Setting up username, keys
        # Calling exchange secret and pub key functions
        self.s.send(
            self.username.encode()
        )  # Inform the server about the username connected
        print(" Connected successfully")
        print(" Exchanging keys")

        self.create_key_pairs()  # Create key pairs
        self.exchange_public_keys()  # Initial public key exchange
        global secret_key  # Global variable to hold the secret key for AES encryption
        # Function to get the secret generated by the server
        secret_key = self.handle_secret()

        print(" Initial set up had been completed!")
        print(" Now you can start to exchange messages \n\n")

        # InputHandle for sending messages and MessageHandle thread for receiving messages
        message_handler = threading.Thread(target=self.handle_messages, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.input_handler, args=())
        input_handler.start()

    @staticmethod
    def decrypt_message(message):
        # Take out the initialization vector and the ciphered text and b64 decode it
        iv, cipherText = b64decode(message["iv"]), b64decode(message["ciphertext"])
        # Create and AES object, parameters: [secret_key], [counter feedback mode], [initialization vector]
        cipher = AES.new(secret_key, AES.MODE_CFB, iv=iv)
        # Use the object to decrypt the ciphertext
        return cipher.decrypt(cipherText)

    # Handle receiving messages
    def handle_messages(self):
        while True:
            message = self.s.recv(1024).decode()
            if message:
                try:
                    temp = json.loads(message)  # Load the json formatted message
                    msg = self.decrypt_message(temp)
                    current_time = datetime.datetime.now()
                    # Decode and print the byte enconded message with a timestamp
                    print(f'{current_time.strftime("%Y-%m-%d %H:%M ")} {msg.decode()}')
                except json.decoder.JSONDecodeError:
                    # If the message is not json formatted, it is a notification
                    print(message)
            else:
                print(" Lost the connection to the server")
                print(" Closing down the connection")
                self.s.shutdown(socket.SHUT_RDWR)
                os._exit(0)

    # Handle user input and send message
    def input_handler(self):
        stop = ["exit", "quit"]
        while True:
            message = input("> ")  # Take the input from the user
            if message.lower() in stop:  # EXIT will close down the client
                break
            else:
                key = secret_key
                # Initialize AES object for encryption, parameters: [key], [counter feedback mode]
                cipher = AES.new(key, AES.MODE_CFB)
                # The message what will be sent, containing the username and the user input
                message_to_encrypt = self.username + ": " + message
                # Byte encode it, because AES input must be byte encoded and Encrypt the message
                encrypted_message = cipher.encrypt(message_to_encrypt.encode())
                # Generate the initialization vector and b64 encode it along with the ciphered text
                iv = b64encode(cipher.iv).decode("utf-8")
                message = b64encode(encrypted_message).decode("utf-8")
                # Create a json formatted message
                result = json.dumps({"iv": iv, "ciphertext": message})
                self.s.send(result.encode())  # Send it in byte encoded form

        self.s.shutdown(socket.SHUT_RDWR)
        os._exit(0)

    # Receiving the secret key for symmetric encryption
    def handle_secret(self):
        # The secret key coming from the server, and used for encryption and decryption
        secret_key = self.s.recv(1024)
        # Import the client private key to decrypt the secret
        private_key = RSA.importKey(open("client_private_key.pem", "r").read())
        # Using the client private key to decrypt the secret
        cipher = PKCS1_OAEP.new(private_key)
        return cipher.decrypt(secret_key)

    # Send the public key to the server to encrypt the secret
    # The secret is generated by the server and used for symmetric encryption
    def exchange_public_keys(self):
        try:
            print(" Getting public key from the server")
            server_public_key = self.s.recv(1024).decode()
            server_public_key = RSA.importKey(server_public_key)

            print(" Sending public key to server")
            public_pem_key = RSA.importKey(open("client_public_key.pem", "r").read())
            self.s.send(public_pem_key.exportKey())
            print(" Exchange completed!")

        except Exception as e:
            print(" ERROR, you messed up something.... " + e)

    # Generate public and private key pairs
    def create_key_pairs(self):
        try:
            private_key = RSA.generate(2048)
            public_key = private_key.publickey()
            private_pem = private_key.exportKey().decode()
            public_pem = public_key.exportKey().decode()
            with open(
                "client_private_key.pem", "w"
            ) as priv:  # writing priv key to pem file
                priv.write(private_pem)
            with open(
                "client_public_key.pem", "w"
            ) as pub:  # writing public key to pem file
                pub.write(public_pem)

        except Exception as e:
            print("ERROR, you messed up somethig.... " + e)


if __name__ == "__main__":
    # Declaring command line Arguments: [server IP], [portNumber], [username]
    arg_parse = argparse.ArgumentParser()
    arg_parse.add_argument("-s", "--server", required=True, help="server ip to connect")
    arg_parse.add_argument(
        "-p", "--port", required=True, type=int, help="port the server listening on"
    )
    arg_parse.add_argument(
        "-u", "--username", required=True, help="username of the user"
    )
    args = arg_parse.parse_args()
    client = Client(args.server, args.port, args.username)
    client.create_connection()