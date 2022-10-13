import json, socket, threading, argparse, os, datetime
from encryption.RSA import RSAEncryptionClient

class Client:
    def __init__(self, server, port, username, encryption):
        self.server = server
        self.port = port
        self.username = username
        self.enc_type = encryption

    # Create the connection to the server
    def create_connection(self):
        # Setting up the socket, takes the serverIP and portNumber arguments to set up the connection to the server
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.s.connect((self.server, self.port))
        except Exception as e:
            print(f"[!] {e}")

        # Initial message exchanges for the communication
        self.s.send(self.username.encode())
        print(" Connected successfully")
        print(" Exchanging keys")

        # Create the RSA object
        # Exchange the keys
        self.rsa = RSAEncryptionClient(self.s)
        self.rsa.exchange_keys()

        print(self.rsa.secret)

        print(" Initial set up had been completed!")
        print(" Now you can start to exchange messages \n\n")

        # InputHandle for sending messages and MessageHandle thread for receiving messages
        message_handler = threading.Thread(target=self.handle_messages, args=())
        message_handler.start()
        input_handler = threading.Thread(target=self.input_handler, args=())
        input_handler.start()

    # Handle receiving messages
    def handle_messages(self):
        while True:
            message = self.s.recv(1024).decode()
            if message:
                try:
                    msg = self.rsa.decrypt_message(json.loads(message))
                    current_time = datetime.datetime.now()
                    # Decode and print the byte enconded message with a timestamp
                    print(f'{current_time.strftime("%Y-%m-%d %H:%M ")} {msg.decode()}')
                except json.decoder.JSONDecodeError:
                    # If the message is not json formatted, it is a notification
                    print(message)
                except Exception as e:
                    print(f"[!] {e}")
            else:
                print(" Lost the connection to the server")
                print(" Closing down the connection")
                self.s.shutdown(socket.SHUT_RDWR)
                os._exit(0)

    # Handle user input and send message
    def input_handler(self):
        stop = ["exit", "quit"]
        while True:
            message = input(" ")  # Take the input from the user
            if message.strip() == "":  # If the user just presses enter, do nothing
                continue
            if message.lower() in stop:  # EXIT will close down the client
                break
            else:
                message = f"{self.username} : {message}"
                result = self.rsa.encrypt_message(message)
                self.s.send(result.encode())  # Send it in byte encoded form

        self.s.shutdown(socket.SHUT_RDWR)
        os._exit(0)


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

    arg_parse.add_argument(
        "-e",
        "--encrypt",
        type=str,
        required=True,
        help="encryption type to use (AES or RSA)",
    )

    args = arg_parse.parse_args()
    client = Client(args.server, args.port, args.username, args.encrypt)
    client.create_connection()
