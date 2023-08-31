import socket
import threading
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import jwt

HOST = "localhost"
PORT = 50004
SERVER_PRIVATE_KEY = ""
MAX_BYTES = 2048

clients = []
authenticated_clients = []


def main():

    server = start_server(HOST, PORT)
    print(f"Server is running on port {PORT}")

    private_key = load_server_private_key()

    #public_key = private_key.public_key()

    on_connection_thread = threading.Thread(
        target=on_connection, args=(server, private_key))
    on_connection_thread.start()


def load_server_private_key():
    with open("server_private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )
    return private_key


def load_public_key(public_key_bytes):
    public_key = serialization.load_pem_public_key(
        public_key_bytes
    )
    return public_key


def sign_key(public_key, private_key):
    signature = private_key.sign(
        public_key,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def encrypt_message(message, public_key):
    ciphertext = public_key.encrypt(
        message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_message(ciphertext, private_key):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode("utf-8")


def serialize_key(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes


def start_server(host, port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen()
    return server


def authenticate_client(username, password):
    if username == "admin" and password == "admin":
        return True
    else:
        return False


def generate_token(username):
    token = jwt.encode({"username": username}, "secret", algorithm="HS256")
    return token


def on_disconnect(client):
    for authenticated_client in authenticated_clients:
        conn, public_key = authenticated_client
        if conn == client:
            authenticated_clients.remove(authenticated_client)
            client.close()
            print(f"Disconnected {conn.getpeername()[0]}")
            break


def on_connection(server, private_key):
    while True:
        try:
            print("Waiting for connection...")
            client, address = server.accept()
            print(f"Connected to {address[0]}:{address[1]}")

            serialized_client_public_key = client.recv(MAX_BYTES)

            client_public_key = load_public_key(serialized_client_public_key)

            client.send(sign_key(serialized_client_public_key, private_key))

            credentials = client.recv(MAX_BYTES)

            credentials = decrypt_message(credentials, private_key)
            username, password = credentials.split(":")

            if authenticate_client(username, password):
                authenticated_clients.append([client, client_public_key])
                print(f"Authenticated {username}")
                client_token = generate_token(username)
                client.send(encrypt_message(client_token, client_public_key))
                on_message_thread = threading.Thread(
                    target=on_message, args=(client, private_key))
                on_message_thread.start()
            else:
                client.send("Not authenticated".encode("utf-8"))
                client.close()

        except Exception as e:
            client.close()
            print(e)


def on_message(client, private_key):
    while True:
        try:
            message = client.recv(MAX_BYTES)
            message = decrypt_message(message, private_key)
            for authenticated_client in authenticated_clients:
                conn, public_key = authenticated_client
                if conn != client:
                    conn.send(
                        encrypt_message(message, public_key))
        except Exception as e:
            print(e)
            on_disconnect(client)
            break


if __name__ == "__main__":
    main()
