import socket
import threading
import getpass
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import jwt

HOST = "localhost"
PORT = 50004
SERVER_PUBLIC_KEY = ""


def load_server_public_key():
    with open("server_public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read()
        )
    return public_key


def main():

    server_public_key = load_server_public_key()

    private_key, public_key = generate_key_pair()

    client, username, token = connect(
        HOST, PORT, public_key, private_key, server_public_key)

    on_message_thread = threading.Thread(
        target=on_message, args=(client, private_key))
    send_message_thread = threading.Thread(
        target=send_message, args=(client, username, server_public_key, token))

    on_message_thread.start()
    send_message_thread.start()
    return


def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    return private_key, public_key


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


def get_credentials():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    return username, password


def serialize_key(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_key_bytes


def connect(host, port, public_key, private_key, server_public_key):

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((host, port))

    serialized_public_key = serialize_key(public_key)
    client.send(serialized_public_key)

    signed_public_key = client.recv(1024)
    try:
        server_public_key.verify(
            signed_public_key,
            serialized_public_key,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        print("Public key not signed by server")
        client.close()
        return

    username, password = get_credentials()
    payload = f"{username}:{password}"
    client.send(encrypt_message(payload, server_public_key))

    data = client.recv(1024)
    token = decrypt_message(data, private_key)

    return client, username, token


def shutdown(client, reason):
    print(reason)
    client.close()


def on_message(client, private_key):
    while True:
        try:
            data = client.recv(1024)
            if not data:
                break
            print(decrypt_message(client.recv(1024), private_key))
        except:
            break


def send_message(client, username, server_public_key, token):
    while True:
        try:
            message = input()
            if message == "/q":
                shutdown(client, "Disconnected")
                break
            client.send(encrypt_message(f"{username}> {message}", server_public_key))
        except:
            break


if __name__ == "__main__":
    main()
