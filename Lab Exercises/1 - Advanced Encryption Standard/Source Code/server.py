import socket
import random
from utilities import *

ROLE = "SERVER"


def generate_private_key():
    return random.randint(2, PRIME - 2)


def compute_public_key(private_key):
    return pow(GENERATOR, private_key, PRIME)


def compute_shared_secret(received_key, private_key):
    return pow(received_key, private_key, PRIME)


clear_screen()
display_title()
display_role(ROLE)

hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
display_waiting_for_connection(ROLE, ip)

# Server setup
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 9999))
server.listen(1)

conn, addr = server.accept()
display_successful_connection()

display_prime_and_generator()

private_key = generate_private_key()
display_private_key(private_key, ROLE)

public_key = compute_public_key(private_key)
display_public_key(private_key, public_key, PRIME, GENERATOR, ROLE)

# Send public key
conn.send(str(public_key).encode())

# Receive client's public key
client_public_key = int(conn.recv(1024).decode())
display_exchange_public_key(client_public_key, ROLE)

shared_secret = compute_shared_secret(client_public_key, private_key)
display_calculate_shared_secret(
    shared_secret, client_public_key, private_key, PRIME, ROLE
)

session_key = derive_key(shared_secret)
display_calculate_session_key(session_key.hex())

display_initiating_chat(session_key.hex())


while True:
    try:
        encrypted_msg = conn.recv(1024).decode()

        decrypted_msg = decrypt_message(session_key, encrypted_msg)
        if decrypted_msg.lower() == "exit":
            display_chat_ended()
            break

        display_encrypted_message(str(encrypted_msg), ROLE, 1)
        display_message(decrypted_msg, ROLE, 1)

        response = input("You: ")
        if response.lower() == "exit" or len(response) == 0:
            print("\033[A", end="\r")
            conn.send("exit")
            display_chat_ended()
            break
        display_message(response, ROLE, 0)

        encrypted_message = encrypt_message(session_key, response).encode()
        conn.send(encrypted_message)
        display_encrypted_message(str(encrypted_message), ROLE, 0)
    except KeyboardInterrupt:
        print("\033[A", end="\r")
        print()
        display_chat_ended()
        break
    except Exception as e:
        display_chat_ended()
        break


server.close()
