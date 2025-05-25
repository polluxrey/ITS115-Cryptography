import socket
import random
from utilities import *

ROLE = "CLIENT"


def generate_private_key():
    return random.randint(2, PRIME - 2)


def compute_public_key(private_key):
    return pow(GENERATOR, private_key, PRIME)


def compute_shared_secret(received_key, private_key):
    return pow(received_key, private_key, PRIME)


clear_screen()
display_title()
display_role(ROLE)

display_waiting_for_connection(ROLE)
ip = input("Enter server's IP: ").strip()
print()

# Client setup
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((ip, 9999))
display_successful_connection()

display_prime_and_generator()

# Receive server's public key
server_public_key = int(client.recv(1024).decode())

private_key = generate_private_key()
display_private_key(private_key, ROLE)

public_key = compute_public_key(private_key)
display_public_key(private_key, public_key, PRIME, GENERATOR, ROLE)

# Send public key to server
client.send(str(public_key).encode())
display_exchange_public_key(server_public_key, ROLE)

shared_secret = compute_shared_secret(server_public_key, private_key)
display_calculate_shared_secret(
    shared_secret, server_public_key, private_key, PRIME, ROLE
)

session_key = derive_key(shared_secret)
display_calculate_session_key(session_key.hex())

display_initiating_chat(session_key.hex())

while True:
    try:
        message = input("You: ")
        if message.lower() == "exit" or len(message) == 0:
            print("\033[A", end="\r")
            client.send("exit")
            display_chat_ended()
            break
        display_message(message, ROLE, 0)

        encrypted_message = encrypt_message(session_key, message).encode()
        client.send(encrypted_message)
        display_encrypted_message(str(encrypted_message), ROLE, 0)

        encrypted_response = client.recv(1024).decode()

        decrypted_message = decrypt_message(session_key, encrypted_response)
        if decrypted_message.lower() == "exit":
            display_chat_ended()
            break

        display_encrypted_message(encrypted_response, ROLE, 1)
        display_message(decrypted_message, ROLE, 1)
    except KeyboardInterrupt:
        print("\033[A", end="\r")
        print()
        display_chat_ended()
        break
    except Exception as e:
        display_chat_ended()
        break

client.close()
