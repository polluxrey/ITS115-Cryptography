import os
import time
import base64
import hashlib
import textwrap
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

PRIME = 104729  # A small prime number for simplicity
GENERATOR = 2  # Generator

wrapper = textwrap.TextWrapper(width=99)


def derive_key(shared_secret: int):
    """Derives a 256-bit AES key from the shared secret."""
    return hashlib.sha256(str(shared_secret).encode()).digest()


def encrypt_message(key, plaintext):
    """Encrypts a message using AES-CBC."""
    iv = os.urandom(16)  # Generate random IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(iv + ciphertext).decode()


def decrypt_message(key, encrypted):
    """Decrypts a message using AES-CBC."""
    raw = base64.b64decode(encrypted)
    iv = raw[:16]  # Extract IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(raw[16:]), AES.block_size)
    return plaintext.decode()


def clear_screen():
    os.system("cls")


def display_title():
    text = """
██       █████  ██████      ███████ ██   ██ ███████ ██████   ██████ ██ ███████ ███████      ██
██      ██   ██ ██   ██     ██       ██ ██  ██      ██   ██ ██      ██ ██      ██          ███
██      ███████ ██████      █████     ███   █████   ██████  ██      ██ ███████ █████        ██
██      ██   ██ ██   ██     ██       ██ ██  ██      ██   ██ ██      ██      ██ ██           ██
███████ ██   ██ ██████      ███████ ██   ██ ███████ ██   ██  ██████ ██ ███████ ███████      ██

███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█ In this lab, you'll use Diffie-Hellman to create a shared secret key, even if the communication     █
█ channel is insecure, and then use Advanced Encryption Standard (AES) to encrypt your chat messages. █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████
    """

    print(text.strip())
    print()


def display_role(role):
    text = """
███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█                                     You are running as: {}                                      █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████
    """

    print(text.format(role).strip())
    print()


def display_waiting_for_connection(role, ip=""):
    if role == "SERVER":
        text = """
███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█                                      Waiting for connection...                                      █
█                                 Server IP address: {:>15}                                  █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████
    """
        print(text.format(ip).strip())
        print()
    else:
        text = """
███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█                                    Connect to the server's IP...                                    █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████\n
    """
        print(text.format(ip).strip())
        print()


def display_successful_connection():
    text = """
███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█                            Client successfully connected to the server!                             █
█                              Initiating Diffie-Hellman Key Exchange...                              █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████
    """

    print(text.strip())
    print()


def display_prime_and_generator(p=PRIME, g=GENERATOR):
    text_1 = """
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ STEP 1: The SERVER and CLIENT agree on a large prime number p and a primitive root (generator) g.   ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """

    text_2 = """
┏━━━━━━━━━┓
┃ p = {:3d} ┃
┃ g = {:3d} ┃
┗━━━━━━━━━┛
    """

    print(text_1.strip())
    print(text_2.format(p, g).strip())
    print()

    time.sleep(2)


def display_private_key(private_key, role):
    text_1 = """
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ STEP 2: The {:6} randomly generates a private key.                                                ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """

    text_2 = """
┏━━━━━━━━━━━━━━━━━━━┓
┃ Private key = {:3d} ┃
┗━━━━━━━━━━━━━━━━━━━┛
    """

    print(text_1.format(role).strip())
    print(text_2.format(private_key).strip())
    print()

    time.sleep(2)


def display_public_key(private_key, public_key, p, g, role):
    text_1 = """
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ STEP 3: Using the generator, its own private key, the prime number,                                 ║
║         the {:6} calculates its public key.                                                       ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """

    text_2 = """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Public key = (g^Private key) mod p ┃
┃            = ({:>3d}^{:>3d}) mod {:3d}     ┃
┃            = {:3d}                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """

    print(text_1.format(role).strip())
    print(text_2.format(g, private_key, p, public_key).strip())
    print()

    time.sleep(2)


def display_exchange_public_key(received_public_key, role):
    other_role = "CLIENT" if role == "SERVER" else "SERVER"

    text_1 = """
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ STEP 4: The SERVER and the CLIENT exchange public keys.                                             ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """

    text_2 = """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Received public key from {:6}: {:3d} ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """

    print(text_1.format(role).strip())
    print(text_2.format(other_role, received_public_key).strip())
    print()

    time.sleep(2)


def display_calculate_shared_secret(
    shared_secret, received_public_key, private_key, p, role
):
    other_role = "CLIENT" if role == "SERVER" else "SERVER"

    text_1 = """
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ STEP 5: Using the {:6}'s public key, the {:6}'s own private key, and the prime number,          ║
║         the {:6} calculates the shared secret.                                                    ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """

    text_2 = """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Shared secret = ({:6}'s public key^{:6}'s Private key) mod p ┃
┃               = ({:>3d}^{:>3d}) mod {:3d}                                ┃
┃               = {:3d}                                              ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """

    print(text_1.format(other_role, role, role).strip())
    print(
        text_2.format(
            other_role, role, received_public_key, private_key, p, shared_secret
        ).strip()
    )
    print()

    time.sleep(2)


def display_calculate_session_key(session_key):
    text_1 = """
╔═════════════════════════════════════════════════════════════════════════════════════════════════════╗
║ STEP 6: We will secure the text chat using AES-256 encryption. This requires a 256-bit key.         ║
║         To create this session key, we will use SHA-256, a hashing algorithm, to convert the shared ║ 
║         secret into a 256-bit value.                                                                ║
╚═════════════════════════════════════════════════════════════════════════════════════════════════════╝
    """

    text_2 = """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Session key in hexadecimal format (using SHA-256):               ┃
┃ {} ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
    """

    print(text_1.strip())
    print(text_2.format(session_key).strip())
    print()

    time.sleep(2)


def display_initiating_chat(session_key):
    text = """
███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█                                           Chat starting!                                            █
█                                   Type EXIT to end the text chat.                                   █
█              Session key: {}          █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████
    """

    print(text.format(session_key).strip())
    print()


def display_message(message, role, mode):
    other_role = "CLIENT" if role == "SERVER" else "SERVER"

    lines = wrapper.wrap(text=message)

    # Mode: To send
    if mode == 0:
        print("\033[A", end="\r")
        print(f"{role:>103}")
    else:
        print(f"{other_role:103}")

    print(
        "╭─────────────────────────────────────────────────────────────────────────────────────────────────────╮"
    )

    for line in lines:
        print(f"│ {line:99} │")

    print(
        "╰─────────────────────────────────────────────────────────────────────────────────────────────────────╯\n"
    )


def display_encrypted_message(encrypted_message, role, mode):
    other_role = "CLIENT" if role == "SERVER" else "SERVER"

    lines = wrapper.wrap(text=encrypted_message)

    # Mode: To send
    if mode == 0:
        text = "SENT MESSAGE TO " + other_role
    else:
        text = "RECEIVED MESSAGE FROM " + other_role

    print(
        "+-----------------------------------------------------------------------------------------------------+"
    )

    print(f"| {text:^99} |")

    for line in lines:
        print(f"| {line:^99} |")

    print(
        "+-----------------------------------------------------------------------------------------------------+\n"
    )


def display_chat_ended():
    text = """
███████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                                     █
█                                            Chat ended.                                              █
█                                                                                                     █
███████████████████████████████████████████████████████████████████████████████████████████████████████
    """

    print(text.format().strip())
    print()
