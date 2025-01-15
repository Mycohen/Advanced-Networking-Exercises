"""
Encrypted Sockets Implementation
Author: Moshe Yaakov Cohen

This module implements secure communication protocols for encrypted sockets.
Features include:
1. Symmetric encryption using a custom block cipher.
2. Diffie-Hellman key exchange for establishing a shared secret.
3. RSA for digital signatures and key validation.
4. Hashing for integrity checks.
5. A simple message protocol for data transfer with length encoding.

Constants:
- LENGTH_FIELD_SIZE: Number of bytes to represent the length of the message.
- PORT: Port number for the socket communication.
- DIFFIE_HELLMAN_P, DIFFIE_HELLMAN_G: Prime and generator for Diffie-Hellman.
"""

import random
from math import gcd

# Constants
LENGTH_FIELD_SIZE = 2  # Number of bytes used to represent the message length
PORT = 8820  # Port for communication

DIFFIE_HELLMAN_P = 65521  # A 16-bit prime number used in Diffie-Hellman
DIFFIE_HELLMAN_G = 65309  # A generator value for Diffie-Hellman

# ----------------------------------------------------------------
# Symmetric Encryption
# ----------------------------------------------------------------

def symmetric_encryption(input_data, key):
    """
    Encrypt data using a custom block cipher.
    :param input_data: The plaintext to encrypt (as bytes).
    :param key: The encryption key (16-bit integer).
    :return: The encrypted data (as bytes).
    """
    key_bytes = key.to_bytes(2, byteorder="big")  # Convert key to 2 bytes
    block_size = 4  # Fixed block size for encryption
    encrypted_data = bytearray()

    # Padding: Ensure data length is a multiple of the block size
    if len(input_data) % block_size != 0:
        padding = block_size - (len(input_data) % block_size)
        input_data += b"\x00" * padding  # Add null bytes as padding

    # Substitution lookup table
    lookup_table = {i: (i * 7) % 256 for i in range(256)}

    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        # Step 1: XOR each byte with the key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Step 2: Substitute bytes using the lookup table
        for j in range(block_size):
            block[j] = lookup_table[block[j]]

        # Step 3: Circular shift (rotate bytes to the left)
        block = block[1:] + block[:1]

        # Step 4: XOR again with the key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        encrypted_data.extend(block)

    return bytes(encrypted_data)


def symmetric_decryption(input_data, key):
    """
    Decrypt data encrypted using the custom block cipher.
    :param input_data: The encrypted data (as bytes).
    :param key: The decryption key (16-bit integer).
    :return: The decrypted data (as bytes).
    """
    key_bytes = key.to_bytes(2, byteorder="big")  # Convert key to 2 bytes
    block_size = 4  # Fixed block size
    decrypted_data = bytearray()

    # Substitution and reverse lookup table
    lookup_table = {i: (i * 7) % 256 for i in range(256)}
    reverse_lookup_table = {v: k for k, v in lookup_table.items()}

    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        # Step 1: XOR with key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Step 2: Reverse circular shift
        block = block[-1:] + block[:-1]

        # Step 3: Reverse substitution
        for j in range(block_size):
            block[j] = reverse_lookup_table[block[j]]

        # Step 4: XOR again with the key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        decrypted_data.extend(block)

    # Remove padding (null bytes)
    while decrypted_data and decrypted_data[-1] == 0:
        decrypted_data.pop()

    return bytes(decrypted_data)

# ----------------------------------------------------------------
# Diffie-Hellman Key Exchange
# ----------------------------------------------------------------

def diffie_hellman_choose_private_key():
    """
    Generate a random private key for Diffie-Hellman.
    :return: A random 16-bit integer as the private key.
    """
    return random.randint(1, 65535)


def diffie_hellman_calc_public_key(private_key):
    """
    Compute the public key for Diffie-Hellman.
    :param private_key: The private key (integer).
    :return: The public key (integer).
    """
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """
    Calculate the shared secret using the other party's public key.
    :param other_side_public: The other party's public key (integer).
    :param my_private: The private key (integer).
    :return: The shared secret (integer).
    """
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)

# ----------------------------------------------------------------
# Hash Function
# ----------------------------------------------------------------

def calc_hash(message):
    """
    Calculate a simple 16-bit hash of a message.
    :param message: The input message (bytes).
    :return: A 16-bit hash value (integer).
    """
    hash_value = 0xFFFF  # Initial hash value
    for byte in message:
        hash_value ^= byte
        hash_value = ((hash_value << 5) | (hash_value >> 11)) & 0xFFFF  # Rotate left
        hash_value = (hash_value * 31 + byte) & 0xFFFF  # Additive factor
    return hash_value

# ----------------------------------------------------------------
# RSA Digital Signature
# ----------------------------------------------------------------

def calc_signature(hash, RSA_private_key, N):
    """
    Sign a hash using RSA.
    :param hash: The hash of the message (integer).
    :param RSA_private_key: The private key for RSA (integer).
    :param N: The modulus (P * Q) for RSA (integer).
    :return: The digital signature (integer).
    """
    return pow(hash, RSA_private_key, N)


def extract_hash(signed, e, n):
    """
    Extract the hash from an RSA signature.
    :param signed: The signed hash (integer).
    :param e: The RSA public exponent (integer).
    :param n: The RSA modulus (integer).
    :return: The extracted hash (integer).
    """
    return pow(signed, e, n)

# ----------------------------------------------------------------
# Message Protocol
# ----------------------------------------------------------------

def create_msg(data):
    """
    Wrap a message with a length field for consistent transmission.
    :param data: The message data (as bytes).
    :return: A length-prefixed message (as bytes).
    """
    length_field = len(data).to_bytes(LENGTH_FIELD_SIZE, byteorder="big")
    return length_field + data


def get_msg(my_socket):
    """
    Read a length-prefixed message from the socket.
    :param my_socket: The socket to read from.
    :return: A tuple (success, message as bytes).
    """
    try:
        # Read the length field
        length_field = my_socket.recv(LENGTH_FIELD_SIZE)
        if len(length_field) < LENGTH_FIELD_SIZE:
            return False, b""
        message_length = int.from_bytes(length_field, byteorder="big")
        # Read the message based on the length
        message = my_socket.recv(message_length)
        if len(message) != message_length:
            return False, b""
        return True, message
    except Exception:
        return False, b""

# ----------------------------------------------------------------
# RSA Key Management
# ----------------------------------------------------------------

def generate_random_p_q():
    """
    Generate two random prime numbers for RSA.
    :return: A tuple (P, Q) where P and Q are primes.
    """
    primes = generate_primes(1024, 65535)
    return random.sample(primes, 2)


def get_RSA_public_key(P, Q):
    """
    Generate an RSA public key (e, N).
    :param P: The first prime number.
    :param Q: The second prime number.
    :return: A tuple (e, N) where e is the public exponent.
    """
    N = P * Q
    Totient = (P - 1) * (Q - 1)
    while True:
        e = random.randint(2, Totient - 1)
        if gcd(e, Totient) == 1:
            return e, N


def get_RSA_private_key(p, q, public_key):
    """
    Generate the RSA private key corresponding to a public key.
    :param p: The first prime number.
    :param q: The second prime number.
    :param public_key: The RSA public exponent.
    :return: The private key (integer).
    """
    totient = (p - 1) * (q - 1)
    return mod_inverse(public_key, totient)

# ----------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------

def is_prime(n):
    """
    Check if a number is prime.
    :param n: The number to check.
    :return: True if prime, False otherwise.
    """
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_primes(start, end):
    """
    Generate a list of prime numbers in a range.
    :param start: Start of the range.
    :param end: End of the range.
    :return: List of primes.
    """
    return [num for num in range(max(start, 2), end + 1) if is_prime(num)]


def mod_inverse(a, m):
    """
    Calculate the modular multiplicative inverse.
    :param a: The number to invert.
    :param m: The modulus.
    :return: The modular inverse.
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1
