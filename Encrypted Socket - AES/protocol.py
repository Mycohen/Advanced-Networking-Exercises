"""
Encrypted Sockets Implementation
Author: [Your Name]
Date: [Date]

This program implements secure socket communication using:
1. Symmetric encryption with a block cipher.
2. Diffie-Hellman for shared key exchange.
3. Hashing for integrity checks.
4. RSA for digital signatures and key validation.

Constants:
- LENGTH_FIELD_SIZE: Number of bytes to represent the length of the message.
- PORT: Port number for the socket communication.
- DIFFIE_HELLMAN_P, DIFFIE_HELLMAN_G: Parameters for Diffie-Hellman.
"""

import random
from math import gcd

# Constants
LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 65521  # A 16-bit prime number
DIFFIE_HELLMAN_G = 65309  # A generator for Diffie-Hellman

# Symmetric Encryption
# Symmetric Encryption
def symmetric_encryption(input_data, key):
    """
    Encrypt data using a block cipher.
    :param input_data: The plaintext to encrypt (as bytes).
    :param key: The 16-bit encryption key (integer).
    :return: The encrypted data (as bytes).
    """
    key_bytes = key.to_bytes(2, byteorder="big")
    block_size = 4
    encrypted_data = bytearray()

    # Add padding if input_data size is not a multiple of block_size
    if len(input_data) % block_size != 0:
        padding = block_size - (len(input_data) % block_size)
        input_data += b"\x00" * padding

    # Lookup table for substitution
    lookup_table = {i: (i * 7) % 256 for i in range(256)}

    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        # Step 1: XOR with key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Step 2: Substitute bytes using the lookup table
        for j in range(block_size):
            block[j] = lookup_table[block[j]]

        # Step 3: Circular shift
        block = block[1:] + block[:1]

        # Step 4: XOR again with the key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        encrypted_data.extend(block)

    return bytes(encrypted_data)


def symmetric_decryption(input_data, key):
    """
    Decrypt data that was encrypted using the block cipher.
    :param input_data: The encrypted data (as bytes).
    :param key: The 16-bit decryption key (integer).
    :return: The decrypted data (as bytes).
    """
    key_bytes = key.to_bytes(2, byteorder="big")
    block_size = 4
    decrypted_data = bytearray()

    # Lookup table and reverse lookup table
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

    # Remove padding
    while decrypted_data and decrypted_data[-1] == 0:
        decrypted_data.pop()

    return bytes(decrypted_data)

# Diffie-Hellman Key Exchange
def diffie_hellman_choose_private_key():
    """Generate a random 16-bit private key."""
    return random.randint(1, 65535)


def diffie_hellman_calc_public_key(private_key):
    """Calculate the public key for Diffie-Hellman."""
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """Calculate the shared secret for Diffie-Hellman."""
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)


# Hash Function
def calc_hash(message):
    """
    Create a 16-bit hash of a message.
    :param message: The input message (bytes).
    :return: A 16-bit hash (integer).
    """
    hash_value = 0xFFFF
    for byte in message:
        hash_value ^= byte
        hash_value = ((hash_value << 5) | (hash_value >> 11)) & 0xFFFF
        hash_value = (hash_value * 31 + byte) & 0xFFFF
    return hash_value


# RSA Digital Signature
def calc_signature(hash, RSA_private_key, N):
    """
    Calculate the RSA signature.
    :param hash: The hash of the message (integer).
    :param RSA_private_key: The private key for RSA (integer).
    :param N: The modulus (P * Q) for RSA (integer).
    :return: The digital signature (integer).
    """
    return pow(hash, RSA_private_key, N)


# Message Protocol
def create_msg(data):
    """
    Create a message with a length field.
    :param data: The message data (as bytes).
    :return: The message with length prepended (as bytes).
    """
    length_field = len(data).to_bytes(LENGTH_FIELD_SIZE, byteorder="big")
    return length_field + data


def get_msg(my_socket):
    """
    Extract the message from the socket.
    :param my_socket: The socket to read from.
    :return: A tuple (success, message as bytes).
    """
    try:
        length_field = my_socket.recv(LENGTH_FIELD_SIZE)
        if len(length_field) < LENGTH_FIELD_SIZE:
            return False, b""
        message_length = int.from_bytes(length_field, byteorder="big")
        message = my_socket.recv(message_length)
        if len(message) != message_length:
            return False, b""
        return True, message
    except Exception as e:
        return False, b""


# RSA Key Management
def check_RSA_public_key(key, totient):
    """Check if a public key is valid for RSA."""
    return key < totient and gcd(key, totient) == 1


def generate_random_p_q():
    primes = generate_primes(pow(2,10), pow(2, 16) - 1)
    p, q = random.sample(primes, 2)
    return p, q


def get_RSA_public_key(P, Q):
    """
    Generate an RSA public key (e, N).
    :return: A tuple (e, N).
    """
    N = P * Q
    Totient = (P - 1) * (Q - 1)

    for candidate in range(2, Totient):
        if check_RSA_public_key(candidate, Totient):
            return candidate, N

    raise ValueError("Failed to find a valid public key.")


def get_RSA_private_key(p, q, public_key):
    """
    Calculate the RSA private key.
    :param p: Prime number P.
    :param q: Prime number Q.
    :param public_key: Public key (e).
    :return: The private key (d).
    """
    totient = (p - 1) * (q - 1)
    return mod_inverse(public_key, totient)


# Utility Functions
def is_prime(n):
    """Check if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_primes(start, end):
    """Generate a list of prime numbers in a given range."""
    if start > end:
        return []
    primes = []
    for num in range(max(start, 2), end + 1):
        if is_prime(num):
            primes.append(num)
    return primes


def mod_inverse(a, m):
    """Calculate the modular multiplicative inverse."""
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1
