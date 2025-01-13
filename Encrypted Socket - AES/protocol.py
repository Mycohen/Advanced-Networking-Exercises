"""Encrypted sockets implementation
   Author:
   Date:
"""

from math import gcd
import random
import math

LENGTH_FIELD_SIZE = 2
PORT = 8820

DIFFIE_HELLMAN_P = 65521
DIFFIE_HELLMAN_G = 65309


def symmetric_encryption(input_data, key):
    """
    Encrypt data using a block cipher as defined in the exercise.
    :param input_data: The plaintext to encrypt (as bytes).
    :param key: The 16-bit encryption key (integer).
    :return: The encrypted data (as bytes).
    """
    key_bytes = key.to_bytes(2, byteorder='big')
    block_size = 4
    encrypted_data = bytearray()

    if len(input_data) % block_size != 0:
        padding = block_size - (len(input_data) % block_size)
        input_data += b'\x00' * padding

    lookup_table = {i: (i * 7) % 256 for i in range(256)}

    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        for j in range(block_size):
            block[j] = lookup_table[block[j]]

        block = block[1:] + block[:1]

        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        encrypted_data.extend(block)

    return bytes(encrypted_data)


def symmetric_decryption(input_data, key):
    key_bytes = key.to_bytes(2, byteorder='big')
    block_size = 4
    decrypted_data = bytearray()

    lookup_table = {i: (i * 7) % 256 for i in range(256)}
    reverse_lookup_table = {v: k for k, v in lookup_table.items()}

    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        block = block[-1:] + block[:-1]

        for j in range(block_size):
            block[j] = reverse_lookup_table[block[j]]

        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        decrypted_data.extend(block)

    while decrypted_data and decrypted_data[-1] == 0:
        decrypted_data.pop()

    return bytes(decrypted_data)


def diffie_hellman_choose_private_key():
    return random.randint(1, 65535)


def diffie_hellman_calc_public_key(private_key):
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)


def calc_hash(message):
    hash_value = 0xFFFF

    for i, char in enumerate(message):
        value = (ord(char) + i) & 0xFFFF
        hash_value ^= value
        hash_value = ((hash_value << 5) | (hash_value >> 11)) & 0xFFFF
        hash_value = (hash_value * 31 + value) & 0xFFFF

    return hash_value


def calc_signature(hash, RSA_private_key):
    _, N = get_RSA_public_key()
    return pow(hash, RSA_private_key, N)


def create_msg(data):
    data_length = len(data)
    length_field = str(data_length).zfill(LENGTH_FIELD_SIZE)
    return f"{length_field}{data}"


def get_msg(my_socket):
    try:
        length_field = my_socket.recv(LENGTH_FIELD_SIZE).decode()
        if not length_field.isdigit():
            return False, "Error"
        message_length = int(length_field)
        message = my_socket.recv(message_length).decode()
        return True, message
    except Exception as e:
        return False, f"Error: {str(e)}"


def check_RSA_public_key(key, totient):
    return key < totient and gcd(key, totient) == 1


def get_RSA_public_key():
    primes = generate_primes(3, pow(2, 16) - 1)
    length = len(primes)

    P = primes[random.randint(0, length - 1)]
    Q = primes[random.randint(0, length - 1)]

    N = P * Q
    Totient = (P - 1) * (Q - 1)

    e = None
    for candidate in range(2, Totient):
        if check_RSA_public_key(candidate, Totient):
            e = candidate
            break

    if e is None:
        raise ValueError("Failed to find a valid public key.")

    return e, N


def get_RSA_private_key(p, q, public_key):
    totient = (p - 1) * (q - 1)
    return mod_inverse(public_key, totient)


def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


def generate_primes(start, end):
    if start > end:
        return []

    if start < 2:
        start = 2

    is_prime = [True] * (end + 1)
    is_prime[0] = is_prime[1] = False

    for i in range(2, int(end**0.5) + 1):
        if is_prime[i]:
            for j in range(i * i, end + 1, i):
                is_prime[j] = False

    return [i for i in range(start, end + 1) if is_prime[i]]


def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1
