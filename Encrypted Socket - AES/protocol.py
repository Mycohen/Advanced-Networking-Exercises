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
    # Convert key to two bytes (16-bit key)
    key_bytes = key.to_bytes(2, byteorder='big')
    block_size = 4  # Block size is 4 bytes
    encrypted_data = bytearray()

    # Add padding if the data size is not a multiple of 4
    if len(input_data) % block_size != 0:
        padding = block_size - (len(input_data) % block_size)
        input_data += b'\x00' * padding  # Pad with zeros

    # Define a lookup table (example values, customize as needed)
    lookup_table = {i: (i * 7) % 256 for i in range(256)}  # Example LUT

    # Encrypt each block
    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        # Step 1: XOR with key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Step 2: Substitute values using the lookup table
        for j in range(block_size):
            block[j] = lookup_table[block[j]]

        # Step 3: Circular shift of bytes
        block = block[1:] + block[:1]

        # Step 4: XOR again with the key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Add encrypted block to the result
        encrypted_data.extend(block)

    return bytes(encrypted_data)


def symmetric_decryption(input_data, key):
    """
    Decrypt data that was encrypted using the block cipher.
    :param input_data: The encrypted data (as bytes).
    :param key: The 16-bit decryption key (integer).
    :return: The decrypted data (as bytes).
    """
    # Convert key to two bytes (16-bit key)
    key_bytes = key.to_bytes(2, byteorder='big')
    block_size = 4  # Block size is 4 bytes
    decrypted_data = bytearray()

    # Define a reverse lookup table (inverse of encryption LUT)
    lookup_table = {i: (i * 7) % 256 for i in range(256)}
    reverse_lookup_table = {v: k for k, v in lookup_table.items()}

    # Decrypt each block
    for i in range(0, len(input_data), block_size):
        block = bytearray(input_data[i:i + block_size])

        # Step 1: XOR with key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Step 2: Reverse circular shift of bytes
        block = block[-1:] + block[:-1]

        # Step 3: Reverse substitution using the reverse lookup table
        for j in range(block_size):
            block[j] = reverse_lookup_table[block[j]]

        # Step 4: XOR again with the key
        for j in range(block_size):
            block[j] ^= key_bytes[j % 2]

        # Add decrypted block to the result
        decrypted_data.extend(block)

    # Remove padding (zero bytes at the end)
    while decrypted_data and decrypted_data[-1] == 0:
        decrypted_data.pop()

    return bytes(decrypted_data)



def diffie_hellman_choose_private_key():
    """Choose a 16-bit private key."""
    private_key = random.randint(1, 65535)
    return private_key


def diffie_hellman_calc_public_key(private_key):
    """G**private_key mod P"""
    return pow(DIFFIE_HELLMAN_G, private_key, DIFFIE_HELLMAN_P)


def diffie_hellman_calc_shared_secret(other_side_public, my_private):
    """other_side_public**my_private mod P"""
    return pow(other_side_public, my_private, DIFFIE_HELLMAN_P)


def calc_hash(message):

    hash_value = 0xFFFF  # Start with all bits set for more complexity

    for i, char in enumerate(message):
        # Combine character with its position in the message
        value = (ord(char) + i) & 0xFFFF  # ASCII value + position, keep 16-bit

        # Update the hash using XOR, shifts, and modular arithmetic
        hash_value ^= value  # XOR with the current hash
        hash_value = ((hash_value << 5) | (hash_value >> 11)) & 0xFFFF  # Rotate left
        hash_value = (hash_value * 31 + value) & 0xFFFF  # Multiply and add

    return hash_value


def calc_signature(hash, RSA_private_key):
    """Calculate the signature, using RSA alogorithm
    hash**RSA_private_key mod (P*Q)"""
    _, N = get_RSA_public_key()
    signature = pow(hash, RSA_private_key,int(N))
    return signature


def create_msg(data):
    """Create a valid protocol message, with length field
    For example, if data = data = "hello world",
    then "11hello world" should be returned"""
    return


def get_msg(my_socket):
    """Extract message from protocol, without the length field
       If length field does not include a number, returns False, "Error" """
    return
    
def check_RSA_public_key(key, totient):
    """Check that the selected public key satisfies the conditions:
    1. key is prime
    2. key < totient
    3. totient mod key != 0
    """
    return key < totient and gcd(key, totient) == 1

def get_RSA_public_key():
    """Generate an RSA public key (e, N)."""
    # Generate a list of prime numbers in the range
    primes = generate_primes(3, pow(2, 16) - 1)
    length = len(primes)

    # Randomly select two primes, P and Q
    P = primes[random.randint(0, length - 1)]
    Q = primes[random.randint(0, length - 1)]

    # Compute N and the totient
    N = P * Q
    Totient = (P - 1) * (Q - 1)

    # Find a valid public key `e`
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

    #  Calculate the private key D
    private_key = mod_inverse(public_key, totient)

    return private_key

def is_prime(n):
    """Check if a number is prime."""
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_primes(start, end):
    """
    Generate all prime numbers in the range [start, end].

    Parameters:
        start (int): The lower bound of the range (inclusive).
        end (int): The upper bound of the range (inclusive).

    Returns:
        list: A list of prime numbers in the range.
    """
    if start > end:
        return []

    # Edge case: If the range includes numbers below 2, adjust the start
    if start < 2:
        start = 2

    # Create a boolean array to track prime numbers
    is_prime = [True] * (end + 1)
    is_prime[0] = is_prime[1] = False  # 0 and 1 are not primes

    # Mark non-prime numbers using the Sieve of Eratosthenes
    for i in range(2, int(end**0.5) + 1):
        if is_prime[i]:
            for j in range(i * i, end + 1, i):
                is_prime[j] = False

    # Generate the list of primes in the specified range
    primes = [i for i in range(start, end + 1) if is_prime[i]]
    return primes

def mod_inverse(a, m):
    """
    Find the modular multiplicative inverse of a under modulo m.
    It solves: (a * x) % m == 1
    """
    m0, x0, x1 = m, 0, 1
    while a > 1:
        # q is quotient
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1