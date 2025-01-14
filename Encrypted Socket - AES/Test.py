import protocol

def my_test():
    # Testing the symmetric encryption and decryption
    plaintext = b"Hello, secure socket!"
    key = 60232  # Example 16-bit key

    print(f"Original Plaintext: {plaintext}")

    # Encrypt the plaintext
    encrypted_data = protocol.symmetric_encryption(plaintext, key)
    print(f"Encrypted Data: {encrypted_data}")

    # Decrypt the encrypted data
    decrypted_data = protocol.symmetric_decryption(encrypted_data, key)
    print(f"Decrypted Data: {decrypted_data}")

    # Verify if decryption matches the original plaintext
    if decrypted_data == plaintext:
        print("Symmetric encryption and decryption test passed!")
    else:
        print("Symmetric encryption and decryption test failed!")

# Run the test
if __name__ == "__main__":
    my_test()
