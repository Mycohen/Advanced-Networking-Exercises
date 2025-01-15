import socket
import protocol

# Generate RSA keys for the client
CLIENT_RSA_P, CLIENT_RSA_Q = protocol.generate_random_p_q()

def main():
    """
    Client implementation for encrypted communication.
    Handles secure message exchange using Diffie-Hellman, RSA, and symmetric encryption.
    """
    try:
        # Create a TCP socket for the client
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect(("127.0.0.1", protocol.PORT))  # Connect to the server

        # Step 1: Perform Diffie-Hellman key exchange
        # Generate the client's private and public Diffie-Hellman keys
        client_DH_private_key = protocol.diffie_hellman_choose_private_key()
        client_DH_public_key = protocol.diffie_hellman_calc_public_key(client_DH_private_key)

        # Receive the server's public Diffie-Hellman key
        valid_msg, server_DH_public_key_msg = protocol.get_msg(my_socket)
        if not valid_msg:
            raise ValueError("Failed to receive server's Diffie-Hellman public key.")
        server_DH_public_key = int(server_DH_public_key_msg.decode())

        # Send the client's public Diffie-Hellman key to the server
        my_socket.send(protocol.create_msg(str(client_DH_public_key).encode()))

        # Compute the shared secret using the server's public key and client's private key
        shared_secret = protocol.diffie_hellman_calc_shared_secret(server_DH_public_key, client_DH_private_key)

        # Step 2: Perform RSA key exchange
        # Generate the client's RSA public and private keys
        client_rsa_e, client_rsa_n = protocol.get_RSA_public_key(CLIENT_RSA_P, CLIENT_RSA_Q)
        client_rsa_d = protocol.get_RSA_private_key(CLIENT_RSA_P, CLIENT_RSA_Q, client_rsa_e)
        client_RSA_public = f"{client_rsa_e}, {client_rsa_n}"

        # Send the client's RSA public key to the server
        my_socket.send(protocol.create_msg(client_RSA_public.encode()))

        # Receive the server's RSA public key
        valid_msg, server_RSA_public_msg = protocol.get_msg(my_socket)
        if not valid_msg:
            raise ValueError("Failed to receive server's RSA public key.")
        server_rsa_e, server_rsa_n = map(int, server_RSA_public_msg.decode().split(','))

        # Step 3: Communication loop
        while True:
            print("Enter a message (type 'EXIT' to close connection):")
            user_input = input()

            # If the user wants to exit, send an EXIT message
            if user_input.upper() == "EXIT":
                print("Exiting...")
                my_socket.send(protocol.create_msg(user_input.encode()))
                break

            try:
                # Encrypt the message using the shared secret
                encrypted_client_message = protocol.symmetric_encryption(user_input.encode(), shared_secret)

                # Hash the encrypted message for integrity
                hashed_client_message = protocol.calc_hash(encrypted_client_message)

                # Sign the hash using RSA private key
                signed_client_message = protocol.calc_signature(hashed_client_message, client_rsa_d, client_rsa_n)

                # Send encrypted message, hash, and signature to the server
                my_socket.send(protocol.create_msg(encrypted_client_message))
                my_socket.send(protocol.create_msg(str(hashed_client_message).encode()))
                my_socket.send(protocol.create_msg(str(signed_client_message).encode()))

                # Receive the server's encrypted response, hash, and signature
                valid_msg1, server_encrypted_message = protocol.get_msg(my_socket)
                valid_msg2, server_hashed_message = protocol.get_msg(my_socket)
                valid_msg3, server_signed_message = protocol.get_msg(my_socket)

                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    raise ValueError("Invalid response from server.")

                # Verify the server's hash
                server_hash = int(server_hashed_message.decode())
                if server_hash != protocol.calc_hash(server_encrypted_message):
                    raise ValueError("Hash mismatch: The response may have been tampered with.")

                # Verify the server's RSA signature
                server_signature = int(server_signed_message.decode())
                calculated_hash_from_signature = pow(server_signature, server_rsa_e, server_rsa_n)
                if calculated_hash_from_signature != server_hash:
                    raise ValueError("Signature mismatch: The response may have been tampered with.")

                # Decrypt the server's response
                decrypted_response = protocol.symmetric_decryption(server_encrypted_message, shared_secret)
                print(f"Server responded: {decrypted_response.decode()}")

            except Exception as e:
                print(f"Error during communication: {e}")
                break

    finally:
        # Close the socket connection gracefully
        print("Closing client socket.")
        my_socket.close()

if __name__ == "__main__":
    main()
