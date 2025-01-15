import socket
import protocol

# Generate RSA keys for the server
SERVER_RSA_P, SERVER_RSA_Q = protocol.generate_random_p_q()

def main():
    """
    Server implementation for encrypted communication.
    Handles secure message exchange using Diffie-Hellman, RSA, and symmetric encryption.
    """
    # Create a TCP socket for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))  # Bind to all network interfaces on the specified port
    server_socket.listen()  # Start listening for incoming client connections
    print("Server is up and running")

    try:
        # Accept a connection from a client
        client_socket, _ = server_socket.accept()
        print("Client connected")

        # Step 1: Perform Diffie-Hellman key exchange
        # Generate the server's private and public Diffie-Hellman keys
        server_DH_private_key = protocol.diffie_hellman_choose_private_key()
        server_DH_public_key = protocol.diffie_hellman_calc_public_key(server_DH_private_key)

        # Send the server's public Diffie-Hellman key to the client
        client_socket.send(protocol.create_msg(str(server_DH_public_key).encode()))

        # Receive the client's public Diffie-Hellman key
        valid_msg, client_DH_public_key_msg = protocol.get_msg(client_socket)
        if not valid_msg:
            raise ValueError("Failed to receive client's Diffie-Hellman public key.")
        client_DH_public_key = int(client_DH_public_key_msg.decode())

        # Compute the shared secret using the client's public key and server's private key
        shared_secret = protocol.diffie_hellman_calc_shared_secret(client_DH_public_key, server_DH_private_key)

        # Step 2: Perform RSA key exchange
        # Generate the server's RSA public and private keys
        server_rsa_e, server_rsa_n = protocol.get_RSA_public_key(SERVER_RSA_P, SERVER_RSA_Q)
        server_rsa_d = protocol.get_RSA_private_key(SERVER_RSA_P, SERVER_RSA_Q, server_rsa_e)
        server_RSA_public = f"{server_rsa_e}, {server_rsa_n}"

        # Send the server's RSA public key to the client
        client_socket.send(protocol.create_msg(server_RSA_public.encode()))

        # Receive the client's RSA public key
        valid_msg, client_RSA_public_msg = protocol.get_msg(client_socket)
        if not valid_msg:
            raise ValueError("Failed to receive client's RSA public key.")
        client_rsa_e, client_rsa_n = map(int, client_RSA_public_msg.decode().split(','))

        # Step 3: Communication loop
        while True:
            try:
                # Receive encrypted message, hash, and signature from the client
                valid_msg1, client_encrypted_message = protocol.get_msg(client_socket)
                valid_msg2, client_hashed_message = protocol.get_msg(client_socket)
                valid_msg3, client_signed_message = protocol.get_msg(client_socket)

                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    raise ValueError("Invalid message from client.")

                # Extract the hash and verify its integrity
                client_hash = int(client_hashed_message.decode())
                if client_hash != protocol.calc_hash(client_encrypted_message):
                    raise ValueError("Hash mismatch: The message may have been tampered with.")

                # Verify the client's RSA signature
                client_signature = int(client_signed_message.decode())
                calculated_hash_from_signature = pow(client_signature, client_rsa_e, client_rsa_n)
                if calculated_hash_from_signature != client_hash:
                    raise ValueError("Signature mismatch: The message may have been tampered with.")

                # Decrypt the client's message
                decrypted_message = protocol.symmetric_decryption(client_encrypted_message, shared_secret)
                client_message = decrypted_message.decode()

                # Check if the client requested to terminate the connection
                if client_message.upper() == "EXIT":
                    print("Client requested to close the connection.")
                    break

                print(f"Client sent: {client_message}")

                # Respond to the client with an encrypted acknowledgment
                response_message = f"Server received: {client_message}"
                encrypted_response = protocol.symmetric_encryption(response_message.encode(), shared_secret)
                hashed_response = protocol.calc_hash(encrypted_response)
                signed_response = protocol.calc_signature(hashed_response, server_rsa_d, server_rsa_n)

                # Send the encrypted response, hash, and signature back to the client
                client_socket.send(protocol.create_msg(encrypted_response))
                client_socket.send(protocol.create_msg(str(hashed_response).encode()))
                client_socket.send(protocol.create_msg(str(signed_response).encode()))

            except Exception as e:
                print(f"Error during communication: {e}")
                break

    finally:
        # Close the sockets gracefully
        print("Closing server socket.")
        client_socket.close()
        server_socket.close()

if __name__ == "__main__":
    main()
