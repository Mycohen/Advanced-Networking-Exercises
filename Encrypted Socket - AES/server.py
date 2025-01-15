import socket
import protocol

# Generate RSA key pairs for the server
SERVER_RSA_P, SERVER_RSA_Q = protocol.generate_random_p_q()


def main():
    # Create a socket for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")

    try:
        # Accept a connection from the client
        client_socket, client_address = server_socket.accept()
        print("Client connected")

        print("# Step 1: server")
        # Step 1: Perform Diffie-Hellman key exchange
        server_DH_private_key = protocol.diffie_hellman_choose_private_key()
        server_DH_public_key = protocol.diffie_hellman_calc_public_key(server_DH_private_key)
        print(f"server_DH_public_key: {server_DH_public_key}")
        client_socket.send(str(server_DH_public_key).encode())  # Send server's public key to the client
        client_DH_public_key = int(client_socket.recv(1024).decode())  # Receive client's public key
        print(f"Received DH key from client:{client_DH_public_key}")
        shared_secret = protocol.diffie_hellman_calc_shared_secret(client_DH_public_key, server_DH_private_key)
        print(f"server shared_secret: {shared_secret}")
        print("Step 2: server")
        # Step 2: Perform RSA key exchange
        server_rsa_e, server_rsa_n = protocol.get_RSA_public_key(SERVER_RSA_P, SERVER_RSA_Q)
        server_rsa_d = protocol.get_RSA_private_key(SERVER_RSA_P, SERVER_RSA_Q, server_rsa_e)
        server_RSA_public = f"{server_rsa_e}, {server_rsa_n}"  # Prepare server's RSA public key
        print(f"Server RSA public key: {server_RSA_public}")
        client_RSA_public = client_socket.recv(1024).decode().split(',')  # Receive client's RSA public key
        print(f"Received RSA public key from client:{client_RSA_public}")
        client_rsa_e, client_rsa_n = int(client_RSA_public[0]), int(client_RSA_public[1])
        client_socket.send(server_RSA_public.encode())  # Send server's RSA public key to the client

        while True:
            try:
                print ("Step 3: server")
                # Step 3: Receive encrypted message, hash, and signature from client
                valid_msg1, client_encrypted_message = protocol.get_msg(client_socket)
                valid_msg2, client_hashed_message = protocol.get_msg(client_socket)
                valid_msg3, client_signed_message = protocol.get_msg(client_socket)

                # Check if all messages are valid
                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    raise ValueError("Failed to receive a valid message from the client.")

                # Verify the client's message
                client_hash = int(client_hashed_message.decode())
                client_signature = int(client_signed_message.decode())
                print(f"Received client signature: {client_signature}")
                print(f"calculated signature, server:{pow(int(client_signature), client_rsa_e, client_rsa_n)}")
                if client_hash != protocol.calc_hash(client_encrypted_message):
                    raise ValueError("Hash mismatch in client's message.")
                #if client_signature != protocol.calc_signature(client_hash, client_rsa_e, client_rsa_n):
                if client_signature != pow(int(client_signature), client_rsa_e, client_rsa_n):
                    raise ValueError("Signature verification failed for client's message.")

                # Decrypt the client's message
                decrypted_message = protocol.symmetric_decryption(client_encrypted_message, shared_secret)
                print(f"Client sent: {decrypted_message.decode()}")

                # Step 4: Create and send a response
                response_message = f"Server received: {decrypted_message.decode()}"
                encrypted_response = protocol.symmetric_encryption(response_message.encode(), shared_secret)
                hashed_response = protocol.calc_hash(encrypted_response)
                signed_response = protocol.calc_signature(hashed_response, server_rsa_d, server_rsa_n)

                # Send the encrypted response, hash, and signature to the client
                client_socket.send(protocol.create_msg(encrypted_response))
                client_socket.send(protocol.create_msg(str(hashed_response).encode()))
                client_socket.send(protocol.create_msg(str(signed_response).encode()))

            except Exception as e:
                # Print any errors during message handling
                print(f"Error: {e}")
                break

    finally:
        # Close the server socket gracefully
        print("Closing server socket.")
        server_socket.close()


if __name__ == "__main__":
    main()
