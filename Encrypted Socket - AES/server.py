import socket
import protocol

SERVER_RSA_P, SERVER_RSA_Q = protocol.generate_random_p_q()
SERVER_RSA_E, SERVER_RSA_N = protocol.get_RSA_public_key(SERVER_RSA_P, SERVER_RSA_Q)
SERVER_RSA_D = protocol.get_RSA_private_key(SERVER_RSA_P, SERVER_RSA_Q, SERVER_RSA_E)


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    client_socket, client_address = server_socket.accept()
    print("Client connected")

    # Diffie-Hellman Key Exchange
    server_private_key = protocol.diffie_hellman_choose_private_key()
    server_public_key = protocol.diffie_hellman_calc_public_key(server_private_key)
    client_socket.send(str(server_public_key).encode())
    client_public_key = int(client_socket.recv(1024).decode())
    shared_secret = protocol.diffie_hellman_calc_shared_secret(client_public_key, server_private_key)

    while True:
        # Receive encrypted message, hash, and signature
        valid_msg1, client_encrypted_message = protocol.get_msg(client_socket)
        valid_msg2, client_hashed_message = protocol.get_msg(client_socket)
        valid_msg3, client_signed_message = protocol.get_msg(client_socket)

        if not (valid_msg1 and valid_msg2 and valid_msg3):
            print("Something went wrong with the length field")
            continue

        # Verify client's hash
        client_hash = int(client_hashed_message)
        client_signature = int(client_signed_message)
        if client_hash != protocol.calc_hash(client_encrypted_message):
            print("The hash does not match the encrypted message. Message integrity failed.")
            continue

        if client_signature != protocol.calc_signature(client_hash, SERVER_RSA_E, SERVER_RSA_N):
            print("The signature verification failed. The message was altered.")
            continue

        # Decrypt the client's message
        decrypted_message = protocol.symmetric_decryption(client_encrypted_message.encode(), shared_secret)
        print(f"Client sent: {decrypted_message.decode()}")

        # Create a response
        response_message = f"Server received: {decrypted_message.decode()}"
        encrypted_response = protocol.symmetric_encryption(response_message.encode(), shared_secret)

        # Hash and sign the response
        hashed_response = protocol.calc_hash(encrypted_response.decode())
        signed_response = protocol.calc_signature(hashed_response, SERVER_RSA_D, SERVER_RSA_N)

        # Send encrypted response, hash, and signature
        client_socket.send(protocol.create_msg(encrypted_response.decode()).encode())
        client_socket.send(protocol.create_msg(str(hashed_response)).encode())
        client_socket.send(protocol.create_msg(str(signed_response)).encode())

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
