import socket
import protocol

CLIENT_RSA_P, CLIENT_RSA_Q = protocol.generate_random_p_q()
CLIENT_RSA_E, CLIENT_RSA_N = protocol.get_RSA_public_key(CLIENT_RSA_P, CLIENT_RSA_Q)
CLIENT_RSA_D = protocol.get_RSA_private_key(CLIENT_RSA_P, CLIENT_RSA_Q, CLIENT_RSA_E)


def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    # Diffie-Hellman Key Exchange
    client_private_key = protocol.diffie_hellman_choose_private_key()
    client_public_key = protocol.diffie_hellman_calc_public_key(client_private_key)
    server_public_key = int(my_socket.recv(1024).decode())
    my_socket.send(str(client_public_key).encode())
    shared_secret = protocol.diffie_hellman_calc_shared_secret(server_public_key, client_private_key)

    while True:
        user_input = input("Enter command\n")
        if user_input == 'EXIT':
            my_socket.send(protocol.create_msg(user_input).encode())
            break

        # Encrypt the message
        encrypted_message = protocol.symmetric_encryption(user_input.encode(), shared_secret)

        # Hash and sign the message
        hashed_message = protocol.calc_hash(encrypted_message.decode())
        signed_message = protocol.calc_signature(hashed_message, CLIENT_RSA_D, CLIENT_RSA_N)

        # Send encrypted message, hash, and signature
        my_socket.send(protocol.create_msg(encrypted_message.decode()).encode())
        my_socket.send(protocol.create_msg(str(hashed_message)).encode())
        my_socket.send(protocol.create_msg(str(signed_message)).encode())

        # Receive server's response (encrypted, hash, signature)
        valid_msg1, server_encrypted_message = protocol.get_msg(my_socket)
        valid_msg2, server_hashed_message = protocol.get_msg(my_socket)
        valid_msg3, server_signed_message = protocol.get_msg(my_socket)

        if not (valid_msg1 and valid_msg2 and valid_msg3):
            print("Something went wrong with the length field")
            continue

        # Verify server's signature
        server_hash = int(server_hashed_message)
        server_signature = int(server_signed_message)
        if server_hash != protocol.calc_hash(server_encrypted_message):
            print("The hash does not match the encrypted message. Message integrity failed.")
            continue

        if server_signature != protocol.calc_signature(server_hash, CLIENT_RSA_E, CLIENT_RSA_N):
            print("The signature verification failed. The message was altered.")
            continue

        # Decrypt the server's message
        decrypted_response = protocol.symmetric_decryption(server_encrypted_message.encode(), shared_secret)
        print(f"Server responded: {decrypted_response.decode()}")

    print("Closing\n")
    my_socket.close()


if __name__ == "__main__":
    main()
