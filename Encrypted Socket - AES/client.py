import socket
import protocol

CLIENT_RSA_P, CLIENT_RSA_Q = protocol.generate_random_p_q()
CLIENT_RSA_E, CLIENT_RSA_N = protocol.get_RSA_public_key(CLIENT_RSA_P, CLIENT_RSA_Q)
CLIENT_RSA_D = protocol.get_RSA_private_key(CLIENT_RSA_P, CLIENT_RSA_Q, CLIENT_RSA_E)


def main():
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect(("127.0.0.1", protocol.PORT))

        client_private_key = protocol.diffie_hellman_choose_private_key()
        client_public_key = protocol.diffie_hellman_calc_public_key(client_private_key)
        server_public_key = int(my_socket.recv(1024).decode())
        my_socket.send(str(client_public_key).encode())
        shared_secret = protocol.diffie_hellman_calc_shared_secret(server_public_key, client_private_key)
        print(f"client shared_secret:{shared_secret}")

        while True:
            user_input = input("Enter command\n")
            if user_input == 'EXIT':
                my_socket.send(protocol.create_msg(user_input))
                print("Exiting...")
                break

            try:
                encrypted_message = protocol.symmetric_encryption(user_input.encode(), shared_secret)
                hashed_message = protocol.calc_hash(encrypted_message)
                signed_message = protocol.calc_signature(hashed_message, CLIENT_RSA_D, CLIENT_RSA_N)

                my_socket.send(protocol.create_msg(encrypted_message))
                my_socket.send(protocol.create_msg(str(hashed_message).encode()))
                my_socket.send(protocol.create_msg(str(signed_message).encode()))

                valid_msg1, server_encrypted_message = protocol.get_msg(my_socket)
                valid_msg2, server_hashed_message = protocol.get_msg(my_socket)
                valid_msg3, server_signed_message = protocol.get_msg(my_socket)

                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    break

                server_hash = int(server_hashed_message.decode())
                server_signature = int(server_signed_message.decode())
                if server_hash != protocol.calc_hash(server_encrypted_message):
                    raise ValueError("Hash mismatch.")
                if server_signature != protocol.calc_signature(server_hash, CLIENT_RSA_E, CLIENT_RSA_N):
                    raise ValueError("Signature verification failed.")

                decrypted_response = protocol.symmetric_decryption(server_encrypted_message, shared_secret)
                print(f"Server responded: {decrypted_response.decode()}")

            except Exception as e:
                print(f"Error: {e}")
                break

    finally:
        print("Closing client socket.")
        my_socket.close()


if __name__ == "__main__":
    main()
