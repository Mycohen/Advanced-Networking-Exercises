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

    try:
        client_socket, client_address = server_socket.accept()
        print("Client connected")

        server_private_key = protocol.diffie_hellman_choose_private_key()
        server_public_key = protocol.diffie_hellman_calc_public_key(server_private_key)
        client_socket.send(str(server_public_key).encode())
        client_public_key = int(client_socket.recv(1024).decode())
        shared_secret = protocol.diffie_hellman_calc_shared_secret(client_public_key, server_private_key)
        print(f"server shared_secret:{shared_secret}")
        while True:
            try:
                valid_msg1, client_encrypted_message = protocol.get_msg(client_socket)
                valid_msg2, client_hashed_message = protocol.get_msg(client_socket)
                valid_msg3, client_signed_message = protocol.get_msg(client_socket)

                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    break

                client_hash = int(client_hashed_message.decode())
                client_signature = int(client_signed_message.decode())
                if client_hash != protocol.calc_hash(client_encrypted_message):
                    raise ValueError("Hash mismatch.")
                if client_signature != protocol.calc_signature(client_hash, SERVER_RSA_E, SERVER_RSA_N):
                    raise ValueError("Signature verification failed.")

                decrypted_message = protocol.symmetric_decryption(client_encrypted_message, shared_secret)
                print(f"Client sent: {decrypted_message.decode()}")

                response_message = f"Server received: {decrypted_message.decode()}"
                encrypted_response = protocol.symmetric_encryption(response_message.encode(), shared_secret)
                hashed_response = protocol.calc_hash(encrypted_response)
                signed_response = protocol.calc_signature(hashed_response, SERVER_RSA_D, SERVER_RSA_N)

                client_socket.send(protocol.create_msg(encrypted_response))
                client_socket.send(protocol.create_msg(str(hashed_response).encode()))
                client_socket.send(protocol.create_msg(str(signed_response).encode()))

            except Exception as e:
                print(f"Error: {e}")
                break

    finally:
        print("Closing server socket.")
        server_socket.close()


if __name__ == "__main__":
    main()
