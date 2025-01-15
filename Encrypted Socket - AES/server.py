import socket
import protocol

SERVER_RSA_P, SERVER_RSA_Q = protocol.generate_random_p_q()

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")

    try:
        client_socket, _ = server_socket.accept()
        print("Client connected")

        server_DH_private_key = protocol.diffie_hellman_choose_private_key()
        server_DH_public_key = protocol.diffie_hellman_calc_public_key(server_DH_private_key)
        client_socket.send(str(server_DH_public_key).encode())
        client_DH_public_key = int(client_socket.recv(1024).decode())
        shared_secret = protocol.diffie_hellman_calc_shared_secret(client_DH_public_key, server_DH_private_key)

        server_rsa_e, server_rsa_n = protocol.get_RSA_public_key(SERVER_RSA_P, SERVER_RSA_Q)
        server_rsa_d = protocol.get_RSA_private_key(SERVER_RSA_P, SERVER_RSA_Q, server_rsa_e)
        server_RSA_public = f"{server_rsa_e}, {server_rsa_n}"
        client_RSA_public = client_socket.recv(1024).decode().split(',')
        client_rsa_e, client_rsa_n = int(client_RSA_public[0]), int(client_RSA_public[1])
        client_socket.send(server_RSA_public.encode())

        while True:
            try:
                valid_msg1, client_encrypted_message = protocol.get_msg(client_socket)
                valid_msg2, client_hashed_message = protocol.get_msg(client_socket)
                valid_msg3, client_signed_message = protocol.get_msg(client_socket)

                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    raise ValueError("Invalid message.")

                client_hash = int(client_hashed_message.decode())
                client_signature = int(client_signed_message.decode())
                if client_hash != protocol.calc_hash(client_encrypted_message):
                    raise ValueError("Hash mismatch.")
                calculated_hash_from_signature = pow(client_signature, client_rsa_e, client_rsa_n)
                if calculated_hash_from_signature != client_hash:
                    raise ValueError("Signature mismatch.")

                decrypted_message = protocol.symmetric_decryption(client_encrypted_message, shared_secret)
                client_message = decrypted_message.decode()

                if client_message.upper() == "EXIT":
                    print("Client requested to close the connection.")
                    break

                response_message = f"Server received: {client_message}"
                encrypted_response = protocol.symmetric_encryption(response_message.encode(), shared_secret)
                hashed_response = protocol.calc_hash(encrypted_response)
                signed_response = protocol.calc_signature(hashed_response, server_rsa_d, server_rsa_n)

                client_socket.send(protocol.create_msg(encrypted_response))
                client_socket.send(protocol.create_msg(str(hashed_response).encode()))
                client_socket.send(protocol.create_msg(str(signed_response).encode()))

            except Exception as e:
                print(f"Error: {e}")
                break

    finally:
        print("Closing server socket.")
        client_socket.close()
        server_socket.close()

if __name__ == "__main__":
    main()
