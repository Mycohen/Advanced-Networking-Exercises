import socket
import protocol

CLIENT_RSA_P, CLIENT_RSA_Q = protocol.generate_random_p_q()



def main():
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect(("127.0.0.1", protocol.PORT))
        print("# Step 1: client")

        # Diffie-Hellman key exchange
        client_DH_private_key = protocol.diffie_hellman_choose_private_key()
        client_DH_public_key = protocol.diffie_hellman_calc_public_key(client_DH_private_key)

        server_DH_public_key = int(my_socket.recv(1024).decode())
        print(f"client_DH_public_key: {client_DH_public_key}")

        print(f"received server_DH_public_key: {server_DH_public_key}")

        my_socket.send(str(client_DH_public_key).encode())
        shared_secret = protocol.diffie_hellman_calc_shared_secret(server_DH_public_key, client_DH_private_key)
        print(f"client shared_secret:{shared_secret}")
        print("Step 2: client")

        # RSA key exchange
        client_rsa_e, client_rsa_n = protocol.get_RSA_public_key(CLIENT_RSA_P, CLIENT_RSA_Q)
        client_rsa_d = protocol.get_RSA_private_key(CLIENT_RSA_P, CLIENT_RSA_Q, client_rsa_e)
        client_RSA_public = f"{client_rsa_e}, {client_rsa_n}"
        print(f"client RSA public key: {client_RSA_public}")

        my_socket.send((client_RSA_public).encode())
        server_RSA_public = my_socket.recv(1024).decode().split(',')
        print(f"Received RSA public key from server:{server_RSA_public}")

        server_rsa_e, server_rsa_n = int(server_RSA_public[0]), int(server_RSA_public[1])



        while True:
            user_input = input("Enter command\n")
            if user_input == 'EXIT':
                my_socket.send(protocol.create_msg(user_input))
                print("Exiting...")
                break

            try:
                print ("Step 3: server")

                # Encrypt the message with the sycret shared key
                encrypted_client_message = protocol.symmetric_encryption(user_input.encode(), shared_secret)
                # Sign the message using RSA
                hashed_client_message = protocol.calc_hash(encrypted_client_message)
                # Sign with the RSA private key
                signed_client_message = protocol.calc_signature(hashed_client_message, client_rsa_d, client_rsa_n)
                # Send the data to the server
                my_socket.send(protocol.create_msg(encrypted_client_message))
                my_socket.send(protocol.create_msg(str(hashed_client_message).encode()))
                my_socket.send(protocol.create_msg(str(signed_client_message).encode()))

                # Receive an encrypted message rom the server
                valid_msg1, server_encrypted_message = protocol.get_msg(my_socket)
                valid_msg2, server_hashed_message = protocol.get_msg(my_socket)
                valid_msg3, server_signed_message = protocol.get_msg(my_socket)

                if not (valid_msg1 and valid_msg2 and valid_msg3):
                    break

                server_hash = int(server_hashed_message.decode())
                server_signature = int(server_signed_message.decode())
                print(f"Received server signature: {server_signature}")
                print(f"calculated signature, client:{pow(int(server_signature), server_rsa_e, server_rsa_n)} ")

                if server_hash != protocol.calc_hash(server_encrypted_message):
                    raise ValueError("Hash mismatch.")
                calculated_hash_from_signature = pow(server_signature, server_rsa_e, server_rsa_n)
                if calculated_hash_from_signature != server_hash:
                    raise ValueError("Signature mismatch: The message may have been tampered with or is not authentic.")

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