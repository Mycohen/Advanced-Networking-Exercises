"""Encrypted socket server implementation
   Author:
   Date:
"""

import socket
import protocol

SERVER_RSA_P = 
SERVER_RSA_Q =


def create_server_rsp(cmd):
    """Based on the command, create a proper response"""
    return "Server response"


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", protocol.PORT))
    server_socket.listen()
    print("Server is up and running")
    (client_socket, client_address) = server_socket.accept()
    print("Client connected")

    # Diffie Hellman
    # 1 - choose private key
    # 2 - calc public key
    # 3 - interact with client and calc shared secret

    # RSA
    # Pick public key
    # Calculate matching private key
    # Exchange RSA public keys with client

    while True:
        # Receive client's message
        valid_msg, message = protocol.get_msg(client_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if client's message is authentic
        # 1 - separate the message and the MAC
        # 2 - decrypt the message
        # 3 - calc hash of message
        # 4 - use client's public RSA key to decrypt the MAC and get the hash
        # 5 - check if both calculations end up with the same result

        if message == "EXIT":
            break

        # Create response. The response would be the echo of the client's message

        # Encrypt
        # apply symmetric encryption to the server's message

        # Send to client
        # Combine encrypted user's message to MAC, send to client
        msg = protocol.create_msg(message)
        client_socket.send(msg.encode())

    print("Closing\n")
    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    main()
