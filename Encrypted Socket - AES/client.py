import socket
import protocol

CLIENT_RSA_P = 
CLIENT_RSA_Q =

def main():
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    my_socket.connect(("127.0.0.1", protocol.PORT))

    # Diffie Hellman
    # 1 - choose private key
    # 2 - calc public key
    # 3 - interact with server and calc shared secret

    # RSA
    # Pick public key
    # Calculate matching private key
    # Exchange RSA public keys with server

    while True:
        user_input = input("Enter command\n")
        # Add MAC (signature)
        # 1 - calc hash of user input
        # 2 - calc the signature

        # Encrypt
        # apply symmetric encryption to the user's input

        # Send to server
        # Combine encrypted user's message to MAC, send to server
        msg = protocol.create_msg(user_input)
        my_socket.send(msg.encode())

        if user_input == 'EXIT':
            break

        # Receive server's message
        valid_msg, message = protocol.get_msg(my_socket)
        if not valid_msg:
            print("Something went wrong with the length field")

        # Check if server's message is authentic
        # 1 - separate the message and the MAC
        # 2 - decrypt the message
        # 3 - calc hash of message
        # 4 - use server's public RSA key to decrypt the MAC and get the hash
        # 5 - check if both calculations end up with the same result

        # Print server's message

    print("Closing\n")
    my_socket.close()

if __name__ == "__main__":
    main()
