import socket

def client_chat():
    # Step 1: Create the client socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Step 2: Connect to the server
    host = '127.0.0.1'  # Server's IP address
    port = 12345        # Server's port number
    client_socket.connect((host, port))
    print("Connected to the server.")

    # Step 3: Chat loop
    while True:
        # Send a message to the server
        client_message = input("Client: ")
        client_socket.send(client_message.encode())
        if client_message.lower() == "bye":  # End the chat if the client says "bye"
            print("You ended the chat.")
            break

        # Receive a message from the server
        server_message = client_socket.recv(1024).decode()
        if server_message.lower() == "bye":  # End the chat if the server says "bye"
            print("Server ended the chat.")
            break
        print(f"Server: {server_message}")

    # Step 4: Close the socket
    client_socket.close()

# Run the client chat
client_chat()
