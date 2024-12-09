

import socket
import select
import protocol

# Server configuration
SERVER_IP = "0.0.0.0"
SERVER_PORT = 8888

# Global data structures
clients_sockets = []  # List of connected client sockets
clients_names = {}    # Dictionary mapping sockets to client names
blocked_users = {}    # Dictionary mapping clients to a list of blocked names


def broadcast_message(sender_socket, message):
    """
    Broadcast a message to all clients except the sender.
    :param sender_socket: The socket of the sender.
    :param message: The message to broadcast.
    """
    sender_name = clients_names.get(sender_socket, "Unknown")
    for client in clients_sockets:
        if client != sender_socket and sender_name not in blocked_users.get(client, []):
            try:
                formatted_message = protocol.create_msg(f"{sender_name}: {message}")
                client.send(formatted_message.encode())
            except Exception as e:
                print(f"Error sending broadcast to {clients_names.get(client, 'Unknown')}: {e}")


def handle_client_request(current_socket, data):
    """
    Handles commands sent by the client.
    :param current_socket: The socket of the client.
    :param data: The data received from the client.
    :return: Response message and target socket if applicable.
    """
    command, arguments = protocol.parse_command(data)

    # Handle NAME command
    if command == "NAME":
        if len(arguments) != 1 or not protocol.is_valid_name(arguments[0]):
            return protocol.build_response("NAME", False, "Invalid name"), current_socket

        new_name = arguments[0]
        if new_name in clients_names.values() or protocol.is_broadcast(new_name):
            return protocol.build_response("NAME", False, "Name already taken or invalid"), current_socket

        clients_names[current_socket] = new_name
        return protocol.build_response("NAME", True, f"Name set to {new_name}"), current_socket

    # Handle GET_NAMES command
    elif command == "GET_NAMES":
        names = ", ".join(clients_names.values())
        return protocol.build_response("GET_NAMES", True, f"Clients: {names}"), current_socket

    # Handle MSG command
    elif command == "MSG":
        if len(arguments) != 2:
            return protocol.build_response("MSG", False, "Invalid parameters"), current_socket

        target_name, message = arguments
        sender_name = clients_names[current_socket]

        # Handle broadcast message
        if protocol.is_broadcast(target_name):
            broadcast_message(current_socket, message)
            return protocol.build_response("MSG", True, "Message broadcasted"), current_socket

        # Handle direct message
        for client, name in clients_names.items():
            if name == target_name:
                # Check if the sender is blocked by the recipient
                if sender_name in blocked_users.get(client, []):
                    return protocol.build_response("MSG", False, f"You are blocked by {target_name}"), current_socket

                # Send the message
                formatted_message = protocol.create_msg(f"{sender_name}: {message}")
                client.send(formatted_message.encode())
                return protocol.build_response("MSG", True, "Message sent"), current_socket

        return protocol.build_response("MSG", False, "Target client not found"), current_socket

    # Handle BLOCK command
    elif command == "BLOCK":
        if len(arguments) != 1 or not protocol.is_valid_name(arguments[0]):
            return protocol.build_response("BLOCK", False, "Invalid name"), current_socket

        blocked_name = arguments[0]

        # Check if the target user exists
        if blocked_name not in clients_names.values():
            return protocol.build_response("BLOCK", False, "Target user not found"), current_socket

        # Add the blocked user to the block list
        if current_socket not in blocked_users:
            blocked_users[current_socket] = []

        if blocked_name not in blocked_users[current_socket]:
            blocked_users[current_socket].append(blocked_name)
            return protocol.build_response("BLOCK", True, f"Blocked {blocked_name}"), current_socket

        return protocol.build_response("BLOCK", False, f"{blocked_name} already blocked"), current_socket

    # Handle EXIT command
    elif command == "EXIT":
        return protocol.build_response("EXIT", True, "Goodbye"), current_socket

    # Handle invalid command
    else:
        return protocol.build_response(command, False, "Unknown command"), current_socket



def remove_disconnected_client(client_socket):
    """
    Removes a client from all data structures when they disconnect.
    :param client_socket: The socket of the client to remove.
    """
    print(f"Client {clients_names.get(client_socket, 'Unknown')} disconnected.")
    clients_sockets.remove(client_socket)
    if client_socket in clients_names:
        del clients_names[client_socket]
    if client_socket in blocked_users:
        del blocked_users[client_socket]
    client_socket.close()


def main():
    print("Starting server...")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen()
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        # Prepare the lists for select
        read_list = [server_socket] + clients_sockets
        write_list = []
        error_list = []

        ready_to_read, _, _ = select.select(read_list, write_list, error_list)

        for current_socket in ready_to_read:
            if current_socket is server_socket:
                # New client connection
                client_socket, client_address = server_socket.accept()
                print(f"New client connected: {client_address}")
                clients_sockets.append(client_socket)
            else:
                # Existing client sent data
                try:
                    data = protocol.get_message(current_socket)
                    if not data:  # Client disconnected
                        remove_disconnected_client(current_socket)
                        continue

                    response, target_socket = handle_client_request(current_socket, data)
                    formatted_response = protocol.create_msg(response)
                    if target_socket:
                        target_socket.send(formatted_response.encode())
                except Exception as e:
                    print(f"Error handling client {clients_names.get(current_socket, 'Unknown')}: {e}")
                    remove_disconnected_client(current_socket)

if __name__ == "__main__":
    main()
