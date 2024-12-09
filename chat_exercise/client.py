
import socket
import select
import msvcrt
import protocol

SERVER_IP = "127.0.0.1"  # Replace with the actual server IP if needed
SERVER_PORT = 8888

def main():
    # Step 1: Create and connect the socket
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        my_socket.connect((SERVER_IP, SERVER_PORT))
        print("Connected to the server.")
    except Exception as e:  
        print(f"Failed to connect to the server: {e}")
        return

    print("Enter commands (NAME, GET_NAMES, MSG, BLOCK, EXIT):")
    message_to_send = ""

    while True:
        # Step 2: Use select to monitor user input and server messages
        rlist, wlist, _ = select.select([my_socket], [my_socket] if message_to_send else [], [], 0.2)

        # Step 3: Check for server messages
        if my_socket in rlist:
            server_message = protocol.get_message(my_socket)
            if not server_message:
                print("Server disconnected.")
                print("")
                break
            print(f"\n[Server]: {server_message}")
            print("")
            print("Enter next command:")  # Print after processing the server response

        # Step 4: Check for user input (non-blocking)
        if msvcrt.kbhit():
            key = msvcrt.getch().decode()
            if key == '\r':  # Enter key pressed
                if message_to_send.strip().upper() == "EXIT":
                    # Handle EXIT command
                    my_socket.send(protocol.create_msg("EXIT").encode())
                    print("You disconnected from the server.")
                    break
                elif message_to_send.strip():  # Send user input to the server
                    formatted_message = protocol.create_msg(message_to_send.strip())
                    my_socket.send(formatted_message.encode())
                message_to_send = ""
                print("\nEnter next command:")  # Prompt user after sending the command
            else:
                message_to_send += key
                print(key, end="", flush=True)

    # Step 5: Close the socket
    my_socket.close()
    print("Client closed.")

if __name__ == "__main__":
    main()
