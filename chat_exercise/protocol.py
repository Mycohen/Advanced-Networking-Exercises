#Moshe Yaakov Cohen
#ID 324692680

# Protocol utilities for the chat application

# Constants
HEADER_LENGTH = 4  # Fixed-length header for message size
INVALID_COMMAND_RESPONSE = "ERROR: Invalid command or parameters"


def create_msg(data):
    """
    Formats a message with a fixed-length header indicating the length of the message.
    :param data: The message string to send.
    :return: A formatted string with a length prefix.
    """
    length = str(len(data)).zfill(HEADER_LENGTH)  # Ensure length is 4 digits
    return length + data


def get_message(sock):
    """
    Reads a message from the socket using the protocol format.
    :param sock: The socket to read from.
    :return: The message string, or an empty string if the connection is closed.
    """
    try:
        # First, read the fixed-length header to get the message length
        header = sock.recv(HEADER_LENGTH).decode()
        if not header:
            return ""  # Connection closed
        length = int(header)

        # Read the full message based on the length
        data = sock.recv(length).decode()
        return data
    except Exception as e:
        print(f"Error reading message: {e}")
        return ""


def parse_command(data):
    """
    Parses a command from the received data.
    :param data: The raw data received.
    :return: A tuple (command, arguments), where arguments is a list of strings.
    """
    parts = data.split(" ", 1)
    command = parts[0].upper()  # Commands are case-insensitive
    arguments = parts[1:] if len(parts) > 1 else []
    if arguments:
        arguments = arguments[0].split(" ", 1)  # Split the first argument and the rest
    return command, arguments


def validate_command(command, arguments):
    """
    Validates the format and content of a command.
    :param command: The command name.
    :param arguments: The command arguments.
    :return: True if the command is valid, False otherwise.
    """
    valid_commands = {
        "NAME": 1,       # NAME <name>
        "GET_NAMES": 0,  # GET_NAMES
        "MSG": 2,        # MSG <name> <message>
        "BLOCK": 1,      # BLOCK <name>
        "EXIT": 0,       # EXIT
    }

    # Check if the command exists and the argument count matches
    if command not in valid_commands:
        return False
    expected_arg_count = valid_commands[command]
    return len(arguments) == expected_arg_count


def build_response(command, success, message=None):
    """
    Builds a formatted response to send back to the client.
    :param command: The command being responded to.
    :param success: True if the operation was successful, False otherwise.
    :param message: Optional message to include in the response.
    :return: A formatted response string.
    """
    status = "SUCCESS" if success else "ERROR"
    if message:
        return f"{command} {status} {message}"
    return f"{command} {status}"


def is_valid_name(name):
    """
    Checks if a name is valid (single word, English, no special characters).
    :param name: The name to validate.
    :return: True if the name is valid, False otherwise.
    """
    return name.isalpha() and len(name.split()) == 1


def is_broadcast(name):
    """
    Checks if a name is "BROADCAST".
    :param name: The name to check.
    :return: True if the name is BROADCAST, False otherwise.
    """
    return name.upper() == "BROADCAST"
