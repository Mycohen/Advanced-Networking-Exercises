import socket
import os

WEBROOT = "webroot"  # Set the base directory for your web resources

IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 0.5

REDIRECTION_DICTIONARY = {"/old-page.html": "/new-page.html"}  # Example redirection mapping
VALID_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]
VALID_HTTP_VERSIONS = ["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"]

def get_file_data(filename):
    """ Get data from file """
    with open(filename, "rb") as file:
        return file.read()


def handle_client_request(resource, client_socket):
    """ Check the required resource, generate proper HTTP response, and send to client """
    try:
        # Handle `/calculate-next`
        if resource.startswith("/calculate-next"):
            query = resource.split("?")[1]  # Extract the query string after "?"
            params = dict(param.split("=") for param in query.split("&"))
            num = int(params.get("num", 0))  # Default to 0 if `num` is not provided

            # Calculate the next number
            next_num = num + 1

            # Return the response
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nNext number is: {next_num}"
            client_socket.sendall(response.encode())
            return

        # Handle `/calculate-area`
        elif resource.startswith("/calculate-area"):
            query = resource.split("?")[1]
            params = dict(param.split("=") for param in query.split("&"))
            height = int(params.get("height", 0))
            width = int(params.get("width", 0))
            area = (height * width) / 2
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nThe area is: {area}"
            client_socket.sendall(response.encode())
            return

        # Handle Redirection (302)
        if resource in REDIRECTION_DICTIONARY:
            new_location = REDIRECTION_DICTIONARY[resource]
            response = (
                f"HTTP/1.1 302 Moved Temporarily\r\n"
                f"Location: {new_location}\r\n\r\n"
            )
            client_socket.sendall(response.encode())
            return

        # Default to `index.html` if the resource is empty
        if resource == '/':
            resource = '/index.html'

        # Remove leading slash and construct the full file path
        file_path = os.path.join(WEBROOT, resource.lstrip("/"))

        # Check if the resource exists
        if not os.path.exists(file_path):
            # Return 404 Not Found if the file does not exist
            response = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n\r\nFile not found"
            client_socket.sendall(response.encode())
            return

        # Determine the file type and set the Content-Type header
        file_extension = file_path.split(".")[-1]
        content_types = {
            "html": "text/html",
            "css": "text/css",
            "js": "application/javascript",
            "png": "image/png",
            "jpg": "image/jpeg",
            "jpeg": "image/jpeg",
            "ico": "image/x-icon"
        }
        content_type = content_types.get(file_extension, "application/octet-stream")

        # Read the file content
        file_data = get_file_data(file_path)

        # Create and send the HTTP response
        response_headers = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: {content_type}\r\n"
            f"Content-Length: {len(file_data)}\r\n"
            f"\r\n"
        ).encode()
        client_socket.sendall(response_headers + file_data)

    except Exception as e:
        # Handle unexpected file read errors
        error_message = f"Error processing request: {e}"
        response = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n{error_message}"
        client_socket.sendall(response.encode())


def validate_HTTP_request(request):
    """
    Check if the request is a valid HTTP request and extract the requested resource.
    Returns:
        - (True, resource) if valid
        - (False, "") if invalid
    """
    try:
        # Extract the first line of the HTTP request
        request_line = request.split("\r\n")[0]  # First line of HTTP request
        method, resource, http_version = request_line.split(" ")

        # Validate the method
        if method not in VALID_HTTP_METHODS:
            print("Invalid HTTP method:", method)
            return False, ""

        # Validate the HTTP version
        if http_version not in VALID_HTTP_VERSIONS:
            print("Invalid HTTP version:", http_version)
            return False, ""

        # If both checks pass, return True with the requested resource
        return True, resource

    except Exception as e:
        print(f"Error while parsing request: {e}")
        return False, ""


def handle_client(socket):
    """ Handles client requests: verifies client's requests are legal HTTP, calls function to handle the requests """
    print('Client connected')

    while True:
        client_request = socket.recv(1024).decode()
        print(f"Request received:\n{client_request}")
        valid_http, resource = validate_HTTP_request(client_request)
        if valid_http:
            print('Got HTTP request')
            handle_client_request(resource, socket)
            break
        else:
            print('Error: invalid HTTP request')
            break

    print('Closing connection')
    socket.close()


def main():
    # Open a socket and loop forever while waiting for clients
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print("Listening for connections on port {}".format(PORT))

    while True:
        client_socket, client_address = server_socket.accept()
        print('New connection received')
        client_socket.settimeout(SOCKET_TIMEOUT)
        handle_client(client_socket)


if __name__ == "__main__":
    # Call the main handler function
    main()
