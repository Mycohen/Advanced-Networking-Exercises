import socket
import os

WEBROOT = "webroot"  # Base directory for your web resources

IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 0.5  # Increase timeout to allow more time for the client
REDIRECTION_DICTIONARY = {
    "/old-page.html": "/new-page.html"  # Ensure the resource /new-page.html exists
}

VALID_HTTP_METHODS = ["GET"]
VALID_HTTP_VERSIONS = ["HTTP/1.0", "HTTP/1.1"]

def get_file_data(filename):
    """ Get data from file """
    with open(filename, "rb") as file:
        return file.read()

def handle_client_request(resource, client_socket):
    """ Process the HTTP request and send the appropriate response """
    try:
        # Handle `/calculate-next`
        if resource.startswith("/calculate-next"):
            query = resource.split("?")[1]  # Extract the query string
            params = dict(param.split("=") for param in query.split("&"))
            num = int(params.get("num", 0))  # Default to 0 if `num` is not provided
            next_num = num + 1
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nNext number is: {next_num}"
            client_socket.sendall(response.encode())
            return

        # Handle `/calculate-area`
        elif resource.startswith("/calculate-area"):
            query = resource.split("?")[1]
            params = dict(param.split("=") for param in query.split("&"))
            height = int(params.get("height", 0))
            width = int(params.get("width", 0))
            area = height * width
            response = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nThe area is: {area}"
            client_socket.sendall(response.encode())
            return

        # Handle Redirection (302)
        if resource in REDIRECTION_DICTIONARY:
            new_location = REDIRECTION_DICTIONARY[resource]
            response = f"HTTP/1.1 302 Moved Temporarily\r\nLocation: {new_location}\r\n\r\n"
            client_socket.sendall(response.encode())
            return

        # Default to `index.html` if the resource is empty
        if resource == '/':
            resource = '/index.html'

        # Construct the full file path
        file_path = os.path.join(WEBROOT, resource.lstrip("/"))

        # Check if the file exists
        if not os.path.exists(file_path):
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
        error_message = f"Error processing request: {e}"
        response = f"HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\n\r\n{error_message}"
        client_socket.sendall(response.encode())

def validate_HTTP_request(request):
    """ Validate the HTTP request and extract the requested resource """
    try:
        request_line = request.split("\r\n")[0]
        method, resource, http_version = request_line.split(" ")

        # Validate the method
        if method not in VALID_HTTP_METHODS:
            print("Invalid HTTP method:", method)
            return False, ""

        # Validate the HTTP version
        if http_version not in VALID_HTTP_VERSIONS:
            print("Invalid HTTP version:", http_version)
            return False, ""

        return True, resource

    except Exception as e:
        print(f"Error parsing request: {e}")
        return False, ""

def handle_client(client_socket):
    """ Handle client connection, process requests, and ensure no crashes """
    print("Client connected")
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)
        while True:
            try:
                client_request = client_socket.recv(1024).decode()
                if not client_request:  # Empty request, client disconnected
                    break
                print(f"Request received:\n{client_request}")
                valid_http, resource = validate_HTTP_request(client_request)
                if valid_http:
                    handle_client_request(resource, client_socket)
                else:
                    response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n\r\nInvalid HTTP request"
                    client_socket.sendall(response.encode())
            except socket.timeout:
                print("Socket timed out. Closing connection.")
                break
    finally:
        print("Closing connection")
        client_socket.close()

def main():
    """ Main function to start the HTTP server """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((IP, PORT))
    server_socket.listen()
    print(f"Listening for connections on port {PORT}")

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            print(f"New connection received from {client_address}")
            handle_client(client_socket)
        except KeyboardInterrupt:
            print("Shutting down server.")
            server_socket.close()
            break

if __name__ == "__main__":
    main()
