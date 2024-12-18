

import socket

# TO DO: set constants
IP = '0.0.0.0'
PORT = 80
SOCKET_TIMEOUT = 0.5
REDIRECTION_DICTIONARY = {old_resource_name: new_resource_name} # Programmer should pick the old and new resources
FIXED_RESPONSE = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/html; charset=ISO-8859-1\r\n\r\nhello"
VALID_HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE", "CONNECT"]
VALID_HTTP_VERSIONS = ["HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"]

def get_file_data(filename):
    """ Get data from file """
    return


def handle_client_request(resource, socket):
    """ Check the required resource, generate proper HTTP response and send to client"""
    # TO DO : add code that given a resource (URL and parameters) generates the proper response
    return


    if resource == '':


    # TO DO: check if URL had been redirected, not available or other error code. For example:
    if url in REDIRECTION_DICTIONARY:
        # TO DO: send 302 redirection response

    # TO DO: extract requested file tupe from URL (html, jpg etc)
    if filetype == 'html':
        http_header = # TO DO: generate proper HTTP header
    elif filetype == 'jpg':
        http_header = # TO DO: generate proper jpg header
    # TO DO: handle all other headers

    # TO DO: read the data from the file and send it to the client
    data = get_file_data(filename)




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