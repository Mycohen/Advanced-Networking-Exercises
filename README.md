# Advanced Computer Networks Exercises

This repository contains solutions for exercises from the **Advanced Computer Networks** course. The exercises cover a variety of topics, including network protocols, communication methods, and secure network services.

## Exercises

### Exercise 1: Chat Application
In this exercise, a simple chat application is implemented. The chat allows communication between multiple clients and a server, where users can send and receive messages in real time. The application includes a user interface (UI) built using **PySide6**.

**Features:**
- Real-time messaging
- Client-server architecture
- Multi-client support
- User interface built with PySide6

### Exercise 2: DNS Resolver
This exercise involves creating a basic DNS (Domain Name System) resolver. It simulates how DNS works by converting domain names to IP addresses and supports basic DNS query functionality.

**Features:**
- Resolving domain names to IP addresses
- Simulating DNS request-response communication
- Handling basic DNS queries

### Exercise 3: HTTP Server
In this exercise, an HTTP server is implemented to handle basic HTTP requests. The server supports serving static files, handling common HTTP status codes, and responding to specific URL patterns such as calculating areas and performing redirections.

**Features:**
- Serving static files from a specified webroot directory
- Supporting HTTP status codes: 200 OK, 302 Moved Temporarily, and 404 Not Found
- Handling dynamic requests
- URL redirection functionality

### Exercise 4: Encrypted Socket Communication
This exercise demonstrates secure communication between a client and server using cryptographic techniques. It implements secure data exchange with encrypted sockets, ensuring confidentiality, integrity, and authenticity of messages.

**Features:**
- **Diffie-Hellman** key exchange for secure key sharing
- **RSA** for digital signatures and key validation
- Custom **symmetric encryption block cipher** for secure data transmission
- Integrity verification using a 16-bit hash function
- Robust message protocol with length-prefixed messages for reliable communication

**Use Cases:**
- Secure communication over an insecure network
- Educational demonstration of cryptographic principles
