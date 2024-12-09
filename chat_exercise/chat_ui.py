from PySide6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QWidget, QScrollArea, QLineEdit, QPushButton, QLabel, QHBoxLayout
)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont
from datetime import datetime
import socket
import protocol
import sys


# Worker thread for receiving messages.
class ReceiveThread(QThread):
    new_message = Signal(str)

    def __init__(self, socket):
        super().__init__()
        self.socket = socket
        self.running = True

    def run(self):
        while self.running:
            try:
                message = protocol.get_message(self.socket)
                if not message:
                    self.new_message.emit("Server disconnected.")
                    self.running = False
                    break
                self.new_message.emit(message)
            except Exception as e:
                self.new_message.emit(f"Error receiving message: {e}")
                self.running = False
                break

    def stop(self):
        self.running = False


# Main Chat UI
class ChatWindow(QMainWindow):
    def __init__(self, client_socket):
        super().__init__()

        self.client_socket = client_socket
        self.username = None

        # Set up the window
        self.setWindowTitle("Chat Application")
        self.setFixedSize(400, 550)  # Slightly larger window
        self.setStyleSheet("background-color: #f7f7f7;")  # Light gray background

        # Main layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(10, 10, 10, 10)
        self.main_layout.setSpacing(10)

        # Command List
        self.command_label = QLabel(
            "Available Commands:\n- NAME <your_name>\n- GET_NAMES\n- MSG <recipient> <message>\n- BLOCK <username>\n- EXIT"
        )
        self.command_label.setStyleSheet("font: 12px 'Helvetica'; color: #007bff;")
        self.main_layout.addWidget(self.command_label)

        # Scroll area for messages
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("background-color: #eef2f7; border: none;")
        self.scroll_widget = QWidget()
        self.scroll_layout = QVBoxLayout(self.scroll_widget)
        self.scroll_layout.setContentsMargins(5, 5, 5, 5)
        self.scroll_layout.setSpacing(10)
        self.scroll_widget.setLayout(self.scroll_layout)
        self.scroll_area.setWidget(self.scroll_widget)
        self.main_layout.addWidget(self.scroll_area)

        # Input area
        self.input_layout = QHBoxLayout()
        self.message_input = QLineEdit()
        self.message_input.setPlaceholderText("Type a message...")
        self.message_input.setStyleSheet(
            "font: 14px 'Helvetica'; padding: 8px; border: 1px solid #ccc; border-radius: 15px;"
        )
        self.message_input.returnPressed.connect(self.send_message)  # Trigger send on Enter
        self.input_layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send")
        self.send_button.setFixedSize(80, 40)
        self.send_button.setStyleSheet(
            "font: bold 14px 'Helvetica'; background-color: #34d058; color: white; border: none; border-radius: 10px;"
        )
        self.send_button.clicked.connect(self.send_message)
        self.input_layout.addWidget(self.send_button)
        self.main_layout.addLayout(self.input_layout)

        # Start the receiving thread
        self.receive_thread = ReceiveThread(self.client_socket)
        self.receive_thread.new_message.connect(self.add_message)
        self.receive_thread.start()

    def add_message(self, message, outgoing=False):
        """
        Add a message to the chat area.
        """
        timestamp = datetime.now().strftime("%H:%M")

        # Create a horizontal layout for the message
        message_layout = QHBoxLayout()

        # Create the message bubble
        message_label = QLabel(f"{message} [{timestamp}]")
        message_label.setWordWrap(True)
        message_label.setStyleSheet(
            f"""
            background-color: {'#dcf8c6' if outgoing else '#ffffff'};
            color: #333;
            padding: 10px;
            border-radius: 10px;
        """
        )
        message_label.setFont(QFont("Helvetica", 12))  # Set font for readability
        message_label.adjustSize()  # Ensure the label resizes to fit text

        # Align based on whether the message is outgoing or incoming
        if outgoing:
            message_layout.addStretch()  # Push the message to the right
            message_layout.addWidget(message_label)
        else:
            message_layout.addWidget(message_label)
            message_layout.addStretch()  # Push the message to the left

        # Add the layout to the scroll area
        message_container = QWidget()
        message_container.setLayout(message_layout)
        self.scroll_layout.addWidget(message_container)

        # Auto-scroll to the bottom
        self.scroll_area.verticalScrollBar().setValue(self.scroll_area.verticalScrollBar().maximum())

    def send_message(self):
        """
        Send a message to the server.
        """
        message = self.message_input.text().strip()
        if not message:
            return

        if message.startswith("NAME "):
            self.username = message.split(" ", 1)[1].strip()

        try:
            formatted_message = protocol.create_msg(message)
            self.client_socket.send(formatted_message.encode())
            self.add_message(f"You: {message}", outgoing=True)
        except Exception as e:
            self.add_message(f"Error sending message: {e}", outgoing=True)

        self.message_input.clear()

    def closeEvent(self, event):
        """
        Handle window close event to stop the thread and disconnect.
        """
        self.receive_thread.stop()
        if self.client_socket:
            try:
                formatted_message = protocol.create_msg("EXIT")
                self.client_socket.send(formatted_message.encode())
            except Exception:
                pass
            self.client_socket.close()
        event.accept()


# Main Application Setup
def main():
    app = QApplication(sys.argv)

    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect(("127.0.0.1", 8888))  # Replace with your server IP and port
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    # Create the chat window
    chat_window = ChatWindow(client_socket)
    chat_window.show()

    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
