import socket
import struct
from Constants.protocol_sizes import HeaderSize as HS
from Constants.utils import Utils
from typing import Tuple
from client.response import Response


class CommunicationHandler:
    def __init__(self):
        self.auth_server_address, self.auth_server_port = self.load_server_info()

    @staticmethod
    def load_server_info() -> Tuple[str, int]:
        """
        Load server information from 'srv.info' file.

        Returns:
            tuple: A tuple containing server address and port.
        """
        with open(Utils.SERVER_INFO_FILE, "r") as file:
            lines = file.readlines()
            server_address, server_port = lines[0].strip().split(":")
            server_port = int(server_port)
            return server_address, server_port

    @staticmethod
    def recv_header(client_socket: socket.socket) -> bytes:
        """
        Receive header from the client socket.

        Args:
            client_socket (socket.socket): The client socket.

        Returns:
            bytes: The received header.
        """
        header = client_socket.recv(7)
        return header

    @staticmethod
    def recv_payload(client_socket: socket.socket, payload_size: int) -> bytes:
        """
        Receive payload from the client socket.

        Args:
            client_socket (socket.socket): The client socket.
            payload_size (int): The size of the payload to receive.

        Returns:
            bytes: The received payload.
        """
        payload = client_socket.recv(payload_size)
        return payload

    @staticmethod
    def extract_payload_size_from_header(header: bytes) -> int:
        """
        Extract payload size from the header.

        Args:
            header (bytes): The header containing payload size information.

        Returns:
            int: The extracted payload size.
        """
        payload_size, = struct.unpack_from(HS.HEADER_PAYLOAD_SIZE_FORMAT, header, HS.HEADER_PAYLOAD_SIZE_OFFSET)
        return payload_size

    def send_and_receive_message(self, request, server_address: str, server_port: int) \
            -> Response:
        """
        Send a request and receive a response from the server.

        Args:
            request (Request): The request object to be sent.
            server_address (str): The IP address of the server.
            server_port (int): The port number of the server.

        Returns:
                Response: The response object received from the server.
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((server_address, server_port))
            client_socket.sendall(request)

            header = self.recv_header(client_socket)
            payload_size = self.extract_payload_size_from_header(header)
            payload = self.recv_payload(client_socket, payload_size)

            response = Response.create_response(header, payload)

            return response

