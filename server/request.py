import base64
import os
import struct
import time
from typing import Optional, Tuple
from response import Response
from files_maintenance import FilesHandler
from crypto import generate_aes_key, generate_iv, aes_encrypt
from utils import extract_msg_server_key, hex_to_byte
from Constants.protocol_codes import ProtocolCodes, ResponsesCodes
from Constants.protocol_sizes import ProtocolSizes, HeaderSize
from Constants.utils import Utils


class Request:
    """
    Represents a client request, parsed from a byte stream.
    """

    def __init__(self, stream: bytes):
        """
        Initialize a Request object by parsing a byte stream.

        Args:
            stream (bytes): The byte stream containing the request data.
        """
        self.client_id = stream[:HeaderSize.CLIENT_ID]
        self.version = int.from_bytes(stream[HeaderSize.CLIENT_ID:17], "little")
        self.code = struct.unpack_from("H", stream, 17)[0]
        self.payload_size = int.from_bytes(stream[19:HeaderSize.PAYLOAD_SIZE], "little")
        self.payload = stream[HeaderSize.PAYLOAD_SIZE:]


files_handler = FilesHandler()


def client_register(payload: bytes) -> Tuple[Response, Optional[bytes]]:
    """
    Handles client registration.

    Args:
        payload (bytes): The payload containing the client registration data.

    Returns:
        Tuple[Response, Optional[bytes]]: The response and, if successful, the unique identifier of the client.
    """
    name = payload[:ProtocolSizes.CLIENT_NAME].decode('ascii', 'ignore').rstrip('\0')
    if files_handler.client_exists(name=name):
        print(f"Client: {name}, already exists")
        return Response(ProtocolCodes.CLIENT_VERSION, ResponsesCodes.REGISTRATION_FAILURE, 7, None), None
    else:
        print("Insert new client")
        uu = files_handler.add_register_client(payload)
        return Response(ProtocolCodes.CLIENT_VERSION, ResponsesCodes.REGISTRATION_SUCCESS, HeaderSize.PAYLOAD_SIZE, uu), uu


def generate_symmetric_key_response(request: bytes) -> Response:
    """
    Generates a symmetric key response for secure communication between the client and server.

    Args:
        request (bytes): The client's request payload.

    Returns:
        Response: The symmetric key response to be sent to the client.
    """
    version, client_id, server_id, nonce = extract_request_values(request)

    aes_key_client_server = generate_aes_key()
    key_iv = generate_iv()
    client_id = hex_to_byte(client_id)
    client_key = hex_to_byte(get_password_hash(client_id))

    padded_data = aes_key_client_server + nonce
    encrypted_client_key = aes_encrypt(key_iv, client_key, padded_data)

    server_private_key = extract_msg_server_key(Utils.MSG_SERVER_INFO_FILE)
    server_private_key_bytes = base64.b64decode(server_private_key)

    ticket = generate_ticket(version, hex_to_byte(client_id), server_id, aes_key_client_server,
                             server_private_key_bytes)

    payload = key_iv + encrypted_client_key + ticket

    print("Generated Symmetric Key for The client")
    return Response(ProtocolCodes.CLIENT_VERSION, ResponsesCodes.SYMMETRIC_KEY_REQUEST, len(payload) + 7, payload)


def generate_ticket(
        version: int,
        client_id: bytes,
        server_id: bytes,
        aes_key_client_server: bytes,
        server_private_key: bytes
) -> bytes:
    """
    Generates a ticket for secure communication between the client and message server.

    Args:
        version (int): Protocol version.
        client_id (bytes): Unique identifier of the client.
        server_id (bytes): Unique identifier of the message server.
        aes_key_client_server (bytes): The AES key shared between client and server.
        server_private_key (bytes): The private key of the message server.

    Returns:
        bytes: The serialized ticket.
    """
    # Generate random IV for the ticket
    ticket_iv = os.urandom(ProtocolSizes.TICKET_IV)

    # Current timestamp and expiration timestamp
    creation_time = int(time.time())
    expiration_time = creation_time + ProtocolSizes.EXPIRATION_TIME  # Ticket valid for 10 seconds

    # Encrypt AES key and expiration timestamp using the message server's private key
    aes_key_encrypted = aes_encrypt(ticket_iv, server_private_key, aes_key_client_server)
    expiration_timestamp_bytes = struct.pack('<Q', expiration_time)  # Pack expiration time as 8 bytes
    expiration_encrypted = aes_encrypt(ticket_iv, server_private_key, expiration_timestamp_bytes)

    # Serialize the ticket
    ticket = struct.pack(
        '<B16s16sQ16s48s16s',  # Format: Version (1 byte), Client ID (16 bytes), Server ID (16 bytes), etc.
        version,
        client_id,
        server_id,
        creation_time,
        ticket_iv,
        aes_key_encrypted,
        expiration_encrypted
    )

    print("Ticket has been initialized")
    return ticket


def extract_request_values(request: bytes) -> tuple[int, bytes, bytes, bytes]:
    """
    Extract important values from a request payload.

    Args:
        request (bytes): The raw request payload.

    Returns:
        tuple[int, bytes, bytes, bytes]: The version, client ID, server ID, and nonce.
    """
    req = Request(request)
    client_id = req.client_id
    version = req.version
    payload = req.payload

    server_id, nonce = struct.unpack_from('<16s8s', payload[-24:])
    return version, client_id, server_id, nonce


def read_clients_file() -> list[str]:
    """
    Read the clients file and return its lines.

    Returns:
        list[str]: A list of lines from the clients file.
    """
    try:
        with open("clients.txt", "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print("Error: 'clients.txt' file not found.")
        return []


def get_password_hash(user_id: str) -> Optional[str]:
    """
    Retrieve the hashed password for a given user ID.

    Args:
        user_id (str): The user ID to search for.

    Returns:
        Optional[str]: The hashed password if found, None otherwise.
    """
    lines = read_clients_file()

    for line in lines:
        parts = line.strip().split(":")
        if len(parts) >= 3:
            file_user_id, _, password_hash = parts[:3]
            if file_user_id == user_id:
                return password_hash
    return None
