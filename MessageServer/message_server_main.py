import base64
import socket
import struct
import threading
import time
from typing import Union, Optional, Dict, Tuple
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from MessageServer.msg_server_info_manager import load_msg_server_info, add_or_update_msg_server_info, get_aes_key
from server.base_64_wrapper import Base64Wrapper
from Constants.utils import Utils
from Constants.protocol_sizes import ProtocolSizes as PS, HeaderSize as HS
from Constants.protocol_codes import ProtocolCodes, RequestsCodes, ResponsesCodes
from colorama import Fore, Style


def extract_msg_server_key(file_path: str) -> Optional[str]:
    """
    Reads a file with the specified structure and returns the last row (symmetric key).

    Args:
        file_path: The path to the file containing the server information.

    Returns:
        The symmetric key (last row) or None if there's an error.
    """
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
            if len(lines) >= 4:
                key_base64 = lines[3].strip()
                return key_base64
            else:
                return None
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None


def aes_decrypt(iv: bytes, key: bytes, message: bytes) -> bytes:
    """
    Decrypt a message using AES encryption.

    Args:
        iv (bytes): The initialization vector.
        key (bytes): The encryption key.
        message (bytes): The message to decrypt.

    Returns:
        bytes: The decrypted message.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(message), AES.block_size)
    return decrypted


class RequestHeader:
    def __init__(self):
        self.requester_id = ""
        self.version = 0
        self.req_code = 0
        self.payload_size = 0

    def pack(self) -> bytes:
        """
        Pack the request header into bytes.

        Returns:
            bytes: The packed request header.
        """
        return struct.pack("<16sBHI", self.requester_id.encode(), self.version, self.req_code, self.payload_size)

    def unpack(self, buf: bytes) -> None:
        """
        Unpack bytes into the request header structure.

        Args:
            buf (bytes): The byte buffer.
        """
        array = bytearray(buf)
        self.requester_id = array[0:PS.CLIENT_ID]
        self.version, self.req_code, self.payload_size = struct.unpack_from("<BHI", array, PS.CLIENT_ID)


class RespondHeader:
    def __init__(self):
        self.version = ProtocolCodes.CLIENT_VERSION
        self.resp_code = 0
        self.payload_size = 0

    def pack(self) -> bytes:
        """
        Pack the response header into bytes.

        Returns:
            bytes: The packed response header.
        """
        return struct.pack("<BHI", self.version, self.resp_code, self.payload_size)

    def unpack(self, buf: bytes) -> None:
        """
        Unpack bytes into the response header structure.

        Args:
            buf (bytes): The byte buffer.
        """
        self.version, self.resp_code, self.payload_size = struct.unpack("<BHI", buf)


class MessageServer:
    def __init__(self):
        self.server_ip = ""
        self.server_port = Utils.DEFAULT_MSG_SERVER_PORT
        self.server_name = ""
        self.server_aes_key = ""


class ServerInfo:
    def __init__(self):
        self.msg_server = MessageServer()

    def read_info(self):
        """
        Reads the server information from the 'msg.info' file and updates the server attributes.

        Raises:
            FileNotFoundError: If the 'msg.info' file is not found.
            ValueError: If the file structure is invalid.
        """
        try:
            # Use context manager to open the file
            with open("msg.info", "r") as file:
                lines = [line.strip() for line in file.readlines()]

            # Ensure file has the minimum required lines
            if len(lines) < 4:
                raise ValueError("Invalid file structure: Expected at least 4 lines.")

            # Parse server details
            self.msg_server.server_ip, port = lines[0].split(':')
            self.msg_server.server_port = int(port)
            self.msg_server.server_name = lines[1]
            self.msg_server.server_aes_key = Base64Wrapper.encode(lines[3])

        except FileNotFoundError:
            print("*** 'msg.info' file not found. ***")
            raise
        except ValueError as ve:
            print(f"*** Error parsing 'msg.info': {ve} ***")
            raise


def extract_authenticator_details(authenticator: bytes, client_mge_server_key: bytes) -> dict[str, int | bytes]:
    """
    Extracts details from the authenticator.

    Args:
        authenticator (bytes): The authenticator bytes.
        client_mge_server_key (bytes): The client message server key.

    Returns:
        dict[str, int | bytes]: A dictionary containing the authenticator details.
    """
    # Define the IV and field offsets
    authenticator_iv = authenticator[:PS.IV]
    fields = {
        "Version": (PS.IV, PS.PADDED_VERSION),
        "Client ID": (PS.IV + PS.PADDED_VERSION, PS.KEY_SIZE),
        "Server ID": (PS.IV + PS.PADDED_VERSION + PS.KEY_SIZE, PS.KEY_SIZE),
        "Creation time": (PS.IV + PS.PADDED_VERSION + PS.KEY_SIZE + PS.KEY_SIZE,
                          len(authenticator) - (PS.IV + PS.PADDED_VERSION + 2 * PS.KEY_SIZE)),
    }

    # Helper function to decrypt a field
    def decrypt_field(field_name: str) -> bytes:
        offset, size = fields[field_name]
        field = authenticator[offset:offset + size]
        return aes_decrypt(authenticator_iv, client_mge_server_key, field)

    # Decrypt and construct the details
    authenticator_details = {
        "Authenticator IV": authenticator_iv,
        "Version": int.from_bytes(decrypt_field("Version"), byteorder='little'),
        "Client ID": decrypt_field("Client ID"),
        "Server ID": decrypt_field("Server ID"),
        "Creation time": decrypt_field("Creation time"),
    }

    return authenticator_details


def valid_expiration_time(expiration_time: bytes) -> bool:
    """
    Check if the expiration time is valid.

    Args:
        expiration_time (bytes): The expiration time as bytes.

    Returns:
        bool: True if the expiration time is valid, False otherwise.
    """
    float_expiration_time = struct.unpack('d', expiration_time)[0]
    return float_expiration_time < time.time()


def extract_ticket_details(ticket: bytes) -> Dict[str, Union[bytes, int]]:
    """
    Extract details from the ticket.

    Args:
        ticket (bytes): The ticket portion of the payload.

    Returns:
        Dict[str, Union[bytes, int]]: A dictionary with ticket details.
    """
    # Decode the server private key
    server_private_key = base64.b64decode(extract_msg_server_key('msg.info'))

    # Define offsets and sizes
    offsets = {
        "Version": (0, HS.VERSION),
        "Client ID": (HS.VERSION, PS.CLIENT_ID),
        "Server ID": (HS.VERSION + PS.CLIENT_ID, PS.SERVER_ID),
        "Creation time": (HS.VERSION + PS.CLIENT_ID + PS.SERVER_ID, PS.CREATION_TIME),
        "Ticket IV": (HS.VERSION + PS.CLIENT_ID + PS.SERVER_ID + PS.CREATION_TIME, PS.TICKET_IV),
        "AES key": (HS.VERSION + PS.CLIENT_ID + PS.SERVER_ID + PS.CREATION_TIME + PS.TICKET_IV, PS.KEY_OFFSET),
        "Expiration time": (
            HS.VERSION + PS.CLIENT_ID + PS.SERVER_ID + PS.CREATION_TIME + PS.TICKET_IV + PS.KEY_OFFSET, PS.TIME_OFFSET),
    }

    # Helper to extract a specific field
    def get_field(name: str) -> bytes:
        offset, size = offsets[name]
        return ticket[offset:offset + size]

    # Extract ticket fields
    ticket_iv = get_field("Ticket IV")
    aes_key = aes_decrypt(ticket_iv, server_private_key, get_field("AES key"))
    expiration_time = aes_decrypt(ticket_iv, server_private_key, get_field("Expiration time"))

    ticket_details = {
        "Version": get_field("Version")[0],  # Assuming it's a single byte
        "Client ID": get_field("Client ID"),
        "Server ID": get_field("Server ID"),
        "Creation time": get_field("Creation time"),
        "Ticket IV": ticket_iv,
        "AES key": aes_key,
        "Expiration time": expiration_time,
    }

    # Update message server info
    msg_server_info = load_msg_server_info()
    add_or_update_msg_server_info(
        msg_server_info,
        ticket_details["Client ID"],
        ticket_details["Server ID"],
        ticket_details["Ticket IV"],
        ticket_details["AES key"],
        ticket_details["Expiration time"]
    )

    return ticket_details


class Server:
    def __init__(self, sock, info):
        self.socket = sock
        self.info = info

    def handle_request(self, request, payload, requester_id):
        if request.req_code == RequestsCodes.MSG_REQUEST:
            if self.confirm_symmetric_key(payload):
                print("Key confirmation successful.")
                return True
            else:
                print("Symmetric key confirmation failed. ")
                return False

        elif request.req_code == RequestsCodes.SEND_MESSAGE:
            if self.print_message(payload, requester_id):
                print("Message processed successfully.")
                return True
            else:
                print("message processing failed.")
                return False
        else:
            print("Unknown request.")
            return False

    @staticmethod
    def extract_authenticator_and_ticket(payload: bytes) -> Tuple[bytes, bytes]:
        """
        Extracts the authenticator and ticket from the given payload.

        :param payload: The payload containing both the authenticator and the ticket.
        :return: A tuple of (authenticator, ticket) extracted from the payload.
        """
        authenticator = payload[:PS.AUTHENTICATOR_SIZE]
        ticket = payload[PS.AUTHENTICATOR_SIZE:PS.AUTHENTICATOR_SIZE + PS.TICKET]

        return authenticator, ticket

    def confirm_symmetric_key(self, payload: bytes) -> bool:
        """
        Confirm the symmetric key based on the payload.

        Args:
            payload (bytes): The payload containing the authenticator and ticket.

        Returns:
            bool: True if symmetric key confirmation is successful, False otherwise.
        """
        respond = RespondHeader()

        authenticator, ticket = self.extract_authenticator_and_ticket(payload)
        ticket_details = extract_ticket_details(ticket)
        authenticator_details = extract_authenticator_details(authenticator, ticket_details["AES key"])

        if not valid_expiration_time(ticket_details['Expiration time']):
            print("Error. The ticket has expired.")
            respond.resp_code = ResponsesCodes.GENERAL_ERROR
        else:
            if self.are_ticket_and_authenticator_valid(ticket_details, authenticator_details):
                print("Symmetric key confirmation success.")
                respond.resp_code = ResponsesCodes.SYMMETRIC_KEY_CONFIRMATION
            else:
                print("Symmetric key confirmation failed.")
                respond.resp_code = ResponsesCodes.GENERAL_ERROR

        respond.payload_size = 0
        self.socket.send(respond.pack())
        return respond.resp_code == ResponsesCodes.SYMMETRIC_KEY_CONFIRMATION

    @staticmethod
    def are_ticket_and_authenticator_valid(ticket_details: Dict, authenticator_details: Dict) -> bool:
        """
        Check if the ticket and authenticator details are valid.

        Args:
            ticket_details (Dict): Details extracted from the ticket.
            authenticator_details (Dict): Details extracted from the authenticator.

        Returns:
            bool: True if all details match, False otherwise.
        """
        keys_to_check = ["Version", "Client ID", "Server ID"]
        return all(ticket_details[key] == authenticator_details[key] for key in keys_to_check)

    def print_message(self, payload: bytes, requester_id: str) -> bool:
        """
        Decrypts and prints a message, and sends a confirmation response.

        Args:
            payload (bytes): The encrypted message payload.
            requester_id (str): The unique ID of the requester.

        Returns:
            bool: True if the message was processed successfully.
        """
        try:
            iv = payload[PS.MESSAGE:PS.MESSAGE + PS.IV]
            encrypted_message = payload[PS.MESSAGE + PS.IV:]

            client_mgs_server_key = get_aes_key(requester_id)
            if not client_mgs_server_key:
                print(f"Error: AES key not found for requester ID: {requester_id}")
                return False

            msg = aes_decrypt(iv, client_mgs_server_key, encrypted_message)
            print("Message: " + msg.decode('utf-8'))

            respond = RespondHeader()
            respond.resp_code = ResponsesCodes.MESSAGE_CONFIRMATION
            respond.payload_size = 0
            self.socket.send(respond.pack())
            return True

        except Exception as e:
            print(f"Error processing message: {e}")
            return False


def extract_payload_size_from_header(header: bytes) -> int:
    """
    Extract the payload size from the header.

    Args:
        header (bytes): The binary header data.

    Returns:
        int: The size of the payload extracted from the header.

    Raises:
        ValueError: If the header length is insufficient for extracting the payload size.
    """
    # Ensure the header is large enough for extraction
    if len(header) < 23:  # Offset (19) + 4 bytes for payload size
        raise ValueError("Header is too short to extract payload size.")

    # Extract the payload size using the provided format and offset
    payload_size, = struct.unpack_from('<I', header, 19)
    return payload_size


def recv_header(client_socket: socket.socket) -> bytes:
    """
    Receive a request header from the client socket.

    Args:
        client_socket (socket.socket): The client socket.

    Returns:
        bytes: The received header.
    """
    header = client_socket.recv(23)
    if len(header) < 23:
        raise ValueError("Incomplete header received.")
    return header


def recv_payload(client_socket: socket.socket, payload_size: int) -> bytes:
    """
    Receive a payload from the client socket.

    Args:
        client_socket (socket.socket): The client socket.
        payload_size (int): The expected size of the payload.

    Returns:
        bytes: The received payload.
    """
    payload = client_socket.recv(payload_size)
    if len(payload) < payload_size:
        raise ValueError("Incomplete payload received.")
    return payload


def manage_client(sock, address, info):
    print(f"New client connected: {address}.")
    server = Server(sock, info)

    while True:
        try:
            header = recv_header(sock)
            request = RequestHeader()
            request.unpack(header)

            payload_size = extract_payload_size_from_header(header)
            payload = recv_payload(sock, payload_size)

            if not server.handle_request(request, payload, request.requester_id):
                break

        except (ValueError, TypeError):
            print("Error with responding to client.")
            break
        break

    sock.close()
    exit(0)


def main():
    info = ServerInfo()
    info.read_info()

    ip = info.msg_server.server_ip
    addr = (ip, info.msg_server.server_port)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(addr)
    server_sock.listen()
    print(Fore.GREEN + Style.BRIGHT + f"Message Server is listening on {ip}:{info.msg_server.server_port} " + Style.RESET_ALL)

    try:
        while True:
            conn, addr = server_sock.accept()
            thread = threading.Thread(target=manage_client, args=(conn, addr, info))
            thread.start()

    except Exception as e:
        print(e)


if __name__ == "__main__":
    main()
