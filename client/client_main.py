import hashlib
import os
import random
import struct
import time
from typing import Tuple

from client.client_info_manager import get_client_details, load_clients_info, add_or_update_client_info
from client.crypto import aes_decrypt, aes_encrypt
from client.server_info_manager import add_or_update_server_info, get_server_details
from communication_handler import CommunicationHandler
from response import Response
from Constants.utils import Utils
from Constants.protocol_sizes import ProtocolSizes as PS, HeaderSize as HS
from Constants.protocol_codes import ProtocolCodes, RequestsCodes

clients_in_ram = {}


def save_to_ram(username: str, user_uid: bytes) -> None:
    """
        Save client details to RAM.

        Args:
            username (str): The username of the client.
            user_uid (bytes): The unique identifier of the client.
        """
    clients_in_ram[username] = user_uid


def load_from_me_info() -> Tuple[str, str] | Tuple[None, None]:
    """
        Load user information from the "me.info" file.

        Returns:
            Tuple[str, str] | Tuple[None, None]: A tuple containing the username and unique identifier
            if found, otherwise (None, None).
        """
    if os.path.isfile(Utils.ME_INFO_FILE):
        with open(Utils.ME_INFO_FILE, "r") as file:
            lines = file.readlines()
            if len(lines) >= Utils.MINIMUM_LINES_ME_INFO:
                username = lines[Utils.FIRST_LINE].strip()
                unique_identifier = lines[Utils.SECOND_LINE].strip()
                return username, unique_identifier
    return None, None


def save_to_me_info(username: str, unique_identifier: bytes) -> None:
    """
      Save the username and unique identifier to the "me.info" file.

      Args:
          username (str): The username to be saved.
          unique_identifier (bytes): The unique identifier to be saved.
      """
    with open(Utils.ME_INFO_FILE, "a") as file:
        file.write(username + "\n")
        file.write(str(unique_identifier) + "\n")


def create_client_registration_request(user_name: str, password: str) -> bytes:
    """
        Create a client registration request.

        Args:
            user_name (str): The username of the client.
            password (str): The password of the client.

        """
    header = struct.pack("<16sBHI", (" " * 16).encode("utf-8"), ProtocolCodes.CLIENT_VERSION, RequestsCodes.CLIENT_REGISTRATION, 510)
    payload = struct.pack("<255s255s", user_name.encode("utf-8"), password.encode("utf-8"))
    return header + payload


def create_symmetric_key_request(client_id: bytes, msg_server_id: bytes, nonce: bytes) -> bytes:
    """
        Create a request between a client and authentication server to receive a symmetric key for conversation
        between a client and a message server.

       Args:
           client_id (bytes): The client ID.
           msg_server_id (bytes): The message server ID.
           nonce (bytes): The nonce value.

       """
    header = struct.pack("<16sBHI", client_id, ProtocolCodes.CLIENT_VERSION, RequestsCodes.SYMMETRIC_KEY_REQUEST, 24)
    payload = struct.pack("<16s8s", msg_server_id, nonce)
    return header + payload


def msg_server_info_request(client_id: bytes) -> bytes:
    """
        Create a request for server information.

        Args:
            client_id (bytes): The client ID.

        """
    header = struct.pack("<16sBHI", client_id, ProtocolCodes.CLIENT_VERSION, RequestsCodes.MESSAGES_SERVERS_LIST, 0)
    return header


def create_sending_symmetric_key(client_id: bytes, authenticator: bytes, ticket: bytes):
    """
        Create a request for sending a symmetric key.

        Args:
            client_id (bytes): The client ID.
            authenticator (bytes): The authenticator.
            ticket (bytes): The ticket.

        Returns:
            Request: The sending symmetric key request object.
        """

    header = struct.pack("<16sBHI", client_id, ProtocolCodes.CLIENT_VERSION, RequestsCodes.MSG_REQUEST, 233)
    payload = struct.pack("<112s121s", authenticator, ticket)
    return header + payload


def create_send_message(client_id: bytes, message: str, symmetric_key: bytes):
    """
       Create a request to send a message.

       Args:
           client_id (bytes): The client ID.
           message (str): The message to be sent.
           symmetric_key (bytes): The symmetric key used for encryption.

       Returns:
           Request: The sending message request object.
       """

    iv = generate_random_iv()
    encrypted_message = aes_encrypt(iv, symmetric_key, message)
    message_size = len(encrypted_message)
    payload_size = 20 + message_size

    header = struct.pack("<16sBHI", client_id, ProtocolCodes.CLIENT_VERSION, RequestsCodes.SEND_MESSAGE, payload_size)
    payload = struct.pack(f"<I16s{message_size}s", message_size, iv, encrypted_message)
    return header + payload


def generate_nonce() -> bytearray:
    """
        Generate a random nonce.

        Returns:
            bytearray: An 8-byte random nonce.
        """
    nonce = bytearray(PS.NONCE)
    for i in range(PS.NONCE):
        nonce[i] = random.randint(Utils.MIN_BYTE_VALUE, Utils.MAX_BYTE_VALUE)
    return nonce


def convert_hex(val) -> bytes | str:
    """
        Convert a hexadecimal string to bytes or vice versa.

        Args:
            val (str | bytes): The value to convert.

        Returns:
            bytes | str: The converted value.
        """
    if isinstance(val, str):
        return bytes.fromhex(val)

    elif isinstance(val, bytes):
        return val.hex()


def generate_authenticator(client_id: bytes, printer_id: bytes, decrypted_key: bytes) -> bytes:
    """
        Generate an authenticator for client-server communication.

        Args:
            client_id (bytes): The client ID.
            printer_id (bytes): The printer ID.
            decrypted_key (bytes): The decrypted symmetric key.

        Returns:
            bytes: The generated authenticator.
        """
    authenticator_iv = generate_random_iv()
    version_byte = bytes([ProtocolCodes.CLIENT_VERSION])
    time_creation = int(time.time()).to_bytes(Utils.TIMESTAMP_LENGTH, byteorder='little')

    authenticator = struct.pack(
        "<16s16s32s32s16s",
        authenticator_iv,
        aes_encrypt(authenticator_iv, decrypted_key, version_byte),
        aes_encrypt(authenticator_iv, decrypted_key, client_id),
        aes_encrypt(authenticator_iv, decrypted_key, printer_id),
        aes_encrypt(authenticator_iv, decrypted_key, time_creation)
    )
    return authenticator


def generate_random_iv() -> bytes:
    """
      Generate a random initialization vector (IV) for encryption.

      Returns:
          bytes: A random 16-byte IV.
    """
    return os.urandom(PS.IV)


def parse_server_info(server_details: Response) -> Tuple[str, str, str, str]:
    """
    Parse server information from the response payload.

    Args:
        server_details (Response): The response containing server information.

    Returns:
        tuple: A tuple containing the IP port, printer name, printer ID, and AES key.
    """
    server_info = server_details.payload.decode().split('\n')
    ip_port = server_info[Utils.FIRST_LINE]
    printer_name = server_info[Utils.SECOND_LINE]
    printer_id = server_info[Utils.THIRD_LINE]
    aes_key = server_info[Utils.FOURTH_LINE]
    return ip_port, printer_name, printer_id, aes_key


def extract_iv_encrypted_data_and_ticket(response: Response) -> Tuple[bytes, bytes, bytes]:
    """
    Extract IV, encrypted data, and ticket from the response payload.

    Args:
        response (Response): The response containing the payload.

    Returns:
        tuple: A tuple containing IV, encrypted data, and ticket.
    """
    iv = response.payload[HS.CLIENT_ID:HS.CLIENT_ID + PS.IV]
    encrypted_data = response.payload[HS.CLIENT_ID + PS.IV:HS.CLIENT_ID + PS.IV + Utils.ENCRYPTED_DATA]
    ticket = response.payload[
             HS.CLIENT_ID + PS.IV + Utils.ENCRYPTED_DATA:HS.CLIENT_ID + PS.IV + Utils.ENCRYPTED_DATA + PS.TICKET]
    return iv, encrypted_data, ticket


def reconnect_user(user_name: str, user_uid: hex, comm_handler: CommunicationHandler) -> None:
    """
        Reconnect a user who is already registered.

        Args:
            user_name (str): The username of the user.
            user_uid (hex): The unique identifier of the user.
            comm_handler (CommunicationHandler): An instance of CommunicationHandler.

        """

    print("Welcome back! You are already registered as a client. Here are your details:")
    print(f"Client: {user_name}, UUID: {user_uid}")
    user_password = input("Enter password to reconnect: ")
    uu = convert_hex(user_uid)
    iv, encrypted_data, ticket, nonce = get_client_details(user_name)
    process_decryption_and_send_msg(user_password, iv, encrypted_data, ticket, nonce, uu, comm_handler)


def register_new_user(comm_handler: CommunicationHandler, nonce: bytearray, client_info: dict) -> None:
    """
       Register a new user.

       Args:
           comm_handler (CommunicationHandler): An instance of CommunicationHandler.
           nonce (bytearray): The nonce for communication.
           client_info (dict): Information about the new user, to be saved.
       """

    print("Client Registration. Please wait a moment while we register you as a new user")
    uu, user_password = None, None
    while True:
        user_name = input("Enter your username (up to 255 characters): ")
        if len(user_name) > PS.CLIENT_NAME:
            print("Error - username too long. Please enter a username with up to 255 characters.")
            continue

        user_password = input("Enter password: ")

        response = comm_handler.send_and_receive_message(
            create_client_registration_request(user_name, user_password), Utils.AUTH_SERVER_IP, Utils.AUTH_SERVER_PORT)

        if response.payload is not None:
            uu = response.payload
            payload_to_byte = convert_hex(response.payload)
            save_to_ram(user_name, payload_to_byte)
            save_to_me_info(user_name, payload_to_byte)
            break
        else:
            print("Client already exists. Please try again with a different username.")

    server_details = comm_handler.send_and_receive_message(
        msg_server_info_request(uu), Utils.AUTH_SERVER_IP, Utils.AUTH_SERVER_PORT)

    ip_port, printer_name, printer_id, aes_key = parse_server_info(server_details)
    add_or_update_server_info(ip_port, printer_name, printer_id, aes_key)

    nonce += bytearray(8 - len(nonce))

    byte_data = struct.pack('<Q', int.from_bytes(nonce, byteorder='little'))

    response = comm_handler.send_and_receive_message(
        create_symmetric_key_request(uu, bytes.fromhex(printer_id),
                                     byte_data), Utils.AUTH_SERVER_IP, Utils.AUTH_SERVER_PORT)

    iv, encrypted_data, ticket = extract_iv_encrypted_data_and_ticket(response)
    add_or_update_client_info(client_info, user_name, iv, encrypted_data, ticket, byte_data)

    process_decryption_and_send_msg(user_password, iv, encrypted_data, ticket, byte_data, uu, comm_handler)


def decrypt_data(user_password: str, iv: bytes, encrypted_data: bytes) -> Tuple[bytes, bytes]:
    """
        Decrypt data using the provided password.

        Args:
            user_password (str): The password to decrypt the data.
            iv (bytes): The initialization vector.
            encrypted_data (bytes): The encrypted data.

        Returns:
            Tuple[bytes, bytes]: The decrypted key and nonce.
        """
    decrypted_data = None
    password_hash = hashlib.sha256(user_password.encode()).hexdigest()
    client_key = convert_hex(password_hash)

    try:
        decrypted_data = aes_decrypt(iv, client_key, encrypted_data)
    except (ValueError, TypeError):
        print("Error: Failed to decrypt data. Incorrect password or corrupted data.")
        exit(1)

    decrypted_key = decrypted_data[:32]
    decrypted_nonce = decrypted_data[32: 40]

    return decrypted_key, decrypted_nonce


def send_message(uu: bytes, message: str, decrypted_key: bytes, ticket: bytes,
                 comm_handler: CommunicationHandler) -> None:
    """
        Sends a message to the message server after establishing a connection.

        Args:
            uu (bytes): The user identifier.
            message (str): The message to be sent.
            decrypted_key (bytes): The decrypted symmetric key.
            ticket (bytes): The ticket for authentication.
            comm_handler (CommunicationHandler): The communication handler object.
        """
    ip_port, printer_name, printer_id, aes_key = get_server_details()
    ip, port = ip_port.split(":")
    authenticator = generate_authenticator(uu, bytes.fromhex(printer_id), decrypted_key)
    message_request = create_sending_symmetric_key(uu, authenticator, ticket)
    comm_handler.send_and_receive_message(message_request, ip, int(port))

    request_message = create_send_message(uu, message, decrypted_key)
    comm_handler.send_and_receive_message(request_message, ip, int(port))


def process_decryption_and_send_msg(user_password: str, iv: bytes, encrypted_data: bytes, ticket: bytes,
                                    nonce: bytes, uu: bytes, comm_handler: CommunicationHandler) -> None:
    """
        Processes decryption of received data and sends a message to the message server.

        Args:
            user_password (str): The user's password.
            iv (bytes): The initialization vector used for encryption.
            encrypted_data (bytes): The encrypted data received from the auth server.
            ticket (bytes): The ticket for authentication.
            nonce (bytes): The nonce for authentication.
            uu (bytes): The user identifier.
            comm_handler (CommunicationHandler): The communication handler object.

        """
    decrypted_key, decrypted_nonce = decrypt_data(user_password, iv, encrypted_data)

    if decrypted_nonce != bytes(nonce):
        print("Error: Nonce mismatch.")
        exit(1)

    print("Sending symmetric key was successful")
    message = input("Enter your message: ")

    send_message(uu, message, decrypted_key, ticket, comm_handler)


def main():
    client_info = load_clients_info()
    user_name, user_uid = load_from_me_info()
    comm_handler = CommunicationHandler()
    nonce = generate_nonce()

    if user_name and user_uid:
        reconnect_user(user_name, user_uid, comm_handler)
    else:
        register_new_user(comm_handler, nonce, client_info)


if __name__ == "__main__":
    main()
