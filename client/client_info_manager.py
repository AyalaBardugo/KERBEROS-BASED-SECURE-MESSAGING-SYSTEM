import json
from typing import Dict, Tuple, Optional


def load_clients_info(filename: str = 'client_info.json') -> Dict[str, dict]:
    """
        Load client information from a JSON file.

        Args:
            filename (str): The name of the JSON file containing client information.

        Returns:
            dict: A dictionary containing client information.
        """

    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_client_info(client_info: dict, filename: str = 'client_info.json') -> None:
    """
    Save client information to a JSON file.

    Args:
        client_info (dict): A dictionary containing client information.
        filename (str): The name of the JSON file to save the client information.
    """

    with open(filename, 'w') as file:
        json.dump(client_info, file, indent=4)


def add_or_update_client_info(client_info: Dict[str, dict], client_name: str, iv: bytes, encrypted_data: bytes,
                              ticket: bytes, nonce: bytearray) -> None:
    """
    Add or update client information in the client info dictionary and save to a JSON file.

    Args:
        client_info (Dict[str, dict]): A dictionary containing client information.
        client_name (str): The name of the client.
        iv (bytes): The initialization vector.
        encrypted_data (bytes): The encrypted data.
        ticket (bytes): The ticket bytes.
        nonce (bytearray): The nonce.
    """

    client_info[client_name] = {
        'user_name': client_name,
        'iv': iv.hex(),
        'encrypted_data': encrypted_data.hex(),
        'ticket_bytes': ticket.hex(),
        'nonce': nonce.hex()
    }
    save_client_info(client_info)


def get_client_details(username: str) -> Tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes]]:
    """
    Get client details from the client info dictionary.

    Args:
        username (str): The username of the client.

    Returns:
        Tuple[Optional[bytes], Optional[bytes], Optional[bytes], Optional[bytes]]: A tuple containing IV, encrypted data,
            ticket bytes, and nonce.
    """

    data = load_clients_info(filename='client_info.json')
    try:
        user_data = data[username]
        iv = bytes.fromhex(user_data['iv'])
        encrypted_data = bytes.fromhex(user_data['encrypted_data'])
        ticket_bytes = bytes.fromhex(user_data['ticket_bytes'])
        nonce = bytes.fromhex(user_data['nonce'])

        return iv, encrypted_data, ticket_bytes, nonce
    except KeyError:
        return None, None, None, None
