import json
from typing import Dict, Tuple, Optional


def load_server_info(filename: str = 'server_info.json') -> Dict[str, dict]:
    """
    Load server information from a JSON file.

    Args:
        filename (str): The name of the JSON file containing server information.

    Returns:
        dict: A dictionary containing server information.
    """

    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_server_info(server_info: dict, filename: str = 'server_info.json') -> None:
    """
    Save server information to a JSON file.

    Args:
        server_info (dict): A dictionary containing server information.
        filename (str): The name of the JSON file to save the server information.
    """

    with open(filename, 'w') as file:
        json.dump(server_info, file, indent=4)


def add_or_update_server_info(ip_port: str, printer_name: str, printer_id: str, aes_key: str) -> None:
    """
    Add or update server information in the database.

    Args:
        ip_port (str): The IP address and port of the message server.
        printer_name (str): The name of the message server.
        printer_id (str): The unique identifier of the message server.
        aes_key (str): The AES encryption key for communication with the message server.
    """

    server_info = load_server_info()

    server_info[printer_id] = {
        'ip_port': ip_port,
        'printer_name': printer_name,
        'printer_id': printer_id,
        'aes_key': aes_key
    }

    save_server_info(server_info)


def get_server_details() -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Retrieve server details from the database.

    Returns:
        Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]: A tuple containing IP address,
        printer name, printer ID, and AES key of the server, or None if no server details are found.
    """

    data = load_server_info()
    try:
        server_info = list(data.values())[0]
        ip_port = server_info['ip_port']
        printer_name = server_info['printer_name']
        printer_id = server_info['printer_id']
        aes_key = server_info['aes_key']
        return ip_port, printer_name, printer_id, aes_key

    except (IndexError, KeyError):
        return None, None, None, None
