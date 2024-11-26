import json
from typing import Dict, Union


def load_msg_server_info(filename: str = 'msg_server_info.json') -> Dict[str, dict]:
    """
          Load message server information from a JSON file.

          Args:
              filename (str): The name of the JSON file containing message server information.

          Returns:
              dict: A dictionary containing message server information.
          """
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_msg_server_info(msg_server_info: Dict, filename: str = 'msg_server_info.json') -> None:
    """
        Save message server information to a JSON file.

        Args:
            msg_server_info (dict): A dictionary containing message server information.
            filename (str): The name of the JSON file to save the message server information.
        """

    with open(filename, 'w') as file:
        json.dump(msg_server_info, file, indent=4)


def add_or_update_msg_server_info(msg_server_info: Dict, client_id: bytes, server_id: bytes, iv: bytes,
                                  aes_key: bytes, expiration_time: bytes) -> None:
    """
    Add or update message server information in the provided dictionary.

    Args:
        msg_server_info (Dict): Dictionary containing message server information.
        client_id (bytes): Client ID.
        server_id (bytes): Server ID.
        iv (bytes): Initialization Vector.
        aes_key (bytes): AES key.
        expiration_time (bytes): Expiration time.
    """

    msg_server_info[client_id.hex()] = {
        'Client ID': client_id.hex(),
        'Server ID': server_id.hex(),
        'Ticket IV': iv.hex(),
        'AES key': aes_key.hex(),
        'Expiration time': expiration_time.hex()
    }
    save_msg_server_info(msg_server_info)


def get_aes_key(msg_server_id: str) -> Union[bytes, None]:
    """
        Retrieves AES key associated with the specified message server ID.

        Args:
            msg_server_id (str): The ID of the message server.

        Returns:
            Union[bytes, None]: The AES key if found, else None.
        """
    data = load_msg_server_info(filename='msg_server_info.json')
    try:
        msg_server_data = data.get(msg_server_id.hex())
        if msg_server_data:
            aes_key = bytes.fromhex(msg_server_data['AES key'])
            return aes_key
    except KeyError:
        pass
    return None
