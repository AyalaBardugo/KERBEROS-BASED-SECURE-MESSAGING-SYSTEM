from Constants.protocol_codes import Config


def extract_msg_server_key(file_path):
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
                return None  # File doesn't have the expected structure
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None


def read_port() -> int:
    """Reads port number from a file and returns it.

    Returns:
        int: The port number read from the file, or the default port number if file not found or value error.
    """
    try:
        with open("port.info", "r") as port_file:
            port = int(port_file.read())
    except (FileNotFoundError, ValueError):
        print("port.info file not found or invalid port number. Using default port 1256")
        port = Config.DEFAULT_PORT_NUMBER

    return port


def hex_to_byte(val: str | bytes) -> bytes | str:
    """
    Convert a hexadecimal string to bytes or bytes to a hexadecimal string.

    Returns:
        bytes | str: If input is a string, returns the corresponding bytes.
                     If input is bytes, returns the corresponding hexadecimal string.

    """
    if isinstance(val, str):
        return bytes.fromhex(val)
    elif isinstance(val, bytes):
        return val.hex()
