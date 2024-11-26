import os
import uuid
import hashlib
import datetime
from typing import Optional
from Constants.protocol_sizes import ProtocolSizes as protocolSize


class FilesHandler:
    def __init__(self):
        """Initialize a FilesHandler object."""
        self.clients_file = "clients.txt"
        self.initialize_file()

    def initialize_file(self) -> None:
        """Check if the clients file exists; if not, create an empty file."""
        if not os.path.exists(self.clients_file):
            with open(self.clients_file, 'w'):
                pass  # Just to ensure the file exists

    def add_register_client(self, payload: bytes) -> bytes:
        """Add a new client registration to the clients file.

        Args:
            payload (bytes): The payload containing client data.

        Returns:
            bytes: The UUID of the registered client.
        """
        try:
            name, password = self.extract_name_and_password(payload)
            password_hash = self.hash_password(password)
            last_seen = self.get_current_time()
            uu = self.generate_uuid_bytes()

            # Format client data as a single string
            client_data_str = f"{uu.hex()}:{name}:{password_hash}:{last_seen}\n"

            # Append the client data to the clients file
            with open(self.clients_file, 'a') as file:
                file.write(client_data_str)

            return uu
        except Exception as e:
            print(f"Error adding client: {e}")
            raise

    def client_exists(self, name: Optional[str] = None) -> bool:
        """Check if a client with the given name exists in the clients file.

        Args:
            name (str, optional): The name of the client to check.

        Returns:
            bool: True if the client exists, False otherwise.
        """
        try:
            with open(self.clients_file, 'r') as file:
                for line in file:
                    _, client_name, _, _ = line.strip().split(":", 3)
                    if client_name == name:
                        return True
        except FileNotFoundError:
            print("Error: Clients file not found.")
        return False

    @staticmethod
    def generate_uuid_bytes() -> bytes:
        """Generate a UUID in bytes format.

        Returns:
            bytes: The generated UUID in bytes format.
        """
        return uuid.uuid4().bytes

    @staticmethod
    def extract_name_and_password(payload: bytes) -> tuple[str, str]:
        """Extract the client's name and password from the payload.

        Args:
            payload (bytes): The payload containing client data.

        Returns:
            tuple[str, str]: The client's name and password.
        """
        name_start = 0
        name_end = name_start + protocolSize.CLIENT_NAME
        name_bytes = payload[name_start:name_end]
        name = name_bytes.split(b'\0', 1)[0].decode('ascii', 'ignore')

        password_start = name_end
        password_end = password_start + protocolSize.PASSWORD
        password_bytes = payload[password_start:password_end]
        password = password_bytes.split(b'\0', 1)[0].decode('ascii', 'ignore')

        return name, password

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using SHA-256.

        Args:
            password (str): The plaintext password.

        Returns:
            str: The hashed password in hexadecimal format.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    @staticmethod
    def get_current_time() -> str:
        """Get the current time in ISO 8601 format.

        Returns:
            str: The current time as a string.
        """
        return datetime.datetime.now().isoformat()
