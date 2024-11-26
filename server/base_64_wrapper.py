import base64


class Base64Wrapper:
    @staticmethod
    def encode(input_str: str) -> str:
        """Encode a string using base64 encoding.

        Args:
            input_str (str): The string to be encoded.

        Returns:
            str: The base64 encoded string.
        """
        return base64.b64encode(input_str.encode()).decode()

    @staticmethod
    def decode(encoded_str: str) -> str:
        """Decode a base64 encoded string.

        Args:
            encoded_str (str): The base64 encoded string.

        Returns:
            str: The decoded string.
        """
        return base64.b64decode(encoded_str.encode()).decode()
