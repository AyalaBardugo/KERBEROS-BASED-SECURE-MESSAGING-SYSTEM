import struct
from typing import Optional
from Constants.protocol_codes import ResponsesCodes


class Response:
    """
    Base class for handling various types of responses.
    """

    def __init__(self, version: int, code: int, payload: Optional[bytes] = None):
        """
        Initialize a Response object.
        param version: Protocol version.
        param code: Response code.
        param payload: Optional payload data.
        """
        self.version = version
        self.code = code
        self.payload = payload or b""
        self.payload_size = len(self.payload)

    @classmethod
    def from_bytes(cls, payload: bytes, offset: int, size_of_bytes: int) -> tuple:
        """
        Extracts bytes from the payload using a given offset and size.
        param payload: The binary data to extract from.
        param offset: The starting position in the payload.
        param size_of_bytes: Number of bytes to read.
        return: A tuple of extracted bytes.
        """
        return struct.unpack_from(f"<{size_of_bytes}B", payload, offset)

    @classmethod
    def create_response(cls, header: bytes, payload: Optional[bytes]) -> 'Response':
        """
        Dynamically create a response object based on the response code.
        param header: The header containing the response code and version.
        param payload: Optional payload data.
        return: An appropriate subclass of Response based on the response code.
        """
        version = cls.from_bytes(header, 0, 1)[0]
        code = struct.unpack_from('<H', header, 1)[0]

        # Map response codes to response classes
        response_classes = {
            ResponsesCodes.REGISTRATION_SUCCESS: RegisterSuccessResponse,
            ResponsesCodes.REGISTRATION_FAILURE: ErrorResponse,
            ResponsesCodes.MESSAGES_SERVERS_LIST: PayloadReceivedResponse,
            ResponsesCodes.SYMMETRIC_KEY_REQUEST: SymmetricKeyResponse,
            ResponsesCodes.SYMMETRIC_KEY_CONFIRMATION: ConfirmationReceivingSymmetricKey,
            ResponsesCodes.MESSAGE_CONFIRMATION: MessageSendingConfirmation,
        }

        response_class = response_classes.get(code, Response)
        return response_class(version, code, payload)

    def to_bytes(self) -> bytes:
        """
        Convert the response to its byte representation.
        :return: A binary representation of the response.
        """
        header = struct.pack("<BH", self.version, self.code)
        return header + self.payload

    def get_code(self) -> int:
        """
        Retrieve the response code.
        :return: The response code as an integer.
        """
        return self.code


class ErrorResponse(Response):
    """
    Handles error responses.
    """

    def __init__(self, version: int, code: int, payload: Optional[bytes] = None):
        super().__init__(version, code, payload)
        print("Failure to register")


class RegisterSuccessResponse(Response):
    """
    Handles successful registration responses.
    """

    def __init__(self, version: int, code: int, payload: bytes):
        super().__init__(version, code, payload)
        self.client_id = payload[16:]  # Extract client ID from the payload.
        print("Registration success")


class PayloadReceivedResponse(Response):
    """
    Handles responses with received payloads.
    """

    def __init__(self, version: int, code: int, payload: bytes):
        super().__init__(version, code, payload)


class SymmetricKeyResponse(Response):
    """
    Handles responses related to symmetric key exchange.
    """

    def __init__(self, version: int, code: int, payload: bytes):
        client_id = payload[:16]  # Extract client ID from the payload.
        updated_payload = client_id + payload
        super().__init__(version, code, updated_payload)
        print("Symmetric key response")


class ConfirmationReceivingSymmetricKey(Response):
    """
    Handles confirmation of receiving a symmetric key.
    """

    def __init__(self, version: int, code: int, payload: bytes):
        super().__init__(version, code, payload)
        print("Confirmation of receiving a symmetric key")


class MessageSendingConfirmation(Response):
    """
    Handles confirmation of successfully sent messages.
    """

    def __init__(self, version: int, code: int, payload: Optional[bytes] = None):
        super().__init__(version, code, payload)
        print("Message sent successfully!")
