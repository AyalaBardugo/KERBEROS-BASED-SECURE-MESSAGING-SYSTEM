import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import unpad, pad
from typing import Union
from Constants.protocol_sizes import ProtocolSizes as protocolSize


def generate_aes_key() -> bytes:
    """Generate a random AES key.

    Returns:
        bytes: The generated AES key.
    """
    return os.urandom(protocolSize.AES_KEY)


def generate_iv() -> bytes:
    """Generate a random initialization vector (IV).

    Returns:
        bytes: The generated IV.
    """
    return Random.new().read(AES.block_size)


def aes_decrypt(iv: bytes, key: bytes, message: bytes) -> bytes:
    """Decrypt a message using AES CBC mode.

    Args:
        iv (bytes): The initialization vector.
        key (bytes): The AES key.
        message (bytes): The message to decrypt.

    Returns:
        bytes: The decrypted message.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(message), AES.block_size)
    return decrypted


def aes_encrypt(iv: bytes, key: bytes, message: Union[str, bytes]) -> bytes:
    """Encrypt a message using AES CBC mode.

    Args:
        iv (bytes): The initialization vector.
        key (bytes): The AES key.
        message (Union[str, bytes]): The message to encrypt.

    Returns:
        bytes: The encrypted message.
    """
    if isinstance(message, str):
        message = message.encode()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(message, AES.block_size)
    encrypted = cipher.encrypt(padded_data)
    return encrypted
