from typing import Union
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


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


def aes_encrypt(iv: bytes, key: bytes, message: Union[str, bytes]) -> bytes:
    """
    Encrypt a message using AES encryption.

    Args:
        iv (bytes): The initialization vector.
        key (bytes): The encryption key.
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
