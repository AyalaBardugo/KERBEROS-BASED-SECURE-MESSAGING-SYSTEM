import socket
from threading import Thread
from colorama import Fore, Style
from request import Request
import request as ReqHandler
from server.response import Response
import server.utils as utils
from Constants.protocol_codes import RequestsCodes, ProtocolCodes, ResponsesCodes
from Constants.protocol_sizes import ProtocolSizes
from Constants.utils import Utils


def handle_client(connection: socket.socket, client_address: tuple) -> None:
    """Handles communication with a client.

    Args:
        connection (socket.socket): The socket object representing the connection with the client.
        client_address (tuple): The address of the client.

    """
    print("Establish new connection with client {}".format(client_address))
    request_stream = connection.recv(ProtocolSizes.STREAM_SIZE)
    request = Request(request_stream)
    request_code = request.code

    if request_code == RequestsCodes.CLIENT_REGISTRATION:
        print("Starting Registration Process")
        response, uu = ReqHandler.client_register(request.payload)
        if response is not None:
            connection.send(response.stream)

    if request_code == RequestsCodes.MESSAGES_SERVERS_LIST:
        with open("msg.info", 'r') as file:
            data = file.read()
            ip_port, printer_name, printer_id, aes_key = data.strip().split('\n')
            version = ProtocolCodes.CLIENT_VERSION
            code = ResponsesCodes.MESSAGES_SERVERS_LIST
            payload = f"{ip_port}\n{printer_name}\n{printer_id}\n{aes_key}".encode()
            payload_size = len(payload) + 7
            response = Response(version, code, payload_size, payload)
            connection.send(response.stream)

    if request.code == RequestsCodes.SYMMETRIC_KEY_REQUEST:
        print("Generating Symmetric Key\n")
        response = ReqHandler.generate_symmetric_key_response(request_stream)
        if response is not None:
            connection.send(response.stream)


def start_server(port: int) -> None:
    """Starts the server on the specified port.

    Args:
        port (int): The port number on which the server will listen for incoming connections.

    """
    sock = socket.socket()
    host = Utils.AUTH_SERVER_IP

    sock.bind((host, port))
    sock.listen(5)

    while True:
        print("wait for client...")
        connection, client_address = sock.accept()

        handler = Thread(target=handle_client, args=(connection, client_address))
        handler.start()


def main():
    port = utils.read_port()

    print(Fore.CYAN + Style.BRIGHT + f"Server is listening on {Utils.AUTH_SERVER_IP}:{port}" + Style.RESET_ALL)
    start_server(port)


if __name__ == "__main__":
    main()
