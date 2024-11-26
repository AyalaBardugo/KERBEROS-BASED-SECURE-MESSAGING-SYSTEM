import struct


class Response:
    def __init__(self, version, code, payload_size, payload):

        # Convert code to integer explicitly before packing
        code = int(code)

        self.stream = bytearray(payload_size)
        struct.pack_into("B", self.stream, 0, version)
        struct.pack_into("H", self.stream, 1, code)
        struct.pack_into("I", self.stream, 3, payload_size - 7)
        if payload is not None:
            self.stream[7:] = payload

