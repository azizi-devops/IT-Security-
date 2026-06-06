import struct


def read_kdbx_header(filename):
    with open(filename, "rb") as f:

        sig1 = struct.unpack("<I", f.read(4))[0]
        sig2 = struct.unpack("<I", f.read(4))[0]
        version = struct.unpack("<I", f.read(4))[0]

        if sig1 != 0x9AA2D903 or sig2 != 0xB54BFB67:
            raise ValueError("Not a KeePass KDBX file")

        header = {}

        while True:
            field_id = f.read(1)[0]
            field_length = struct.unpack("<H", f.read(2))[0]
            field_data = f.read(field_length)

            header[field_id] = field_data

            if field_id == 0:
                break

        encrypted_data = f.read()

    return header, encrypted_data