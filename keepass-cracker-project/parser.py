import struct
<<<<<<< HEAD
import sys
import time
from itertools import product
from Crypto.Cipher import AES
from Crypto.Hash import SHA256



def read_kdbx_header(filename):
    """
    analyze the KeePass kdbx file header to find important parameters
    and the encrypted data.
    """
    with open(filename, 'rb') as f:
        # read and check file signatures
        s1 = f.read(4)
        s2 = f.read(4)
        version = f.read(4)

        # KeePass 2 signature : 0x9AA2D903 and 0xB54BFB67 (in little-endian order)
        if s1 != b'\x03\xd9\xa2\x9a' or s2 != b'\x67\xfb\x4b\xb5':
            raise ValueError("This is not a KeePass 2 kdbx file")

        headers = {}
        while True:
            field_id_bytes = f.read(1)
            if not field_id_bytes:
                break
            field_id = field_id_bytes[0]

            # read field length (2 bytes, little-endian)
            field_len = struct.unpack('<H', f.read(2))[0]
            field_data = f.read(field_len)

            headers[field_id] = field_data
            if field_id == 0:  # End of header
                break

        # the encrypted data stream starts direct after the end-of-header field
        encrypted_data = f.read()
        return headers, encrypted_data


def test_password(password_str, headers, encrypted_data):

    """
      derive the  key according Appendix A.1 and validate it according  Appendix A.2.
    """
    master_seed = headers[4]
    transform_seed = headers[5]

    # first check if transform_rounds is packed as a 4-byte or 8-byte integer
    rounds_data = headers[6]

    if len(rounds_data) == 4:
        transform_rounds = struct.unpack('<I', rounds_data)[0]
    else:
        transform_rounds = struct.unpack('<Q', rounds_data)[0]

    iv = headers[7]
    stream_start_bytes = headers[9]

    # Step 1 : compute initial credentials = SHA-256(SHA-256(password))
    pass_to_bytes = password_str.encode('utf-8')
    first_hash = SHA256.new(pass_to_bytes).digest()
    credentials = SHA256.new(first_hash).digest()  # exactly 32 bytes

    # Step 2 : we transform Key with AES-256 ECB mode with 'transform_rounds' iterations
    # credentials is 32 bytes and ECB mode encrypts two blocks (2 * 16 byte) independently.
    cipher_ecb = AES.new(transform_seed, AES.MODE_ECB)
    current = credentials
    for _ in range(transform_rounds):
        current = cipher_ecb.encrypt(current)

    transformed_credentials = SHA256.new(current).digest()

    # Step 3: derive final AES  key to decrypt data that come after header
    final_key = SHA256.new(master_seed + transformed_credentials).digest()

    # Step 4: decryption of the first 32 bytes
    cipher_cbc = AES.new(final_key, AES.MODE_CBC, iv=iv)
    decrypted_start = cipher_cbc.decrypt(encrypted_data[:32])

    # If the decrypted bytes is same stream start bytes in header , then password is correct
    return decrypted_start == stream_start_bytes


def brute_force(filename):
    print(f"[*] analyze database file: {filename}...")
    try:
        headers, encrypted_data = read_kdbx_header(filename)
    except ValueError as e:
        print(e)
        return

    # Check all important header fields if exit

    if 4 not in headers:
        print("Master Seed missing")
        return

    if 5 not in headers:
        print("Transform Seed missing")
        return

    if 6 not in headers:
        print("Transform Rounds missing")
        return

    if 7 not in headers:
        print("IV missing")
        return

    if 9 not in headers:
        print("Stream Start Bytes missing")
        return

    print(" start brute-force attack ...")

    start_time = time.time()
    tested_passwords = 0

    # generate password from length 1 to 4
    def found_password(candidate):
        end_time = time.time()

        time_to_find = end_time - start_time
        speed = tested_passwords / time_to_find

        print(f"\n[+] SUCCESS! Password found: {candidate}")
        print(f"Tested passwords : {tested_passwords}")
        print(f"Time : {time_to_find:.2f} seconds")
        print(f"Passwords/second : {speed:.2f}")

        return candidate

    for n in range(1, 5):
        counter=n
        for digit_1 in range(0, 10):
            if n == 1:
                if counter == n:
                 print(f"[*] Checking passwords of length {n}...")
                 counter+=1
                tested_passwords += 1
                candidate = f"{digit_1}"
                if test_password(candidate, headers, encrypted_data):
                    return found_password(candidate)


            elif n == 2:
                if counter == n:
                 print(f"[*] Checking passwords of length {n}...")
                 counter+=1
                for digit_2 in range(0, 10):
                    tested_passwords += 1
                    candidate = f"{digit_1}{digit_2}"
                    if test_password(candidate, headers, encrypted_data):
                        return found_password(candidate)

            elif n == 3:
                if counter == n:
                 print(f"[*] Checking passwords of length {n}...")
                 counter+=1
                for digit_2 in range(0, 10):
                    for digit_3 in range(0, 10):
                        tested_passwords += 1
                        candidate = f"{digit_1}{digit_2}{digit_3}"
                        if test_password(candidate, headers, encrypted_data):
                            return found_password(candidate)

            elif n == 4:
                if counter == n:
                 print(f"[*] Checking passwords of length {n}...")
                 counter+=1
                for digit_2 in range(0, 10):
                    for digit_3 in range(0, 10):
                        for digit_4 in range(0, 10):
                            tested_passwords += 1
                            candidate = f"{digit_1}{digit_2}{digit_3}{digit_4}"
                            if test_password(candidate, headers, encrypted_data):
                                return found_password(candidate)

    print("\n[-] brute-force_attack finished. No valid password found.")
    end_time = time.time()

    passed_time = end_time - start_time
    speed = tested_passwords / passed_time

    print(f"Tested passwords : {tested_passwords}")
    print(f"Time             : {passed_time:.2f} seconds")
    print(f"Passwords/second : {speed:.2f}")
    return None


if __name__ == "__main__":
    # the file that we want to find its password (Azizishk.kdbx)
    database_file = "Azizishk.kdbx"
    brute_force(database_file)
=======


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
>>>>>>> 24134dcbd09f1df1c27f7265ff911b8f6534eadd
