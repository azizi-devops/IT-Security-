import struct
from parser import read_kdbx_header
from key_derivation import derive_key
from decryptor import decrypt_database, is_correct_password
from brute_force import brute_force_password

filename = "Azizishk.kdbx"

header, encrypted_data = read_kdbx_header(filename)

master_seed = header[4]
transform_seed = header[5]
transform_rounds = struct.unpack("<Q", header[6])[0]
iv = header[7]
stream_start_bytes = header[9]

print("Header parsed successfully")

print("master_seed:", len(master_seed))
print("transform_seed:", len(transform_seed))
print("rounds:", transform_rounds)
print("iv:", len(iv))
print("stream_start_bytes:", len(stream_start_bytes))
print("encrypted:", len(encrypted_data))


test_password = "0000"
key = derive_key(test_password, master_seed, transform_seed, transform_rounds)

print("test password:", test_password)
print("generated key length:", len(key))
print("generated key:", key.hex())

plaintext = decrypt_database(encrypted_data, key, iv)

if is_correct_password(plaintext, stream_start_bytes):
    print("Correct password:", test_password)
else:
    print("Wrong password:", test_password)




found_password = brute_force_password(
    master_seed,
    transform_seed,
    transform_rounds,
    iv,
    stream_start_bytes,
    encrypted_data
)

if found_password:
    print("FOUND PASSWORD:", found_password)
else:
    print("Password not found")
