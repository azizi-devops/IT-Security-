from key_derivation import derive_key
from decryptor import decrypt_database, is_correct_password


def generate_passwords():
    for length in range(1, 5):
        for number in range(10 ** length):
            yield str(number).zfill(length)


def brute_force_password(master_seed, transform_seed, transform_rounds, iv, stream_start_bytes, encrypted_data):
    for i, password in enumerate(generate_passwords()):
        if i % 100 == 0:
            print("Trying:", password)

        key = derive_key(password, master_seed, transform_seed, transform_rounds)
        plaintext = decrypt_database(encrypted_data, key, iv)

        if is_correct_password(plaintext, stream_start_bytes):
            return password

    return None