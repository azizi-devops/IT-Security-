<<<<<<< HEAD
import time

=======
>>>>>>> 24134dcbd09f1df1c27f7265ff911b8f6534eadd
from key_derivation import derive_key
from decryptor import decrypt_database, is_correct_password


def generate_passwords():
    for length in range(1, 5):
        for number in range(10 ** length):
            yield str(number).zfill(length)


def brute_force_password(master_seed, transform_seed, transform_rounds, iv, stream_start_bytes, encrypted_data):
<<<<<<< HEAD
    tested = 0
    start = time.time()

    for i, password in enumerate(generate_passwords()):
        tested += 1

=======
    for i, password in enumerate(generate_passwords()):
>>>>>>> 24134dcbd09f1df1c27f7265ff911b8f6534eadd
        if i % 100 == 0:
            print("Trying:", password)

        key = derive_key(password, master_seed, transform_seed, transform_rounds)
        plaintext = decrypt_database(encrypted_data, key, iv)

        if is_correct_password(plaintext, stream_start_bytes):
<<<<<<< HEAD
            end = time.time()
            elapsed = end - start
            speed = tested / elapsed

            print("Found password:", password)
            print("Tested passwords:", tested)
            print(f"Time: {elapsed:.2f} seconds")
            print(f"Passwords per second: {speed:.2f}")

            return password

    end = time.time()
    elapsed = end - start
    speed = tested / elapsed if elapsed > 0 else 0

    print("Password not found")
    print("Tested passwords:", tested)
    print(f"Time: {elapsed:.2f} seconds")
    print(f"Passwords per second: {speed:.2f}")

=======
            return password

>>>>>>> 24134dcbd09f1df1c27f7265ff911b8f6534eadd
    return None