from hashlib import sha256
from Crypto.Cipher import AES


def derive_key(password, master_seed, transform_seed, transform_rounds):
    password_bytes = password.encode("utf-8")

    credentials = sha256(sha256(password_bytes).digest()).digest()

    cipher = AES.new(transform_seed, AES.MODE_ECB)

    x = credentials
    for _ in range(transform_rounds):
        x = cipher.encrypt(x)

    transformed_credentials = sha256(x).digest()

    final_key = sha256(master_seed + transformed_credentials).digest()

    return final_key