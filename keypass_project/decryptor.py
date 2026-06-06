from Crypto.Cipher import AES


def decrypt_database(encrypted_data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(encrypted_data)
    return plaintext


def is_correct_password(plaintext, stream_start_bytes):
    return plaintext[:32] == stream_start_bytes