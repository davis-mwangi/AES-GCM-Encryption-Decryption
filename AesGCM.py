import base64
import hashlib

from Cryptodome.Cipher import AES  # from pycryptodomex v-3.10.4
from Cryptodome.Random import get_random_bytes

HASH_NAME = "SHA256"
IV_LENGTH = 12
ITERATION_COUNT = 65536
KEY_LENGTH = 32
SALT_LENGTH = 16
TAG_LENGTH = 16

"""
used python 3.9 with package pycryptodomex version 3.10.4)
"""

def encrypt(password, plain_message):
    salt = get_random_bytes(SALT_LENGTH)  # Random salt of 16 bytes
    secret = get_secret_key(password, salt)

    iv = get_random_bytes(IV_LENGTH)  # Random IV of 12 bytes
    cipher = AES.new(secret, AES.MODE_GCM, iv)

    encrypted_message_byte, tag = cipher.encrypt_and_digest(plain_message.encode("utf-8"))
    cipher_byte = iv + salt + encrypted_message_byte + tag

    encoded_cipher_byte = base64.b64encode(cipher_byte)
    return bytes.decode(encoded_cipher_byte)


def decrypt(password, cipher_message):
    decoded_cipher_byte = base64.b64decode(cipher_message)

    iv = decoded_cipher_byte[:IV_LENGTH]
    salt = decoded_cipher_byte[IV_LENGTH:(IV_LENGTH + SALT_LENGTH)]
    encrypted_message_byte = decoded_cipher_byte[(IV_LENGTH + SALT_LENGTH):-TAG_LENGTH]
    tag = decoded_cipher_byte[-TAG_LENGTH:]

    secret = get_secret_key(password, salt)
    cipher = AES.new(secret, AES.MODE_GCM, iv)

    decrypted_message_byte = cipher.decrypt_and_verify(encrypted_message_byte, tag)
    return decrypted_message_byte.decode("utf-8")


def get_secret_key(password, salt):
    return hashlib.pbkdf2_hmac(HASH_NAME, password.encode(), salt, ITERATION_COUNT, KEY_LENGTH)


outputFormat = "{:<25}:{}"
secret_key = "yourSecretKey"
plain_text = "M0993000353"

print("------ AES-GCM Encryption ------")
cipher_text = encrypt(secret_key, plain_text)
print(outputFormat.format("encryption input", plain_text))
print(outputFormat.format("encryption output", cipher_text))

decrypted_text = decrypt(secret_key, cipher_text)

print("\n------ AES-GCM Decryption ------")
print(outputFormat.format("decryption input", cipher_text))
print(outputFormat.format("decryption output", decrypted_text))