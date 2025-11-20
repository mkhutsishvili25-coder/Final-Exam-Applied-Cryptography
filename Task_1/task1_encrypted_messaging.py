"""
Task 1 – Encrypted Messaging App Prototype
Hybrid RSA + AES messaging

Deliverables:
- message.txt
- encrypted_message.bin
- aes_key_encrypted.bin
- decrypted_message.txt
- userA_public.pem, userA_private.pem (for clarity)
"""

import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# ---------------- RSA KEY UTILS ---------------- #

def generate_rsa_keypair(private_path="userA_private.pem", public_path="userA_public.pem"):
    if os.path.exists(private_path) and os.path.exists(public_path):
        return  # already exist

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Save private key
    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    # Save public key
    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_private_key(path="userA_private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_public_key(path="userA_public.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


# ---------------- AES UTILS ---------------- #

def aes_encrypt(plaintext: bytes, key: bytes):
    """
    AES-256-CBC with PKCS7 padding.
    We prepend IV to ciphertext for storage.
    """
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()  # block size 128 bits
    padded_data = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext  # IV || ciphertext


def aes_decrypt(iv_and_ciphertext: bytes, key: bytes):
    iv = iv_and_ciphertext[:16]
    ciphertext = iv_and_ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# ---------------- MAIN LOGIC ---------------- #

def main():
    # 1. Ensure RSA keys exist (User A)
    generate_rsa_keypair()

    # 2. Ensure message.txt exists
    if not os.path.exists("message.txt"):
        with open("message.txt", "w", encoding="utf-8") as f:
            f.write("Hello from User B to User A using hybrid RSA + AES!")

    with open("message.txt", "r", encoding="utf-8") as f:
        message = f.read().encode("utf-8")

    # 3. User B encrypts the message
    aes_key = os.urandom(32)  # AES-256 key
    encrypted_message = aes_encrypt(message, aes_key)
    with open("encrypted_message.bin", "wb") as f:
        f.write(encrypted_message)

    # Encrypt AES key with User A's public RSA key
    public_key = load_public_key()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open("aes_key_encrypted.bin", "wb") as f:
        f.write(encrypted_aes_key)

    # 4. User A decrypts
    private_key = load_private_key()

    with open("aes_key_encrypted.bin", "rb") as f:
        enc_key = f.read()
    decrypted_aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("encrypted_message.bin", "rb") as f:
        enc_msg = f.read()
    decrypted_message = aes_decrypt(enc_msg, decrypted_aes_key)

    with open("decrypted_message.txt", "w", encoding="utf-8") as f:
        f.write(decrypted_message.decode("utf-8"))

    print("Task 1 complete.")
    print("Check message.txt and decrypted_message.txt – they should match.")


if __name__ == "__main__":
    main()
