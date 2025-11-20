"""
Task 2 – Secure File Exchange Using RSA + AES

Deliverables:
- alice_message.txt
- encrypted_file.bin
- aes_key_encrypted.bin
- decrypted_message.txt
- public.pem, private.pem
- original_hash.txt (helper for hash comparison)
"""

import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend


# ------------ RSA KEY UTILS (BOB) ------------ #

def generate_bob_keypair(private_path="private.pem", public_path="public.pem"):
    if os.path.exists(private_path) and os.path.exists(public_path):
        return

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    with open(private_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    public_key = private_key.public_key()
    with open(public_path, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )


def load_bob_private_key(path="private.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())


def load_bob_public_key(path="public.pem"):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


# ------------ AES UTILS ------------ #

def aes_encrypt_file(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return iv + ciphertext


def aes_decrypt_file(iv_and_cipher: bytes, key: bytes) -> bytes:
    iv = iv_and_cipher[:16]
    ciphertext = iv_and_cipher[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    # 1. Generate Bob's RSA key pair
    generate_bob_keypair()

    # 2. Ensure alice_message.txt exists
    if not os.path.exists("alice_message.txt"):
        with open("alice_message.txt", "w", encoding="utf-8") as f:
            f.write("Secret message from Alice to Bob using hybrid encryption.")

    # 3. Compute original SHA-256 hash and store
    original_hash = sha256_file("alice_message.txt")
    with open("original_hash.txt", "w") as f:
        f.write(original_hash)

    # 4. Alice encrypts file using AES-256
    with open("alice_message.txt", "rb") as f:
        plaintext_data = f.read()

    aes_key = os.urandom(32)  # 256-bit key
    encrypted_file = aes_encrypt_file(plaintext_data, aes_key)
    with open("encrypted_file.bin", "wb") as f:
        f.write(encrypted_file)

    # 5. Encrypt AES key with Bob's public RSA key
    public_key = load_bob_public_key()
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

    # 6. Bob decrypts AES key using private key
    private_key = load_bob_private_key()
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

    # 7. Bob decrypts file
    with open("encrypted_file.bin", "rb") as f:
        enc_file_data = f.read()
    decrypted_data = aes_decrypt_file(enc_file_data, decrypted_aes_key)
    with open("decrypted_message.txt", "wb") as f:
        f.write(decrypted_data)

    # 8. Verify integrity via SHA-256
    decrypted_hash = sha256_file("decrypted_message.txt")

    print("Original SHA-256:", original_hash)
    print("Decrypted SHA-256:", decrypted_hash)

    if original_hash == decrypted_hash:
        print("Integrity check: PASS (hashes match)")
    else:
        print("Integrity check: FAIL (hashes differ)")


if __name__ == "__main__":
    main()
