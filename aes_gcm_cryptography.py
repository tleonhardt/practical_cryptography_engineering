#!/usr/bin/env python3
# coding=utf-8
"""
This is a simple example of using the cryptography module to securely encrypt and decrypt data with
AES in GCM mode.

GCM (Galois Counter Mode) is a mode of operation for block ciphers. An AEAD (authenticated
encryption with additional data) mode is a type of block cipher mode that simultaneously encrypts
the message as awell as authenticating it. Additional unencrypted data may also be authenticated.
Additional means of verifying integrity such as HMAC are not necessary.

NOTE: There is a better way to do AES-GCM in Cryptography version 2.0 or newer using the AES-GCM construction which is
composed of the AES block cipher utilizing GCM mode.  This version is intended to be compatible with version 1.7
or newer of the Cryptography module.
"""
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def encrypt(key: bytes, iv: bytes, plaintext: bytes, associated_data: bytes) -> (bytes, bytes):
    # Construct an AES-GCM Cipher object with the given key and a randomly generated nonce.
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

    # associated_data will be authenticated but not encrypted, it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.  GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Cryptography will generate a 128-bit tag when finalizing encryption.  This tag is authenticated when decrypting.
    return ciphertext, encryptor.tag


def decrypt(key: bytes, iv: bytes, ciphertext: bytes, associated_data: bytes, tag: bytes) -> bytes:
    # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message.
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

    # We put associated_data back in or the tag will fail to verify when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext. If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


if __name__ == '__main__':
    # The message we which to transmit in a secret fashion
    data = b"a secret message!"

    # Associated data which will be authenticated but not encrypted (must be passed into both encrypt and decrypt)
    aad = b"authenticated but not encrypted payload"

    # Generate a random 256-bit key which must be kept secret
    key = os.urandom(32)

    # Generate a random 96-bit nonce. NIST recommends a 96-bit IV length for performance, but can be up to 2^64 - 1 bits
    nonce = os.urandom(12)

    # Encrypt a secret message
    cipher_text, tag = encrypt(key, nonce, data, aad)

    # Decrypt the secret message - if GCM fails to authenticate, an InvalidTag exception is raised
    decrypted = decrypt(key, nonce, cipher_text, aad, tag)

    # So the nonce, add, and tag all get sent unencrypted along with the encrypted ciphertext.

    print('plain text: {!r}'.format(data))
    print('ciphertext: {!r}'.format(cipher_text))
    print('decrypted : {!r}'.format(decrypted))
