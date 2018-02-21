#!/usr/bin/env python3
# coding=utf-8
"""
This is a simple example of using the cryptography module to securely encrypt and decrypt data to and from files using
AES in GCM mode.

GCM (Galois Counter Mode) is a mode of operation for block ciphers. An AEAD (authenticated
encryption with additional data) mode is a type of block cipher mode that simultaneously encrypts
the message as well as authenticating it. Additional unencrypted data may also be authenticated.
Additional means of verifying integrity such as HMAC are not necessary.

NOTE: There is a better way to do AES-GCM in Cryptography version 2.0 or newer using the AES-GCM construction which is
composed of the AES block cipher utilizing GCM mode.  This should be compatible with Cryptograhpy 1.7 or newer.

This is intended to be used in conjunction with teh "aesgcm_file.c" example code for demonstrating interoperability
between Python's Cryptography module and the mbed TLS C library for AES-256 in GCM mode.
"""
import os
import sys

import colorama
from colorama import Fore

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MODE_ENCRYPT = 0
MODE_DECRYPT = 1

IV_BYTES = 12
TAG_BYTES = 16


def encrypt(key: bytes, iv: bytes, plaintext: bytes, associated_data: bytes) -> (bytes, bytes):
    """Perform AES-256 encryption in GCM mode"""
    # Construct an AES-GCM Cipher object with the given key and a randomly generated nonce.
    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend()).encryptor()

    # associated_data will be authenticated but not encrypted, it must also be passed in on decryption.
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext and get the associated ciphertext.  GCM does not require padding.
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Cryptography will generate a 128-bit tag when finalizing encryption.  This tag is authenticated when decrypting.
    return ciphertext, encryptor.tag


def decrypt(key: bytes, iv: bytes, ciphertext: bytes, associated_data: bytes, tag: bytes) -> bytes:
    """Perform AES-256 decryption in GCM mode"""
    # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message.
    decryptor = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend()).decryptor()

    # We put associated_data back in or the tag will fail to verify when we finalize the decryptor.
    decryptor.authenticate_additional_data(associated_data)

    # Decryption gets us the authenticated plaintext. If the tag does not match an InvalidTag exception will be raised.
    return decryptor.update(ciphertext) + decryptor.finalize()


USAGE = """Usage:
    {0} <mode> <input filename> <output filename> <key> <additional data>

Where:            
    <mode>: 0 = encrypt, 1 = decrypt

Example:
    {0} 0 plain.txt cipher.txt hex:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF "add data"
""".format(sys.argv[0])


def print_usage() -> None:
    """Display intended command-line usage"""
    print(Fore.CYAN + USAGE)


if __name__ == '__main__':
    colorama.init(autoreset=True)

    # Parse the command-line arguments
    expected_args = 5
    if len(sys.argv) != expected_args + 1:
        print(Fore.RED + 'Expected {} arguments, but got {}'.format(expected_args, len(sys.argv) - 1))
        print_usage()
        sys.exit(1)

    # Are we encrypting or decrypting?
    mode = int(sys.argv[1])
    if mode != MODE_ENCRYPT and mode != MODE_DECRYPT:
        print(Fore.RED + 'invalid operation mode')
        sys.exit(2)

    # Input and output filenames are required to be different
    if sys.argv[2] == sys.argv[3]:
        print(Fore.RED + 'input and output filenames must differ')
        sys.exit(3)
    in_file = os.path.expanduser(sys.argv[2])
    out_file = os.path.expanduser(sys.argv[3])

    # Make sure input file exists and is a file
    if not os.path.isfile(in_file):
        print(Fore.RED + "input file {!r} doesn't exist or isn't a directory".format(in_file))

    # Make sure output directory is writeable
    out_dir = os.path.dirname(out_file)
    if not os.access(out_dir, os.O_WRONLY):
        print(Fore.RED + "output directory {!r} isn't writeable".format(out_dir))

    # Read the secret key from command line as hex digits (all caps) prefaced by "hex:"
    if sys.argv[4].startswith('hex:'):
        key = bytes.fromhex(sys.argv[4][4:])
    else:
        print(Fore.RED + 'invalid key format')
        sys.exit(5)

    # Red the additional authenticated but unencrypted data from the command line
    aad = sys.argv[5].encode()

    file_size = os.stat(in_file).st_size

    if mode == MODE_ENCRYPT:
        print(Fore.GREEN + 'Encrypting {} bytes of data in file {!r} output to file {!r}'.format(file_size, in_file,
                                                                                                 out_file))

        # Generate a random 96-bit IV. NIST recommends a 96-bit IV for performance, but can be up to 2^64 - 1 bits
        nonce = os.urandom(IV_BYTES)

        # Read in the plaintext data we want to encrypt from the input file
        with open(in_file, mode='rb') as fin:
            data = fin.read()

        # Encrypt the data
        cipher_text, tag = encrypt(key, nonce, data, aad)

        # Write the IV, ciphertext, and tag to the output file
        with open(out_file, mode='wb') as fout:
            fout.write(nonce)
            fout.write(cipher_text)
            fout.write(tag)
    else:
        if file_size < (IV_BYTES + TAG_BYTES):
            print(Fore.RED + 'File too short to be encrypted')
            sys.exit(6)

        plain_len = file_size - (IV_BYTES + TAG_BYTES)

        print(Fore.GREEN + 'Decrypting {} bytes of ciphertext in file {!r} output to file {!r}'.format(plain_len,
                                                                                                       in_file,
                                                                                                       out_file))

        # Read in the IV, ciphertext, and tag from the encrypted file
        with open(in_file, mode='rb') as fin:
            nonce = fin.read(IV_BYTES)
            data = fin.read()
            cipher_text = data[:-TAG_BYTES]
            tag = data[-TAG_BYTES:]

        # Decrypt the secret message - if GCM fails to authenticate, an InvalidTag exception is raised
        decrypted = decrypt(key, nonce, cipher_text, aad, tag)

        # So the nonce, add, and tag all get sent unencrypted along with the encrypted ciphertext.

        print(Fore.GREEN + 'Decryption successful')

        # Write the decrypted data to the output file
        with open(out_file, mode='wb') as fout:
            fout.write(decrypted)
