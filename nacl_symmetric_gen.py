#!/usr/bin/env python3
# coding=utf-8
""" Generates a random 256-bit (32-byte) secret symmetric key using the PyNaCl wrapper around the libsodium C library
 *
 * This key is intended tobe used with libsodium "secretbox" secret-key authenticated encryption routines.
 *
 * These routines use the XSalsa20 stream cipher for encryption and the Poly1305 MAC for authentication
 * in pre-packaged set of routines for doing authenticated encryption using symmetric keys.
 *
 * NOTE: This is NOT an AEAD (Authenticated Encryption with Additional Data) mode because the MAC computation
 * is done over the encrypted ciphertext and does not include any additional data.
 *
 * XSalsa20 is a stream cipher based upon Salsa20 but with a much longer nonce: 192 bits instead of 64 bits.
 *
 * XSalsa20 uses a 256-bit key as well as the first 128 bits of the nonce in order to compute a subkey. This subkey, as
 * well as the remaining 64 bits of the nonce, are the parameters of the Salsa20 function used to actually generate the
 * stream.
 *
 * Like Salsa20, XSalsa20 is immune to timing attacks and provides its own 64-bit block counter to avoid incrementing
 * the nonce after each block. But with XSalsa20's longer nonce, it is safe to generate nonces using randombytes_buf()
 * for every message encrypted with the same key without having to worry about a collision.
"""
import sys

import colorama
from colorama import Fore
from nacl.secret import SecretBox
import nacl.utils


if __name__ == '__main__':
    colorama.init(autoreset=True)

    expected_args = 1
    received_args = len(sys.argv) - 1
    if received_args != expected_args:
        print(Fore.RED + 'require {} argument, but received {}'.format(expected_args, received_args))
        print(Fore.CYAN + 'USAGE:  {} <key_file>'.format(sys.argv[0]))
        sys.exit(1)

    key_filename = sys.argv[1]

    # Generate a new random 256-bit (32 byte) secret symmetric key
    key = nacl.utils.random(SecretBox.KEY_SIZE)

    # Display the key as hexadecimal digits on stdout
    # Print out the public Verifying key
    print(Fore.GREEN + 'Generated a {}-bit secret symmetric key: {}'.format(len(key) * 8, key.hex().upper()))

    # Save the key to a file
    with open(key_filename, 'wb') as key_file:
        # Saves 32 bytes of binary data (signing key) to a file
        key_file.write(key)

    print(Fore.LIGHTBLUE_EX + 'Key saved to {}-byte binary file {!r}'.format(len(key), key_filename))

    # Now go through a full example of encrypting and then decrypting a fixed test message
    # The purpose is twofold:
    #   1) Demonstrate how to properly use the libsodium secretbox API for authenticated encryption
    #   2) Serve as a built-in unit test

    # This an instance of the class which encapsulates the encrypt and decrypt methods
    box = SecretBox(key)

    # This is our message to send, it must be a bytestring as SecretBox will treat it as just a binary blob of data.
    message = b"The president will be exiting through the lower levels"

    # PyNaCl can automatically generate a random nonce for us, making the encryption very simple:
    encrypted = box.encrypt(message)
    # However, if we need to use an explicit nonce, it can be passed along with the message:
    # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    # encrypted = box.encrypt(message, nonce)

    # The encrypted message will be exactly 40 bytes longer than the original message
    #   - It stores authentication information (16 bytes) and the nonce (24 bytes) alongside it

    # Decrypt message - an exception will be raised if the encryption was tampered with or there was otherwise an error
    plaintext = box.decrypt(encrypted)

    # Display everything
    print('Test message: {!r}'.format(message))
    print('Authenticated and authenticated bundle including nonce: {!r}'.format(encrypted.hex().upper()))
    print('Decrypted message: {!r}'.format(plaintext))
