#!/usr/bin/env python3
# coding=utf-8
"""
Generates a random ed25519 SigningKey/VerifyingKey key pair for use with a digital signature system using PyNaCl
"""
import sys

import colorama
from colorama import Fore
from nacl.encoding import HexEncoder, RawEncoder
from nacl.signing import SigningKey


if __name__ == '__main__':
    colorama.init(autoreset=True)

    expected_args = 2
    received_args = len(sys.argv) - 1
    if received_args != expected_args:
        print(Fore.RED + 'require {} argument, but received {}'.format(expected_args, received_args))
        print(Fore.CYAN + 'USAGE:  {} <private_keyfile> <public_keyfile>'.format(sys.argv[0]))
        sys.exit(1)

    private_filename = sys.argv[1]
    public_filename = sys.argv[2]

    # Generate a new random private SigningKey for producing digital signatures using the Ed25519 algorithm
    signing_key = SigningKey.generate()

    # Extract the public VerifyingKey counterpart for verifying digital signatures created with the SigningKey
    verify_key = signing_key.verify_key

    # Serialize the signing  and verify keys to raw bytes for archival storage
    signing_bytes = signing_key.encode(encoder=RawEncoder)
    verify_bytes = verify_key.encode(encoder=RawEncoder)

    # Save the private Signing key to a file
    with open(private_filename, 'wb') as private_file:
        # Saves 32 bytes of binary data (signing key) to a file
        private_file.write(signing_bytes)

    # Save the public Verifying key to a file
    with open(public_filename, 'wb') as public_file:
        # Saves 32 bytes of binary data (verify key) to a file
        public_file.write(verify_bytes)

    # Serialize the signing  and verify keys to  hexadecimal for display on stdout
    signing_hex = signing_key.encode(encoder=HexEncoder)
    verify_hex = verify_key.encode(encoder=HexEncoder)

    # Print out the public Verifying key
    print(Fore.GREEN + 'the  public key is ({} bytes): {}'.format(len(verify_bytes), verify_hex))

    # Print out the private Signing key
    print(Fore.YELLOW + 'the private key is ({} bytes): {}'.format(len(signing_bytes), signing_hex))
