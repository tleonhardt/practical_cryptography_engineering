#!/usr/bin/env python3
# coding=utf-8
"""
Uses PyNaCl  to verify an ed25519 signature for a specific message
"""
import sys

import colorama
from colorama import Fore
from nacl.encoding import HexEncoder, RawEncoder
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey


if __name__ == '__main__':
    colorama.init(autoreset=True)

    expected_args = 2
    received_args = len(sys.argv) - 1
    if received_args != expected_args:
        print(Fore.RED + 'require {} arguments, but received {}'.format(expected_args, received_args))
        print(Fore.CYAN + 'USAGE:  {} <public_keyfile> <signature_file>'.format(sys.argv[0]))
        sys.exit(1)

    key_filename = sys.argv[1]
    sig_filename = sys.argv[2]

    # Open the public key file and read in the VerifyKey bytes
    with open(key_filename, 'rb') as key_file:
        keydata_bytes = key_file.read()

    # Reconstruct the VerifyKey instance from the serialized form
    verify_key = VerifyKey(keydata_bytes, encoder=RawEncoder)

    # Print out the public Verifying key
    verify_hex = verify_key.encode(encoder=HexEncoder)
    print(Fore.LIGHTBLUE_EX + 'the public key is {}'.format(verify_hex))

    # Open the signature file and read the signature which also contains the original message
    with open(sig_filename, 'rb') as sig_file:
        sig = sig_file.read()

    # Check the validity of a message's signature
    try:
        # Will raise nacl.exceptions.BadSignatureError if the signature check fails
        verify_key.verify(sig)
        print(Fore.GREEN + "signature is good")
    except BadSignatureError as err:
        print(Fore.RED + "signature is bad: {}".format(err))
