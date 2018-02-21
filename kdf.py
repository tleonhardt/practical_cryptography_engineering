#!/usr/bin/env python3
# coding=utf-8
"""
This is a simple example of doing an elliptic curve Diffie-Hellman ECDH) key exchange.

It allows two parties to jointly agree on a shared secret using an insecure channel.

NOTE: Cryptography version 2.0 in combination with very new versions of OpenSSL support a simpler
interface to use Curve25519 via from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
"""
import sys

import colorama
from colorama import Fore
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Choose a key derivation function (KDF)
PBKDF = 'password-based'
KBKDF = 'key-based'
KDF = PBKDF

USAGE = """Usage:
    {0} <password> <salt>

Example:
    {0} 1337P@ssw0rd hex:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
""".format(sys.argv[0])


def print_usage() -> None:
    """Display intended command-line usage"""
    print(Fore.CYAN + USAGE)


if __name__ == '__main__':
    colorama.init(autoreset=True)

    # Parse the command-line arguments
    expected_args = 2
    if len(sys.argv) != expected_args + 1:
        print(Fore.RED + 'Expected {} arguments, but got {}'.format(expected_args, len(sys.argv) - 1))
        print_usage()
        sys.exit(1)

    # Read the password
    password = sys.argv[1].encode()

    # Read the salt from command line as hex digits (all caps) prefaced by "hex:"
    if sys.argv[2].startswith('hex:'):
        salt = bytes.fromhex(sys.argv[2][4:])
    else:
        print(Fore.RED + 'invalid salt format')
        sys.exit(2)

    # cryptography backend (i.e. OpenSSL)
    backend = default_backend()

    # instance of a HashAlgorithm to use with the kdf
    hash_algo = hashes.SHA512()

    print(Fore.CYAN + 'Using {} Key Derivation Function (KDF) with {} hash algorithm \n'.format(KDF, hash_algo.name))
    print(Fore.LIGHTMAGENTA_EX + 'Password: {!r}'.format(password.decode()))
    print(Fore.LIGHTBLUE_EX + 'Salt: {!r}'.format(salt.hex().upper()))

    # Derive a key using a Key Derivation Function (KDF)
    if KDF == PBKDF:
        # The PBKDF2 (Password Based Key Derivation Function 2) is part of RSA Laboratories' Public-Key Cryptography
        # Standards (PKCS) series, specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's
        # RFC 2898.  It is available in most cryptographic libraries.

        # Salts should be randomly generated
        kdf = PBKDF2HMAC(algorithm=hash_algo,   # An instance of HashAlgorithm
                         length=32,             # The desired length of the derived key in bytes
                         salt=salt,             # A salt. Secure values are 128-bits (16 bytes) or longer
                         iterations=100000,     # The number of iterations to perform of the hash function
                         backend=backend)       # An instance of PBKDF2HMACBackend
    else:

        # The KBKDF (Key Based Key Derivation Function) used here is defined by the NIST SP 800-108 document, to be used
        # to derive additional keys from a key that has been established through an automated key-establishment scheme
        label = b'KBKDF HMAC Label'
        context = b'KBKDF HMAC Context'
        kdf = KBKDFHMAC(algorithm=hash_algo,    # An instance of HashAlgorithm
                        mode=Mode.CounterMode,  # The desired mode of the PRF.A value from the Mode enum
                        length=32,              # The desired length of the derived key in bytes
                        rlen=4,                 # An integer that indicates the length of the counter in bytes
                        llen=4,                 # An integer that indicates the length of the length in bytes
                        location=CounterLocation.BeforeFixed,   # The desired location of the counter
                        label=label,            # Application specific label information.  Byte string or None
                        context=context,        # Application specific context information.  Byte string or None
                        fixed=None,             # Instead of specifying label and context, supply your own fixed data
                        backend=backend)        # A cryptography backend HashBackend instance

    # Derive a new key from the shared secret
    derived_key = kdf.derive(password)

    # Make sure shared keys agree
    print(Fore.GREEN + '\nDerived AES key ({} bits): {}'.format(len(derived_key) * 8, derived_key.hex().upper()))
