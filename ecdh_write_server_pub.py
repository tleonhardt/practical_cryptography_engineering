#!/usr/bin/env python3
# coding=utf-8
"""
This is a simple example of doing an elliptic curve Diffie-Hellman ECDH) key exchange.

It allows two parties to jointly agree on a shared secret using an insecure channel.

NOTE: Cryptography version 2.0 in combination with very new versions of OpenSSL support a simpler
interface to use Curve25519 via from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
"""
import colorama
from colorama import Fore
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

# Choose a particular Elliptic Curve.  In a DH handshake both peers must agree on a common set of parameters.  For
# ECDH, this is equivalent to choosing the same curve.  Curves with a size of less than 224 bits should not be used.
# Generally the NIST prime filed ("P") curves are significantly faster than other types.
CURVE = ec.SECP521R1()


if __name__ == '__main__':
    colorama.init(autoreset=True)

    # Elliptic Curve common parameters
    curve = CURVE
    backend = default_backend()

    # Filenames to serialize the public and private keys to
    server_public_filename = 'server_public.xy'
    server_private_filename = 'server_private.der'

    # Serialization encoding, format, and encryption for the private key
    pri_encoding = serialization.Encoding.DER
    pri_format = serialization.PrivateFormat.PKCS8
    pri_encrypt = serialization.NoEncryption()

    print(Fore.CYAN + 'ECDH using Elliptic Curve {!r} with {}-bit key size and {} encoding\n'.format(curve.name,
                                                                                                     curve.key_size,
                                                                                                     pri_encoding.name))

    # Generate server's private key
    # NOTE: Private keys can be loaded from serialized format using functions like serialization.load_pem_private_key()
    server_private = ec.generate_private_key(curve, backend)

    # Get server's public key to pass to client
    server_public = server_private.public_key()

    # Encode the elliptic curve point (public key) to a byte string (X followed by Y, each big endian)
    server_pub_serialized = server_public.public_numbers().encode_point()[1:]

    # Serialize server's private key to DER format
    server_pri_serialized = server_private.private_bytes(pri_encoding, pri_format, pri_encrypt)

    # Print out the server private key
    print(Fore.LIGHTMAGENTA_EX + 'Server private key ({} bytes):\n{}\n'.format(len(server_pri_serialized),
                                                                               server_pri_serialized.hex().upper()))

    # Print out the server public key
    print(Fore.LIGHTGREEN_EX + 'Server public key ({} bytes):\n{}\n'.format(len(server_pub_serialized),
                                                                            server_pub_serialized.hex().upper()))

    # Save data to files
    print('Saving server private key to {!r}'.format(server_private_filename))
    with open(server_private_filename, 'wb') as server_private_file:
        server_private_file.write(server_pri_serialized)

    print('Saving server public key to {!r}'.format(server_public_filename))
    with open(server_public_filename, 'wb') as server_public_file:
        server_public_file.write(server_pub_serialized)
