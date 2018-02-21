#!/usr/bin/env python3
# coding=utf-8
"""
This is a simple example of doing an elliptic curve Diffie-Hellman ECDH) key exchange.

It allows two parties to jointly agree on a shared secret using an insecure channel.

NOTE: Cryptography version 2.0 in combination with very new versions of OpenSSL support a simpler
interface to use Curve25519 via from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
"""
import os

import colorama
from colorama import Fore
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFHMAC, Mode
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# Choose a particular Elliptic Curve.  In a DH handshake both peers must agree on a common set of parameters.  For
# ECDH, this is equivalent to choosing the same curve.  Curves with a size of less than 224 bits should not be used.
# Generally the NIST prime filed ("P") curves are significantly faster than other types.
CURVE = ec.SECP521R1()

# Choose a key derivation function (KDF)
PBKDF = 'password-based'
KBKDF = 'key-based'
KDF = PBKDF


if __name__ == '__main__':
    colorama.init(autoreset=True)

    # Elliptic Curve common parameters
    curve = CURVE
    backend = default_backend()
    algorithm = ec.ECDH()

    # instance of a HashAlgorithm to use with the kdf
    hash_algo = hashes.SHA512()

    print(Fore.CYAN + 'Using Elliptic Curve {!r} with {}-bit key size and {} KDF ({} hmac)\n'.format(curve.name,
                                                                                                     curve.key_size,
                                                                                                     KDF,
                                                                                                     hash_algo.name))

    # Encoding for serialized public and private keys
    ser_encoding = serialization.Encoding.DER

    # Serialization encoding and format for the public keys
    pub_format = serialization.PublicFormat.SubjectPublicKeyInfo

    # Serialization format for the private keys
    pri_format = serialization.PrivateFormat.PKCS8
    pri_encrypt = serialization.BestAvailableEncryption(b'password')

    # Generate Alice's private key for use in the exchange
    # NOTE: Private keys can be loaded from serialized format using functions like serialization.load_pem_private_key()
    alice_private = ec.generate_private_key(curve, backend)

    # Get Alice's public key to pass to Bob
    alice_public = alice_private.public_key()

    # Serialize Alice's public key to DER format to pass it to Bob
    alice_pub_serialized = alice_public.public_bytes(ser_encoding, pub_format)

    # In a real handshake the peer public key (bob_public) will be received from the other party.  For this example
    # we'll generate it here.  In a real handshake a function such as serialization.load_pem_public_key() would be used.
    bob_private = ec.generate_private_key(curve, backend)
    bob_public = bob_private.public_key()
    bob_pub_serialized = bob_public.public_bytes(ser_encoding, pub_format)

    # Alice reconstructs Bob's public key given the serialized format she is passed
    alice_copy_bob_public = serialization.load_der_public_key(bob_pub_serialized, backend)
    assert alice_copy_bob_public.public_bytes(ser_encoding, pub_format) == bob_pub_serialized

    # Bob reconstructs Alice's public key given the serialized format he is passed
    bob_copy_alice_public = serialization.load_der_public_key(alice_pub_serialized, backend)
    assert bob_copy_alice_public.public_bytes(ser_encoding, pub_format) == alice_pub_serialized

    # Generate shared secret from Alice's perspective given her private key and Bob's public key
    alice_shared = alice_private.exchange(algorithm, alice_copy_bob_public)

    # Generate shared secret from Bob's perspective given his private key and Alice's public key
    bob_shared = bob_private.exchange(algorithm, bob_copy_alice_public)

    # Print out the private keys
    print('Alice private key:\n{}\n'.format(alice_private.private_bytes(ser_encoding, pri_format, pri_encrypt)))
    print('Bob private key:\n{}\n'.format(bob_private.private_bytes(ser_encoding, pri_format, pri_encrypt)))

    # Print out the public keys
    print('Alice public key:\n{}\n'.format(alice_pub_serialized))
    print('Bob public key:\n{}\n'.format(bob_pub_serialized))

    # Print out the shared secret key to make sure it matches
    print(Fore.LIGHTBLUE_EX + 'Alice shared secret ({} bits): {}'.format(len(alice_shared) * 8,
                                                                         alice_shared.hex().upper()))
    print(Fore.LIGHTBLUE_EX + '  Bob shared secret ({} bits): {}'.format(len(bob_shared) * 8,
                                                                         bob_shared.hex().upper()))

    # The shared secret should be passed to a key derivation function to generate the shared symmetric cipher key
    if KDF == PBKDF:
        # The PBKDF2 (Password Based Key Derivation Function 2) is part of RSA Laboratories' Public-Key Cryptography
        # Standards (PKCS) series, specifically PKCS #5 v2.0, also published as Internet Engineering Task Force's
        # RFC 2898.  It is available in most cryptographic libraries.

        # Salts should be randomly generated
        salt = os.urandom(16)
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
    derived_key = kdf.derive(alice_shared)

    # Make sure shared keys agree
    if alice_shared == bob_shared:
        print(Fore.GREEN + '\nDerived AES key ({} bits): {}'.format(len(derived_key) * 8, derived_key.hex().upper()))
    else:
        print(Fore.RED + "\nERROR: Shared secrets don't match!")

