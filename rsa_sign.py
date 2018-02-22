#!/usr/bin/env python3
# coding=utf-8
"""
 * RSA signature creation program
 *
 * Usage:
 *     rsa_sig <priv_key> <filename>
 *
 * Where:
 *  - priv_key - is a path to an RSA private key file in PEM or DER format
 *  - filename - is a path to an input file you wish to create an RSA signature for
 *
 * Output:
 *  - filename.sig - signature is saved to filename.sig where "filename" is the complete input filename
 *
 * Notes:
 *  This uses the Probabilistic Signature Scheme (PSS) standardized as part of PKCS#1 v2.1 along with SHA-512 hashes.
"""
import sys

import colorama
from colorama import Fore
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# RSA Padding scheme - PSS (Probabilistic Signature Scheme) should be prefered
# PSS is more complex than PKCS1, but has a security proof
PSS_PADDING = 'PSS'
PKCS1_PADDING = 'PKCS1v15'
# RSA_PADDING = PSS_PADDING
RSA_PADDING = PKCS1_PADDING

USAGE = """Usage:
    {0} <private_keyfile> <file_to_sign>

Example:
    {0} private_key.pem myfile.txt"
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

    # cryptography backend (i.e. OpenSSL)
    backend = default_backend()

    # Load the private key from a PEM file
    print('Reading the private key from {!r}'.format(sys.argv[1]))
    with open(sys.argv[1], 'rb') as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=backend)

    # Read the message we want to sign from the input file
    print('Reading the input file from {!r}'.format(sys.argv[2]))
    with open(sys.argv[2], 'rb') as input_file:
        message = input_file.read()

    # Instantiate an instance of AsymmetricPadding to use
    if RSA_PADDING == PSS_PADDING:
        # PKCS#1 v2.1 probabilistic padding scheme (PSS)
        padding = padding.PSS(mgf=padding.MGF1(hashes.SHA512()),  # A mask generation function object
                              salt_length=padding.PSS.MAX_LENGTH)  # The length of the salt
    else:
        # PKCS1v1.5 deterministic padding
        padding = padding.PKCS1v15()

    # Use the private key to sign the message
    print(Fore.LIGHTBLUE_EX + 'Generating the RSA/SHA-512 signature using {} padding'.format(RSA_PADDING))
    signature = private_key.sign(message,
                                 padding,
                                 hashes.SHA512())

    # Write the signature to a new file named "<input_file>.sig"
    sig_file = sys.argv[2] + '.sig'
    with open(sig_file, 'wb') as signature_file:
        signature_file.write(signature)

    print(Fore.GREEN + '\nDone.  Wrote signature to {!r}'.format(sig_file))
