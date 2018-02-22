#!/usr/bin/env python3
# coding=utf-8
"""
 * RSA signature verification program using Python cryptography module
 *
 * Usage:
 *     rsa_verify <pub_key> <filename>
 *
 * Where:
 *  - pub_key  - is a path to an RSA public key file in PEM or DER format
 *  - filename - is a path to an input file you wish to verify an RSA signature of
 *
 * ASSUMPTION:
 *  - signature has been saved to filename.sig where "filename" is the complete input filename
 *
 * Notes:
 *  This uses the Probabilistic Signature Scheme (PSS) standardized as part of PKCS#1 v2.1 along with SHA-512 hashes.
"""
import sys
import traceback

import colorama
from colorama import Fore
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# RSA Padding scheme - PSS (Probabilistic Signature Scheme) should be prefered
# PSS is more complex than PKCS1, but has a security proof
PSS_PADDING = 'PSS'
PKCS1_PADDING = 'PKCS1v15'
# RSA_PADDING = PSS_PADDING
RSA_PADDING = PKCS1_PADDING

USAGE = """Usage:
    {0} <public_keyfile> <file_to_verify_signature_for>

Example:
    {0} public_key.pem myfile.txt"
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

    # Load the public key from a PEM file
    print('Reading the public key from {!r}'.format(sys.argv[1]))
    with open(sys.argv[1], 'rb') as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=backend)

    # Read the message we want to verify the signature for from the input file
    print('Reading the input message from {!r}'.format(sys.argv[2]))
    with open(sys.argv[2], 'rb') as input_file:
        message = input_file.read()

    # Read the signature from the .sig file
    sig_file = sys.argv[2] + '.sig'
    print('Reading the RSA signature from {!r}'.format(sig_file))
    with open(sig_file, 'rb') as signature_file:
        signature = signature_file.read()

    # Instantiate an instance of AsymmetricPadding to use
    if RSA_PADDING == PSS_PADDING:
        # PKCS#1 v2.1 probabilistic padding sheme (PSS)
        padding = padding.PSS(mgf=padding.MGF1(hashes.SHA512()),    # A mask generation function object
                              salt_length=padding.PSS.MAX_LENGTH)   # The length of the salt
    else:
        # PKCS1v1.5 deterministic padding
        padding = padding.PKCS1v15()

    # Use the public key to verify that the private key associated with it was used to sign that specific message
    print(Fore.LIGHTBLUE_EX + 'Verifying the RSA/SHA-512 signature using {} padding'.format(RSA_PADDING))
    try:
        public_key.verify(signature,
                          message,
                          padding,
                          hashes.SHA512())
    except InvalidSignature as err:
        # If the signature does not match, verify() will raise an InvalidSignature exception
        print(Fore.RED + '\nThe signature does not match!  ERROR - {!r}:'.format(err))
        traceback.print_exc(file=sys.stdout)
    else:
        print(Fore.GREEN + '\nOK (the signature is valid)')
