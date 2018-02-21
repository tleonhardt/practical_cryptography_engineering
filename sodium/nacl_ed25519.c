/* Round trip unit test of using libsodiums Ed25519 digtial signature code.
 *
 * 1) Generates a random Ed25519 Secret(signing)/Public(verifying) key pair using libsodium
 * 2) Signs a test message
 * 3) Verifies the signature of this test message
 */

// A project using libsodium should include the sodium.h header.
// Including individual headers from libsodium is neither required nor recommended.
#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;

    // The sodium_init() function should be called before any other function.
    // It is safe to call sodium_init() multiple times, or from different threads; it will
    // immediately return 1 without doing anything if the library has already been initialized.
    // After this function returns, all of the other functions provided by Sodium will be
    // thread-safe.  Before returning, the function ensures that the system's random number
    // generator has been properly seeded.  On some Linux systems, this may take some time,
    // especially when called right after a reboot of the system
    if (sodium_init() < 0)
    {
        /* panic! the library couldn't be initialized, it is not safe to use */
        printf("ERROR: The sodium library couldn't be initialied!\n");
        return EXIT_FAILURE;
    }

    // Buffer to hold the public key (verifying key)
    unsigned char public_key[crypto_sign_PUBLICKEYBYTES];

    // Buffer to hold the secret key (signing key) - has extra info so public key can be derived
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];

    // Buffers to hold hexadecimal encoded versions of the keys (with a null terminator)
    #define PUBLICKEY_HEX_BYTES (2 * crypto_sign_PUBLICKEYBYTES + 1)
    #define SECRETKEY_HEX_BYTES (2 * crypto_sign_SECRETKEYBYTES + 1)
    char hex_public[PUBLICKEY_HEX_BYTES];
    char hex_secret[SECRETKEY_HEX_BYTES];

    // crypto_sign_keypair() function randomly generates a secret key and a corresponding public key
    crypto_sign_keypair(public_key, secret_key);

    // Convert the binary keys into a hexadecimal strings
    sodium_bin2hex(hex_public, PUBLICKEY_HEX_BYTES, public_key, crypto_sign_PUBLICKEYBYTES);
    sodium_bin2hex(hex_secret, SECRETKEY_HEX_BYTES, secret_key, crypto_sign_SECRETKEYBYTES);

    // Print the keys to the screen with hexadecimal encoding
    printf("Generated a signing/verifying key pair:\n");
    printf("\tSecret key: %s\n", hex_secret);
    printf("\tPublic key: %s\n", hex_public);

    // Now go through a full sign and verify process with a dummy message just to make sure it works
    #define MESSAGE (const unsigned char *) "test"
    #define MESSAGE_LEN 4

    unsigned char signed_message[crypto_sign_BYTES + MESSAGE_LEN];
    unsigned long long signed_message_len;

    printf("Signing a test message ...");
    crypto_sign(signed_message, &signed_message_len, MESSAGE, MESSAGE_LEN, secret_key);
    printf(" Done\n");

    unsigned char unsigned_message[MESSAGE_LEN];
    unsigned long long unsigned_message_len;
    printf("Verifying the test signed message ...");
    ret = crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message, signed_message_len, public_key);
    if ( ret != 0)
    {
        printf(" invalid signature");
    }
    else
    {
        printf(" OK\n");
    }

    return ret;
}