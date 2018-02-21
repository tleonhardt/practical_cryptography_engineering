/* Generates a random Ed25519 Secret(signing)/Public(verifying) key pair using libsodium
 */

// A project using libsodium should include the sodium.h header.
// Including individual headers from libsodium is neither required nor recommended.
#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    FILE *file_secret = NULL;
    FILE *file_public = NULL;

    // Parse command line arguments
    if( argc != 3 )
    {
        printf( "usage: %s <secret_keyfile> <public_keyfile>\n", argv[0] );
        goto exit;
    }

    char *secret_filename = argv[1];
    char *public_filename = argv[2];

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

    // Buffer to hold the private key (signing key) - has extra info so public key can be derived
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

    // Save the secret key to a binary file
    printf("\nSaving secret key to file '%s' ...", secret_filename);
    file_secret = fopen( secret_filename, "wb+" );
    if(  NULL == file_secret )
    {
        printf( " failed\n  ! Could not create %s\n\n", secret_filename );
        goto exit;
    }

    size_t bytes_written = fwrite( secret_key, 1, crypto_sign_SECRETKEYBYTES, file_secret );
    if( crypto_sign_SECRETKEYBYTES != bytes_written )
    {
        printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    // Save the public key to a binary file
    printf("Saving public key to file '%s' ...", public_filename);
    file_public =fopen( public_filename, "wb+" );
    if(  NULL == file_public )
    {
        printf( " failed\n  ! Could not create %s\n\n", public_filename );
        goto exit;
    }

    bytes_written = fwrite( public_key, 1, crypto_sign_PUBLICKEYBYTES, file_public );
    if( crypto_sign_PUBLICKEYBYTES != bytes_written )
    {
        printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

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
    ret = crypto_sign_open(unsigned_message, &unsigned_message_len, signed_message,
                           signed_message_len, public_key);
    if ( ret != 0)
    {
        printf(" invalid signature");
    }
    printf(" OK\n");

    ret = EXIT_SUCCESS;

exit:
    // Perform any necessary cleanup

    // Close any open file handles
    if( NULL != file_secret )
    {
        fclose( file_secret );
    }
    if( NULL != file_public )
    {
        fclose( file_public );
    }

    // TODO: Zero-out key storage memory


    return ret;
}