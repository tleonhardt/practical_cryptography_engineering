/* Generates a random 256-bit (32-byte) secret symmetric key using libsodium
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

    // Parse command line arguments
    if( argc != 2 )
    {
        printf( "usage: %s <secret_keyfile>\n", argv[0] );
        goto exit;
    }

    char *secret_filename = argv[1];

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
        printf("ERROR: The sodium library couldn't be initialized!\n");
        return EXIT_FAILURE;
    }

    // Print the sodium version
    printf("Using libsodium version %s\n", sodium_version_string());

    // Buffer to hold the symmetric secret key (256-bits = 32 bytes)
    unsigned char key[crypto_secretbox_KEYBYTES];

    // Buffer to hold hexadecimal encoded version of the key (with a null terminator) for display
    #define KEY_HEX_BYTES (2 * crypto_secretbox_KEYBYTES + 1)
    char hex_key[KEY_HEX_BYTES];

    // Create a random key - equivalent to calling randombytes_buf() but improves code clarity
//    crypto_secretbox_keygen(key);   // Function added in libsodium version 1.12
    randombytes_buf(key, crypto_secretbox_KEYBYTES);

    // Convert the binary key into a hexadecimal string
    sodium_bin2hex(hex_key, KEY_HEX_BYTES, key, crypto_secretbox_KEYBYTES);

    // Print the key to the screen with hexadecimal encoding
    printf("Generated a random secret key: %s\n", hex_key);

    // Save the secret key to a binary file
    printf("\nSaving secret key to file '%s' ...", secret_filename);
    file_secret = fopen( secret_filename, "wb+" );
    if(  NULL == file_secret )
    {
        printf( " failed\n  ! Could not create %s\n\n", secret_filename );
        goto exit;
    }

    size_t bytes_written = fwrite( key, 1, crypto_secretbox_KEYBYTES, file_secret );
    if( crypto_secretbox_KEYBYTES != bytes_written )
    {
        printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }
    printf(" Done\n");


    // Now go through a full example of encrypting and then decrypting a fixed test message
    // The purpose is twofold:
    //   1) Demonstrate how to properly use the libsodium secretbox API for authenticated encryption
    //   2) Serve as a built-in unit test
    #define MESSAGE ((const unsigned char *) "test")
    #define MESSAGE_LEN 4

    // In combined mode the authentication tag and the encrypted message are stored together
    #define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

    // XSalsa20 uses a 192-bit nonce
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char ciphertext[CIPHERTEXT_LEN];
    unsigned char decrypted[MESSAGE_LEN+1]; // Extra byte so we can null terminate and use as a CString for display

    // The nonce doesn't have to be confidential, but it should never ever be reused with the same key
    randombytes_buf(nonce, sizeof nonce);

    // Encrypts a message with a key and a nonce in combined mode
    printf("Encrypting a test message and computing an authentication tag ...");
    ret = crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, key);
    if ( ret != 0)
    {   // The only I can see for this function to fail is if the message length is too large (> 2^64 - 16)
        printf(" failed.  Message length = %d\n", MESSAGE_LEN);
    }
    printf(" Done\n");

    // Verify and decrypt a ciphertext produced by crypto_secretbox_easy()
    printf("Authenticating and decrypting the secret message ...");
    ret = crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, key);
    if ( ret != 0)
    {
        printf(" message authentication failed.  Ciphertext length = %d\n", CIPHERTEXT_LEN);
    }
    printf(" OK\n");

    // Null terminate decrypted message here before displaying it as a CString
    decrypted[MESSAGE_LEN] = '\0';
    printf("Decrypted test message is: '%s'\n", decrypted);

    ret = EXIT_SUCCESS;

exit:
    // Perform any necessary cleanup

    // Close any open file handles
    if( NULL != file_secret )
    {
        fclose( file_secret );
    }

    // TODO: Zero-out key storage memory


    return ret;
}
