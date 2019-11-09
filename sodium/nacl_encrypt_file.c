/* Encrypts a file using libsodium's "secretbox" secret-key authenticated encryption routines.
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
 *
 * WARNING:
 *  This example encrypts the entire file in one shot and only works when everything can fit in your computer's RAM.
 *  For very large files which cannot fit in your computer's memory, then stream-based encryption is required; for more
 *  info see the following:
 *  https://download.libsodium.org/doc/secret-key_cryptography/secretstream#file-encryption-example-code
 */

// A project using libsodium should include the sodium.h header.
// Including individual headers from libsodium is neither required nor recommended.
#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    FILE *file_key = NULL;
    FILE *file_message = NULL;
    FILE *file_cipher = NULL;
    unsigned char *message = NULL;
    unsigned char *ciphertext = NULL;

    // Parse command line arguments
    if( argc != 4 )
    {
        printf( "usage: %s <secret_keyfile> <plaintext_file> <ciphertext_file>\n", argv[0] );
        goto exit;
    }

    char *key_filename = argv[1];
    char *message_filename = argv[2];
    char *cipher_filename = argv[3];

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

    // Buffer to hold the symmetric secret key (256-bits = 32 bytes)
    unsigned char key[crypto_secretbox_KEYBYTES];

    // Buffer to hold hexadecimal encoded version of the key (with a null terminator) for display
    #define KEY_HEX_BYTES (2 * crypto_secretbox_KEYBYTES + 1)
    char hex_key[KEY_HEX_BYTES];

    // Read in the secret key from file
    printf("\nReading secret key from file '%s' ...", key_filename);
    file_key = fopen( key_filename, "rb" );
    if(  NULL == file_key )
    {
        printf( " failed\n  ! Could not open %s\n\n", key_filename );
        goto exit;
    }

    size_t bytes_read = fread( key, 1, crypto_secretbox_KEYBYTES, file_key );
    if( crypto_secretbox_KEYBYTES != bytes_read )
    {
        printf( "failed\n  ! fread failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    // Convert the binary key into a hexadecimal string
    sodium_bin2hex(hex_key, KEY_HEX_BYTES, key, crypto_secretbox_KEYBYTES);

    // Print the key to the screen with hexadecimal encoding
    printf("Secret key: %s\n", hex_key);


    // Read in the message from file
    printf("\nReading message to encrypt from file '%s' ...", message_filename);
    file_message = fopen( message_filename, "rb" );
    if(  NULL == file_message )
    {
        printf( " failed\n  ! Could not open %s\n\n", message_filename );
        goto exit;
    }

    // Get the file size
#if defined(_WIN32)
    LARGE_INTEGER li_size;
    _int64 seeksize;
    // Support large files (> 2Gb) on Win32
    li_size.QuadPart = 0;
    li_size.LowPart  = SetFilePointer( (HANDLE) _get_osfhandle( _fileno( file_message ) ), li_size.LowPart,
                                       &li_size.HighPart, FILE_END );

    if( li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR )
    {
        printf( " SetFilePointer(0,FILE_END) failed\n" );
        goto exit;
    }

    seeksize = li_size.QuadPart;
#else
    // POSIX
    off_t seeksize;
    if( ( seeksize = lseek( fileno( file_message ), 0, SEEK_END ) ) < 0 )
    {
        printf( " lseek failed\n" );
        goto exit;
    }
#endif
    size_t filesize = (size_t)seeksize;

    // Rewind back to the beginning of the file
    if( fseek( file_message, 0, SEEK_SET ) < 0 )
    {
        printf( " fseek(0,SEEK_SET) failed\n" );
        goto exit;
    }

    // Allocate buffers big enough to hold the message and the authenticated ciphertext
    unsigned long long message_len = filesize;
    unsigned long long ciphertext_len = crypto_secretbox_MACBYTES + message_len;

    // WARNING: This code makes the assumption that the file can fit in memory and doesn't check for malloc failure
    message = (unsigned char*)malloc(message_len + 1);
    ciphertext = (unsigned char*)malloc(ciphertext_len + 1);

    // Read in the message from the file
    bytes_read = fread( message, 1, message_len, file_message );
    if( message_len != bytes_read )
    {
        printf( "failed\n  ! fread failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    // Display message size and contents
    printf("Message is %llu bytes: %s\n", message_len, (char*)message);


    // The 192-bit (24-byte) nonce doesn't have to be confidential, but it should never ever be reused with the same key
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    randombytes_buf(nonce, sizeof nonce);

    // Encrypts a message with key and nonce in combined mode where the ciphertext and a 16-byte tag are stored together
    printf("Encrypting message and computing an authentication tag ...");
    ret = crypto_secretbox_easy(ciphertext, message, message_len, nonce, key);
    if ( ret != 0)
    {   // This can fail if the message is too large to fit in your computer's memory
        printf(" failed.  Message length = %lld\n", message_len);
    }
    printf(" Done\n");


    // Save the nonce and authenticated ciphertext to a binary file
    printf("\nSaving authenticated ciphertext to file '%s' ...", cipher_filename);
    file_cipher = fopen( cipher_filename, "wb+" );
    if(  NULL == file_cipher )
    {
        printf( " failed\n  ! Could not create %s\n\n", cipher_filename );
        goto exit;
    }

    // Save the 24-byte (192-bit) nonce to the authenticated ciphertext file first (unencrypted)
    size_t bytes_written = fwrite( nonce, 1, crypto_secretbox_NONCEBYTES, file_cipher );
    if( crypto_secretbox_NONCEBYTES != bytes_written )
    {
        printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }

    bytes_written = fwrite( ciphertext, 1, ciphertext_len, file_cipher );
    if( ciphertext_len != bytes_written )
    {
        printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    ret = EXIT_SUCCESS;

exit:
    // Perform any necessary cleanup

    // Close any open file handles
    if( NULL != file_key )
    {
        fclose( file_key );
    }
    if( NULL != file_message )
    {
        fclose( file_message );
    }
    if( NULL != file_cipher )
    {
        fclose( file_cipher );
    }

    // TODO: Zero-out statically allocated key storage memory

    // Free any dynamically allocated memory (but zero it out first)
    if( message )
    {
        memset(message, 0, message_len);
        free( message );
    }
    if( ciphertext )
    {
        memset(ciphertext, 0, ciphertext_len);
        free( ciphertext );
    }

    return ret;
}
