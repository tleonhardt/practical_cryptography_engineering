/* Uses libsodium to sign a message using the Ed25519 digital signature algorithm
 */

// A project using libsodium should include the sodium.h header.
// Including individual headers from libsodium is neither required nor recommended.
#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#if !defined(_WIN32_WCE)
#include <io.h>
#endif
#else
#include <sys/types.h>
#include <unistd.h>
#endif


int main(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    FILE *file_secret = NULL;
    FILE *file_message = NULL;
    FILE *file_signature = NULL;
    unsigned char *message = NULL;
    unsigned char *signed_message = NULL;

    // Parse command line arguments
    if( argc != 4 )
    {
        printf( "usage: %s <secret_keyfile> <file_to_sign> <signature_file>\n", argv[0] );
        goto exit;
    }

    char *secret_filename = argv[1];
    char *message_filename = argv[2];
    char *signature_filename = argv[3];

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

    // Buffer to hold the private key (signing key) - has extra info so public key can be derived
    unsigned char secret_key[crypto_sign_SECRETKEYBYTES];


    // Buffer to hold hexadecimal encoded versions of the secret key (with a null terminator)
    #define SECRETKEY_HEX_BYTES (2 * crypto_sign_SECRETKEYBYTES + 1)
    char hex_secret[SECRETKEY_HEX_BYTES];

    // Read in the secret key from file
    printf("\nReading secret key from file '%s' ...", secret_filename);
    file_secret = fopen( secret_filename, "rb" );
    if(  NULL == file_secret )
    {
        printf( " failed\n  ! Could not open %s\n\n", secret_filename );
        goto exit;
    }

    size_t bytes_read = fread( secret_key, 1, crypto_sign_SECRETKEYBYTES, file_secret );
    if( crypto_sign_SECRETKEYBYTES != bytes_read )
    {
        printf( "failed\n  ! fread failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    // Convert the binary key into a hexadecimal strings for display purposes
    sodium_bin2hex(hex_secret, SECRETKEY_HEX_BYTES, secret_key, crypto_sign_SECRETKEYBYTES);

    // Print the secret key to the screen with hexadecimal encoding
    printf("Secret key: %s\n", hex_secret);


    // Read in the message from file
    printf("\nReading message to sign from file '%s' ...", message_filename);
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

    // Allocate buffers big enough to hold the message and the signed message
    unsigned long long message_len = filesize;
    unsigned long long signed_message_len = crypto_sign_BYTES + message_len;
    message = (unsigned char*)malloc(message_len + 1);
    signed_message = (unsigned char*)malloc(signed_message_len + 1);

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


    // Sign the message in combined mode where a signed message is generaed (including message)
    unsigned long long actual_len = 0;
    printf("Signing the message ...");
    ret = crypto_sign(signed_message, &actual_len, message, message_len, secret_key);
    if( 0 != ret)
    {
        printf(" failed\n");
    }
    printf(" Done\n");

    // Convert the signed message to hexadecimal for display purposes
    size_t signed_hex_len = 2*signed_message_len + 1;
    char *hex_signed = malloc(signed_hex_len);
    sodium_bin2hex(hex_signed, signed_hex_len, signed_message, signed_message_len);

    // Display the signed message size and contents (contents in hexadecimal)
    printf("Signed message is %llu bytes: %s\n", signed_message_len, hex_signed);
    free(hex_signed);


    // Save the signed message to a binary file
    printf("\nSaving signed message to file '%s' ...", signature_filename);
    file_signature = fopen( signature_filename, "wb+" );
    if(  NULL == file_signature )
    {
        printf( " failed\n  ! Could not create %s\n\n", signature_filename );
        goto exit;
    }

    size_t bytes_written = fwrite( signed_message, 1, signed_message_len, file_signature );
    if( signed_message_len != bytes_written )
    {
        printf( "failed\n  ! fwrite failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    ret = EXIT_SUCCESS;

exit:
    // Perform any necessary cleanup

    // Close any open file handles
    if( file_secret )
    {
        fclose( file_secret );
    }
    if( file_message )
    {
        fclose( file_message );
    }
    if( file_signature )
    {
        fclose( file_signature );
    }

    // TODO: Zero-out statically allocated key or message storage memory as appropriate

    // Free any dynamically allocated memory (but zero it out first)
    if( message )
    {
        memset(message, 0, message_len);
        free( message );
    }
    if( signed_message )
    {
        memset(signed_message, 0, signed_message_len);
        free( signed_message );
    }


    return ret;
}