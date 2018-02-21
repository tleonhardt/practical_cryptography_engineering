/* Uses libsodium to verify a signed message using the Ed25519 digital signature algorithm
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
    FILE *file_public = NULL;
    FILE *file_signature = NULL;
    unsigned char *message = NULL;
    unsigned char *signed_message = NULL;

    // Parse command line arguments
    if( argc != 3 )
    {
        printf( "usage: %s <public_keyfile> <signature_file>\n", argv[0] );
        goto exit;
    }

    char *public_filename = argv[1];
    char *signature_filename = argv[2];

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


    // Buffer to hold hexadecimal encoded versions of the public key (with a null terminator)
    #define PUBLICKEY_HEX_BYTES (2 * crypto_sign_PUBLICKEYBYTES + 1)
    char hex_public[PUBLICKEY_HEX_BYTES];

    // Read in the public key from file
    printf("\nReading public key from file '%s' ...", public_filename);
    file_public = fopen( public_filename, "rb" );
    if(  NULL == file_public )
    {
        printf( " failed\n  ! Could not open %s\n\n", public_filename );
        goto exit;
    }

    size_t bytes_read = fread( public_key, 1, crypto_sign_PUBLICKEYBYTES, file_public );
    if( crypto_sign_PUBLICKEYBYTES != bytes_read )
    {
        printf( "failed\n  ! fread failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    // Convert the binary key into a hexadecimal strings for display purposes
    sodium_bin2hex(hex_public, PUBLICKEY_HEX_BYTES, public_key, crypto_sign_PUBLICKEYBYTES);

    // Print the public key to the screen with hexadecimal encoding
    printf("Public key: %s\n", hex_public);


    // Read in the signed message from the signature file
    printf("\nReading signed message to verify from file '%s' ...", signature_filename);
    file_signature = fopen( signature_filename, "rb" );
    if(  NULL == file_signature )
    {
        printf( " failed\n  ! Could not open %s\n\n", signature_filename );
        goto exit;
    }

    // Get the file size
#if defined(_WIN32)
    LARGE_INTEGER li_size;
    _int64 seeksize;
    // Support large files (> 2Gb) on Win32
    li_size.QuadPart = 0;
    li_size.LowPart  = SetFilePointer( (HANDLE) _get_osfhandle( _fileno( file_signature ) ), li_size.LowPart,
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
    if( ( seeksize = lseek( fileno( file_signature ), 0, SEEK_END ) ) < 0 )
    {
        printf( " lseek failed\n" );
        goto exit;
    }
#endif
    size_t filesize = (size_t)seeksize;

    if(filesize < crypto_sign_BYTES)
    {
        printf("Signed message file is too small to contain a valid signature\n");
        goto exit;
    }

    // Rewind back to the beginning of the file
    if( fseek( file_signature, 0, SEEK_SET ) < 0 )
    {
        printf( " fseek(0,SEEK_SET) failed\n" );
        goto exit;
    }

    // Allocate buffers big enough to hold the signed message and the unsigned message
    unsigned long long signed_message_len = filesize;
    unsigned long long message_len = signed_message_len - crypto_sign_BYTES;
    message = (unsigned char*)malloc(message_len + 1);
    signed_message = (unsigned char*)malloc(signed_message_len + 1);

    // Read in the signed message from the file
    bytes_read = fread( signed_message, 1, signed_message_len, file_signature );
    if( signed_message_len != bytes_read )
    {
        printf( "failed\n  ! fread failed\n\n" );
        goto exit;
    }
    printf(" Done\n");

    // Open the combined-mode signed message which verifies signature and extracts original message
    unsigned long long actual_len = 0;
    printf("Verifying the message ...");
    ret = crypto_sign_open(message, &actual_len, signed_message, signed_message_len, public_key);
    if( 0 != ret)
    {
        printf(" incorrect signature\n");
        goto exit;
    }
    else if( actual_len != message_len)
    {
        printf(" incorrect message length\n");
    }
    printf(" OK\n");


    // Display the original message, first making sure it is null terminated
    message[message_len] = '\0';
    printf("\nOriginal message is:\n%s\n", message);

    ret = EXIT_SUCCESS;

exit:
    // Perform any necessary cleanup

    // Close any open file handles
    if( file_public )
    {
        fclose( file_public );
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