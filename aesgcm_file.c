/*
 * AES-256 file encryption program using Galois Counter Mode (GCM)
 *
 * It has been greatly simplified in the interests of readability at the cost of not being cross-platform compatible.
 */
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#define mbedtls_printf     printf
#endif

#include "mbedtls/entropy.h"    // mbedtls_entropy_context
#include "mbedtls/ctr_drbg.h"   // mbedtls_ctr_drbg_context
#include "mbedtls/cipher.h"     // MBEDTLS_CIPHER_ID_AES
#include "mbedtls/error.h"      // mbedtls_strerror()
#include "mbedtls/gcm.h"        // mbedtls_gcm_context

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
    // Windows
    #include <windows.h>
    #include <io.h>
#else
    // POSIX
    #include <sys/types.h>
    #include <unistd.h>
#endif

#define MODE_ENCRYPT    0
#define MODE_DECRYPT    1

#define USAGE   \
    "\n  %s <mode> <input filename> <output filename> <key> <additional_data>\n" \
    "\n   <mode>: 0 = encrypt, 1 = decrypt\n" \
    "\n  example: %s 0 plain.txt cipher.txt hex:0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF " \
    "\"additional unencrypted but authenticated data\"\n" \
    "\n", argv[0], argv[0]


#define KEY_BYTES 32    // 256-bit AES key
#define  IV_BYTES 12    //  96-bit IV for performance - can be larger, but shouldn't be smaller for security
#define TAG_BYTES 16    // 128-bit GCM tag - can be larger, but shouldn't be much smaller for security

// Size of buffer used to translate mbed TLS error codes into a string representation
#define MBED_ERR_BUF 80


int main( int argc, char *argv[] )
{
    // Return value, 0 = success
    int ret = 0;

    // File pointers for input and output files
    FILE *fin = NULL;
    FILE *fout = NULL;

    // Statically allocated fixed-size buffers
    unsigned char key[KEY_BYTES];
    unsigned char iv[IV_BYTES];
    unsigned char tag[TAG_BYTES];
    memset(key, 0, KEY_BYTES);
    memset(iv, 0, IV_BYTES);
    memset(tag, 0, TAG_BYTES);
    char mbed_err[MBED_ERR_BUF];

    // Dynamically allocated variable buffers for input and output files
    unsigned char *plain_text = NULL;
    unsigned char *cipher_text = NULL;

    // mbed TLS context structures
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_gcm_context gcm_ctx;

    // Intiailize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
    mbedtls_gcm_init(&gcm_ctx);

    // Parse the command-line arguments.
    if( argc != 6 )
    {
        printf( USAGE );
        goto exit;
    }

    // Are we encrypting or decrypting?
    int mode = atoi( argv[1] );
    if( mode != MODE_ENCRYPT && mode != MODE_DECRYPT )
    {
        fprintf( stderr, "invalid operation mode\n" );
        goto exit;
    }

    // Input and output filenames are required to be different
    if( strcmp( argv[2], argv[3] ) == 0 )
    {
        fprintf( stderr, "input and output filenames must differ\n" );
        goto exit;
    }

    // Open input file for reading as a binary file
    if( ( fin = fopen( argv[2], "rb" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,rb) failed\n", argv[2] );
        goto exit;
    }

    // Open output file for writing as a binary file (but where we can also read its contents)
    if( ( fout = fopen( argv[3], "wb+" ) ) == NULL )
    {
        fprintf( stderr, "fopen(%s,wb+) failed\n", argv[3] );
        goto exit;
    }

    // Read the secret key from command line as hex digits (all caps)
    if( memcmp( argv[4], "hex:", 4 ) == 0 )
    {
        char *p = &argv[4][4];
        unsigned int n;
        size_t keylen = 0;

        while( sscanf( p, "%02X", &n ) > 0 && keylen < sizeof( key ) )
        {
            key[keylen++] = (unsigned char) n;
            p += 2;
        }

        if( keylen != KEY_BYTES)
        {
            fprintf(stderr, "key given is too short, this requires a 256-bit (32 byte) key\n");
            goto exit;
        }
    }
    else
    {
        perror( "invalid key format" );
        goto exit;
    }

    // Read the additional authenticated but unencrypted data from the command line
    unsigned char *add_data = (unsigned char*)argv[5];
    size_t add_len = strlen(argv[5]);

    // Get the file size
#if defined(_WIN32)
    // Windows
    LARGE_INTEGER li_size;
    __int64 seeksize;
#else
    // POSIX
    off_t seeksize;
#endif

#if defined(_WIN32)
    // Support large files (> 2Gb) on Win32
    li_size.QuadPart = 0;
    li_size.LowPart  = SetFilePointer( (HANDLE) _get_osfhandle( _fileno( fin ) ),
                                       li_size.LowPart, &li_size.HighPart, FILE_END );

    if( li_size.LowPart == 0xFFFFFFFF && GetLastError() != NO_ERROR )
    {
        fprintf( stderr, "SetFilePointer(0,FILE_END) failed\n" );
        goto exit;
    }

    seeksize = li_size.QuadPart;
#else
    if( ( seeksize = lseek( fileno( fin ), 0, SEEK_END ) ) < 0 )
    {
        perror( "lseek" );
        goto exit;
    }
#endif

    size_t filesize = (size_t)seeksize;
    size_t plain_len = filesize;

    // Rewind back to the beginning of the file
    if( fseek( fin, 0, SEEK_SET ) < 0 )
    {
        fprintf( stderr, "fseek(0,SEEK_SET) failed\n" );
        goto exit;
    }

    // Initialize the GCM context with our key and desired cipher
    ret = mbedtls_gcm_setkey(&gcm_ctx,                  // GCM context to be initialized
                             MBEDTLS_CIPHER_ID_AES,     // cipher to use (a 128-bit block cipher)
                             key,                       // encryption key
                             KEY_BYTES * 8);            // key bits (must be 128, 192, or 256)
    if( ret != 0 )
    {
        printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
        goto exit;
    }

    size_t bytes_read;
    size_t bytes_written;

    if( mode == MODE_ENCRYPT )
    {
        // The personalization string should be unique to your application in order to add some
        // personalized starting randomness to your random sources.
        char *pers = "aes generate key";

        // Initialize the entropy pool and the random source
        mbedtls_entropy_init( &entropy );
        mbedtls_ctr_drbg_init( &ctr_drbg );

        // CTR_DRBG initial seeding Seed and setup entropy source for future reseeds
        ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)pers, strlen(pers) );
        if( ret != 0 )
        {
            printf( "mbedtls_ctr_drbg_seed() failed - returned -0x%04x\n", -ret );
            goto exit;
        }

        // Extract data for your IV, in this case we generate 12 bytes (96 bits) of random data
        ret = mbedtls_ctr_drbg_random( &ctr_drbg, iv, IV_BYTES );
        if( ret != 0 )
        {
            printf( "mbedtls_ctr_drbg_random failed to extract IV - returned -0x%04x\n", -ret );
            goto exit;
        }

        // Append the IV at the beginning of the output.
        if( fwrite( iv, 1, IV_BYTES, fout ) != IV_BYTES )
        {
            fprintf( stderr, "fwrite(%d bytes) failed to write IV\n", IV_BYTES );
            goto exit;
        }

        // Allocated buffers big enough to hold the entire input plaintext file and encrypted ciphertext version thereof
        plain_text = (unsigned char*) malloc(plain_len + 1);
        cipher_text = (unsigned char*) malloc(plain_len + 1);  // In GCM mode, cipher text size is always same as plaintext size

        // Read in the entire plaintext file
        bytes_read = fread( plain_text, 1, plain_len, fin );
        if( bytes_read != plain_len )
        {
            fprintf( stderr, "fread failed to read plaintext input file:  expected to read %zu bytes, but read %zu bytes\n", plain_len, bytes_read);
            goto exit;
        }

        // GCM buffer encryption using a block cipher (NOTE: GCM mode doesn't require padding)
        ret = mbedtls_gcm_crypt_and_tag( &gcm_ctx,            // GCM context
                                         MBEDTLS_GCM_ENCRYPT, // mode
                                         plain_len,           // length of input data
                                         iv,                  // initialization vector
                                         IV_BYTES,            // lenght of IV
                                         add_data,            // additional data
                                         add_len,             // lnegth of additional data
                                         plain_text,          // buffer holding the input data
                                         cipher_text,         // buffer for holding the output data
                                         TAG_BYTES,           // length of the tag to generate
                                         tag);                // buffer for holding the tag
        if( ret != 0 )
        {
            printf( "mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned -0x%04x\n", -ret );
            goto exit;
        }

        // Write the ciphertext
        bytes_written = fwrite( cipher_text, 1, plain_len, fout );
        if( bytes_written != plain_len )
        {
            fprintf( stderr, "fwrite failed to write the ciphertext output file:  expected to write %zu bytes, but wrote %zu\n", plain_len, bytes_written );
            goto exit;
        }

        // Finally write the GCM tag.
        if( fwrite( tag, 1, TAG_BYTES, fout ) != TAG_BYTES )
        {
            fprintf( stderr, "fwrite(%d bytes) failed to write the GCM tag\n", TAG_BYTES );
            goto exit;
        }
    }

    if( mode == MODE_DECRYPT )
    {
        /*
         *  The encrypted file must be structured as follows:
         *
         *        00 .. 11              Initialization Vector (12 bytes)
         *        12 .. 12+N            AES-GCM Encrypted Data (no padding to a block size required)
         *      12+N .. 12+N + 16       GCM Tag (16 bytes)
         */
        if( filesize < (IV_BYTES + TAG_BYTES) )
        {
            fprintf( stderr, "File too short to be encrypted.\n" );
            goto exit;
        }

        // Subtract the IV + Tag length from the filezie to get the ciphertext length, which in GCM mode is same as plaintext length
        plain_len -= IV_BYTES + TAG_BYTES;

        // Read the IV
        if( fread( iv, 1, IV_BYTES, fin ) != IV_BYTES )
        {
            fprintf( stderr, "fread(%d bytes) failed to read the IV\n", IV_BYTES );
            goto exit;
        }

        // Allocated buffers big enough to hold the entire input ciphertext and decrypted plaintext version thereof
        plain_text = (unsigned char*) malloc(plain_len);
        cipher_text = (unsigned char*) malloc(plain_len);  // In GCM mode, cipher text size is always same as plaintext size

        // Read in the chunk of ciphertext from the file
        if( fread( cipher_text, 1, plain_len, fin ) != (size_t) plain_len )
        {
            fprintf( stderr, "fread(%zu bytes) failed to read the ciphertext\n", plain_len );
            goto exit;
        }

        // Read in the GCM Tag from the file
        if( fread( tag, 1, TAG_BYTES, fin ) != (size_t) TAG_BYTES )
        {
            fprintf( stderr, "fread(%d bytes) failed to read the GCM tag\n", TAG_BYTES );
            goto exit;
        }

        // GCM buffer authenticated decryption using a block cipher
        ret = mbedtls_gcm_auth_decrypt( &gcm_ctx,           // GCM context
                                        plain_len,          // length of the input ciphertext data (always same as length of plain text in GCM mode)
                                        iv,                 // initialization vector
                                        IV_BYTES,           // lenght of IV
                                        add_data,           // additional data
                                        add_len,            // length of additional data
                                        tag,                // buffer holding the tag
                                        TAG_BYTES,          // length of the tag
                                        cipher_text,        // buffer holding the input ciphertext data
                                        plain_text );       // buffer for holding the output decrypted data
        if( ret != 0 )
        {
            printf( "mbedtls_gcm_auth_decrypt failed to decrypt the ciphertext - tag doesn't match\n");
            goto exit;
        }

        // Write the plaintext
        if( fwrite( plain_text, 1, plain_len, fout ) != plain_len )
        {
            fprintf( stderr, "fwrite(%zu bytes) failed to write the plaintext\n", plain_len );
            goto exit;
        }
    }

    ret = EXIT_SUCCESS;

exit:
    // If there was an error, translate an mbed TLS error code into a string representation
    if( ret != EXIT_SUCCESS )
    {
        mbedtls_strerror(ret, mbed_err, MBED_ERR_BUF);
        mbedtls_printf( "mbedTLS ERROR: %s\n", mbed_err);
    }

    if( fin )
    {
        fclose( fin );
    }
    if( fout )
    {
        fclose( fout );
    }

    if( plain_text )
    {
        memset(plain_text, 0, plain_len);
        free(plain_text);
    }
    if( cipher_text )
    {
        memset(cipher_text, 0, plain_len);
        free(cipher_text);
    }

    /* Zeroize all command line arguments to also cover
       the case when the user has missed or reordered some,
       in which case the key might not be in argv[4]. */
    for( unsigned int i = 0; i < (unsigned int) argc; i++ )
    {
        memset( argv[i], 0, strlen( argv[i] ) );
    }

    memset(key, 0, KEY_BYTES);
    memset(iv, 0, IV_BYTES);
    memset(tag, 0, TAG_BYTES);

    // Free the data in the encropy context
    mbedtls_entropy_free(&entropy);

    // Clear CTR_CRBG context data
    mbedtls_ctr_drbg_free(&ctr_drbg);

    // Free the GCM context and underlying cipher sub-context
    mbedtls_gcm_free(&gcm_ctx);


    return( ret );

}
