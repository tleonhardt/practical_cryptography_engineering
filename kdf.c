/*
 *  Example Key Derivation Function (KDF) program using mbedTLS
 *
 *  This file uses a password-based key derivation function specified in PKCS#5 PBKDF2 and implemented in mbedTLS in the
 * mbedtls_pkcs5_pbkdf2_hmac() function in the pkcs5.h/.c files.
 *
 * PBDKF2 is a KDF with sliding computation cost aimed to reduce the vulnerability of encrypted keys to brute force
 * attacks.  PBKDF2 is part of RSA Laboratorie's Public-Key Cryptography Standards (PKCS) series, specifically PKCS#5
 * v2.0, also published as Internet Engineering Task Force's RFC 2898.  It supercedes PBKDF1, which could only produce
 * keys up to 160 bits long.
 *
 * There are better KDF functions available which address weaknesses in PBDKF2, but PBKDF2 is widely available in most
 * libraries.
 *
 * PBKDF2 applies a pseudorandom function, such as a hash-based message authentication code (HMAC), to the input
 * password along with a salt value and repeats the process many times to produce a derived key, which can then be used
 * as a cryptographic key in subsequent operations. The added computation work makes password cracking much more
 * difficult, and is known as key stretching.
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
#define mbedtls_printf  printf
#endif

#include <string.h>

#if !defined(MBEDTLS_SHA512_C) || !defined(MBEDTLS_MD_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_SHA512_C and/or MBEDTLS_MD_C not defined\n");
    return( 0 );
}
#else

#include "mbedtls/entropy.h"    // entropy gathering
#include "mbedtls/ctr_drbg.h"   // CSPRNG
#include "mbedtls/error.h"      // error code to string conversion
#include "mbedtls/md.h"         // hash algorithms
#include "mbedtls/pkcs5.h"      // pbkdf2 KDF

#define USAGE   \
    "\n  %s <password>\n" \
    "\n  example: %s 1337P@ssw0rd\n" \
    "\n", argv[0], argv[0]

// Size of buffer used to translate mbed TLS error codes into a string representation
#define MBED_ERR_BUF 80

// Define which hash algorithm to use for the HMAC
//#define HASH_ALGORITHM MBEDTLS_MD_SHA256
//#define HASH_ALGORITHM MBEDTLS_MD_SHA384
#define HASH_ALGORITHM MBEDTLS_MD_SHA512

// Length of salt
#define SALT_BYTES 16

// Iteration count (how many times to iteratively run through the HMAC)
#define ITERATION_COUNT 100000

// Length of generated key in bytes
#define KEY_BYTES 32


int main( int argc, char *argv[] )
{
    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_md_context_t sha_ctx;

    // Create buffers for the salt, output key, and string representation of error codes
    unsigned char salt[SALT_BYTES];
    unsigned char key[KEY_BYTES];
    char mbed_err[MBED_ERR_BUF];

    // Process command-line arguments - require password passed as 1st argument on command line
    if(argc < 2)
    {
        mbedtls_printf( USAGE );
        return -1;
    }

    // Password to use when generating the derived key
    unsigned char *password = (unsigned char*) argv[1];

    // Length of password
    size_t plen = strlen(argv[1]);

    mbedtls_printf( "Password: '%s' (length %zu)\n", argv[1], plen);

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_md_init( &sha_ctx );

    mbedtls_printf( "Using Hash Algorithm:  ");
    switch(HASH_ALGORITHM)
    {
    case MBEDTLS_MD_SHA256:
        mbedtls_printf( "SHA256\n" );
        break;
    case MBEDTLS_MD_SHA384:
        mbedtls_printf( "SHA384\n" );
        break;
    case MBEDTLS_MD_SHA512:
        mbedtls_printf( "SHA512\n" );
        break;
    default:
        mbedtls_printf( "ERROR - Invalid Hash Algorithm selected!\n" );
        goto exit;
    }

    // Initialize random number generation
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );
    const char pers[] = "kdf";
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof pers );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );


    // Select hash algorithm to use for the HMAC and allocate internal structures
    mbedtls_printf( "  . Setting up hash algorithm context..." );
    fflush( stdout );
    ret = mbedtls_md_setup( &sha_ctx,   // MD context to set up
                            mbedtls_md_info_from_type( HASH_ALGORITHM ),    // md_info struct MD to use
                            1 );    // non-zero implies HMAC is going to be used (0 saves memory, but is less secure)
    if( ret != 0 )
    {
        mbedtls_printf( "  ! mbedtls_md_setup() returned -0x%04x\n", -ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );

    // Generate random data for the salt
    mbedtls_printf( "  . Generating a random salt..." );
    ret = mbedtls_ctr_drbg_random( &ctr_drbg, salt, SALT_BYTES );
    if( ret != 0 )
    {
        printf( "mbedtls_ctr_drbg_random failed to extract key - returned -0x%04x\n", -ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );

    // Derive a key from a password using PBKDF2 function with HMAC
    mbedtls_printf( "  . Deriving a key from the password using PBKDF2 with HMAC..." );
    ret = mbedtls_pkcs5_pbkdf2_hmac( &sha_ctx,  // Generic HMAC context
                                     password,  // Password to use when generating key
                                     plen,      // Length of password
                                     salt,      // Salt to use when generating key
                                     SALT_BYTES,// Length of salt
                                     ITERATION_COUNT, //Iteration count
                                     KEY_BYTES, // Length of generated key in bytes
                                     key );     // Generated key. Must be at least as big as previous argument
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pkcs5_pbkdf2_hmac - returned -0x%04x\n", -ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );

    mbedtls_printf( "Random %d byte salt (hex):  ", SALT_BYTES );
    for(size_t i = 0; i < SALT_BYTES; i++)
    {
        mbedtls_printf("%02X", salt[i]);
    }
    printf("\n");

    mbedtls_printf( "Derived a %d byte key (hex):  ", KEY_BYTES );
    for(size_t i = 0; i < KEY_BYTES; i++)
    {
        mbedtls_printf("%02X", key[i]);
    }
    printf("\n");


    // NOTE:  The salt affects the derived key, so it needs to be shared, though it can be sent in the clear

exit:
    // If there was an error, translate an mbed TLS error code into a string representation
    if( ret != 0 )
    {
        mbedtls_strerror(ret, mbed_err, MBED_ERR_BUF);
        mbedtls_printf( "mbedTLS ERROR: %s\n", mbed_err);
    }

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_md_free( &sha_ctx );

    return( ret != 0 );
}
#endif /* MBEDTLS_MD_SHA512 && MBEDTLS_MD_C */
