/*
 * RSA signature verification program
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
 *  This uses the Probabilisitc Signature Scheme (PSS) standardized as part of PKCS#1 v2.1 along with SHA-512 hashes.
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
#define mbedtls_snprintf   snprintf
#define mbedtls_printf     printf
#endif

#if !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_SHA512_C) ||        \
    !defined(MBEDTLS_PK_PARSE_C) || !defined(MBEDTLS_FS_IO) ||    \
    !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf("MBEDTLS_MD_C and/or MBEDTLS_ENTROPY_C and/or "
           "MBEDTLS_RSA_C and/or MBEDTLS_SHA512_C and/or "
           "MBEDTLS_PK_PARSE_C and/or MBEDTLS_FS_IO and/or "
           "MBEDTLS_CTR_DRBG_C not defined.\n");
    return( 0 );
}
#else

#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509.h"

#include <stdio.h>
#include <string.h>

// Set RSA padding scheme, use PKCS_V21 for PKCS#1 v2.1 PSS probabilistic signatures or PKCS_V15 for older PKCS#1 v1.5
// The RSA Probabilisitc Signature Scheme (PSS) should be used since it is more secure.
// However, some older encryption libraries only support the older deterministic PKCS#1 v.15 scheme
//#define RSA_PADDING MBEDTLS_RSA_PKCS_V21
#define RSA_PADDING MBEDTLS_RSA_PKCS_V15

// Size of buffer used to translate mbed TLS error codes into a string representation
#define MBED_ERR_BUF 80

// Buffer sizes
#define HASH_BYTES 64       // // 64 bytes for SHA-512
#define MAX_FILENAME 512


int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 0;
    size_t i;
    unsigned char hash[HASH_BYTES]; // Buffer for SHA-512 hash of the input file
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];    // Buffer to store RSA signature read from the signature file
    char filename[MAX_FILENAME];    // Buffer for signature filename
    char mbed_err[MBED_ERR_BUF];    // Buffer to store error strings

    mbedtls_pk_context pk;
    mbedtls_pk_init( &pk );

    if( argc != 3 )
    {
        mbedtls_printf( "usage: %s <public_keyfile> <filename>\n", argv[0] );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    char *key_file = argv[1];
    char *input_file = argv[2];

    // Load and parse a public key from a file in PEM or DER format
    mbedtls_printf( "\n  . Reading public key from '%s'", key_file );
    fflush( stdout );
    ret = mbedtls_pk_parse_public_keyfile( &pk,         // key to be initialized (pk_context must be empty)
                                           key_file );  // path to filename to read the public key from
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not read key from '%s'\n", key_file );
        mbedtls_printf( "  ! mbedtls_pk_parse_public_keyfile returned %d\n\n", ret );
        goto exit;
    }

    // Make sure the key parsed from the public key file actually is a valid RSA key
    if( !mbedtls_pk_can_do( &pk, MBEDTLS_PK_RSA ) )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Key is not an RSA key\n" );
        goto exit;
    }

    // Set padding for an already initialized RSA context
    mbedtls_rsa_set_padding( mbedtls_pk_rsa( pk ),  // RSA context to be set
                             RSA_PADDING,           // Padding scheme (MBEDTLS_RSA_PKCS_V21 or MBEDTLS_RSA_PKCS_V15)
                             MBEDTLS_MD_SHA512 );   // MBEDTLS_RSA_PKCS_V21 hash identifier (ignored for PKCS_V15)

    // Extract the RSA signature from the .sig file
    ret = 1;
    mbedtls_snprintf( filename, MAX_FILENAME, "%s.sig", input_file );
    if( ( f = fopen( filename, "rb" ) ) == NULL )
    {
        mbedtls_printf( "\n  ! Could not open %s\n\n", filename );
        goto exit;
    }

    i = fread( buf, 1, MBEDTLS_MPI_MAX_SIZE, f );

    fclose( f );

    // Compute the SHA-512 hash of the input file
    mbedtls_printf( "\n  . Verifying the RSA/SHA-512 signature using" );
    if( RSA_PADDING == MBEDTLS_RSA_PKCS_V21 )
    {
        mbedtls_printf( " PSS padding" );
    }
    else
    {
        mbedtls_printf( " PKCS1v1.5 padding");
    }
    fflush( stdout );
    ret = mbedtls_md_file(mbedtls_md_info_from_type( MBEDTLS_MD_SHA512 ), input_file, hash );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", input_file );
        goto exit;
    }

    // Verify the RSA signature of the hash (includes padding if relevant)
    ret = mbedtls_pk_verify( &pk,               // PK context to use
                             MBEDTLS_MD_SHA512, // Hash algorithm used
                             hash,              // Hash of the message to verify signature for
                             0,                 // hash length (0 -> use length associated with the Hash algorithm)
                             buf,               // Signature to verify
                             i );               // Signature length
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_verify returned %d\n\n", ret );
        goto exit;
    }

    mbedtls_printf( "\n  . OK (the signature is valid)\n\n" );

    ret = 0;

exit:
    // If there was an error, translate an mbed TLS error code into a string representation
    if( ret != 0 )
    {
        mbedtls_strerror(ret, mbed_err, MBED_ERR_BUF);
        mbedtls_printf( "mbedTLS ERROR: %s\n", mbed_err);
    }

    mbedtls_pk_free( &pk );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_RSA_C && MBEDTLS_SHA512_C &&
          MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO */
