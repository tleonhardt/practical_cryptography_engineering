/*
 * RSA signature creation program
 *
 * Usage:
 *     rsa_sig <priv_key> <filename>
 *
 * Where:
 *  - priv_key - is a path to an RSA private key file in PEM or DER format
 *  - filename - is a path to an input file you wish to create an RSA signature for
 *
 * Output:
 *  - filename.sig - signature is saved to filename.sig where "filename" is the complete input filename
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

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/rsa.h"
#include "mbedtls/md.h"
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
#define HASH_BYTES 64       // 64 bytes for SHA-512
#define MAX_FILENAME 512


int main( int argc, char *argv[] )
{
    FILE *f;
    int ret = 0;
    unsigned char hash[HASH_BYTES]; // Buffer for SHA-512 hash of the input file
    unsigned char buf[MBEDTLS_MPI_MAX_SIZE];    // Buffer to store RSA signature before writing it to the output file
    char filename[MAX_FILENAME];    // Buffer for output filename
    char mbed_err[MBED_ERR_BUF];    // Buffer to store error strings

    // Use the mbedTLS public key abstraction layer which makes it easier to deal with keys from files and such
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Initialize mbedTLS context structures
    mbedtls_entropy_init( &entropy );
    mbedtls_pk_init( &pk );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if( argc != 3 )
    {
        mbedtls_printf( "usage: %s <private_keyfile> <filename>\n", argv[0] );

#if defined(_WIN32)
        mbedtls_printf( "\n" );
#endif

        goto exit;
    }

    char *key_file = argv[1];
    char *input_file = argv[2];

    mbedtls_printf( "\n  . Seeding the random number generator..." );
    fflush( stdout );
    const char *pers = "rsa_sign_pss";
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg,                     // CTR_DRBG context to be seeded
                                 mbedtls_entropy_func,          // Entropy callback function
                                 &entropy,                      // Entropy context
                                 (const unsigned char *) pers,  // Personalization data
                                 strlen( pers ));               // Length of personalization data
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( "\n  . Reading private key from '%s'", key_file );
    fflush( stdout );
    ret = mbedtls_pk_parse_keyfile( &pk, key_file, "" );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not read key from '%s'\n", key_file );
        mbedtls_printf( "  ! mbedtls_pk_parse_public_keyfile returned %d\n\n", ret );
        goto exit;
    }

    // Make sure the key parsed from the private key file actually is a valid RSA key
    if( !mbedtls_pk_can_do( &pk, MBEDTLS_PK_RSA ) )
    {
        ret = 0;
        mbedtls_printf( " failed\n  ! Key is not an RSA key\n" );
        goto exit;
    }

    // Set padding for an already initialized RSA context
    mbedtls_rsa_set_padding( mbedtls_pk_rsa( pk ),  // RSA context to be set
                             RSA_PADDING,           // Padding scheme (MBEDTLS_RSA_PKCS_V21 or MBEDTLS_RSA_PKCS_V15)
                             MBEDTLS_MD_SHA512 );   // MBEDTLS_RSA_PKCS_V21 hash identifier (ignored for PKCS_V15)

    // Compute the SHA-512 hash of the input file
    mbedtls_printf( "\n  . Generating the RSA/SHA-512 signature using" );
    if( RSA_PADDING == MBEDTLS_RSA_PKCS_V21 )
    {
        mbedtls_printf( " PSS padding" );
    }
    else
    {
        mbedtls_printf( " PKCS1v1.5 padding");
    }
    fflush( stdout );
    ret = mbedtls_md_file(mbedtls_md_info_from_type( MBEDTLS_MD_SHA512 ),   // mbedtls_md_info_t struct
                          input_file,   // path to the file we wish to calculate a hash for the contents
                          hash );       // output buffer to store the hash in
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! Could not open or read %s\n\n", input_file );
        goto exit;
    }

    // Calculate the RSA signature of the hash, including padding
    size_t olen = 0;
    ret = mbedtls_pk_sign( &pk,                     // PK context to use - must hold a private key
                           MBEDTLS_MD_SHA512,       // Hash algorithm used
                           hash,                    // Hash of the message to sign
                           0,                       // hash length (0 -> use length associated with the Hash algorithm)
                           buf,                     // Place to write the signature
                           &olen,                   // Number of bytes written
                           mbedtls_ctr_drbg_random, // RNG function
                           &ctr_drbg );             // RNG parameter
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_pk_sign returned %d\n\n", ret );
        goto exit;
    }

    // Write the signature into <filename>.sig
    mbedtls_snprintf( filename, MAX_FILENAME, "%s.sig", input_file );
    f = fopen( filename, "wb+" );
    if( f == NULL )
    {
        ret = 1;
        mbedtls_printf( " failed\n  ! Could not create %s\n\n", filename );
        goto exit;
    }

    if( fwrite( buf, 1, olen, f ) != olen )
    {
        mbedtls_printf( "failed\n  ! fwrite failed\n\n" );
        fclose( f );
        goto exit;
    }

    fclose( f );

    mbedtls_printf( "\n  . Done (created \"%s\")\n\n", filename );

exit:
    // If there was an error, translate an mbed TLS error code into a string representation
    if( ret != 0 )
    {
        mbedtls_strerror(ret, mbed_err, MBED_ERR_BUF);
        mbedtls_printf( "mbedTLS ERROR: %s\n", mbed_err);
    }

    mbedtls_pk_free( &pk );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

#if defined(_WIN32)
    mbedtls_printf( "  + Press Enter to exit this program.\n" );
    fflush( stdout ); getchar();
#endif

    return( ret );
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_RSA_C &&
          MBEDTLS_SHA512_C && MBEDTLS_PK_PARSE_C && MBEDTLS_FS_IO &&
          MBEDTLS_CTR_DRBG_C */
