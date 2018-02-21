/*
 *  Example Elliptic Curve Diffie-Hellman (ECDH) key exchange program
 *
 *  This file uses mbedTLS to do all of the following:
 *  - Read in a peer public ECDH key from a file
 *  - Generate an ECDH private and public key pair
 *  - Write the ECDH public key to a file
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

// Define which Elliptic Curve we wish to use
//#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_CURVE25519
//#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP384R1
#define ELLIPTIC_CURVE MBEDTLS_ECP_DP_SECP521R1

// Size of buffer used to store the public keys exchanged between the client and sever
// Buffer size should be the following:
// Curve    Public Key Buffer Size
// -----    ----------------------
// 25519    32
// SECP384  48
// SECP521  66
#define BUF_BYTES 66    // Safe to use the largest buffer size

// Size of buffer used to translate mbed TLS error codes into a string representation
#define MBED_ERR_BUF 80

#if !defined(MBEDTLS_ECDH_C) || \
    !defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) || \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C)
int main( void )
{
    mbedtls_printf( "MBEDTLS_ECDH_C and/or "
                    "MBEDTLS_ECP_DP_SECP521R1_ENABLED and/or "
                    "MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C "
                    "not defined\n" );
    return( 0 );
}
#else

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/error.h"


int main( int argc, char *argv[] )
{
    int ret;
    mbedtls_ecdh_context ctx_cli;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    unsigned char cli_to_srv_x[BUF_BYTES];
    unsigned char cli_to_srv_y[BUF_BYTES];
    unsigned char srv_to_cli_x[BUF_BYTES];
    unsigned char srv_to_cli_y[BUF_BYTES];
    const char pers[] = "ecdh";
    char mbed_err[MBED_ERR_BUF];

    ((void) argc);
    ((void) argv);

    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    mbedtls_printf( "Using Elliptic Curve:  ");
    switch(ELLIPTIC_CURVE)
    {
    case MBEDTLS_ECP_DP_CURVE25519:
        mbedtls_printf( "Curve25519 (offering 128 bits of security)\n" );
        break;
    case MBEDTLS_ECP_DP_SECP384R1:
        mbedtls_printf( "SECP384R1 NIST P-384 (offering 192 bits of security)\n" );
        break;
    case MBEDTLS_ECP_DP_SECP521R1:
        mbedtls_printf( "SECP521R1 NIST P-521 (offering 256 bits of security)\n" );
        break;
    default:
        mbedtls_printf( "ERROR - Invalid Curve selected!\n" );
        goto exit;
    }

    // Initialize random number generation
    mbedtls_printf( "  . Seeding the random number generator..." );
    fflush( stdout );
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) pers, sizeof pers );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );


    // Client: initialize context and generate keypair
    mbedtls_printf( "  . Setting up client context..." );
    fflush( stdout );

    // Set a group (in the abstract algebra sense) using well-known domain parameters - configure elliptic curve used
    ret = mbedtls_ecp_group_load( &ctx_cli.grp,     // Destination group
                                  ELLIPTIC_CURVE ); // Index in the list of well-known domain parameters
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    // Generate a public key
    ret = mbedtls_ecdh_gen_public( &ctx_cli.grp,            // ECP group
                                   &ctx_cli.d,              // Destination MPI (secret exponent, aka private key)
                                   &ctx_cli.Q,              // Destination point (public key)
                                   mbedtls_ctr_drbg_random, // RNG function
                                   &ctr_drbg );             //RNG parameter
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    // Export multi-precision integer (MPI) into unsigned binary data, big endian (X coordinate of ECP point)
    ret = mbedtls_mpi_write_binary( &ctx_cli.Q.X,   // Source MPI
                                    cli_to_srv_x,   // Output buffer
                                    BUF_BYTES );    // Output buffer size
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    // Export multi-precision integer (MPI) into unsigned binary data, big endian (Y coordinate of ECP point)
    ret = mbedtls_mpi_write_binary( &ctx_cli.Q.Y,   // Source MPI
                                    cli_to_srv_y,   // Output buffer
                                    BUF_BYTES );    // Output buffer size
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );


    // Server: read in public key data from file
    mbedtls_printf( "  . Reading server public key from file..." );
    fflush( stdout );

    // TODO: Read the server public key data into srv_to_cli_x and srv_to_cli_y buffers


    // Client: set peer (server) public key
    mbedtls_printf( "  . Setting server's public key within client context key and computing secret..." );
    fflush( stdout );

    // Set the Z component of the peer's public value (public key) to 1
    ret = mbedtls_mpi_lset( &ctx_cli.Qp.Z,  // MPI to set
                            1 );            // Value to use
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    // Set the X component of the peer's public value based on what was passed from client in the buffer
    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.X,   // Destination MPI
                                   srv_to_cli_x,    // Input buffer
                                   BUF_BYTES );     // Input buffer size
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    // Set the Y component of the peer's public value based on what was passed from client in the buffer
    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.Y,   // Destination MPI
                                   srv_to_cli_y,    // Input buffer
                                   BUF_BYTES );     // Input buffer size
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    // Compute shared secret
    ret = mbedtls_ecdh_compute_shared( &ctx_cli.grp,            // ECP group
                                       &ctx_cli.z,              // Destination MPI (shared secret)
                                       &ctx_cli.Qp,             // Public key from other party
                                       &ctx_cli.d,              // Our secret exponent (private key)
                                       mbedtls_ctr_drbg_random, // RNG function - countermeasure against timing attacks
                                       &ctr_drbg );             // RNG parameter
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned -0x%04x\n", -ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );


    // TODO: Export Shared secret to a buffer

    // TODO: Print Shared secret to screen or save to a file

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

    mbedtls_ecdh_free( &ctx_cli );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret != 0 );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_SECP521R1_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
