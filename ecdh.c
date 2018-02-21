/*
 *  Example Elliptic Curve Diffie-Hellman (ECDH) key exchange program
 *
 *  This file is a modification of the ecdh_curve25519.c example which ships with mbedTLS to use different curves
 *
 * Curve25519 is very fast, but only uses 256 bits (128 bits of security) even though it is highly respected as being
 * safe by pretty much everyone.  This curve is suitable for an asymmetric ECDH key exchange used to derive a 128-bit
 * key for use with a symmetric cipher such as AES-128.Python's Cryptography module doesn't have support for curve25519
 * until version 2.0 and even then it only supports it with a bleeding-edge version of OpenSSL.
 *
 * Elliptic Curve SECP384R1 is a 384-bit NIST curve over a prime field.  This is a curve with intermediate performance
 * and intermediate security.  It should be suitable for an asymmetric ECDH key exchange used to derive a 192-bit key
 * for use with a symmetric cipher such as AES-192.  Python's Cryptography module has support for this curve in all
 * recent versions.  The "SafeCurves" website specifically marks this curve as unsafe.  NSA "Suite B" includes this
 * curve in the list of recommended curves.
 *
 * Elliptic Curve SECP521R1 is a 521-bit NIST curve over a prime field.  This is slower than most other recommended
 * curves due to the larger bit size, but should be very secure and suitable for an asymmetric ECDH key exchange used to
 * derive a 256-bit key for use with a symmetric cipher such as AES-256.  Python's Cryptography module has support for
 * this curve in all recent versions.  The "SafeCurves" website doesn't comment on this particular NIST curve in any
 * way shape or form.  Notably, this particular NIST curve is not included in the "NSA Suite B" set of recommended
 * curves, ostensibly because Suite B was only shooting for 192 bits of security and this curve would be overkill for
 * that.
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
    mbedtls_ecdh_context ctx_cli, ctx_srv;
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
    mbedtls_ecdh_init( &ctx_srv );
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


    // Server: initialize context and generate keypair
    mbedtls_printf( "  . Setting up server context..." );
    fflush( stdout );

    // Set a group (in the abstract algebra sense) using well-known domain parameters - configure elliptic curve used
    ret = mbedtls_ecp_group_load( &ctx_srv.grp, ELLIPTIC_CURVE );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecp_group_load returned %d\n", ret );
        goto exit;
    }

    // Generate a public key
    ret = mbedtls_ecdh_gen_public( &ctx_srv.grp, &ctx_srv.d, &ctx_srv.Q, mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_gen_public returned %d\n", ret );
        goto exit;
    }

    // Export multi-precision integer into unsigned binary data, big endian (X coordinate of ECP point)
    ret = mbedtls_mpi_write_binary( &ctx_srv.Q.X, srv_to_cli_x, BUF_BYTES );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    // Export multi-precision integer into unsigned binary data, big endian (Y coordinate of ECP point)
    ret = mbedtls_mpi_write_binary( &ctx_srv.Q.Y, srv_to_cli_y, BUF_BYTES );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_write_binary returned %d\n", ret );
        goto exit;
    }

    mbedtls_printf( " ok\n" );

    // Server: read peer's key and generate shared secret
    mbedtls_printf( "  . Server reading client key and computing secret..." );
    fflush( stdout );

    // Set the Z component of the peer's public value (public key) to 1
    ret = mbedtls_mpi_lset( &ctx_srv.Qp.Z,  // MPI to set
                            1 );            // Value to use
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    // Set the X component of the peer's public value based on what was passed from client in the buffer
    ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.X,   // Destination MPI
                                   cli_to_srv_x,    // Input buffer
                                   BUF_BYTES );     // Input buffer size
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    // Set the Y component of the peer's public value based on what was passed from client in the buffer
    ret = mbedtls_mpi_read_binary( &ctx_srv.Qp.Y,   // Destination MPI
                                   cli_to_srv_y,    // Input buffer
                                   BUF_BYTES );     // Input buffer size
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    // Compute shared secret
    ret = mbedtls_ecdh_compute_shared( &ctx_srv.grp,            // ECP group
                                       &ctx_srv.z,              // Destination MPI (shared secret)
                                       &ctx_srv.Qp,             // Public key from other party
                                       &ctx_srv.d,              // Our secret exponent (private key)
                                       mbedtls_ctr_drbg_random, // RNG function - countermeasure against timing attacks
                                       &ctr_drbg );             // RNG parameter
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned -0x%04x\n", -ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );


    // Client: read peer's key and generate shared secret
    mbedtls_printf( "  . Client reading server key and computing secret..." );
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_cli.Qp.Z, 1 );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_lset returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.X, srv_to_cli_x, BUF_BYTES );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_cli.Qp.Y, srv_to_cli_y, BUF_BYTES );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_mpi_read_binary returned %d\n", ret );
        goto exit;
    }

    ret = mbedtls_ecdh_compute_shared( &ctx_cli.grp, &ctx_cli.z, &ctx_cli.Qp, &ctx_cli.d,
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );

    // Verification: are the computed secrets equal?
    mbedtls_printf( "  . Checking if both computed secrets are equal..." );
    fflush( stdout );

    // Compare two signed multi-precision integers
    ret = mbedtls_mpi_cmp_mpi( &ctx_cli.z, &ctx_srv.z );
    if( ret != 0 )
    {
        mbedtls_printf( " failed\n  ! mbedtls_ecdh_compute_shared returned %d\n", ret );
        goto exit;
    }
    mbedtls_printf( " ok\n" );

    // TODO: Use a Key Derivation Function (KDF) to derive a 256-bit AES key from the 521-bit shared secret


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

    mbedtls_ecdh_free( &ctx_srv );
    mbedtls_ecdh_free( &ctx_cli );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    return( ret != 0 );
}
#endif /* MBEDTLS_ECDH_C && MBEDTLS_ECP_DP_SECP521R1_ENABLED &&
          MBEDTLS_ENTROPY_C && MBEDTLS_CTR_DRBG_C */
