/*
This file contains a simple example of using the mbedTLS C library to
generate a random AES key, encrypt data with AES-GCM, and then decrypt
the output ciphertext.

An AES key is nothing more than a random bitstring of the right length.
For a 128-bit AES key, you need 16 bytes, for a 256-bit AES key, you
need 32 bytes.

mbed TLS includes the CTR-DRBG module and an Entropy Collection module
to help you with making an AES key generator for your key.
*/
#include <stdio.h>
#include <string.h>

#include "mbedtls/entropy.h"    // mbedtls_entropy_context
#include "mbedtls/ctr_drbg.h"   // mbedtls_ctr_drbg_context
#include "mbedtls/cipher.h"     // MBEDTLS_CIPHER_ID_AES
#include "mbedtls/gcm.h"        // mbedtls_gcm_context

// Sizes for statically allocated arrays
#define KEY_BYTES 32
#define IV_BYTES 12
#define BUF_SIZE 128
#define TAG_BYTES 16

int main(void)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_gcm_context gcm;

    unsigned char key[KEY_BYTES];
    unsigned char iv[IV_BYTES];
    unsigned char input[BUF_SIZE];
    unsigned char add_data[BUF_SIZE];
    unsigned char output[BUF_SIZE];
    unsigned char decrypted[BUF_SIZE];
    unsigned char tag[TAG_BYTES];

    // The personalization string should be unique to your application in order to add some
    // personalized starting randomness to your random sources.
    char *pers = "aes generate key";
    int ret;

    // Initialize the entropy pool and the random source
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    // Initialize GCM context (just makes references valid) - makes the context ready for mbedtls_gcm_setkey()
    mbedtls_gcm_init(&gcm);

    // CTR_DRBG initial seeding Seed and setup entropy source for future reseeds
    ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *)pers, strlen(pers) );
    if( ret != 0 )
    {
        printf( "mbedtls_ctr_drbg_seed() failed - returned -0x%04x\n", -ret );
        goto exit;
    }

    // Extract data for your key, in this case we generate 32 bytes (256 bits) of random data
    ret = mbedtls_ctr_drbg_random( &ctr_drbg, key, KEY_BYTES );
    if( ret != 0 )
    {
        printf( "mbedtls_ctr_drbg_random failed to extract key - returned -0x%04x\n", -ret );
        goto exit;
    }

    // Extract data for your IV, in this case we generate 12 bytes (96 bits) of random data
    ret = mbedtls_ctr_drbg_random( &ctr_drbg, iv, IV_BYTES );
    if( ret != 0 )
    {
        printf( "mbedtls_ctr_drbg_random failed to extract IV - returned -0x%04x\n", -ret );
        goto exit;
    }

    // Now you can use the data in key as a 256-bit AES key and in iv as a 128-bit IV


    // Clear out data buffers
    memset(input, 0, BUF_SIZE);
    memset(add_data, 0, BUF_SIZE);
    memset(output, 0, BUF_SIZE);
    memset(decrypted, 0, BUF_SIZE);

    // Fill input with a secret message
    snprintf((char *)input, BUF_SIZE, "a secret message!");
    size_t plain_len = strlen((char *)input);
    printf("plain text: '%s'  (length %zu)\n", input, plain_len);

    // Fill the additional data with something
    snprintf((char *)add_data, BUF_SIZE, "authenticated but not encrypted payload");
    size_t add_len = strlen((char *)add_data);
    printf("additional: '%s'  (length %zu)\n", add_data, add_len);

    // Initialize the GCM context with our key and desired cipher
    ret = mbedtls_gcm_setkey(&gcm,                      // GCM context to be initialized
                             MBEDTLS_CIPHER_ID_AES,     // cipher to use (a 128-bit block cipher)
                             key,                       // encryption key
                             KEY_BYTES * 8);            // key bits (must be 128, 192, or 256)
    if( ret != 0 )
    {
        printf( "mbedtls_gcm_setkey failed to set the key for AES cipher - returned -0x%04x\n", -ret );
        goto exit;
    }

    // GCM buffer encryption using a block cipher (NOTE: GCM mode doesn't require padding)
    ret = mbedtls_gcm_crypt_and_tag( &gcm,                // GCM context
                                     MBEDTLS_GCM_ENCRYPT, // mode
                                     plain_len,           // length of input data
                                     iv,                  // initialization vector
                                     IV_BYTES,            // length of IV
                                     add_data,            // additional data
                                     add_len,             // length of additional data
                                     input,               // buffer holding the input data
                                     output,              // buffer for holding the output data
                                     TAG_BYTES,           // length of the tag to generate
                                     tag);                // buffer for holding the tag
    if( ret != 0 )
    {
        printf( "mbedtls_gcm_crypt_and_tag failed to encrypt the data - returned -0x%04x\n", -ret );
        goto exit;
    }
    printf("ciphertext: '%s'  (length %zu)\n", output, strlen((char*)output));


    // Uncomment this line to corrupt the add_data so that GCM will fail to authenticate on decryption
    // memset(add_data, 0, BUF_SIZE);

    // GCM buffer authenticated decryption using a block cipher
    ret = mbedtls_gcm_auth_decrypt( &gcm,               // GCM context
                                    plain_len,          // length of the input ciphertext data (always same as plain)
                                    iv,                 // initialization vector
                                    IV_BYTES,           // length of IV
                                    add_data,           // additional data
                                    add_len,            // length of additional data
                                    tag,                // buffer holding the tag
                                    TAG_BYTES,          // length of the tag
                                    output,             // buffer holding the input ciphertext data
                                    decrypted );        // buffer for holding the output decrypted data
    if( ret != 0 )
    {
        printf( "mbedtls_gcm_auth_decrypt failed to decrypt the ciphertext - tag doesn't match\n");
        goto exit;
    }
    printf("decrypted : '%s'  (length %zu)\n", decrypted, strlen((char *)decrypted));


exit:
    // Free the data in the entropy context
    mbedtls_entropy_free(&entropy);

    // Clear CTR_CRBG context data
    mbedtls_ctr_drbg_free(&ctr_drbg);

    // Free the GCM context and underlying cipher sub-context
    mbedtls_gcm_free(&gcm);

    return ret;
}
