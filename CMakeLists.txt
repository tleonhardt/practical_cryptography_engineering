cmake_minimum_required(VERSION 3.4)
project("mbed_AES" C)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -O2 -Wall")

set(MBED_DIR mbedtls)

include_directories(. ${MBED_DIR})

# Files to build for mbedTLS crypto routines (not including all of the SSL stuff)
set(MBED_CRYPTO
    ${MBED_DIR}/aes.c
    ${MBED_DIR}/aesni.c
    ${MBED_DIR}/arc4.c
    ${MBED_DIR}/asn1parse.c
    ${MBED_DIR}/asn1write.c
    ${MBED_DIR}/base64.c
    ${MBED_DIR}/bignum.c
    ${MBED_DIR}/blowfish.c
    ${MBED_DIR}/camellia.c
    ${MBED_DIR}/ccm.c
    ${MBED_DIR}/cipher.c
    ${MBED_DIR}/cipher_wrap.c
    ${MBED_DIR}/cmac.c
    ${MBED_DIR}/ctr_drbg.c
    ${MBED_DIR}/des.c
    ${MBED_DIR}/dhm.c
    ${MBED_DIR}/ecdh.c
    ${MBED_DIR}/ecdsa.c
    ${MBED_DIR}/ecjpake.c
    ${MBED_DIR}/ecp.c
    ${MBED_DIR}/ecp_curves.c
    ${MBED_DIR}/entropy.c
    ${MBED_DIR}/entropy_poll.c
    ${MBED_DIR}/error.c
    ${MBED_DIR}/gcm.c
    ${MBED_DIR}/havege.c
    ${MBED_DIR}/hmac_drbg.c
    ${MBED_DIR}/md.c
    ${MBED_DIR}/md2.c
    ${MBED_DIR}/md4.c
    ${MBED_DIR}/md5.c
    ${MBED_DIR}/md_wrap.c
    ${MBED_DIR}/memory_buffer_alloc.c
    ${MBED_DIR}/oid.c
    ${MBED_DIR}/padlock.c
    ${MBED_DIR}/pem.c
    ${MBED_DIR}/pk.c
    ${MBED_DIR}/pk_wrap.c
    ${MBED_DIR}/pkcs12.c
    ${MBED_DIR}/pkcs5.c
    ${MBED_DIR}/pkparse.c
    ${MBED_DIR}/pkwrite.c
    ${MBED_DIR}/platform.c
    ${MBED_DIR}/ripemd160.c
    ${MBED_DIR}/rsa.c
    ${MBED_DIR}/sha1.c
    ${MBED_DIR}/sha256.c
    ${MBED_DIR}/sha512.c
    ${MBED_DIR}/threading.c
    ${MBED_DIR}/timing.c
    ${MBED_DIR}/version.c
    ${MBED_DIR}/version_features.c
    ${MBED_DIR}/xtea.c
)

# Files to build for each executable
set(AES_GCM aes_gcm.c)
set(AESGCM_FILE aesgcm_file.c)
set(ECDH ecdh.c)
set(KDF kdf.c)
set(RSA_SIGN rsa_sign.c)
set(RSA_VERIFY rsa_verify.c)


# Library type to build (uncomment one of the following lines to choose either a static or dynamic (shared) library type
set(LIB_TYPE STATIC)
#set(LIB_TYPE SHARED)

# Build mbedTLS crypto code as a library so it only builds once
set(MBED_LIB mbed_crypto)
add_library(${MBED_LIB} ${LIB_TYPE} ${MBED_CRYPTO})
set_property(TARGET mbed_crypto PROPERTY C_STANDARD 99)


# Executables to build
set(AES_TGT aes_gcm)
add_executable(${AES_TGT} ${AES_GCM})
set_property(TARGET ${AES_TGT} PROPERTY C_STANDARD 99)
target_link_libraries(${AES_TGT} ${MBED_LIB})

set(AES_FILE_TGT aesgcm_file)
add_executable(${AES_FILE_TGT} ${AESGCM_FILE})
set_property(TARGET ${AES_FILE_TGT} PROPERTY C_STANDARD 99)
target_link_libraries(${AES_FILE_TGT} ${MBED_LIB})

set(ECDH_TGT ecdh)
add_executable(${ECDH_TGT} ${ECDH})
set_property(TARGET ${ECDH_TGT} PROPERTY C_STANDARD 99)
target_link_libraries(${ECDH_TGT} ${MBED_LIB})

set(KDF_TGT kdf)
add_executable(${KDF_TGT} ${KDF})
set_property(TARGET ${KDF_TGT} PROPERTY C_STANDARD 99)
target_link_libraries(${KDF_TGT} ${MBED_LIB})

set(RSA_SIG_TGT rsa_sign)
add_executable(${RSA_SIG_TGT} ${RSA_SIGN})
set_property(TARGET ${RSA_SIG_TGT} PROPERTY C_STANDARD 99)
target_link_libraries(${RSA_SIG_TGT} ${MBED_LIB})

set(RSA_VER_TGT rsa_verify)
add_executable(${RSA_VER_TGT} ${RSA_VERIFY})
set_property(TARGET ${RSA_VER_TGT} PROPERTY C_STANDARD 99)
target_link_libraries(${RSA_VER_TGT} ${MBED_LIB})
