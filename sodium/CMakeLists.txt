cmake_minimum_required(VERSION 3.4)
project("hello_sodium" C)

# Set compiler flags in a generic cross-platform compatible manner
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -g -O2 -Wall")

# Projects which statically link Sodium in Visual Studio must define a macro named SODIUM_STATIC
add_definitions(-DSODIUM_STATIC)

# Tell CMake where to look for header files
include_directories(${CMAKE_SOURCE_DIR}/include)

# Tell CMake where to look for libraries
link_directories(${CMAKE_SOURCE_DIR})

set(libs sodium)

# Files to build for each executable
set(HELLO_SRC hello_sodium.c)
set(GENKEY_SRC nacl_genkey.c)
set(SIGN_SRC nacl_sign.c)
set(VERIFY_SRC nacl_verify.c)
set(ED25519_SRC nacl_ed25519.c)
set(PYNACL_COMPAT_SRC ed25519_sodium_pynacl.c)
set(SYMMETRIC_GEN_SRC nacl_symmetric_gen.c)
set(SYMMETRIC_ENCRYPT_SRC nacl_encrypt_file.c)
set(SYMMETRIC_DECRYPT_SRC nacl_decrypt_file.c)

# Executables to build
set(HELLO_EXE hello_sodium)
add_executable(${HELLO_EXE} ${HELLO_SRC})
target_link_libraries(${HELLO_EXE} ${libs})

set(GENKEY_EXE nacl_keygen)
add_executable(${GENKEY_EXE} ${GENKEY_SRC})
target_link_libraries(${GENKEY_EXE} ${libs})

set(SIGN_EXE nacl_sign)
add_executable(${SIGN_EXE} ${SIGN_SRC})
target_link_libraries(${SIGN_EXE} ${libs})

set(VERIFY_EXE nacl_verify)
add_executable(${VERIFY_EXE} ${VERIFY_SRC})
target_link_libraries(${VERIFY_EXE} ${libs})

set(ED255159_EXE test_ed25519)
add_executable(${ED255159_EXE} ${ED25519_SRC})
target_link_libraries(${ED255159_EXE} ${libs})

set(PYNACL_COMPAT_EXE test_pynacl_compatibility)
add_executable(${PYNACL_COMPAT_EXE} ${PYNACL_COMPAT_SRC})
target_link_libraries(${PYNACL_COMPAT_EXE} ${libs})

set(SYMMETRIC_GENKEY_EXE symmetric_keygen)
add_executable(${SYMMETRIC_GENKEY_EXE} ${SYMMETRIC_GEN_SRC})
target_link_libraries(${SYMMETRIC_GENKEY_EXE} ${libs})

set(SYMMETRIC_ENCRYPT_EXE symmetric_encrypt)
add_executable(${SYMMETRIC_ENCRYPT_EXE} ${SYMMETRIC_ENCRYPT_SRC})
target_link_libraries(${SYMMETRIC_ENCRYPT_EXE} ${libs})

set(SYMMETRIC_DECRYPT_EXE symmetric_decrypt)
add_executable(${SYMMETRIC_DECRYPT_EXE} ${SYMMETRIC_DECRYPT_SRC})
target_link_libraries(${SYMMETRIC_DECRYPT_EXE} ${libs})
