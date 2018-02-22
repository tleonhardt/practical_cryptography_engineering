Installing libsodium
====================

Before building these examples, you need to make sure libosdium is installed.

Installing on macOS
-------------------
The easiest way to install on macOS is with Homebrew:

```bash
brew install libsodium
xcode-select --install
```

Installing on Linux
-------------------
For any Linux distro which uses the **apt** package manager (Ubuntu, Debian, Mint, etc.), do the following:
```bash
sudo apt install libsodium-dev
```

Installing on Windows
---------------------
The easiest way to use libsodium on Windows is to use the [pre-built libraries](https://download.libsodium.org/doc/installation/).


Building libsodium examples
===========================
These examples require CMake to be installed along with the platform default C compiler.

Building on Windows
-------------------

On Windows, CMake generates a Visual Studio solution for either x86 or x64 (not both).  So in general you have to
create two separate build folders.

Here, we have only included an x64 static libsodium library, so we will build for that.

Build requires CMake and Visual Studio 2015

Use the following sequence of commands to build on Windows:

```bash
mkdir build64 & pushd build64
cmake -G "Visual Studio 14 2015 Win64" ..
popd
cmake --build build64 --config Release
```

This will generate the executables in the build64\Release folder.

Building on Linux or macOS
==========================
```bash
mkdir build; pushd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

This will generate the executables in the build directory.


File Contents
=============

Installation Verification
-------------------------    
* hello_sodium.c
    * "hello world" code to make sure you have libsodium installed and are linking to it correctly
    
Symmetric Encryption
--------------------
These examples use the simple [crypto_secretbox](https://download.libsodium.org/doc/secret-key_cryptography/authenticated_encryption.html) 
API which is an [authenticated encryption](https://en.wikipedia.org/wiki/Authenticated_encryption) (AE) cryptographic 
primitive that combines an [XSalsa20](https://download.libsodium.org/doc/advanced/xsalsa20.html) 
stream cipher with a [Poly1305](https://en.wikipedia.org/wiki/Poly1305) MAC.  This API is very easy to use and is 
particularly suitable for use by newcomers to cryptography.  If you have need for authenticating additional data which 
is transmitted in an unencrypted fashion, then you may prefer an [AEAD](https://download.libsodium.org/doc/secret-key_cryptography/aead.html) 
primitive instead.

* nacl_symmetric_gen.c
    * Generates a random 256-bit (32-byte) secret symmetric key for use with the **secretbox** API
* nacl_encrypt_file.c
    * Encrypts a file using libsodium's **secretbox** secret-key routines and adds a MAC of the ciphertext
* nacl_decrypt_file.c
    * Authenticates and decrypts a ciphertext file encrypted using libsodium's **secretbox** encryption routines

Public-key Digital Signatures
-----------------------------
These examples use the simple [crypto_sign](https://download.libsodium.org/doc/public-key_cryptography/public-key_signatures.html) 
API which is a public-key digital signature cryptographic primitive based on elliptic curves and uses the 
[Ed25519](https://ed25519.cr.yp.to) algorithm.

* nacl_genkey.c
    *  Generates a random Ed25519 Secret(signing)/Public(verifying) key pair using libsodium
* nacl_sign.c
    * Uses libsodium to sign a message using the Ed25519 digital signature algorithm
* nacl_verify.c
    * Uses libsodium to verify a signed message using the Ed25519 digital signature algorithm
* ed25519_sodium_pynacl.c
    * Round trip "unit test" of using libsodium Ed25519 digital signature code along with PyNacl digital signature code
    

