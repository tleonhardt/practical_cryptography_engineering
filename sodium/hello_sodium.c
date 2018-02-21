// A project using libsodium should include the sodium.h header.
// Including individual headers from libsodium is neither required nor recommended.
#include <sodium.h>

#include <stdio.h>

int main(void)
{
    int ret = 0;

    // The sodium_init() function should be called before any other function.
    // It is safe to call sodium_init() multiple times, or from different threads; it will
    // immediately return 1 without doing anything if the library has already been initialized.
    // After this function returns, all of the other functions provided by Sodium will be
    // thread-safe.  Before returning, the function ensures that the system's random number
    // generator has been properly seeded.  On some Linux systems, this may take some time,
    // especially when called right after a reboot of the system
    if (sodium_init() < 0)
    {
        /* panic! the library couldn't be initialized, it is not safe to use */
        printf("ERROR: The sodium library couldn't be initialied!\n");
        ret = 1;
    }
    else
    {
        printf("libsodium version %s has been successfully initialized\n", sodium_version_string());
    }

    return ret;
}
