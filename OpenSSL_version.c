#include <stdio.h>
#include <stdlib.h>
#include <openssl/crypto.h>

#if OPENSSL_VERSION_NUMBER < 0x10002000L
#error Better not use OpenSSL versions older than 1.0.2. They are unsupported and insecure.
#endif
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OpenSSL_version_num SSLeay
#endif

int main(int argc, char *argv[])
{
    unsigned long runtime_version = OpenSSL_version_num();
    if (runtime_version != OPENSSL_VERSION_NUMBER) {
        fprintf(stderr, "OpenSSL runtime version 0x%lx does not match version 0x%lx used by compiler\n",
                runtime_version, OPENSSL_VERSION_NUMBER);
        return EXIT_FAILURE;
    }
    fprintf(stdout, "%s (0x%lx)\n", OPENSSL_VERSION_TEXT, runtime_version);
    return EXIT_SUCCESS;
}
