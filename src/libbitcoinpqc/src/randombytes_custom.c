/*
 * Consolidated custom randombytes implementation.
 *
 * Provides the single randombytes() definition used by both the Dilithium
 * and SPHINCS+ reference implementations.  User-provided entropy is
 * injected via pqc_randombytes_init(); when no custom data is set the
 * function falls back to /dev/urandom.
 *
 * The Dilithium-style signature (uint8_t*, size_t) is used here.  It is
 * ABI-compatible with the SPHINCS+ signature (unsigned char*,
 * unsigned long long) on LP64 platforms.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "randombytes_custom.h"

/* Global entropy state */
static const uint8_t *g_random_data = NULL;
static size_t g_random_data_size = 0;
static size_t g_random_data_offset = 0;

void pqc_randombytes_init(const uint8_t *data, size_t size) {
    g_random_data = data;
    g_random_data_size = size;
    g_random_data_offset = 0;
}

void pqc_randombytes_cleanup(void) {
    g_random_data = NULL;
    g_random_data_size = 0;
    g_random_data_offset = 0;
}

/*
 * randombytes() — called by the upstream Dilithium and SPHINCS+ reference
 * implementations during keygen and signing.
 */
void randombytes(uint8_t *out, size_t outlen) {
    if (!out || outlen == 0) {
        return;
    }

    /* No custom data: fall back to system randomness */
    if (g_random_data == NULL || g_random_data_size == 0) {
        FILE *f = fopen("/dev/urandom", "r");
        if (!f) {
            memset(out, 0, outlen);
            return;
        }

        size_t bytes_read = fread(out, 1, outlen, f);
        fclose(f);

        if (bytes_read < outlen) {
            memset(out + bytes_read, 0, outlen - bytes_read);
        }
        return;
    }

    /* Serve from user-provided buffer, cycling if necessary */
    size_t total_copied = 0;

    while (total_copied < outlen) {
        size_t amount = outlen - total_copied;
        if (amount > g_random_data_size - g_random_data_offset) {
            amount = g_random_data_size - g_random_data_offset;
        }

        memcpy(out + total_copied, g_random_data + g_random_data_offset, amount);

        total_copied += amount;
        g_random_data_offset += amount;

        if (g_random_data_offset >= g_random_data_size) {
            g_random_data_offset = 0;
        }
    }
}
