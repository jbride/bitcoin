#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "../../sphincsplus/ref/api.h"
#include "../../sphincsplus/ref/fors.h"
#include "../../sphincsplus/ref/hash.h"
#include "../../sphincsplus/ref/thash.h"
#include "../../sphincsplus/ref/utils.h"
#include "../../sphincsplus/ref/address.h"
#include "libbitcoinpqc/slh_dsa.h"
#include "../randombytes_custom.h"

/*
 * This file implements utility functions for SLH-DSA-Shake-128s (SPHINCS+)
 * particularly related to random data handling
 */

/* Initialize the random data source */
void slh_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size) {
    pqc_randombytes_init(random_data, random_data_size);
}

/* Setup custom random function - this is called before keygen/sign */
void slh_dsa_setup_custom_random() {
    /* Nothing to do here, as our randombytes function is already set up */
}

/* Restore original random function - this is called after keygen/sign */
void slh_dsa_restore_original_random() {
    pqc_randombytes_cleanup();
}

/* Simple implementation of deterministic randomness from message and key */
void slh_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    /* Create a buffer to hold combined data */
    size_t combined_len = mlen + CRYPTO_SECRETKEYBYTES;
    uint8_t *combined = malloc(combined_len);

    if (combined) {
        /* Combine secret key and message */
        memcpy(combined, sk, CRYPTO_SECRETKEYBYTES);
        memcpy(combined + CRYPTO_SECRETKEYBYTES, m, mlen);

        /* Use custom hash function (simple XOR of message with key for each block) */
        uint8_t buffer[64] = {0};
        for (size_t i = 0; i < combined_len; i++) {
            buffer[i % 64] ^= combined[i];
        }

        /* Ensure the randomness looks random enough */
        for (size_t i = 0; i < 10; i++) {
            for (size_t j = 0; j < 64; j++) {
                buffer[j] = buffer[(j + 1) % 64] ^ buffer[(j + 7) % 64] ^ buffer[(j + 13) % 64];
            }
        }

        /* Copy the result */
        memcpy(seed, buffer, 64);

        /* Clean up */
        memset(combined, 0, combined_len);
        free(combined);
    } else {
        /* Fallback if memory allocation fails */
        memset(seed, 0, 64);
    }
}
