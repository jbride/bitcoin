#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../../dilithium/ref/api.h"
#include "../../dilithium/ref/fips202.h"
#include "../../dilithium/ref/params.h"
#include "libbitcoinpqc/ml_dsa.h"
#include "../randombytes_custom.h"

/*
 * This file implements utility functions for ML-DSA-44 (CRYSTALS-Dilithium)
 * particularly related to random data handling
 */

/* Initialize the random data source */
void ml_dsa_init_random_source(const uint8_t *random_data, size_t random_data_size) {
    pqc_randombytes_init(random_data, random_data_size);
}

/* Setup custom random function - this is called before keygen/sign */
void ml_dsa_setup_custom_random() {
    /* Nothing to do here, as our randombytes function is already set up */
}

/* Restore original random function - this is called after keygen/sign */
void ml_dsa_restore_original_random() {
    pqc_randombytes_cleanup();
}

/* Function to derive deterministic randomness from message and key */
void ml_dsa_derandomize(uint8_t *seed, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    /* Use SHAKE-256 to derive deterministic randomness from message and secret key */
    keccak_state state;

    /* Initialize the hash context */
    shake256_init(&state);

    /* Absorb secret key first */
    shake256_absorb(&state, sk, CRYPTO_SECRETKEYBYTES);

    /* Absorb message */
    shake256_absorb(&state, m, mlen);

    /* Finalize and extract randomness */
    shake256_finalize(&state);
    shake256_squeeze(seed, 64, &state);
}
