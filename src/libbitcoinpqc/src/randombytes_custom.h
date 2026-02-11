#ifndef PQC_RANDOMBYTES_CUSTOM_H
#define PQC_RANDOMBYTES_CUSTOM_H

#include <stddef.h>
#include <stdint.h>

/*
 * Shared entropy state for user-provided randomness.
 *
 * Call pqc_randombytes_init() before invoking any upstream keygen/sign
 * function that calls randombytes(), and pqc_randombytes_cleanup()
 * afterwards to clear the global state.
 */

void pqc_randombytes_init(const uint8_t *data, size_t size);
void pqc_randombytes_cleanup(void);

#endif /* PQC_RANDOMBYTES_CUSTOM_H */
