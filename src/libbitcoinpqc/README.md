# libbitcoinpqc

A C library for Post-Quantum Cryptographic (PQC) signature algorithms. This library implements two NIST PQC standard signature algorithms for use with [BIP-360](https://github.com/cryptoquick/bips/blob/p2qrh/bip-0360.mediawiki) and the Bitcoin QuBit soft fork:

1. **ML-DSA-44** (formerly CRYSTALS-Dilithium): A structured lattice-based digital signature scheme that is part of the NIST PQC standardization.
2. **SLH-DSA-Shake-128s** (formerly SPHINCS+): A stateless hash-based signature scheme with minimal security assumptions.

Notice that all PQC signature algorithms used are certified according to the Federal Information Processing Standards, or FIPS. This should help in the future with native hardware support.

## Bitcoin QuBit Integration

This library serves as the cryptographic foundation for the Bitcoin QuBit soft fork, which aims to make Bitcoin's signature verification quantum-resistant through the implementation of BIP-360. QuBit introduces new post-quantum secure transaction types that can protect Bitcoin from potential threats posed by quantum computers.

## Features

- Clean, unified C API for all three signature algorithms
- User-provided entropy (bring your own randomness)
- Key generation, signing, and verification functions
- Minimal dependencies

## Key Characteristics

| Algorithm | Public Key Size | Secret Key Size | Signature Size | Security Level |
|-----------|----------------|----------------|----------------|----------------|
| secp256k1 | 32 bytes | 32 bytes | 64 bytes | Classical |
| ML-DSA-44 | 1,312 bytes | 2,528 bytes | 2,420 bytes | NIST Level 2 |
| SLH-DSA-SHAKE-128s | 32 bytes | 64 bytes | 7,856 bytes | NIST Level 1 |

## Security Notes

- This library does not provide its own random number generation. It is essential that the user provide entropy from a cryptographically secure source.
- Random data is required for key generation, but not for signing. All signatures are deterministic, based on the message and secret key.
- The implementations are based on reference code from the NIST PQC standardization process and are not production-hardened.
- Care should be taken to securely manage secret keys in applications.

## BIP-360 Compliance

This library implements the cryptographic primitives required by [BIP-360](https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki), which defines the standard for post-quantum resistant signatures in Bitcoin. It supports all three recommended algorithms with the specified parameter sets.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Dependencies

Cryptographic dependencies included in this project:

- https://github.com/sphincs/sphincsplus - `7ec789ace6874d875f4bb84cb61b81155398167e`
- https://github.com/pq-crystals/dilithium - `444cdcc84eb36b66fe27b3a2529ee48f6d8150c2`

## Building the Library

### Prerequisites

- CMake 3.10 or higher
- C99 compiler

### Building

```bash
# Clone the repository
git clone https://github.com/bitcoin/libbitcoinpqc.git
cd libbitcoinpqc

# Build the C library using CMake
mkdir build
cd build
cmake ..
make
```

## C API Usage

```c
#include <libbitcoinpqc/bitcoinpqc.h>

// Generate random data (from a secure source in production)
uint8_t random_data[256];
// Fill random_data with entropy...

// Generate a key pair
bitcoin_pqc_keypair_t keypair;
bitcoin_pqc_keygen(BITCOIN_PQC_MLDSA44, &keypair, random_data, sizeof(random_data));

// Sign a message
const uint8_t message[] = "Message to sign";
bitcoin_pqc_signature_t signature;
bitcoin_pqc_sign(BITCOIN_PQC_MLDSA44, keypair.secret_key, keypair.secret_key_size,
                message, sizeof(message) - 1, &signature);

// Verify the signature
bitcoin_pqc_error_t result = bitcoin_pqc_verify(BITCOIN_PQC_MLDSA44,
                                             keypair.public_key, keypair.public_key_size,
                                             message, sizeof(message) - 1,
                                             signature.signature, signature.signature_size);

// Clean up resources
bitcoin_pqc_signature_free(&signature);
bitcoin_pqc_keypair_free(&keypair);
```

## Acknowledgments

- The original NIST PQC competition teams for their reference implementations
- The NIST PQC standardization process for advancing post-quantum cryptography
- The Bitcoin QuBit soft fork contributors and BIP-360 contributors
