// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <hash.h>
#include <key.h>
#include <primitives/transaction.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <span.h>
#include <test/util/transaction_utils.h>
#include <uint256.h>

#include <array>
#include <cassert>
#include <cstdint>
#include <vector>
#include <iostream>
#include <cstdlib>

// Helper function to get preimage size from environment variable
static size_t GetPreimageSize() {
    const char* env_var = std::getenv("PREIMAGE_SIZE_BYTES");
    if (env_var != nullptr) {
        char* endptr;
        long size = std::strtol(env_var, &endptr, 10);
        if (*endptr == '\0' && size > 0) {
            return static_cast<size_t>(size);
        }
    }
    return 1; // Default value
}

// Microbenchmark for verification of a basic P2WPKH script. Can be easily
// modified to measure performance of other types of scripts.
static void VerifyScriptBench(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};

    const uint32_t flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH};
    const int witnessversion = 0;

    // Key pair.
    CKey key;
    static const std::array<unsigned char, 32> vchKey = {
        {
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        }
    };
    key.Set(vchKey.begin(), vchKey.end(), false);
    CPubKey pubkey = key.GetPubKey();
    uint160 pubkeyHash;
    CHash160().Write(pubkey).Finalize(pubkeyHash);

    // Script.
    CScript scriptPubKey = CScript() << witnessversion << ToByteVector(pubkeyHash);
    CScript scriptSig;
    CScript witScriptPubkey = CScript() << OP_DUP << OP_HASH160 << ToByteVector(pubkeyHash) << OP_EQUALVERIFY << OP_CHECKSIG;

    const CMutableTransaction& txCredit = BuildCreditingTransaction(scriptPubKey, 1);
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, CScriptWitness(), CTransaction(txCredit));
    CScriptWitness& witness = txSpend.vin[0].scriptWitness;
    witness.stack.emplace_back();
    key.Sign(SignatureHash(witScriptPubkey, txSpend, 0, SIGHASH_ALL, txCredit.vout[0].nValue, SigVersion::WITNESS_V0), witness.stack.back());
    witness.stack.back().push_back(static_cast<unsigned char>(SIGHASH_ALL));
    witness.stack.push_back(ToByteVector(pubkey));

    // Benchmark.
    bench.run([&] {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL),
            &err);
        if (err != SCRIPT_ERR_OK) {
            std::cerr << "Script verification failed: " << ScriptErrorString(err) << std::endl;
        }
        assert(err == SCRIPT_ERR_OK);
        assert(success);
    });
}

static void VerifyNestedIfScript(benchmark::Bench& bench)
{
    std::vector<std::vector<unsigned char>> stack;
    CScript script;
    for (int i = 0; i < 100; ++i) {
        script << OP_1 << OP_IF;
    }
    for (int i = 0; i < 1000; ++i) {
        script << OP_1;
    }
    for (int i = 0; i < 100; ++i) {
        script << OP_ENDIF;
    }
    bench.run([&] {
        auto stack_copy = stack;
        ScriptError error;
        bool ret = EvalScript(stack_copy, script, 0, BaseSignatureChecker(), SigVersion::BASE, &error);
        assert(ret);
    });
}

static void VerifySHA256Bench(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};

    const uint32_t flags{SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_P2SH};
    const int witnessversion = 0;

    // Create a custom script that hashes the remaining stack element and returns true
    // We need to drop the hash result and just push 1 (true)
    CScript customScript = CScript() << OP_SHA256 << OP_DROP << OP_1; // Hash, drop hash, push 1 (true)
    
    // Create scriptPubKey with the hash of our custom script
    uint256 scriptHash;
    CSHA256().Write(customScript.data(), customScript.size()).Finalize(scriptHash.begin());
    CScript scriptPubKey = CScript() << witnessversion << ToByteVector(scriptHash);
    
    CScript scriptSig;

    const CMutableTransaction& txCredit = BuildCreditingTransaction(scriptPubKey, 1);
    CMutableTransaction txSpend = BuildSpendingTransaction(scriptSig, CScriptWitness(), CTransaction(txCredit));
    CScriptWitness& witness = txSpend.vin[0].scriptWitness;
    
    // Add a large item to the stack first with size from environment variable
    size_t preimage_size = GetPreimageSize();
    std::vector<unsigned char> largeData(preimage_size, 0x42);
    std::cout << "Preimage size: " << preimage_size << std::endl;
    witness.stack.push_back(largeData);
    
    // Add the custom script as the LAST witness element (required for P2WSH)
    witness.stack.emplace_back(customScript.begin(), customScript.end());

    // Benchmark.
    bench.run([&] {
        ScriptError err;
        bool success = VerifyScript(
            txSpend.vin[0].scriptSig,
            txCredit.vout[0].scriptPubKey,
            &txSpend.vin[0].scriptWitness,
            flags,
            MutableTransactionSignatureChecker(&txSpend, 0, txCredit.vout[0].nValue, MissingDataBehavior::ASSERT_FAIL),
            &err);
        if (err != SCRIPT_ERR_OK) {
            std::cerr << "Script verification failed: " << ScriptErrorString(err) << std::endl;
        }
        assert(err == SCRIPT_ERR_OK);
        assert(success);
    });
}

static void ForceMemoryLeak(benchmark::Bench& bench)
{
    ECC_Context ecc_context{};

    // Benchmark.
    bench.run([&] {
        int* array = new int[100];
        array[100] = 42; // buffer overflow
        volatile int result = array[100]; // Force the read to prevent optimization
        (void)result;
        // deliberate leak; don't delete array

        // Add some work that can't be optimized away
        volatile int dummy = 0;
        dummy = dummy + 1;
        (void)dummy; // Suppress unused variable warning
    });
}

BENCHMARK(VerifyScriptBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifyNestedIfScript, benchmark::PriorityLevel::HIGH);
BENCHMARK(VerifySHA256Bench, benchmark::PriorityLevel::HIGH);
BENCHMARK(ForceMemoryLeak, benchmark::PriorityLevel::HIGH);
