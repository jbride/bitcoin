#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Pay-to-Merkle-Root consensus behavior."""

from test_framework.blocktools import (
    COINBASE_MATURITY,
    add_witness_commitment,
    create_block,
    create_coinbase,
)
from test_framework.key import TaggedHash
from test_framework.messages import (
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    COIN,
    SEQUENCE_FINAL,
    ser_string,
)
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    OP_2,
    OP_TRUE,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class P2MRTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.extra_args = [["-acceptnonstdtxn=1"]]

    def _mine_block(self, txs=None, *, script_pubkey=None):
        node = self.nodes[0]
        height = node.getblockcount() + 1
        block = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(height, script_pubkey=script_pubkey),
            ntime=self._next_block_time(),
            txlist=txs or [],
        )
        if txs:
            add_witness_commitment(block)
        block.solve()
        assert_equal(node.submitblock(block.serialize().hex()), None)
        return block

    def _next_block_time(self):
        return self.nodes[0].getblockheader(self.nodes[0].getbestblockhash())["mediantime"] + 1

    def _p2mr_root(self, leaf_script):
        return TaggedHash("TapLeaf", bytes([LEAF_VERSION_TAPSCRIPT]) + ser_string(bytes(leaf_script)))

    def _spend_tx(self, funding_tx, witness_stack):
        spend = CTransaction()
        spend.vin.append(CTxIn(COutPoint(funding_tx.txid_int, 0), b"", SEQUENCE_FINAL))
        spend.vout.append(CTxOut(49 * COIN, CScript([OP_TRUE])))
        spend.vout.append(CTxOut(COIN - 10_000, CScript([OP_TRUE])))
        spend.wit.vtxinwit = [CTxInWitness()]
        spend.wit.vtxinwit[0].scriptWitness.stack = witness_stack
        return spend

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Mine native v2 32-byte outputs")
        leaf_script = CScript([OP_TRUE])
        valid_p2mr_script = CScript([OP_2, self._p2mr_root(leaf_script)])
        valid_funding_block = self._mine_block(script_pubkey=valid_p2mr_script)
        valid_funding_tx = valid_funding_block.vtx[0]

        invalid_p2mr_script = CScript([OP_2, b"\x11" * 32])
        invalid_funding_block = self._mine_block(script_pubkey=invalid_p2mr_script)
        invalid_funding_tx = invalid_funding_block.vtx[0]

        self.generate(node, COINBASE_MATURITY)

        self.log.info("Accept and mine a valid depth-zero P2MR spend")
        valid_spend = self._spend_tx(valid_funding_tx, [bytes(leaf_script), b"\xc1"])
        mempool_accept = node.testmempoolaccept([valid_spend.serialize().hex()])[0]
        assert mempool_accept["allowed"], mempool_accept
        valid_txid = node.sendrawtransaction(valid_spend.serialize().hex())
        block_hash = self.generate(node, 1)[0]
        assert valid_txid in [tx["txid"] for tx in node.getblock(block_hash, 2)["tx"]]

        self.log.info("Reject a block that spends P2MR through the unknown-witness path")
        spend = self._spend_tx(invalid_funding_tx, [b"not a p2mr script path"])

        height = node.getblockcount() + 1
        bad_block = create_block(
            hashprev=int(node.getbestblockhash(), 16),
            coinbase=create_coinbase(height),
            ntime=self._next_block_time(),
            txlist=[spend],
        )
        add_witness_commitment(bad_block)
        bad_block.solve()
        assert_equal(node.submitblock(bad_block.serialize().hex()), "mandatory-script-verify-flag-failed (Witness program hash mismatch)")


if __name__ == "__main__":
    P2MRTest(__file__).main()
