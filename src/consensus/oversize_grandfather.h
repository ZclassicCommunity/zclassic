// Copyright (c) 2026 Rhett Creighton
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_OVERSIZE_GRANDFATHER_H
#define BITCOIN_CONSENSUS_OVERSIZE_GRANDFATHER_H

#include "uint256.h"

#include <stddef.h>
#include <stdint.h>

/**
 * Historical oversize transactions.
 *
 * Commit 8d6d05e63 (v2.1.1-58, 2023) lowered MAX_TX_SIZE_AFTER_SAPLING from
 * 2000000 to 102000 without a height gate. The mainnet chain holds 413
 * post-Sapling transactions above 102000 bytes (heights 478544..1968856, the
 * largest 1922197 bytes) that were valid when mined. A node validating the
 * chain from genesis must accept exactly those transactions inside blocks.
 *
 * The rule is the one Z23 implements (core/consensus/src/tx_structural.c): a
 * transaction larger than MAX_TX_SIZE_AFTER_SAPLING is accepted only when it
 * is checked as part of a block, its serialized size is at most
 * MAX_TX_SIZE_GRANDFATHER_CEILING, and its (txid, serialized size) pair is in
 * the table of 413 entries. Mempool, relay, wallet and RPC checks never see
 * this exception. The same rule applies on every network; the txids of the
 * mainnet transactions do not occur elsewhere.
 */

/** Largest serialized size a grandfathered transaction may have (Z23 uses MAX_BLOCK_SIZE = 2000000). */
static const unsigned int MAX_TX_SIZE_GRANDFATHER_CEILING = 2000000;

/** Number of entries in the table. */
size_t OversizeGrandfatherCount();

/** Entry i (0 <= i < OversizeGrandfatherCount()) in ascending memcmp order of txid; false if out of range. */
bool OversizeGrandfatherEntry(size_t i, uint256& txid, uint32_t& nSize);

/**
 * True iff txid is one of the 413 grandfathered transactions and nSize equals
 * its recorded serialized size exactly. Callers apply this only to a
 * transaction being validated inside a block.
 */
bool IsOversizeGrandfathered(const uint256& txid, size_t nSize);

#endif // BITCOIN_CONSENSUS_OVERSIZE_GRANDFATHER_H
