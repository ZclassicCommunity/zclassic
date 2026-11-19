// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCLASSIC_SHIELDEDCACHE_H
#define ZCLASSIC_SHIELDEDCACHE_H

#include "uint256.h"

#include <stddef.h>
#include <stdint.h>

/** Default -maxshieldedcachesize, in MiB (64 bytes are budgeted per entry). */
static const unsigned int DEFAULT_MAX_SHIELDED_CACHE_SIZE = 4;

/**
 * Positive-only cache of Sapling verification verdicts.
 *
 * ContextualCheckTransaction verifies every Sapling spend proof, spendAuthSig,
 * output proof and the binding signature of a transaction twice: once when it
 * enters the mempool and again when its block is connected. This cache lets
 * the second evaluation be skipped, in the same way the signature cache
 * (script/sigcache.cpp) does for ECDSA.
 *
 * Soundness argument (why a hit may skip the Sapling block):
 *  - The key is (txid, consensus branch id). The txid is SHA256d over the
 *    complete transaction serialization, which includes every input of the
 *    Sapling checks: cv, anchor, nullifier, rk, zkproof and spendAuthSig of
 *    every spend, cv, cm, ephemeralKey and zkproof of every output,
 *    valueBalance and bindingSig. The sighash those checks verify against is
 *    SignatureHash(tx, branchId), a pure function of the same key.
 *  - Only successes are inserted. A miss runs the full, unchanged check, so
 *    the first evaluation of a transaction, its reject reason and its DoS
 *    score are exactly what they were without the cache, and an invalid
 *    transaction can never be accepted because of it.
 *  - Entries are SHA256(random nonce || txid || branchId LE32), so peers
 *    cannot predict table positions. Eviction only turns a hit into a miss.
 */

/** True iff (txid, branchId) was inserted and has not been evicted since. */
bool ShieldedVerdictContains(const uint256& txid, uint32_t branchId);

/** Record that the Sapling checks of txid passed under branchId. Callers must
 *  only call this right after those checks returned success. */
void ShieldedVerdictInsert(const uint256& txid, uint32_t branchId);

/** Empty the cache and re-read -maxshieldedcachesize (tests only). */
void ShieldedVerdictClearForTest();

/** Number of entries currently held (tests only). */
size_t ShieldedVerdictSizeForTest();

/** Maximum number of entries under the current bound (tests only). */
size_t ShieldedVerdictMaxEntriesForTest();

#endif // ZCLASSIC_SHIELDEDCACHE_H
