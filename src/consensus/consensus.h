// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

/** The minimum allowed block version (network rule) */
static const int32_t MIN_BLOCK_VERSION = 4;
/** The minimum allowed transaction version (network rule) */
static const int32_t SPROUT_MIN_TX_VERSION = 1;
/** The minimum allowed Overwinter transaction version (network rule) */
static const int32_t OVERWINTER_MIN_TX_VERSION = 3;
/** The maximum allowed Overwinter transaction version (network rule) */
static const int32_t OVERWINTER_MAX_TX_VERSION = 3;
/** The minimum allowed Sapling transaction version (network rule) */
static const int32_t SAPLING_MIN_TX_VERSION = 4;
/** The maximum allowed Sapling transaction version (network rule) */
static const int32_t SAPLING_MAX_TX_VERSION = 4;
/** The maximum allowed size for a serialized block, in bytes (network rule) */
static const unsigned int MAX_BLOCK_SIZE = 200000;

/** The maximum block size we tolerate when loading blocks from disk during -reindex,
 *  -loadblock, or bootstrap.dat import. The canonical mainnet chain contains 1,272 blocks
 *  whose serialized size is strictly between 200000 and 2000000 bytes (max observed
 *  1,999,599 B as of height ~3.1M). These blocks are accepted on the normal P2P/ConnectBlock
 *  path via the local GENEROUS_BLOCK_SIZE_LIMIT in CheckBlock ("checkpoint validates
 *  correctness" + hash chain). LoadExternalBlockFile was not widened when the generous
 *  tolerance was added, causing silent drops (nSize check + undersized CBufferedFile).
 *  This constant makes the import path match CheckBlock so that -reindex can rebuild
 *  real mainnet history. Safety remains: subsequent ProcessNewBlock still runs CheckBlock
 *  (which applies the same generous limit) and the checkpoint hash proof for historical
 *  blocks. See BLK-01 (Critical in 2026-06 full source review, rev 3).
 */
static const unsigned int GENEROUS_BLOCK_SIZE_LIMIT = 2000000;

/** The maximum allowed number of signature check operations in a block (network rule) */
static const unsigned int MAX_BLOCK_SIGOPS = 20000;
/** The maximum size of a transaction (network rule) */
static const unsigned int MAX_TX_SIZE_BEFORE_SAPLING = 100000;
static const unsigned int MAX_TX_SIZE_AFTER_SAPLING = 102000; // a little extra
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;
/** The minimum value which is invalid for expiry height, used by CTransaction and CMutableTransaction */
static constexpr uint32_t TX_EXPIRY_HEIGHT_THRESHOLD = 500000000;

/** Flags for LockTime() */
enum {
    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1 << 1),
};

/** Used as the flags parameter to CheckFinalTx() in non-consensus code */
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_MEDIAN_TIME_PAST;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
