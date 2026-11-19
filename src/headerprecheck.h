// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCLASSIC_HEADERPRECHECK_H
#define ZCLASSIC_HEADERPRECHECK_H

#include "primitives/block.h"

#include <stddef.h>
#include <vector>

/** Default for -headerprecheck. */
static const bool DEFAULT_HEADER_PRECHECK = true;

/** Upper bound on worker threads one call may use. */
static const unsigned int MAX_HEADER_PRECHECK_THREADS = 8;

/** A message with fewer candidate headers than this is left to the serial loop. */
static const size_t MIN_HEADER_PRECHECK_CANDIDATES = 8;

/**
 * Verify the Equihash solutions of a "headers" message on a few worker
 * threads, outside cs_main, before the serial AcceptBlockHeader loop runs.
 *
 * The only effect is to warm the process-wide positive-only Equihash memo
 * (equihashmemo.h): valid headers are inserted keyed by their own hash, and
 * results are otherwise discarded. The serial loop still checks every header
 * through CheckEquihashSolutionMemo, so a memo hit gives the same "true" a
 * fresh verification would, and any header that is invalid (or that the
 * pre-pass did not reach) is verified inline with the unchanged error and
 * Misbehaving path. Accept/reject results cannot change.
 *
 * DoS bound: only headers that the serial loop would itself verify are
 * candidates. Leading headers already in mapBlockIndex are skipped, but none
 * is a candidate when one of them is marked failed or breaks hashPrevBlock
 * continuity (the serial loop stops there). The first candidate must follow
 * the header before it and its parent must be known and not marked failed.
 * Collection stops at the first break in continuity and at the first header
 * that fails the cheap checks CheckBlockHeader makes around the Equihash one
 * (nVersion >= MIN_BLOCK_VERSION, CheckProofOfWork). Workers stop claiming new
 * headers as soon as one fails, so a hostile message costs at most about one
 * extra verification per worker past its first bad solution.
 *
 * Returns the number of headers verified (for tests and benchmarks).
 */
size_t PreverifyHeadersEquihash(const std::vector<CBlockHeader>& headers);

#endif // ZCLASSIC_HEADERPRECHECK_H
