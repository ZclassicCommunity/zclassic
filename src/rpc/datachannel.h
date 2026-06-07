// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SHIELD pillar — test seams ONLY (E-2).
//
// The data-channel RPCs (z_senddatafile / z_listdatatransfers /
// z_getdatatransfer) live entirely in rpc/datachannel.cpp and need a live
// CWallet + Sapling notes to drive end-to-end (covered by the cross-wallet
// regtest qa/zslp/zdc-xwallet-regtest.sh). This header exposes the THREE
// wallet-independent registry/DoS-guard pieces so zcash-gtest can gate them:
//
//   * ZdcExpireOld()  — TTL pruning of the in-memory transfer registry.
//   * ZdcRateGuard()  — the basic per-window rate limit (throws when exceeded).
//   * a minimal seam to seed / count / reset the registry + rate state.
//
// The functions' logic + production call sites are UNCHANGED; this header only
// un-hides them (they were file-static). Nothing here weakens a guard. The
// verify-before-decrypt failure modes (ERR_NO_KEY / ERR_AEAD_FAIL /
// ERR_HASH_MISMATCH) and the fingerprint-grouping fallback that calls
// GetFilteredNotes are NOT exposed — they are codec-tested (test_zdc.cpp) and
// regtest-driven respectively.

#ifndef BITCOIN_RPC_DATACHANNEL_H
#define BITCOIN_RPC_DATACHANNEL_H

#include <stdint.h>
#include <cstddef>

// Drop every registry record older than the TTL (ZDC_INFLIGHT_TTL_SEC), wiping
// each dropped key. Caller need not hold cs_zdc here; the seam locks internally.
void ZdcTestExpireOld();

// Run the per-window rate guard exactly as z_senddatafile does; returns true if
// the call is admitted, false if the guard would have thrown (rate exceeded).
bool ZdcTestRateGuardAdmits();

// Test helpers (seed/inspect/reset) — no-ops for production paths.
void   ZdcTestSeedTransfer(uint64_t transferId, int64_t createdAt);
size_t ZdcTestTransferCount();
bool   ZdcTestHasTransfer(uint64_t transferId);
void   ZdcTestReset();

#endif // BITCOIN_RPC_DATACHANNEL_H
