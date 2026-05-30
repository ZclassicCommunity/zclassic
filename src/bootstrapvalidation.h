// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BOOTSTRAPVALIDATION_H
#define BITCOIN_BOOTSTRAPVALIDATION_H

#include "uint256.h"

#include <boost/thread.hpp>

class CScheduler;

// Background full-validation of a trustless (option B) bootstrap snapshot.
//
// A node that accepts a self-snapshot in -bootstrapmode=trustless starts using it
// PROVISIONALLY, then a background thread re-derives the UTXO set from genesis to
// the snapshot height using the already-imported block data and compares it
// (CCoinsViewDB::GetStats().hashSerialized) to the digest captured at import
// (S_imported). On a match the snapshot LATCHES validated; on a mismatch it is
// FAILED and the node reindexes from local block data on the next start, falling
// back to a fully validated chain with no operator involvement. The latch is
// durable in the block tree DB, so a crash never silently assumes "validated".
enum BootstrapValidationState {
    BVS_DISABLED = 0,            //!< no trustless snapshot in play
    BVS_PROVISIONAL = 1,         //!< accepted provisionally; validating in background
    BVS_VALIDATED = 2,           //!< re-derived UTXO set matched; fully trusted
    BVS_FAILED = 3,             //!< re-derived UTXO set mismatched; reindex queued
    BVS_PROVISIONAL_PRUNED = 4,  //!< cannot re-derive (pruned); stays provisional
};

struct BootstrapValidationStatus {
    int state;
    int height;          //!< snapshot tip height H
    int validatedHeight; //!< highest height re-derived so far (progress)
    uint256 hashBlock;   //!< snapshot tip hash
    uint256 commitment;  //!< S_imported (advertised + verified at import)

    BootstrapValidationStatus() : state(BVS_DISABLED), height(-1), validatedHeight(-1) {}
};

//! Load the persisted validation record from pblocktree into memory. Call once
//! after the chain databases are opened, before starting the thread.
void LoadBootstrapValidationState();

//! Record a freshly provisional-accepted trustless snapshot (sets PROVISIONAL and
//! persists H, tip hash, and S_imported). Call from init right after the
//! provisional gate passes, while the tip is still exactly at H.
void BeginBootstrapValidation(int height, const uint256& hashBlock, const uint256& sImported);

//! If a snapshot awaits validation (PROVISIONAL) and the node is not pruned, spawn
//! the background validation thread and register the failure->reindex poll. No-op
//! otherwise. Call after StartNode().
void MaybeStartBootstrapValidation(CScheduler& scheduler);

//! Cheap copy of the current status for RPC/logging.
BootstrapValidationStatus GetBootstrapValidationStatus();

//! True while finalization must be PAUSED because of a bootstrap import. Lock-free,
//! safe to call from the consensus path under cs_main. It is the OR of two
//! independent conditions:
//!   (a) a trustless-imported snapshot is still PROVISIONAL (background re-derivation
//!       not yet complete, including the pruned-and-stuck case); and
//!   (b) the "imported tip unconfirmed" hold: this node imported blocks ABOVE the
//!       last compiled checkpoint that it did not validate live, and the live
//!       network has not yet corroborated that tip (see ArmBootstrapTipHold).
//! Pausing auto-finalization keeps the reorg-depth rule from permanently pinning the
//! node to an as-yet-unproven (possibly forged / minority-fork) imported chain before
//! it has converged with the majority. Always false on a normal node that never
//! imported an above-checkpoint snapshot, so the finalization path is byte-identical
//! to upstream there.
bool BootstrapValidationHoldsFinalization();

//! Arm the "imported tip unconfirmed" finalization hold for a node that just imported
//! blocks up to (height, hashBlock) ABOVE the last compiled checkpoint (trustless or
//! growable). Durable: persisted under its own block-tree key and re-armed on restart
//! until the live network corroborates the tip. No-op (and MUST NOT be called) for a
//! pure-anchor import whose tip == a compiled checkpoint. Call at accept time, before
//! the first ConnectTip, while the imported tip is the active tip.
void ArmBootstrapTipHold(int height, const uint256& hashBlock);

//! Clear the imported-tip hold (live network corroborated the tip, or the imported
//! chain was reorged away). Idempotent; clears the durable key.
void ReleaseBootstrapTipHold();

//! The (height, hash) of the armed imported-tip hold, or height<0 if none is armed.
void GetBootstrapTipHold(int& height, uint256& hashBlock);

//! Scheduler poll (registered when a tip hold is armed): under cs_main, evaluate
//! whether the live network has corroborated the imported tip and, if so, release the
//! hold. Safe no-op when no hold is armed.
void EvaluateBootstrapTipRelease();

//! Interrupt and JOIN the background validation thread (if running). Must be
//! called during Shutdown() BEFORE the chain databases (pblocktree/pcoinsTip) are
//! freed, on both the normal and the init-failure path, so the thread cannot race
//! into freed state (use-after-free). No-op if the thread was never started.
void InterruptBootstrapValidation();

#endif // BITCOIN_BOOTSTRAPVALIDATION_H
