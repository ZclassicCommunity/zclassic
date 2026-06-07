// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP write path — the shared OP_RETURN transaction builder.
//
// NON-consensus: this builds an ordinary transparent payment that carries one
// SLP OP_RETURN at vout[0]; unchanged ZClassic nodes relay and mine it. The
// builder's whole job is to make the *overlay* ledger effect deterministic and
// burn-proof:
//   (a) fixed layout  vout[0]=OP_RETURN(value 0), vout[1..N]=token recipients
//       (dust), ZEC change STRICTLY after the token outputs (or none) — the
//       stock CWallet::CreateTransaction inserts change at a RANDOM index
//       (wallet.cpp:3680), which would land at vout[0] or between token outputs
//       and burn/mis-credit the token;
//   (b) anti-burn funding — token UTXOs and mint batons are pinned (intended
//       inputs) or excluded (everything else) so no token rides a fee/change
//       coin into a burn;
//   (c) self-validate the FINAL signed tx with the REAL indexer parse
//       (CZSLPIndexer::ParseTx) + the read-only CZSLPStore::WouldBeValid
//       conservation check, and refuse to broadcast on any mismatch (R-WALLET-9).
//
// The single entry point BuildAndCommitZSLP and its ZSLPBuildReq live in
// wallet.h (BuildAndCommitZSLP is a friend of CWallet so it can reach the
// private SelectCoins seam). This header only carries the small dust constant
// and the wallet-side token-UTXO enumeration helper that the RPCs share.

#ifndef BITCOIN_WALLET_ZSLPWALLET_H
#define BITCOIN_WALLET_ZSLPWALLET_H

#include "amount.h"
#include "primitives/transaction.h" // COutPoint
#include "script/script.h"          // CScript (helper return type)
#include "uint256.h"

#include <stdint.h>
#include <string>
#include <vector>

class CWallet;
class CZSLPStore;
class UniValue;

// Standard SLP/BCH dust convention: 546 sat per token-bearing output. The
// 54-sat relay dust floor (transaction.h:452-467 with the default
// -minrelaytxfee) leaves ~10x headroom; the builder also asserts dynamically
// that 546 is not dust under the active fee rate before using it.
static const CAmount SLP_TOKEN_DUST = 546;

/**
 * On-chain (big-endian / display) byte order of a daemon uint256 — the inverse
 * of the indexer's TokenIdToUint256. This is what the SLP MINT/SEND encoders
 * (ZSLPBuildMint / ZSLPBuildSend) expect for a token id. Shared (DRY) by
 * rpc/zslp.cpp (mint/send) and rpc/nftoffer.cpp (the sell template's vout[0]),
 * so the reversal lives in exactly one place.
 */
inline void ZSLPTokenIdToBE(const uint256& tokenId, uint8_t out[32])
{
    const unsigned char* p = tokenId.begin(); // internal little-endian
    for (int i = 0; i < 32; ++i)
        out[i] = p[31 - i];
}

/** A wallet token UTXO discovered by intersecting AvailableCoins with the store. */
struct ZSLPWalletUtxo {
    COutPoint outpoint;
    uint256 tokenId;
    int64_t amount;     //!< 0 for a baton
    bool isMintBaton;
    int64_t height;     //!< for deterministic (height,txid,vout) selection order
};

/**
 * Enumerate the wallet's spendable, confirmed token UTXOs for `tokenId`
 * (the §2.5 intersection: AvailableCoins ∩ store->GetUtxo). When `wantBaton`
 * is true, returns ONLY the live mint baton(s); otherwise returns ONLY
 * quantity-bearing UTXOs (amount>0, never the baton). Sorted deterministically
 * by (height, txid, vout). Requires cs_main + the wallet's cs_wallet held and
 * the ZSLP index enabled (returns false with `err` set otherwise).
 */
bool ZSLPFindWalletTokenUtxos(CWallet* w, const uint256& tokenId,
                              bool wantBaton,
                              std::vector<ZSLPWalletUtxo>& out,
                              std::string& err);

/**
 * The ONE token-UTXO classifier shared by the global anti-burn filter
 * (CWallet::AvailableCoins, R-WALLET-2/4/5), the builder's pin/exclude fence
 * and its pre-broadcast post-check (R-WALLET-3). Returns true IFF `op` carries
 * (or would carry) a live ZSLP token quantity or a mint baton, so it MUST NOT
 * be spent as an ordinary fee/change coin.
 *
 * It is the union of TWO sources, because the indexer's confirmed store alone
 * misses just-created (0-conf) token-change:
 *   (1) CONFIRMED truth — the store reports a live token UTXO/baton at `op`
 *       (amount>0 || isMintBaton).
 *   (2) PENDING/0-conf truth — `op` is a token-bearing output of a wallet
 *       transaction whose vout[0] parses (via the REAL CZSLPIndexer::ParseTx,
 *       vout[0]-only) as an SLP GENESIS/MINT/SEND, and `op.n` is one of the
 *       output indices that message would create as a token UTXO or baton
 *       (computed exactly as CZSLPStore::ApplyTransaction would). This protects
 *       the token-change a zslp_send/mint/genesis just produced before it
 *       confirms (the indexer is ChainTip-only, so the store has no row yet).
 *
 * `store` may be NULL (index off): source (1) is skipped but source (2) still
 * protects the wallet's own pending ZSLP outputs. Requires cs_main + w->cs_wallet.
 */
bool ZSLPIsProtectedTokenOutpoint(const CWallet* w, CZSLPStore* store,
                                  const COutPoint& op);

// ── Shared RPC helpers (B-1/B-2: ONE canonical copy for both rpc/zslp.cpp and
//    rpc/nftoffer.cpp) ────────────────────────────────────────────────────
//
// These were previously duplicated in each RPC TU (verbatim, only re-prefixed to
// dodge a symbol clash). They are load-bearing: they build the real scriptPubKeys
// for token carriers + the sell template and gate every command on the index.
// Defined once in zslpwallet.cpp so the bound/behavior cannot drift.

/**
 * The ZSLP token store, or a friendly JSONRPCError(RPC_MISC_ERROR) when the
 * NON-consensus index is off. Fails CLOSED: every ZSLP/NFT command starts here.
 */
CZSLPStore* ZSLPStoreOrThrow();

/**
 * Decode a transparent (t-) address to its P2PKH/P2SH scriptPubKey. Throws
 * JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY) on an invalid address.
 */
CScript ZSLPScriptForTAddr(const std::string& addr);

/**
 * Reserve a fresh wallet t-address scriptPubKey (default recipient / token-
 * change / payout). Throws JSONRPCError(RPC_WALLET_KEYPOOL_RAN_OUT) if the
 * keypool is empty. ENABLE_WALLET only.
 */
CScript ZSLPFreshWalletScript();

/**
 * Decode a scriptPubKey back to a t-address string ("" if not a standard,
 * extractable destination).
 */
std::string ZSLPAddrFromScript(const CScript& spk);

/**
 * Parse a non-negative integer money/quantity field from a JSON value that is a
 * STRING or a small integer (digits-only, overflow-guarded). The ONE shared
 * amount parser (B-1): callers pass their own inclusive upper bound and the
 * "what" phrase used in the over-bound message, so each call site PRESERVES its
 * historical bound + wording exactly. Throws JSONRPCError on any violation.
 *
 *   maxInclusive  the largest accepted value (inclusive)
 *   what          the upper-bound phrase, e.g. "the maximum (2^63-1)" or
 *                 "MAX_MONEY" — rendered as: <field> exceeds <what>
 *   unitNote      optional suffix on the digits-only rejection, e.g. " (zatoshi)"
 *                 so NftParseZat keeps its exact historical wording ("" by default)
 */
int64_t ZSLPParseAmountField(const UniValue& v, const std::string& field,
                             int64_t maxInclusive, const char* what,
                             const char* unitNote = "");

#endif // BITCOIN_WALLET_ZSLPWALLET_H
