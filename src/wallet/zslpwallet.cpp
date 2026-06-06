// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZSLP write path — shared OP_RETURN tx builder. See zslpwallet.h.

#include "wallet/zslpwallet.h"

#include "script/standard.h"   // CTxDestination — must precede coincontrol.h
#include "coincontrol.h"
#include "consensus/upgrades.h"
#include "key_io.h"
#include "main.h"
#include "script/sign.h"
#include "wallet/wallet.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"

#include <algorithm>

// ── Anti-burn coin-lock RAII ────────────────────────────────────────
//
// Lock every OTHER wallet token/baton outpoint for the duration of the build so
// AvailableCoins (which honors IsLockedCoin, wallet.cpp:3180) cannot auto-select
// it for fee/change. UNCONDITIONALLY released on every exit path (success,
// failure, exception) — a failed build must never leave the user's tokens
// locked (R-WALLET-6 / risk #6). Locks are in-memory only (setLockedCoins) so
// they also clear on restart, but unlock-on-throw is still mandatory.
namespace {
class ScopedTokenLock
{
public:
    ScopedTokenLock(CWallet* w) : wallet(w) {}
    ~ScopedTokenLock()
    {
        // cs_wallet is held by the caller for the whole build; LockCoin/UnlockCoin
        // assert it. We never throw here.
        for (size_t i = 0; i < locked.size(); ++i) {
            COutPoint op = locked[i];
            wallet->UnlockCoin(op);
        }
    }
    void lock(const COutPoint& op)
    {
        COutPoint tmp = op; // LockCoin takes a non-const reference
        wallet->LockCoin(tmp);
        locked.push_back(op);
    }
private:
    CWallet* wallet;
    std::vector<COutPoint> locked;
};
} // namespace

// Would the parsed SLP message `parsed` create a token UTXO or a mint baton at
// output index `vout`? This mirrors EXACTLY which outputs CZSLPStore::Apply-
// Transaction creates (so the 0-conf protection matches the confirmed truth the
// store will later record):
//   GENESIS: vout[1] iff initialQuantity>0 && voutCount>1; baton at mintBatonVout
//            iff 2<=mintBatonVout<voutCount.
//   MINT:    vout[1] iff additionalQuantity>0 && voutCount>1; baton likewise.
//   SEND:    vout[1+j] for each j in [0,numOutputs) with outputQuantities[j]>0
//            and 1+j<voutCount.
// It is intentionally INDEPENDENT of conservation/baton-input validity: an
// output the message NAMES as token-bearing must be protected from being spent
// as fee even before we know the carrying tx is ledger-valid (the wallet must
// not burn its own pending token-change on a follow-up spend). `voutCount` is
// the carrying tx's tx.vout.size().
static bool MsgWouldMakeTokenOutput(const CZSLPParsedMsg& parsed,
                                    int32_t voutCount, int32_t vout)
{
    switch (parsed.type) {
    case ZSLP_MSG_GENESIS:
        if (vout == 1 && parsed.initialQuantity > 0 && voutCount > 1)
            return true;
        if (vout == parsed.mintBatonVout && parsed.mintBatonVout >= 2 &&
            parsed.mintBatonVout < voutCount)
            return true;
        return false;
    case ZSLP_MSG_MINT:
        if (vout == 1 && parsed.additionalQuantity > 0 && voutCount > 1)
            return true;
        if (vout == parsed.mintBatonVout && parsed.mintBatonVout >= 2 &&
            parsed.mintBatonVout < voutCount)
            return true;
        return false;
    case ZSLP_MSG_SEND: {
        int n = parsed.numOutputs;
        for (int j = 0; j < n; ++j) {
            if (parsed.outputQuantities[j] > 0 && (int32_t)(1 + j) == vout &&
                vout < voutCount)
                return true;
        }
        return false;
    }
    default:
        return false;
    }
}

bool ZSLPIsProtectedTokenOutpoint(const CWallet* w, CZSLPStore* store,
                                  const COutPoint& op)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);

    // (1) CONFIRMED truth — the live indexer recorded a token UTXO/baton here.
    if (store != NULL) {
        CZSLPTokenUtxo rec;
        if (store->GetUtxo(op.hash, (int32_t)op.n, rec) &&
            (rec.amount > 0 || rec.isMintBaton))
            return true;
    }

    // (2) PENDING/0-conf truth — this is a token-bearing output of a wallet tx
    //     whose vout[0] parses as SLP, but the (ChainTip-only) indexer has not
    //     recorded it yet. Protect it so a follow-up spend cannot burn it.
    const CWalletTx* wtx = w->GetWalletTx(op.hash);
    if (wtx == NULL)
        return false;
    if ((size_t)op.n >= wtx->vout.size())
        return false;
    // Only the wallet's OWN created token outputs need this 0-conf cover; a
    // received token UTXO becomes confirmed before it is spendable and is then
    // covered by (1). Restricting to from-me also bounds the parse work.
    if (!wtx->IsFromMe(ISMINE_ALL))
        return false;
    CZSLPParsedMsg parsed;
    CZSLPToken genesisMeta;
    bool haveGenesisMeta = false;
    if (!CZSLPIndexer::ParseTx(*wtx, /*height=*/0, parsed, genesisMeta,
                               haveGenesisMeta))
        return false;
    return MsgWouldMakeTokenOutput(parsed, (int32_t)wtx->vout.size(),
                                   (int32_t)op.n);
}

bool ZSLPFindWalletTokenUtxos(CWallet* w, const uint256& tokenId,
                              bool wantBaton,
                              std::vector<ZSLPWalletUtxo>& out,
                              std::string& err)
{
    out.clear();
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);

    if (g_zslpIndexer == NULL || g_zslpIndexer->Store() == NULL) {
        err = "ZSLP index is not enabled. Start zclassicd with -zslpindex.";
        return false;
    }
    CZSLPStore* store = g_zslpIndexer->Store();

    std::vector<COutput> coins;
    // fExcludeZSLPTokens=false: we are LOOKING for token UTXOs; the global
    // anti-burn filter would otherwise drop the very coins we need.
    w->AvailableCoins(coins, /*fOnlyConfirmed=*/true, /*coinControl=*/NULL,
                      /*fIncludeZeroValue=*/false, /*fIncludeCoinBase=*/true,
                      /*fExcludeZSLPTokens=*/false);

    for (size_t i = 0; i < coins.size(); ++i) {
        const COutput& c = coins[i];
        if (!c.fSpendable)
            continue;
        CZSLPTokenUtxo rec;
        if (!store->GetUtxo(c.tx->GetHash(), c.i, rec))
            continue;
        if (rec.tokenId != tokenId)
            continue;
        if (wantBaton) {
            if (!rec.isMintBaton)
                continue;
        } else {
            if (rec.isMintBaton || rec.amount <= 0)
                continue;
        }
        ZSLPWalletUtxo u;
        u.outpoint = COutPoint(c.tx->GetHash(), c.i);
        u.tokenId = rec.tokenId;
        u.amount = rec.amount;
        u.isMintBaton = rec.isMintBaton;
        u.height = rec.height;
        out.push_back(u);
    }

    // Deterministic selection order (height, txid, vout).
    std::sort(out.begin(), out.end(),
              [](const ZSLPWalletUtxo& a, const ZSLPWalletUtxo& b) {
                  if (a.height != b.height) return a.height < b.height;
                  if (a.outpoint.hash != b.outpoint.hash)
                      return a.outpoint.hash < b.outpoint.hash;
                  return a.outpoint.n < b.outpoint.n;
              });
    return true;
}

bool BuildAndCommitZSLP(CWallet* w, const ZSLPBuildReq& req,
                        CWalletTx& wtxOut, std::string& err)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);

    // (0) Fail CLOSED if the index is off: without the store the wallet cannot
    //     classify dust / self-validate (R-WALLET-6).
    if (g_zslpIndexer == NULL || g_zslpIndexer->Store() == NULL) {
        err = "ZSLP index is not enabled. Start zclassicd with -zslpindex.";
        return false;
    }
    CZSLPStore* store = g_zslpIndexer->Store();

    // (1) Sanity on the request.
    if (req.opret.empty()) {
        err = "internal: empty OP_RETURN script (metadata too large or invalid)";
        return false;
    }
    if (req.opret.size() > MAX_OP_RETURN_RELAY) {
        err = "metadata too large for one OP_RETURN (max 223 bytes)";
        return false;
    }
    if (req.tokenOuts.empty()) {
        err = "internal: a ZSLP tx needs at least one token output";
        return false;
    }

    const CFeeRate& relayFee = ::minRelayTxFee;

    // (2) Anti-burn fence. Lock every OTHER wallet token/baton outpoint so the
    //     funding pool excludes them; pin the intended token inputs.
    ScopedTokenLock tokenLock(w);
    {
        std::set<COutPoint> intended(req.tokenInputs.begin(), req.tokenInputs.end());
        // Enumerate WITHOUT the global token filter so we can SEE the token
        // coins we need to lock (fExcludeZSLPTokens=false); the global filter
        // would otherwise have already dropped them.
        std::vector<COutput> allCoins;
        w->AvailableCoins(allCoins, true, NULL, false, true,
                          /*fExcludeZSLPTokens=*/false);
        for (size_t i = 0; i < allCoins.size(); ++i) {
            COutPoint op(allCoins[i].tx->GetHash(), allCoins[i].i);
            if (intended.count(op))
                continue; // pinned input — leave spendable
            // Confirmed token UTXO/baton OR a wallet's own pending (0-conf)
            // token output — both must be fenced off from fee/change selection.
            if (ZSLPIsProtectedTokenOutpoint(w, store, op))
                tokenLock.lock(op);
        }
    }

    CCoinControl cc;
    cc.fAllowOtherInputs = true;
    for (size_t i = 0; i < req.tokenInputs.size(); ++i)
        cc.Select(req.tokenInputs[i]);

    // (3) Sum of token-output dust (paid from fee coins) and a dust pre-check.
    CAmount dustTotal = 0;
    for (size_t i = 0; i < req.tokenOuts.size(); ++i) {
        CAmount d = req.tokenOuts[i].dustSats;
        CTxOut probe(d, req.tokenOuts[i].dest);
        if (probe.IsDust(relayFee)) {
            err = "internal: token output below the dust threshold";
            return false;
        }
        dustTotal += d;
    }

    // Value the token inputs contribute (they are ZEC dust outputs, spent as
    // inputs); SelectCoins counts them via the preset path, so the fee loop's
    // target already nets them out.

    CReserveKey reservekey(w);

    int nextBlockHeight = chainActive.Height() + 1;

    // (4) Fee + funding loop. Mirrors CreateTransaction's loop (wallet.cpp:3539-
    //     3788) but with the FIXED canonical layout and change appended LAST.
    CMutableTransaction txNew;
    CAmount nFeeRet = 0;
    std::set<std::pair<const CWalletTx*, unsigned int> > setCoins;
    bool reservedChangeKey = false;
    while (true) {
        txNew = CreateNewContextualCMutableTransaction(
            Params().GetConsensus(), nextBlockHeight);

        // Discourage fee sniping (same as CreateTransaction).
        txNew.nLockTime = std::max(0, chainActive.Height() - 10);
        assert(txNew.nLockTime <= (unsigned int)chainActive.Height());
        assert(txNew.nLockTime < LOCKTIME_THRESHOLD);

        // Target = dust outputs + fee (the OP_RETURN carries value 0). The token
        // inputs are pinned (preset) so SelectCoins already credits their ~546
        // sat each toward the target.
        CAmount nTarget = dustTotal + nFeeRet;

        setCoins.clear();
        CAmount nValueIn = 0;
        bool fOnlyCoinbase = false, fNeedCoinbase = false;
        if (!w->SelectCoins(nTarget, setCoins, nValueIn, fOnlyCoinbase,
                            fNeedCoinbase, &cc)) {
            if (fOnlyCoinbase && Params().GetConsensus().fCoinbaseMustBeProtected)
                err = "Coinbase funds can only be sent to a zaddr";
            else if (fNeedCoinbase)
                err = "Insufficient funds (coinbase must be shielded first)";
            else
                err = "Insufficient funds to pay the dust outputs + network fee";
            return false;
        }

        // (4a) Build the canonical layout from scratch each pass.
        txNew.vin.clear();
        txNew.vout.clear();

        // vout[0] = OP_RETURN (value 0).
        txNew.vout.push_back(CTxOut(0, req.opret));
        // vout[1..N] = token outputs in canonical order.
        for (size_t i = 0; i < req.tokenOuts.size(); ++i)
            txNew.vout.push_back(CTxOut(req.tokenOuts[i].dustSats,
                                        req.tokenOuts[i].dest));

        // (4b) ZEC change appended STRICTLY at the tail (never index 0, never
        //      between token outputs).
        CAmount nChange = nValueIn - dustTotal - nFeeRet;
        if (nChange > 0) {
            CScript scriptChange;
            CPubKey vchPubKey;
            // Clean failure (NOT assert) on keypool exhaustion: GetReservedKey
            // returns false when the keypool is empty (a locked wallet cannot
            // refill it). assert() would crash the node, and is a no-op under
            // NDEBUG (then proceeding with an invalid CPubKey). The RAII guard
            // unlocks any locked tokens on this early return.
            if (!reservekey.GetReservedKey(vchPubKey)) {
                err = "Keypool ran out, call keypoolrefill first";
                return false;
            }
            reservedChangeKey = true;
            scriptChange = GetScriptForDestination(vchPubKey.GetID());

            CTxOut changeOut(nChange, scriptChange);
            if (changeOut.IsDust(relayFee)) {
                // Fold dust change into the fee (matches CreateTransaction
                // wallet.cpp:3672-3676). No change output is added.
                nFeeRet += nChange;
                reservekey.ReturnKey();
                reservedChangeKey = false;
            } else {
                txNew.vout.push_back(changeOut); // tail position guaranteed
            }
        } else {
            reservekey.ReturnKey();
            reservedChangeKey = false;
        }

        // (4c) Fill vin (sequence max()-1 so nLockTime works), as
        //      CreateTransaction does.
        for (std::set<std::pair<const CWalletTx*, unsigned int> >::iterator
                 it = setCoins.begin(); it != setCoins.end(); ++it) {
            txNew.vin.push_back(CTxIn(it->first->GetHash(), it->second, CScript(),
                                      std::numeric_limits<unsigned int>::max() - 1));
        }

        // (4d) Sign each input (mirror wallet.cpp:3712-3737). Signing is the
        //      LAST step because moving any output invalidates every sig.
        uint32_t consensusBranchId =
            CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());
        CTransaction txConst(txNew);
        int nIn = 0;
        bool signOk = true;
        for (std::set<std::pair<const CWalletTx*, unsigned int> >::iterator
                 it = setCoins.begin(); it != setCoins.end(); ++it) {
            const CScript& spk = it->first->vout[it->second].scriptPubKey;
            CAmount amt = it->first->vout[it->second].nValue;
            SignatureData sigdata;
            if (!ProduceSignature(
                    TransactionSignatureCreator(w, &txConst, nIn, amt, SigHashType()),
                    spk, sigdata, consensusBranchId)) {
                signOk = false;
                break;
            }
            UpdateTransaction(txNew, nIn, sigdata);
            nIn++;
        }
        if (!signOk) {
            err = "Signing transaction failed";
            return false;
        }

        unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
        CAmount nFeeNeeded = w->GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
        if (nFeeRet >= nFeeNeeded)
            break; // enough fee — layout finalized.
        nFeeRet = nFeeNeeded;
        // Loop again: a higher fee changes the target/selection. If we had
        // reserved a change key this pass, ReturnKey it so we don't leak keys.
        if (reservedChangeKey) {
            reservekey.ReturnKey();
            reservedChangeKey = false;
        }
    }

    const CTransaction finalTx(txNew);

    // (5) Defensive anti-burn post-check (R-WALLET-3): no FEE input is a live
    //     token/baton of any token (only the explicitly pinned token inputs may
    //     be token UTXOs).
    {
        std::set<COutPoint> intended(req.tokenInputs.begin(), req.tokenInputs.end());
        for (size_t k = 0; k < finalTx.vin.size(); ++k) {
            const COutPoint& op = finalTx.vin[k].prevout;
            if (intended.count(op))
                continue;
            // Catches both confirmed token UTXOs/batons and the wallet's own
            // pending (0-conf) token-change a prior ZSLP build produced.
            if (ZSLPIsProtectedTokenOutpoint(w, store, op)) {
                err = "anti-burn: a funding input is a live token UTXO/baton — refusing to broadcast";
                return false;
            }
        }
    }

    // (6) SELF-VALIDATE the FINAL signed tx with the REAL indexer parse +
    //     read-only conservation (R-WALLET-9). Refuse to broadcast on mismatch.
    {
        CZSLPParsedMsg parsed;
        CZSLPToken genesisMeta;
        bool haveGenesisMeta = false;
        // Use the EXACT production parse seam (vout[0]-only).
        if (!CZSLPIndexer::ParseTx(finalTx, nextBlockHeight, parsed, genesisMeta,
                                   haveGenesisMeta)) {
            err = "self-validate: built tx has no parsable SLP message at vout[0]";
            return false;
        }

        // The parsed token must be the one we intended to act on.
        const uint256 expectId = req.isGenesis ? finalTx.GetHash()
                                               : req.selfValidateTokenId;
        if (req.isGenesis) {
            if (parsed.type != ZSLP_MSG_GENESIS) {
                err = "self-validate: expected GENESIS message";
                return false;
            }
            // GENESIS tokenId == txid (the indexer sets parsed.tokenId = txid).
            if (parsed.tokenId != expectId) {
                err = "self-validate: GENESIS token id mismatch";
                return false;
            }
        } else {
            if (parsed.type == ZSLP_MSG_GENESIS) {
                err = "self-validate: unexpected GENESIS message";
                return false;
            }
            if (parsed.tokenId != expectId) {
                err = "self-validate: message token id does not match the intended token";
                return false;
            }
        }

        std::vector<COutPoint> vin;
        vin.reserve(finalTx.vin.size());
        for (size_t k = 0; k < finalTx.vin.size(); ++k)
            vin.push_back(finalTx.vin[k].prevout);

        std::string reason;
        if (!store->WouldBeValid(vin, &parsed, finalTx.GetHash(),
                                 haveGenesisMeta ? &genesisMeta : NULL,
                                 (int32_t)finalTx.vout.size(), reason)) {
            err = "self-validate: built tx would not be valid in the token ledger (" +
                  reason + ")";
            return false;
        }
    }

    // (7) Embed + commit. Only now do we broadcast.
    *static_cast<CTransaction*>(&wtxOut) = finalTx;
    wtxOut.BindWallet(w);
    wtxOut.fFromMe = true;
    wtxOut.fTimeReceivedIsTxTime = true;

    if (!w->CommitTransaction(wtxOut, reservekey)) {
        err = "CommitTransaction failed (tx was signed + self-validated but rejected by mempool)";
        return false;
    }
    return true;
}
