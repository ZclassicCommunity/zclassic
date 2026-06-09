// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// ZNAM (ZCL Names) write path — the vin[0]-owner-pinned OP_RETURN tx builder.
// See znamwallet.h / wallet.h (ZNAMBuildReq + BuildAndCommitZNAM).
//
// NON-consensus: builds an ordinary transparent payment carrying one ZNAM
// OP_RETURN at vout[0]. The builder's whole job is determinism + safety:
//   (a) vin[0] = the OWNER's plain UTXO, so the indexer derives the intended FIFS
//       owner (vin[0] P2PKH signer); funding/fee coins follow at vin[1..];
//   (b) fee coins exclude token/NFT UTXOs (anti-burn) — AvailableCoins' global
//       filter already drops them, and the owner input is required to be plain;
//   (c) ZEC change returns to the OWNER address (keeps it funded to manage the
//       name later) at the tail (never vout[0]);
//   (d) self-validate the FINAL signed tx with the REAL CZNAMIndexer::ParseTx
//       (command+name match) and confirm vin[0] maps to the expected owner, and
//       only then broadcast.

#include "wallet/znamwallet.h"

#include "script/standard.h"   // CTxDestination — must precede coincontrol.h
#include "coincontrol.h"
#include "consensus/upgrades.h"
#include "key_io.h"
#include "main.h"
#include "script/sign.h"
#include "wallet/wallet.h"
#include "wallet/zslpwallet.h"  // ZSLPAddrFromScript (generic script->addr decode)
#include "znam/znamindexer.h"   // CZNAMIndexer::ParseTx / ExtractP2PKHOwnerFromScript
#include "znam/znammsg.h"

#include <limits>
#include <utility>
#include <vector>

bool ZNAMFindOwnerInput(CWallet* w, std::string& ownerAddr,
                        COutPoint& out, CScript& outScript, std::string& err)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);

    std::vector<COutput> coins;
    // fExcludeZSLPTokens=true: never pick a token/NFT UTXO as the owner input
    // (spending it would burn the token). Coinbase is usable as a transparent
    // owner input ONLY where the chain permits transparent coinbase spends
    // (regtest); on mainnet/testnet coinbase must be shielded first, so exclude it.
    const bool includeCoinbase = !Params().GetConsensus().fCoinbaseMustBeProtected;
    w->AvailableCoins(coins, /*fOnlyConfirmed=*/true, /*coinControl=*/NULL,
                      /*fIncludeZeroValue=*/false, /*fIncludeCoinBase=*/includeCoinbase,
                      /*fExcludeZSLPTokens=*/true);

    int bestIdx = -1;
    CAmount bestVal = -1;
    std::string bestAddr;
    for (size_t i = 0; i < coins.size(); ++i) {
        const COutput& c = coins[i];
        if (!c.fSpendable)
            continue;
        const CTxOut& txout = c.tx->vout[c.i];
        std::string addr = ZSLPAddrFromScript(txout.scriptPubKey);
        if (addr.empty())
            continue; // not a standard extractable t-address
        if (!ownerAddr.empty() && addr != ownerAddr)
            continue; // a specific owner was requested
        if (txout.nValue > bestVal) {
            bestVal = txout.nValue;
            bestIdx = (int)i;
            bestAddr = addr;
        }
    }
    if (bestIdx < 0) {
        err = ownerAddr.empty()
            ? std::string("the wallet has no plain spendable (confirmed, non-NFT, "
                          "non-coinbase) UTXO to register a name from; receive some ZCL first")
            : ("owner address " + ownerAddr + " has no plain spendable (confirmed, "
               "non-NFT, non-coinbase) UTXO; send a small amount of ZCL to it first "
               "so it can sign name operations");
        return false;
    }
    const COutput& chosen = coins[bestIdx];
    out = COutPoint(chosen.tx->GetHash(), chosen.i);
    outScript = chosen.tx->vout[chosen.i].scriptPubKey;
    if (ownerAddr.empty())
        ownerAddr = bestAddr; // report the chosen default owner
    return true;
}

bool BuildAndCommitZNAM(CWallet* w, const ZNAMBuildReq& req,
                        CWalletTx& wtxOut, std::string& err)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(w->cs_wallet);

    // (1) Sanity on the request.
    if (req.opret.empty()) {
        err = "internal: empty OP_RETURN script (ZNAM metadata too large or invalid)";
        return false;
    }
    if (req.opret.size() > MAX_OP_RETURN_RELAY) {
        err = "ZNAM metadata too large for one OP_RETURN (max 223 bytes)";
        return false;
    }
    if (req.ownerInput.IsNull()) {
        err = "internal: no owner input pinned for vin[0]";
        return false;
    }
    // The pinned input MUST map to the intended P2PKH owner (this is what the
    // indexer will derive from vin[0]); fail closed if not.
    {
        std::string derived;
        if (!CZNAMIndexer::ExtractP2PKHOwnerFromScript(req.ownerScript, derived) ||
            derived != req.expectedOwner) {
            err = "internal: owner input is not the expected P2PKH owner";
            return false;
        }
    }

    const CFeeRate& relayFee = ::minRelayTxFee;
    const unsigned int kSeq = std::numeric_limits<unsigned int>::max() - 1;

    // Pin the owner UTXO; allow other wallet coins for the fee.
    CCoinControl cc;
    cc.fAllowOtherInputs = true;
    cc.Select(req.ownerInput);

    CReserveKey reservekey(w); // unused (change returns to owner) — harmless to pass
    int nextBlockHeight = chainActive.Height() + 1;

    CMutableTransaction txNew;
    CAmount nFeeRet = 0;
    std::set<std::pair<const CWalletTx*, unsigned int> > setCoins;

    // (2) Fee + funding loop (mirrors BuildAndCommitZSLP). No dust outputs: the
    //     OP_RETURN carries value 0, so the only target is the network fee.
    while (true) {
        txNew = CreateNewContextualCMutableTransaction(
            Params().GetConsensus(), nextBlockHeight);
        txNew.nLockTime = std::max(0, chainActive.Height() - 10); // discourage fee-sniping
        assert(txNew.nLockTime <= (unsigned int)chainActive.Height());

        CAmount nTarget = nFeeRet;
        setCoins.clear();
        CAmount nValueIn = 0;
        bool fOnlyCoinbase = false, fNeedCoinbase = false;
        if (!w->SelectCoins(nTarget, setCoins, nValueIn, fOnlyCoinbase,
                            fNeedCoinbase, &cc)) {
            if (fOnlyCoinbase && Params().GetConsensus().fCoinbaseMustBeProtected)
                err = "Coinbase funds can only be sent to a zaddr; shield first";
            else if (fNeedCoinbase)
                err = "Insufficient funds (coinbase must be shielded first)";
            else
                err = "Insufficient funds to pay the network fee for the name operation";
            return false;
        }

        // Locate the owner entry inside setCoins (SelectCoins includes the
        // preset/pinned input).
        const CWalletTx* ownerWtx = NULL;
        std::vector<std::pair<const CWalletTx*, unsigned int> > others;
        for (std::set<std::pair<const CWalletTx*, unsigned int> >::iterator
                 it = setCoins.begin(); it != setCoins.end(); ++it) {
            if (it->first->GetHash() == req.ownerInput.hash &&
                it->second == req.ownerInput.n) {
                ownerWtx = it->first;
            } else {
                others.push_back(*it);
            }
        }
        if (ownerWtx == NULL) {
            err = "internal: owner input was not selected by coin control";
            return false;
        }

        // (2a) Outputs: vout[0] = OP_RETURN(0); change (if any) to the OWNER
        //      address at the tail.
        txNew.vin.clear();
        txNew.vout.clear();
        txNew.vout.push_back(CTxOut(0, req.opret));
        CAmount nChange = nValueIn - nFeeRet;
        if (nChange > 0) {
            CTxOut changeOut(nChange, req.ownerScript);
            if (changeOut.IsDust(relayFee))
                nFeeRet += nChange;      // fold dust change into the fee
            else
                txNew.vout.push_back(changeOut);
        }

        // (2b) Inputs: OWNER FIRST (vin[0] = the FIFS signer), then the rest in a
        //      stable order. Build a parallel (scriptPubKey, amount) list for
        //      signing in the exact same order.
        std::vector<std::pair<CScript, CAmount> > inMeta;
        txNew.vin.push_back(CTxIn(req.ownerInput.hash, req.ownerInput.n, CScript(), kSeq));
        inMeta.push_back(std::make_pair(req.ownerScript,
                                        ownerWtx->vout[req.ownerInput.n].nValue));
        for (size_t k = 0; k < others.size(); ++k) {
            const CWalletTx* tx = others[k].first;
            unsigned int n = others[k].second;
            txNew.vin.push_back(CTxIn(tx->GetHash(), n, CScript(), kSeq));
            inMeta.push_back(std::make_pair(tx->vout[n].scriptPubKey, tx->vout[n].nValue));
        }

        // (2c) Sign each input in vin order (last step — moving any output or
        //      input invalidates every signature).
        uint32_t consensusBranchId =
            CurrentEpochBranchId(chainActive.Height() + 1, Params().GetConsensus());
        CTransaction txConst(txNew);
        bool signOk = true;
        for (int nIn = 0; nIn < (int)inMeta.size(); ++nIn) {
            SignatureData sigdata;
            if (!ProduceSignature(
                    TransactionSignatureCreator(w, &txConst, nIn, inMeta[nIn].second,
                                                SigHashType()),
                    inMeta[nIn].first, sigdata, consensusBranchId)) {
                signOk = false;
                break;
            }
            UpdateTransaction(txNew, nIn, sigdata);
        }
        if (!signOk) {
            err = "Signing the name transaction failed (is the wallet unlocked and "
                  "does it hold the owner key?)";
            return false;
        }

        unsigned int nBytes = ::GetSerializeSize(txNew, SER_NETWORK, PROTOCOL_VERSION);
        CAmount nFeeNeeded = w->GetMinimumFee(nBytes, nTxConfirmTarget, mempool);
        if (nFeeRet >= nFeeNeeded)
            break; // enough fee — layout finalized
        nFeeRet = nFeeNeeded; // loop: a higher fee changes the target/selection
    }

    const CTransaction finalTx(txNew);

    // (3) SELF-VALIDATE with the REAL production parse seam: the built tx must
    //     carry exactly the intended ZNAM command+name, and vin[0] must be the
    //     pinned owner input (so the indexer derives the expected owner).
    {
        ZNAMMessage parsed;
        int32_t recordVout = -1;
        if (!CZNAMIndexer::ParseTx(finalTx, parsed, recordVout)) {
            err = "self-validate: built tx has no parsable ZNAM record";
            return false;
        }
        if ((int)parsed.command != req.expectedCommand ||
            parsed.name != req.expectedName) {
            err = "self-validate: built ZNAM record does not match the request";
            return false;
        }
        if (finalTx.vin.empty() ||
            finalTx.vin[0].prevout != req.ownerInput) {
            err = "self-validate: owner input is not at vin[0]";
            return false;
        }
    }

    // (4) Embed + commit. Only now do we broadcast.
    *static_cast<CTransaction*>(&wtxOut) = finalTx;
    wtxOut.BindWallet(w);
    wtxOut.fFromMe = true;
    wtxOut.fTimeReceivedIsTxTime = true;
    if (!w->CommitTransaction(wtxOut, reservekey)) {
        err = "CommitTransaction failed (tx was signed + self-validated but rejected "
              "by mempool)";
        return false;
    }
    return true;
}
