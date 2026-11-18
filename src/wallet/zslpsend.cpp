// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/zslpsend.h"

#include "chain.h"
#include "core_io.h"
#include "key_io.h"
#include "main.h"
#include "script/standard.h"
#include "tinyformat.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "wallet/tokenguard.h"
#include "wallet/wallet.h"
#include "coincontrol.h"
#include "zslp/zslpindex.h"
#include "zslp/zslpservice.h"

#include <algorithm>
#include <set>

namespace zslp {

namespace {

struct TokenCoin {
    COutPoint op;
    uint64_t units;
    CAmount value;
    CScript script;
    int depth;
    TokenCoin() : units(0), value(0), depth(0) {}
};

bool CoinBefore(const TokenCoin& a, const TokenCoin& b)
{
    // larger quantities first; ties by outpoint so the choice is deterministic
    if (a.units != b.units)
        return a.units > b.units;
    if (a.op.hash != b.op.hash)
        return a.op.hash < b.op.hash;
    return a.op.n < b.op.n;
}

bool Fail(std::string& err, WalletErrKind& kind, WalletErrKind k, const std::string& why)
{
    err = why;
    kind = k;
    return false;
}

/** What a built transaction must look like, decided before it is built. */
struct Expect {
    int type;                   //! message type 1/2/3
    bool genesis;               //! the token id is the transaction's own id
    uint256 token;
    uint64_t inputUnits;        //! SEND only
    bool checkInputUnits;
    uint64_t createdTokenUnits; //! sum of the token outputs it creates
    unsigned int createdBatons;
    uint64_t minted;
    uint64_t burned;
    Expect() : type(0), genesis(false), inputUnits(0), checkInputUnits(false), createdTokenUnits(0), createdBatons(0),
               minted(0), burned(0) {}
};

bool DecodeTransparent(const std::string& text, CScript& script, std::string& err)
{
    if (text.empty()) {
        err = "the address is empty";
        return false;
    }
    if (!IsValidDestinationString(text)) {
        if (IsValidPaymentAddressString(text))
            err = strprintf("%s is a shielded address; ZSLP tokens live on transparent outputs and can only be sent to a transparent (t) address", text);
        else
            err = strprintf("%s is not a valid ZClassic transparent address", text);
        return false;
    }
    script = GetScriptForDestination(DecodeDestination(text));
    return true;
}

std::string AddressOfScript(const CScript& script)
{
    CTxDestination d;
    if (!ExtractDestination(script, d))
        return "";
    return EncodeDestination(d);
}

/** Chain data in an error message: printable ASCII only. */
std::string Printable(const std::string& s)
{
    std::string r;
    for (size_t i = 0; i < s.size() && i < 32; i++)
        r += (s[i] >= 0x20 && s[i] < 0x7f) ? s[i] : (char)63;
    return r;
}

/** The index must exist, be free of errors, and be at the active tip (cs_main held). */
bool RequireCurrentIndex(ZslpService& svc, std::string& err, WalletErrKind& kind)
{
    const ServiceInfo si = svc.GetInfo();
    if (!si.error.empty())
        return Fail(err, kind, ERRK_STATE, "the ZSLP token index reports a problem (" + si.error + "); token transactions are refused until it is healthy");
    if (!si.synced)
        return Fail(err, kind, ERRK_STATE,
                    strprintf("the ZSLP token index is not synced yet (indexed height %d, chain height %d); wait for zslp_getindexinfo to say synced",
                              si.hasIndexed ? si.indexedHeight : -1, si.chainHeight));
    return true;
}

/** This wallet's confirmed, spendable outputs that the index holds as unspent outputs of `token` with `role`. */
void GatherCoins(CWallet* wallet, const ZslpIndex& idx, const uint256& token, int role, int minconf,
                 std::vector<TokenCoin>& out)
{
    out.clear();
    std::vector<COutput> coins;
    // fIncludeZeroValue: a token or baton output may carry 0 zatoshi (consensus allows it, relay calls it dust).
    // zslp_listunspent counts it, so the send paths must find it too; the checks below keep only real token outputs.
    wallet->AvailableCoins(coins, true, NULL, true, false);
    for (size_t i = 0; i < coins.size(); i++) {
        const COutput& c = coins[i];
        if (!c.fSpendable || c.nDepth < std::max(1, minconf))
            continue;
        if (!c.tx->IsTokenBearingOutput(c.i))
            continue; // the wallet token guard is a superset of the index: skip the store lookup for ordinary coins
        OutInfo oi;
        if (!idx.GetOutput(c.tx->GetHash(), c.i, oi) || oi.token != token || oi.role != role)
            continue;
        TokenCoin tc;
        tc.op = COutPoint(c.tx->GetHash(), c.i);
        tc.units = oi.amount;
        tc.value = c.tx->vout[c.i].nValue;
        tc.script = c.tx->vout[c.i].scriptPubKey;
        tc.depth = c.nDepth;
        out.push_back(tc);
    }
    std::sort(out.begin(), out.end(), CoinBefore);
}

bool SumUnits(const std::vector<TokenCoin>& v, uint64_t& sum)
{
    sum = 0;
    for (size_t i = 0; i < v.size(); i++) {
        if (v[i].units > MAX_QUANTITY - sum)
            return false;
        sum += v[i].units;
    }
    return true;
}

/** Fewest inputs: one that matches exactly (no change), else the largest first until covered. */
bool PickInputs(const std::vector<TokenCoin>& all, uint64_t need, std::vector<TokenCoin>& picked, uint64_t& have)
{
    picked.clear();
    have = 0;
    for (size_t i = 0; i < all.size(); i++) {
        if (all[i].units == need) {
            picked.push_back(all[i]);
            have = need;
            return true;
        }
    }
    for (size_t i = 0; i < all.size() && have < need; i++) {
        if (all[i].units > MAX_QUANTITY - have)
            return false;
        picked.push_back(all[i]);
        have += all[i].units;
    }
    return have >= need;
}

/** Coins locked for the duration of one build only (cs_wallet is held throughout), released on every path. */
class ScopedFeeExclusion
{
public:
    explicit ScopedFeeExclusion(CWallet* w) : wallet(w) {}
    ~ScopedFeeExclusion()
    {
        for (size_t i = 0; i < locked.size(); i++)
            wallet->UnlockCoin(locked[i]);
    }
    void Lock(COutPoint op)
    {
        wallet->LockCoin(op);
        locked.push_back(op);
    }
    size_t Count() const { return locked.size(); }

private:
    CWallet* wallet;
    std::vector<COutPoint> locked;
};

/**
 * Z23's rules (validity_note_input_baton) make a SEND or MINT of token T UNKNOWN or INVALID when ANY input,
 * an ordinary ZCL fee input included, was created by a transaction of T whose own status is not VALID
 * (send_parent_unknown, send_ancestry_invalid, mint_parent_unknown, mint_baton_lineage_invalid), and such a
 * transaction burns every token input it has. Anyone can pay this wallet ordinary ZCL inside an invalid
 * transaction of T, so those coins are kept out of the fee selection of a transaction of T. (The check after
 * the build would refuse the transaction anyway; this keeps the wallet able to send.)
 */
void ExcludePoisonedFeeCoins(CWallet* wallet, const ZslpIndex& idx, const uint256& token,
                             const std::set<COutPoint>& intended, ScopedFeeExclusion& excl)
{
    std::vector<COutput> coins;
    wallet->AvailableCoins(coins, false, NULL, false, true);
    std::map<uint256, bool> poisoned; // creating txid -> excluded
    for (size_t i = 0; i < coins.size(); i++) {
        const COutput& c = coins[i];
        const uint256 txid = c.tx->GetHash();
        if (intended.count(COutPoint(txid, c.i)) || wallet->IsLockedCoin(txid, c.i))
            continue;
        std::map<uint256, bool>::iterator it = poisoned.find(txid);
        if (it == poisoned.end()) {
            TxInfo ti;
            const bool bad = idx.GetTx(txid, ti) && ti.type != 0 && ti.token == token && ti.status != STATUS_VALID;
            it = poisoned.insert(std::make_pair(txid, bad)).first;
        }
        if (it->second)
            excl.Lock(COutPoint(txid, c.i));
    }
}

/** Build, check, and (unless a dry run) broadcast. cs_main and cs_wallet are held by the caller. */
bool BuildAndSend(CWallet* wallet, ZslpService& svc, const TokenLayout& layout, const std::vector<TokenCoin>& inputs,
                  const Expect& want, CAmount fixedFee, bool dryRun, CReserveKey& ownerKey, bool ownerKeyUsed,
                  TokenTxResult& res, std::string& err, WalletErrKind& kind)
{
    ScopedFeeExclusion excluded(wallet);
    if (!want.genesis) {
        std::set<COutPoint> chosen;
        for (size_t i = 0; i < inputs.size(); i++)
            chosen.insert(inputs[i].op);
        ExcludePoisonedFeeCoins(wallet, svc.Index(), want.token, chosen, excluded);
    }

    CCoinControl cc;
    cc.fAllowOtherInputs = true; // ordinary ZCL coins may be added for the fee, but never token outputs
    cc.fChangeLast = true;       // the ZCL change must not take a token slot
    cc.nFixedFee = fixedFee;
    // A token transaction: only the outputs selected below (none for a GENESIS) may
    // carry tokens, whatever -tokenguard says about ordinary sends.
    cc.fAllowTokenOutputs = true;
    for (size_t i = 0; i < inputs.size(); i++)
        cc.Select(inputs[i].op);

    std::vector<CRecipient> vecSend;
    for (size_t i = 0; i < layout.vout.size(); i++) {
        CRecipient r = {layout.vout[i].scriptPubKey, layout.vout[i].nValue, false};
        vecSend.push_back(r);
    }

    CReserveKey changeKey(wallet);
    CWalletTx wtx;
    CAmount nFee = 0;
    int nChangePos = -1;
    std::string reason;
    if (!wallet->CreateTransaction(vecSend, wtx, changeKey, nFee, nChangePos, reason, &cc)) {
        const bool funds = reason.find("Insufficient funds") != std::string::npos;
        const std::string left = excluded.Count() == 0 ? "" :
            strprintf(" (%u coin(s) paid to this wallet inside a non-valid transaction of this token were left out: "
                      "spending one here would make the token transaction invalid and burn its tokens)",
                      (unsigned)excluded.Count());
        return Fail(err, kind, funds ? ERRK_ZCL_FUNDS : ERRK_STATE,
                    funds ? "not enough ordinary ZCL for the fee and the token dust outputs (token outputs and mint batons are never used as ZCL)" + left + ": " + reason
                          : reason);
    }

    // ---- the built transaction must be exactly what was planned ----
    const CTransaction& tx = wtx;
    if (tx.vout.size() < layout.vout.size() || tx.vout.size() > layout.vout.size() + 1)
        return Fail(err, kind, ERRK_INTERNAL, "internal error: the wallet changed the number of outputs; nothing was sent");
    for (size_t i = 0; i < layout.vout.size(); i++)
        if (tx.vout[i] != layout.vout[i])
            return Fail(err, kind, ERRK_INTERNAL, strprintf("internal error: output %u was changed by the wallet; nothing was sent", (unsigned)i));
    if (tx.vout.size() == layout.vout.size() + 1 && nChangePos != (int)layout.vout.size())
        return Fail(err, kind, ERRK_INTERNAL, "internal error: the ZCL change is not the last output; nothing was sent");

    std::set<COutPoint> intended;
    for (size_t i = 0; i < inputs.size(); i++)
        intended.insert(inputs[i].op);
    std::set<COutPoint> present;
    for (size_t i = 0; i < tx.vin.size(); i++) {
        const COutPoint& op = tx.vin[i].prevout;
        present.insert(op);
        if (intended.count(op))
            continue;
        // an input we did not choose for its tokens is a plain ZCL coin: the wallet guard must agree
        std::map<uint256, CWalletTx>::const_iterator it = wallet->mapWallet.find(op.hash);
        if (it == wallet->mapWallet.end() || it->second.IsTokenBearingOutput(op.n))
            return Fail(err, kind, ERRK_INTERNAL, "internal error: a fee input carries tokens or is unknown; nothing was sent");
    }
    if (present.size() != tx.vin.size() || present.size() < intended.size())
        return Fail(err, kind, ERRK_INTERNAL, "internal error: duplicate or missing token inputs; nothing was sent");
    for (std::set<COutPoint>::const_iterator it = intended.begin(); it != intended.end(); ++it)
        if (!present.count(*it))
            return Fail(err, kind, ERRK_INTERNAL, "internal error: a chosen token input is missing; nothing was sent");

    Evaluation ev;
    std::string ierr;
    if (!svc.Index().EvaluateTx(tx, ev, ierr))
        return Fail(err, kind, ERRK_INTERNAL, "the token index could not judge the transaction: " + ierr);
    if (!ev.isSlp || ev.status != STATUS_VALID)
        return Fail(err, kind, ERRK_INTERNAL, "internal error: the token rules would not accept this transaction (" + ev.reason + "); nothing was sent");
    if (ev.type != want.type)
        return Fail(err, kind, ERRK_INTERNAL, "internal error: wrong message type; nothing was sent");
    if (ev.token != (want.genesis ? tx.GetHash() : want.token))
        return Fail(err, kind, ERRK_INTERNAL, "internal error: the message names another token; nothing was sent");
    if (want.checkInputUnits && ev.inputUnits != want.inputUnits)
        return Fail(err, kind, ERRK_INTERNAL, "internal error: the token inputs differ from the plan; nothing was sent");
    if (ev.burnedUnits != want.burned)
        return Fail(err, kind, ERRK_INTERNAL, strprintf("internal error: the transaction would burn %llu base units, expected %llu; nothing was sent",
                                                         (unsigned long long)ev.burnedUnits, (unsigned long long)want.burned));
    if (ev.mintedUnits != want.minted)
        return Fail(err, kind, ERRK_INTERNAL, "internal error: minted quantity differs from the plan; nothing was sent");
    uint64_t createdUnits = 0;
    unsigned int createdBatons = 0;
    for (size_t i = 0; i < ev.created.size(); i++) {
        if (ev.created[i].role == ROLE_TOKEN)
            createdUnits += ev.created[i].amount;
        else
            createdBatons++;
    }
    if (createdUnits != want.createdTokenUnits || createdBatons != want.createdBatons)
        return Fail(err, kind, ERRK_INTERNAL, "internal error: the token outputs differ from the plan; nothing was sent");
    for (size_t i = 0; i < ev.spent.size(); i++) {
        COutPoint op(ev.spent[i].txid, ev.spent[i].vout);
        if (!intended.count(op))
            return Fail(err, kind, ERRK_INTERNAL, "internal error: the transaction would also spend a token output that was not chosen; nothing was sent");
    }
    std::string standardReason;
    if (!IsStandardTx(tx, standardReason, chainActive.Height() + 1))
        return Fail(err, kind, ERRK_PARAM, "the transaction would not be relayed by this node's policy (" + standardReason + "); nothing was sent");

    res.txid = tx.GetHash();
    res.fee = nFee;
    res.tokenInputs = (unsigned int)inputs.size();
    res.broadcast = false;
    if (dryRun) {
        res.hex = EncodeHexTx(tx);
        return true;
    }

    // a fresh address picked for the tokens is only kept once the transaction is real
    if (ownerKeyUsed)
        ownerKey.KeepKey();
    if (!wallet->CommitTransaction(wtx, changeKey))
        return Fail(err, kind, ERRK_STATE, "the transaction was built and checked, but this node rejected it (the coins may already be spent or the mempool refused it); see debug.log");
    res.broadcast = true;
    return true;
}

bool FeeOk(CAmount fee, std::string& err, WalletErrKind& kind)
{
    if (fee == -1)
        return true;
    if (fee < 0 || fee > maxTxFee)
        return Fail(err, kind, ERRK_PARAM, strprintf("the fee must be between 0 and %s", FormatMoney(maxTxFee)));
    return true;
}

} // namespace

bool WalletTokenSend(CWallet* wallet, ZslpService& svc, const SendRequest& req, TokenTxResult& res,
                     std::string& err, WalletErrKind& kind)
{
    res = TokenTxResult();
    res.kind = "send";
    if (!FeeOk(req.fee, err, kind))
        return false;
    if (req.minconf < 1)
        return Fail(err, kind, ERRK_PARAM, "minconf must be at least 1: a token output is spent only after it is confirmed");
    if (req.to.empty())
        return Fail(err, kind, ERRK_PARAM, "there is no recipient");
    LOCK2(cs_main, wallet->cs_wallet);
    if (!RequireCurrentIndex(svc, err, kind))
        return false;
    TokenInfo ti;
    if (!svc.Index().GetToken(req.token, ti))
        return Fail(err, kind, ERRK_PARAM, "no such token in the index: " + req.token.GetHex());

    std::vector<Recipient> recipients;
    uint64_t total = 0;
    std::string perr;
    for (size_t i = 0; i < req.to.size(); i++) {
        Recipient r;
        if (!DecodeTransparent(req.to[i].first, r.script, perr))
            return Fail(err, kind, ERRK_PARAM, perr);
        if (!ParsePositiveQuantity(req.to[i].second, ti.decimals, r.units, perr))
            return Fail(err, kind, ERRK_PARAM, strprintf("amount for %s: %s", req.to[i].first, perr));
        if (r.units > MAX_QUANTITY - total)
            return Fail(err, kind, ERRK_PARAM, "the total amount is above 2^63-1 base units");
        total += r.units;
        recipients.push_back(r);
    }

    std::vector<TokenCoin> all, picked;
    GatherCoins(wallet, svc.Index(), req.token, ROLE_TOKEN, req.minconf, all);
    uint64_t have = 0, balance = 0;
    SumUnits(all, balance);
    if (!PickInputs(all, total, picked, have))
        return Fail(err, kind, ERRK_TOKEN_FUNDS,
                    strprintf("insufficient confirmed token balance: this wallet holds %s %s in confirmed outputs (minconf %d) and %s was requested; "
                              "tokens that are unconfirmed, or locked, are not spent",
                              FormatAmount(balance, ti.decimals), Printable(ti.ticker), req.minconf, FormatAmount(total, ti.decimals)));

    TokenLayout layout;
    if (!LayoutSend(req.token, recipients, have, picked[0].script, TokenDust(::minRelayTxFee), layout, perr))
        return Fail(err, kind, ERRK_PARAM, perr);

    Expect want;
    want.type = 3;
    want.token = req.token;
    want.inputUnits = have;
    want.checkInputUnits = true;
    want.createdTokenUnits = have;
    want.createdBatons = 0;
    CReserveKey unused(wallet);
    if (!BuildAndSend(wallet, svc, layout, picked, want, req.fee, req.dryRun, unused, false, res, err, kind))
        return false;
    res.token = req.token;
    res.decimals = ti.decimals;
    res.units = total;
    res.tokenChange = layout.tokenChange;
    if (layout.tokenChange > 0)
        res.changeAddress = AddressOfScript(picked[0].script);
    return true;
}

bool WalletTokenBurn(CWallet* wallet, ZslpService& svc, const BurnRequest& req, TokenTxResult& res,
                     std::string& err, WalletErrKind& kind)
{
    res = TokenTxResult();
    res.kind = "burn";
    if (!FeeOk(req.fee, err, kind))
        return false;
    if (req.minconf < 1)
        return Fail(err, kind, ERRK_PARAM, "minconf must be at least 1");
    LOCK2(cs_main, wallet->cs_wallet);
    if (!RequireCurrentIndex(svc, err, kind))
        return false;
    TokenInfo ti;
    if (!svc.Index().GetToken(req.token, ti))
        return Fail(err, kind, ERRK_PARAM, "no such token in the index: " + req.token.GetHex());
    uint64_t burn = 0;
    std::string perr;
    if (!ParsePositiveQuantity(req.quantity, ti.decimals, burn, perr))
        return Fail(err, kind, ERRK_PARAM, perr);

    std::vector<TokenCoin> all, picked;
    GatherCoins(wallet, svc.Index(), req.token, ROLE_TOKEN, req.minconf, all);
    uint64_t have = 0, balance = 0;
    SumUnits(all, balance);
    if (!PickInputs(all, burn, picked, have))
        return Fail(err, kind, ERRK_TOKEN_FUNDS,
                    strprintf("insufficient confirmed token balance: this wallet holds %s %s in confirmed outputs and %s was asked to be burned",
                              FormatAmount(balance, ti.decimals), Printable(ti.ticker), FormatAmount(burn, ti.decimals)));

    TokenLayout layout;
    if (!LayoutBurn(req.token, burn, have, picked[0].script, TokenDust(::minRelayTxFee), layout, perr))
        return Fail(err, kind, ERRK_PARAM, perr);

    Expect want;
    want.type = 3;
    want.token = req.token;
    want.inputUnits = have;
    want.checkInputUnits = true;
    want.createdTokenUnits = layout.tokenChange;
    want.burned = burn;
    CReserveKey unused(wallet);
    if (!BuildAndSend(wallet, svc, layout, picked, want, req.fee, req.dryRun, unused, false, res, err, kind))
        return false;
    res.token = req.token;
    res.decimals = ti.decimals;
    res.units = burn;
    res.burned = burn;
    res.tokenChange = layout.tokenChange;
    res.changeAddress = AddressOfScript(picked[0].script);
    return true;
}

bool WalletTokenGenesis(CWallet* wallet, ZslpService& svc, const GenesisRequest& req, TokenTxResult& res,
                        std::string& err, WalletErrKind& kind)
{
    res = TokenTxResult();
    res.kind = "genesis";
    if (!FeeOk(req.fee, err, kind))
        return false;
    GenesisParams p;
    p.ticker = req.ticker;
    p.name = req.name;
    p.documentUrl = req.documentUrl;
    p.decimals = req.decimals;
    p.baton = req.hasBaton;
    std::string perr;
    if (!req.documentHashHex.empty()) {
        if (req.documentHashHex.size() != 64 || !IsHex(req.documentHashHex))
            return Fail(err, kind, ERRK_PARAM, "documenthash must be 64 hex characters (32 bytes) or null");
        const std::vector<unsigned char> h = ParseHex(req.documentHashHex);
        memcpy(p.documentHash, &h[0], 32);
        p.hasDocumentHash = true;
    }
    if (req.decimals > MAX_DECIMALS)
        return Fail(err, kind, ERRK_PARAM, "decimals must be between 0 and 8");
    if (!ParsePositiveQuantity(req.quantity, req.decimals, p.quantity, perr))
        return Fail(err, kind, ERRK_PARAM, "initialquantity: " + perr);
    if (!ValidateGenesis(p, perr))
        return Fail(err, kind, ERRK_PARAM, perr);

    LOCK2(cs_main, wallet->cs_wallet);
    if (!RequireCurrentIndex(svc, err, kind))
        return false;

    CScript ownerScript, batonScript;
    CReserveKey ownerKey(wallet);
    bool keyUsed = false;
    CScript fresh;
    if (req.address.empty() || (req.hasBaton && req.batonAddress.empty())) {
        CPubKey pk;
        if (!ownerKey.GetReservedKey(pk))
            return Fail(err, kind, ERRK_STATE, "the key pool is empty; unlock the wallet and try again");
        fresh = GetScriptForDestination(pk.GetID());
        keyUsed = true;
    }
    if (req.address.empty()) ownerScript = fresh;
    else if (!DecodeTransparent(req.address, ownerScript, perr)) return Fail(err, kind, ERRK_PARAM, perr);
    if (req.hasBaton) {
        if (req.batonAddress.empty()) batonScript = fresh;
        else if (!DecodeTransparent(req.batonAddress, batonScript, perr)) return Fail(err, kind, ERRK_PARAM, perr);
    }

    TokenLayout layout;
    if (!LayoutGenesis(p, ownerScript, batonScript, TokenDust(::minRelayTxFee), layout, perr))
        return Fail(err, kind, ERRK_PARAM, perr);

    Expect want;
    want.type = 1;
    want.genesis = true;
    want.createdTokenUnits = p.quantity;
    want.createdBatons = req.hasBaton ? 1 : 0;
    want.minted = p.quantity;
    std::vector<TokenCoin> none;
    if (!BuildAndSend(wallet, svc, layout, none, want, req.fee, req.dryRun, ownerKey, keyUsed, res, err, kind))
        return false;
    res.token = res.txid;
    res.decimals = req.decimals;
    res.units = p.quantity;
    res.changeAddress = AddressOfScript(ownerScript);
    return true;
}

bool WalletTokenMint(CWallet* wallet, ZslpService& svc, const MintRequest& req, TokenTxResult& res,
                     std::string& err, WalletErrKind& kind)
{
    res = TokenTxResult();
    res.kind = "mint";
    if (!FeeOk(req.fee, err, kind))
        return false;
    if (req.minconf < 1)
        return Fail(err, kind, ERRK_PARAM, "minconf must be at least 1");
    LOCK2(cs_main, wallet->cs_wallet);
    if (!RequireCurrentIndex(svc, err, kind))
        return false;
    TokenInfo ti;
    if (!svc.Index().GetToken(req.token, ti))
        return Fail(err, kind, ERRK_PARAM, "no such token in the index: " + req.token.GetHex());
    uint64_t qty = 0;
    std::string perr;
    if (!ParsePositiveQuantity(req.quantity, ti.decimals, qty, perr))
        return Fail(err, kind, ERRK_PARAM, perr);
    if (ti.minted > MAX_QUANTITY - qty)
        return Fail(err, kind, ERRK_PARAM, "minting this much would take the total supply above 2^63-1 base units, which the token rules treat as unknown");

    std::vector<TokenCoin> batons;
    GatherCoins(wallet, svc.Index(), req.token, ROLE_BATON, req.minconf, batons);
    if (batons.empty())
        return Fail(err, kind, ERRK_TOKEN_FUNDS,
                    "this wallet does not hold the confirmed mint baton of this token (the baton, if it still exists, is " +
                    std::string(ti.hasBaton ? ti.batonTx.GetHex() + strprintf(":%u", ti.batonVout) : "gone: the supply is closed") + ")");
    std::vector<TokenCoin> baton(1, batons[0]);

    CScript recipientScript, batonScript;
    CReserveKey ownerKey(wallet);
    bool keyUsed = false;
    if (req.address.empty()) {
        CPubKey pk;
        if (!ownerKey.GetReservedKey(pk))
            return Fail(err, kind, ERRK_STATE, "the key pool is empty; unlock the wallet and try again");
        recipientScript = GetScriptForDestination(pk.GetID());
        keyUsed = true;
    } else if (!DecodeTransparent(req.address, recipientScript, perr)) {
        return Fail(err, kind, ERRK_PARAM, perr);
    }
    if (req.hasBaton) {
        if (req.batonAddress.empty()) batonScript = baton[0].script; // Z23: the baton returns to where it was
        else if (!DecodeTransparent(req.batonAddress, batonScript, perr)) return Fail(err, kind, ERRK_PARAM, perr);
    }

    TokenLayout layout;
    if (!LayoutMint(req.token, qty, recipientScript, req.hasBaton, batonScript, TokenDust(::minRelayTxFee), layout, perr))
        return Fail(err, kind, ERRK_PARAM, perr);

    Expect want;
    want.type = 2;
    want.token = req.token;
    want.createdTokenUnits = qty;
    want.createdBatons = req.hasBaton ? 1 : 0;
    want.minted = qty;
    if (!BuildAndSend(wallet, svc, layout, baton, want, req.fee, req.dryRun, ownerKey, keyUsed, res, err, kind))
        return false;
    res.token = req.token;
    res.decimals = ti.decimals;
    res.units = qty;
    res.changeAddress = req.hasBaton ? AddressOfScript(batonScript) : "";
    return true;
}

} // namespace zslp
