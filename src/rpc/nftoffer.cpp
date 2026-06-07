// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// NFT SELL pillar — non-consensus atomic NFT->ZCL sale RPCs.
//
// Mechanism A' from doc/nft/NFT_SELL_DESIGN.md (canonical): a fixed 3-output
// ZSLP SEND template, ALL outputs pinned by the seller's SIGHASH_ALL|ANYONECANPAY
// signature on vin[0] (the NFT dust UTXO); the buyer may only APPEND funding
// inputs (vin[1..]), never edit an output. The settlement is ONE ordinary
// transparent transaction that unmodified ZClassic nodes relay and mine.
//
//   vout[0] = OP_RETURN ZSLP SEND { tokenId, [1] }   (value 0; credits vout[1])
//   vout[1] = buyer NFT dust  (D sat, sealed to buyerNftAddr)   ← new owner
//   vout[2] = seller ZCL payout (priceZat)
//
// DRY: vout[0] is built with the EXISTING ZSLP SEND encoder (ZSLPBuildSend);
// the anti-burn filter (ZSLPIsProtectedTokenOutpoint), the read-only
// conservation check (CZSLPStore::WouldBeValid), and the real parse seam
// (CZSLPIndexer::ParseTx) are all reused, not reimplemented. Cancel reuses the
// whole BuildAndCommitZSLP path (a 1-output self-send SEND).
//
//   nft_makeoffer   {tokenId,priceZat,payoutAddr?,buyerNftAddr,expiryHeight?}
//   nft_verifyoffer {offerBlob}                         (read-only, mandatory)
//   nft_takeoffer   {offerBlob,fundingInputs?,changeAddr?,acknowledge?}
//   nft_listoffers  ()                                  (no filter; all are yours)
//   nft_canceloffer {offerId}
//   nft_requestbuy  {tokenId|offerId}

#include "rpc/server.h"

#include "rpc/nftoffer.h"  // CNftOfferBlob, NftVerifyResult, NftVerify (E-1)
#include "base58.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "hash.h"
#include "key_io.h"
#include "main.h"
#include "net.h"
#include "rpc/protocol.h"
#include "script/sign.h"
#include "script/standard.h"
#include "streams.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "zslp/zslpindexer.h"
#include "zslp/zslpmsg.h"
#include "zslp/zslpstore.h"

#ifdef ENABLE_WALLET
#include "init.h"          // pwalletMain
#include "wallet/wallet.h"
#include "wallet/zslpwallet.h"
extern bool EnsureWalletIsAvailable(bool avoidException);
#endif

#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <stdint.h>
#include <univalue.h>

#ifdef ENABLE_WALLET

// ── shared helpers ──────────────────────────────────────────────────
//
// B-2: the store-or-throw + t-addr script/addr helpers are now ONE canonical
// copy in wallet/zslpwallet.{h,cpp} (alongside ZSLPTokenIdToBE), used by both
// this file and rpc/zslp.cpp. These thin shims keep the existing Nft*-prefixed
// call sites reading unchanged while the byte-for-byte behavior lives in one
// place (they build the real token-carrier + offer-template scriptPubKeys).

static inline CZSLPStore* NftGetStoreOrThrow() { return ZSLPStoreOrThrow(); }

// A t-address string -> P2PKH/P2SH script (throws on invalid).
static inline CScript NftScriptForTAddr(const std::string& addr)
{
    return ZSLPScriptForTAddr(addr);
}

// Decode a script back to a t-address string ("" if not a standard address).
static inline std::string NftAddrFromScript(const CScript& spk)
{
    return ZSLPAddrFromScript(spk);
}

static inline CScript NftFreshWalletScript() { return ZSLPFreshWalletScript(); }

// Parse a non-negative zatoshi amount from a JSON string|integer.
// B-1: the parse/overflow logic is shared (ZSLPParseAmountField); this pins THIS
// family's bound (<= MAX_MONEY) and its exact wording ("exceeds MAX_MONEY", and
// the "(zatoshi)" digits-only note) so behavior is unchanged.
static int64_t NftParseZat(const UniValue& v, const std::string& field)
{
    return ZSLPParseAmountField(v, field, MAX_MONEY, "MAX_MONEY", " (zatoshi)");
}

// Fee-rate-derived dust floor for a token-bearing output (§2.2). Never below the
// SLP convention 546 so older relays that assume that floor still accept it.
static CAmount NftTokenDust(const CScript& dest)
{
    CTxOut probe(0, dest);
    CAmount floor = probe.GetDustThreshold(::minRelayTxFee);
    return std::max((CAmount)SLP_TOKEN_DUST, floor);
}

// ── offer blob format (base64; §4) ──────────────────────────────────
//
// The class + SerializationOp + the magic/version constants live in
// rpc/nftoffer.h (so the gtest can construct one for the de-static NftVerify,
// E-1). Only these three non-template methods are defined here.

std::string CNftOfferBlob::ToBase64() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    return EncodeBase64((const unsigned char*)&ss[0], ss.size());
}

// offerId = first 8 bytes of SHA256(blob) hex; stable content fingerprint.
std::string CNftOfferBlob::OfferId() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    uint256 h = Hash((const unsigned char*)&ss[0],
                     (const unsigned char*)&ss[0] + ss.size());
    return h.GetHex().substr(0, 16);
}

bool CNftOfferBlob::FromBase64(const std::string& b64, std::string& err)
{
    bool invalid = false;
    std::vector<unsigned char> raw = DecodeBase64(b64.c_str(), &invalid);
    if (invalid) { err = "offer blob is not valid base64"; return false; }
    try {
        CDataStream ss(raw, SER_NETWORK, PROTOCOL_VERSION);
        ss >> *this;
    } catch (const std::exception& e) {
        err = std::string("offer blob decode failed: ") + e.what();
        return false;
    }
    return true;
}

// Strip a "znftoffer:" URI prefix if present, returning the bare base64.
static std::string NftStripPrefix(const std::string& in)
{
    const std::string p = "znftoffer:";
    if (in.size() >= p.size() && in.compare(0, p.size(), p) == 0)
        return in.substr(p.size());
    return in;
}

// ── local offer store (datadir/nftoffers.json) ──────────────────────
//
// A small, human-inspectable cache (NOT leveldb): the canonical blob holder +
// status cache. listoffers recomputes status live against the UTXO set.
static boost::filesystem::path NftOfferStorePath()
{
    return GetDataDir() / "nftoffers.json";
}

static UniValue NftLoadStore()
{
    UniValue arr(UniValue::VARR);
    boost::filesystem::path p = NftOfferStorePath();
    if (!boost::filesystem::exists(p))
        return arr;
    boost::filesystem::ifstream f(p);
    std::string data((std::istreambuf_iterator<char>(f)),
                     std::istreambuf_iterator<char>());
    if (data.empty())
        return arr;
    UniValue parsed;
    if (!parsed.read(data) || !parsed.isArray())
        return arr; // corrupt/legacy: start fresh rather than crash
    return parsed;
}

static void NftSaveStore(const UniValue& arr)
{
    boost::filesystem::path p = NftOfferStorePath();
    boost::filesystem::path tmp = p;
    tmp += ".tmp";
    {
        boost::filesystem::ofstream f(tmp);
        f << arr.write(1) << "\n";
    }
    boost::filesystem::rename(tmp, p); // atomic replace
}

// Upsert a record by offerId.
static void NftUpsertOffer(const UniValue& rec)
{
    std::string id = find_value(rec, "offerId").get_str();
    UniValue arr = NftLoadStore();
    UniValue out(UniValue::VARR);
    bool replaced = false;
    for (size_t i = 0; i < arr.size(); ++i) {
        if (find_value(arr[i], "offerId").get_str() == id) {
            out.push_back(rec);
            replaced = true;
        } else {
            out.push_back(arr[i]);
        }
    }
    if (!replaced)
        out.push_back(rec);
    NftSaveStore(out);
}

static bool NftFindOffer(const std::string& offerId, UniValue& recOut)
{
    UniValue arr = NftLoadStore();
    for (size_t i = 0; i < arr.size(); ++i) {
        if (find_value(arr[i], "offerId").get_str() == offerId) {
            recOut = arr[i];
            return true;
        }
    }
    return false;
}

// ── decode + verify the partial offer tx (the core safety logic) ────
//
// NftVerifyResult lives in rpc/nftoffer.h. NftVerify is now non-static (E-1) so
// test_nftoffer.cpp can drive the REAL verifier instead of hand-rolling a copy;
// its signature + logic are unchanged. It re-derives every advertised field from
// offerHex and re-runs the real indexer parse + conservation check + a live-UTXO
// check on vin[0]. Used by nft_verifyoffer (read-only), nft_takeoffer
// (refuse-if-not-ok), and nft_makeoffer's self-validate.
void NftVerify(CZSLPStore* store, const CNftOfferBlob& blob,
               NftVerifyResult& r)
{
    AssertLockHeld(cs_main);
    r.expiryHeight = blob.expiryHeight;

    CMutableTransaction mtx;
    {
        CTransaction tmp;
        if (!DecodeHexTx(tmp, blob.offerHex)) {
            r.reasons.push_back("offerHex does not decode as a transaction");
            r.ok = false;
            return;
        }
        mtx = CMutableTransaction(tmp);
    }
    r.tx = mtx;
    const CTransaction tx(mtx);

    // Output shape.
    if (tx.vout.size() != 3) {
        r.reasons.push_back(strprintf("expected exactly 3 outputs, got %d",
                                      (int)tx.vout.size()));
    }
    if (tx.vin.empty()) {
        r.reasons.push_back("offer has no inputs (vin[0] = NFT missing)");
        r.ok = false;
        return; // nothing more we can check without vin[0]
    }

    // vout[0] must parse as a ZSLP SEND crediting vout[1] with qty 1.
    CZSLPParsedMsg parsed;
    CZSLPToken genesisMeta;
    bool haveGenesisMeta = false;
    int nextHeight = chainActive.Height() + 1;
    bool parsedOk = CZSLPIndexer::ParseTx(tx, nextHeight, parsed, genesisMeta,
                                          haveGenesisMeta);
    if (!parsedOk) {
        r.reasons.push_back("vout[0] is not a parsable ZSLP message");
    } else {
        if (parsed.type != ZSLP_MSG_SEND)
            r.reasons.push_back("vout[0] is not a ZSLP SEND");
        r.tokenId = parsed.tokenId;
        if (parsed.tokenId != blob.tokenId)
            r.reasons.push_back("vout[0] token id does not match the offered token");
        if (parsed.numOutputs != 1 || parsed.outputQuantities[0] != 1)
            r.reasons.push_back("vout[0] SEND does not credit exactly qty 1 to vout[1]");
    }

    // vout[1] sealed to buyerNftAddr; vout[2] price + payout (re-derived).
    if (tx.vout.size() >= 2) {
        std::string gotBuyer = NftAddrFromScript(tx.vout[1].scriptPubKey);
        r.buyerNftAddr = gotBuyer;
        if (gotBuyer.empty() || gotBuyer != blob.buyerNftAddr)
            r.reasons.push_back("vout[1] (NFT recipient) does not match buyerNftAddr");
    }
    if (tx.vout.size() >= 3) {
        std::string gotPayout = NftAddrFromScript(tx.vout[2].scriptPubKey);
        r.payoutAddr = gotPayout;
        r.priceZat = tx.vout[2].nValue;
        if (tx.vout[2].nValue != blob.priceZat)
            r.reasons.push_back("vout[2] (payout) value does not match priceZat");
        if (gotPayout.empty() || gotPayout != blob.payoutAddr)
            r.reasons.push_back("vout[2] (payout) address does not match payoutAddr");
    }

    // vin[0] must be the LIVE unspent NFT UTXO for this token (qty 1).
    const COutPoint& nftOp = tx.vin[0].prevout;
    {
        CCoins coins;
        bool live = pcoinsTip->GetCoins(nftOp.hash, coins) &&
                    coins.IsAvailable(nftOp.n);
        if (!live) {
            r.reasons.push_back("vin[0] is not a live (unspent) UTXO — already spent or never existed");
        } else {
            r.nftPrevScript = coins.vout[nftOp.n].scriptPubKey;
            r.nftPrevValue  = coins.vout[nftOp.n].nValue;

            // CRYPTOGRAPHIC BACKSTOP (the buyer pays on the strength of this):
            // the seller's ALL|ANYONECANPAY signature on vin[0] must validly bind
            // these EXACT outputs. Run VerifyScript over the live prevout exactly
            // as signrawtransaction validates each input (rawtransaction.cpp:976).
            // A signature that does not cover the outputs (a price/recipient edit),
            // or a missing/garbage scriptSig, must make ok=false HERE — not only
            // later at broadcast.
            uint32_t branchId = CurrentEpochBranchId(nextHeight,
                                                     Params().GetConsensus());
            CTransaction txConst(tx);
            ScriptError serr = SCRIPT_ERR_OK;
            if (!VerifyScript(tx.vin[0].scriptSig, r.nftPrevScript,
                              STANDARD_SCRIPT_VERIFY_FLAGS,
                              TransactionSignatureChecker(&txConst, 0,
                                                          r.nftPrevValue),
                              branchId, &serr)) {
                r.reasons.push_back(
                    std::string("seller signature does not validly bind this "
                                "offer (vin[0] VerifyScript failed: ") +
                    ScriptErrorString(serr) + ")");
            }
        }
        CZSLPTokenUtxo rec;
        bool isToken = store->GetUtxo(nftOp.hash, (int32_t)nftOp.n, rec);
        if (!isToken) {
            r.reasons.push_back("vin[0] is not a confirmed ZSLP token UTXO");
        } else {
            if (!r.tokenId.IsNull() && rec.tokenId != r.tokenId)
                r.reasons.push_back("vin[0] token UTXO is a different token than vout[0] declares");
            if (rec.amount != 1 || rec.isMintBaton)
                r.reasons.push_back("vin[0] is not a quantity-1 NFT UTXO");
        }
    }

    // Not expired.
    if (tx.nExpiryHeight > 0 &&
        tx.nExpiryHeight <= (uint32_t)(nextHeight + TX_EXPIRING_SOON_THRESHOLD)) {
        r.reasons.push_back(strprintf("offer is expired or expiring too soon (expiry %d, tip+1 %d)",
                                      tx.nExpiryHeight, nextHeight));
    }

    // Conservation: the overlay ledger would fully credit the buyer.
    if (parsedOk) {
        std::vector<COutPoint> vin;
        for (size_t k = 0; k < tx.vin.size(); ++k)
            vin.push_back(tx.vin[k].prevout);
        std::string why;
        if (!store->WouldBeValid(vin, &parsed, tx.GetHash(),
                                 haveGenesisMeta ? &genesisMeta : NULL,
                                 (int32_t)tx.vout.size(), why)) {
            r.reasons.push_back("ledger conservation check failed: " + why);
        }
    }

    r.ok = r.reasons.empty();
}

// ── nft_makeoffer ───────────────────────────────────────────────────

UniValue nft_makeoffer(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "nft_makeoffer '{\"tokenId\":?,\"priceZat\":?,\"buyerNftAddr\":?,"
            "\"payoutAddr\":?,\"expiryHeight\":?}'\n"
            "\nCreate a buyer-sealed atomic sell offer for an NFT (mechanism A').\n"
            "Builds the fixed 3-output ZSLP SEND template, signs ONLY vin[0]\n"
            "(your NFT dust UTXO) with ALL|ANYONECANPAY so the buyer can only\n"
            "append funding inputs, locks the NFT outpoint, self-validates, and\n"
            "returns a base64 offer blob to share offline.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"params\" (object, required)\n"
            "     tokenId       (string, required) the NFT token id (hex)\n"
            "     priceZat      (string|numeric, required) asking price in zatoshi\n"
            "     buyerNftAddr  (string, required) the buyer's NFT receive t-address\n"
            "     payoutAddr    (string, optional) your payout t-address (default: fresh)\n"
            "     expiryHeight  (numeric, optional) offer deadline (default: tip+~7d)\n"
            "\nResult:\n"
            "{ \"offerBlob\":\"base64\", \"offerId\":\"hex\", \"nftOutpoint\":\"txid:n\",\n"
            "  \"fingerprint\":\"hex\" }\n"
            "\nExamples:\n"
            + HelpExampleCli("nft_makeoffer",
                "'{\"tokenId\":\"<txid>\",\"priceZat\":\"100000000\",\"buyerNftAddr\":\"t1...\"}'"));

    CZSLPStore* store = NftGetStoreOrThrow();
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const UniValue& o = params[0].get_obj();
    uint256 tokenId = ParseHashV(find_value(o, "tokenId"), "tokenId");
    int64_t priceZat = NftParseZat(find_value(o, "priceZat"), "priceZat");
    if (priceZat <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "priceZat must be > 0");

    const UniValue& vBuyer = find_value(o, "buyerNftAddr");
    if (!vBuyer.isStr() || vBuyer.get_str().empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "buyerNftAddr is required");
    std::string buyerNftAddr = vBuyer.get_str();
    CScript buyerScript = NftScriptForTAddr(buyerNftAddr);

    std::string payoutAddr;
    CScript payoutScript;
    { const UniValue& v = find_value(o, "payoutAddr");
      if (v.isStr() && !v.get_str().empty()) {
          payoutAddr = v.get_str();
          payoutScript = NftScriptForTAddr(payoutAddr);
      } else {
          payoutScript = NftFreshWalletScript();
          payoutAddr = NftAddrFromScript(payoutScript);
      } }

    CZSLPToken token;
    if (!store->GetToken(tokenId, token))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Token not found");

    EnsureWalletIsUnlocked();

    // PRECONDITION: a CONFIRMED quantity-1 NFT UTXO in this wallet.
    std::vector<ZSLPWalletUtxo> utxos;
    std::string ferr;
    if (!ZSLPFindWalletTokenUtxos(pwalletMain, tokenId, /*wantBaton=*/false,
                                  utxos, ferr))
        throw JSONRPCError(RPC_WALLET_ERROR, ferr);
    const ZSLPWalletUtxo* nft = NULL;
    for (size_t i = 0; i < utxos.size(); ++i)
        if (utxos[i].amount == 1) { nft = &utxos[i]; break; }
    if (nft == NULL)
        throw JSONRPCError(RPC_WALLET_ERROR,
            "No confirmed quantity-1 NFT UTXO for that token in this wallet "
            "(if you just minted/received it, wait for it to confirm)");
    COutPoint nftOutpoint = nft->outpoint;

    // Confirmed-truth assertion on the chosen outpoint.
    {
        CZSLPTokenUtxo rec;
        if (!store->GetUtxo(nftOutpoint.hash, (int32_t)nftOutpoint.n, rec) ||
            rec.amount != 1 || rec.isMintBaton)
            throw JSONRPCError(RPC_WALLET_ERROR,
                "internal: chosen NFT UTXO is not a confirmed qty-1 token");
    }

    // Live prevout (script + value) for signing the NFT input.
    CCoins coins;
    if (!pcoinsTip->GetCoins(nftOutpoint.hash, coins) ||
        !coins.IsAvailable(nftOutpoint.n))
        throw JSONRPCError(RPC_WALLET_ERROR,
            "NFT UTXO is not live in the chainstate (still confirming?)");
    const CScript nftScript = coins.vout[nftOutpoint.n].scriptPubKey;
    const CAmount nftValue  = coins.vout[nftOutpoint.n].nValue;

    // Dust floor for vout[1] (fee-rate-derived; never below 546).
    CAmount D = NftTokenDust(buyerScript);

    // vout[0] = ZSLP SEND { tokenId, [1] } via the EXISTING encoder (DRY).
    uint8_t tidBE[32]; ZSLPTokenIdToBE(tokenId, tidBE);
    std::vector<uint64_t> quantities; quantities.push_back(1);
    std::vector<unsigned char> opret = ZSLPBuildSend(tidBE, quantities);
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build SEND OP_RETURN");

    // Expiry: default tip + ~7d of 150s blocks; validate the relay bounds the
    // way createrawtransaction does (rawtransaction.cpp:514-522).
    int tip = chainActive.Height();
    uint32_t expiry;
    { const UniValue& v = find_value(o, "expiryHeight");
      if (!v.isNull()) {
          int e = v.get_int();
          if (e < 0) throw JSONRPCError(RPC_INVALID_PARAMETER, "expiryHeight must be >= 0");
          expiry = (uint32_t)e;
      } else {
          expiry = (uint32_t)(tip + 7 * 1440);
      } }
    if (expiry < (uint32_t)(tip + 1 + TX_EXPIRING_SOON_THRESHOLD))
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("expiryHeight %d is too soon; must be >= %d",
                      expiry, tip + 1 + TX_EXPIRING_SOON_THRESHOLD));
    if (expiry >= TX_EXPIRY_HEIGHT_THRESHOLD)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("expiryHeight must be < %d", TX_EXPIRY_HEIGHT_THRESHOLD));

    // Assemble the fixed template.
    CMutableTransaction mtx = CreateNewContextualCMutableTransaction(
        Params().GetConsensus(), tip + 1);
    mtx.nExpiryHeight = expiry;
    mtx.nLockTime = 0;
    mtx.vin.clear();
    mtx.vin.push_back(CTxIn(nftOutpoint, CScript(),
                            std::numeric_limits<unsigned int>::max()));
    mtx.vout.clear();
    mtx.vout.push_back(CTxOut(0, CScript(opret.begin(), opret.end()))); // vout[0]
    mtx.vout.push_back(CTxOut(D, buyerScript));                          // vout[1]
    mtx.vout.push_back(CTxOut(priceZat, payoutScript));                  // vout[2]

    // Sign ONLY vin[0] with ALL|ANYONECANPAY (the exact primitives
    // signrawtransaction wraps; in-process to avoid a re-entrant RPC).
    uint32_t branchId = CurrentEpochBranchId(tip + 1, Params().GetConsensus());
    {
        CTransaction txConst(mtx);
        SignatureData sigdata;
        if (!ProduceSignature(
                TransactionSignatureCreator(pwalletMain, &txConst, 0, nftValue,
                    SigHashType(SIGHASH_ALL | SIGHASH_ANYONECANPAY)),
                nftScript, sigdata, branchId))
            throw JSONRPCError(RPC_WALLET_ERROR,
                "failed to sign the NFT input (vin[0]) — wallet does not hold its key?");
        UpdateTransaction(mtx, 0, sigdata);

        // Verify the seller's own signature now (catches a broken sig early).
        ScriptError serr = SCRIPT_ERR_OK;
        if (!VerifyScript(mtx.vin[0].scriptSig, nftScript,
                          STANDARD_SCRIPT_VERIFY_FLAGS,
                          TransactionSignatureChecker(&txConst, 0, nftValue),
                          branchId, &serr))
            throw JSONRPCError(RPC_WALLET_ERROR,
                std::string("self-check: seller signature did not verify: ") +
                ScriptErrorString(serr));
    }

    // Self-validate the PARTIAL (vout[0]-only parse + conservation; vin[0]
    // alone gives availIn=1, requiredOut=1).
    {
        CTransaction partial(mtx);
        CNftOfferBlob probe;
        probe.tokenId = tokenId;
        probe.priceZat = priceZat;
        probe.payoutAddr = payoutAddr;
        probe.buyerNftAddr = buyerNftAddr;
        probe.expiryHeight = expiry;
        probe.offerHex = EncodeHexTx(partial);
        NftVerifyResult vr;
        NftVerify(store, probe, vr);
        if (!vr.ok) {
            std::string joined;
            for (size_t i = 0; i < vr.reasons.size(); ++i)
                joined += (i ? "; " : "") + vr.reasons[i];
            throw JSONRPCError(RPC_WALLET_ERROR,
                "self-validate of the built offer failed: " + joined);
        }
    }

    // Lock the NFT outpoint so coin selection can't spend/double-offer it.
    { COutPoint tmp = nftOutpoint; pwalletMain->LockCoin(tmp); }

    // Build + persist the blob.
    CNftOfferBlob blob;
    blob.tokenId = tokenId;
    blob.priceZat = priceZat;
    blob.payoutAddr = payoutAddr;
    blob.buyerNftAddr = buyerNftAddr;
    blob.expiryHeight = expiry;
    blob.offerHex = EncodeHexTx(CTransaction(mtx));
    std::string offerId = blob.OfferId();
    std::string offerB64 = blob.ToBase64();
    std::string nftOutStr = nftOutpoint.hash.GetHex() + ":" +
                            std::to_string(nftOutpoint.n);

    {
        UniValue rec(UniValue::VOBJ);
        rec.push_back(Pair("offerId", offerId));
        rec.push_back(Pair("role", "sell"));
        rec.push_back(Pair("tokenId", tokenId.GetHex()));
        rec.push_back(Pair("priceZat", priceZat));
        rec.push_back(Pair("payoutAddr", payoutAddr));
        rec.push_back(Pair("buyerNftAddr", buyerNftAddr));
        rec.push_back(Pair("nftOutpoint", nftOutStr));
        rec.push_back(Pair("expiryHeight", (int64_t)expiry));
        rec.push_back(Pair("offerBlob", offerB64));
        rec.push_back(Pair("createdHeight", (int64_t)tip));
        rec.push_back(Pair("status", "open"));
        NftUpsertOffer(rec);
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("offerBlob", "znftoffer:" + offerB64));
    ret.push_back(Pair("offerId", offerId));
    ret.push_back(Pair("nftOutpoint", nftOutStr));
    ret.push_back(Pair("fingerprint", offerId));
    return ret;
}

// ── nft_verifyoffer ─────────────────────────────────────────────────

UniValue nft_verifyoffer(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "nft_verifyoffer '{\"offerBlob\":\"...\"}'\n"
            "\nMANDATORY read-only safety check the buyer runs BEFORE signing.\n"
            "Decodes the offer, re-derives every field from the partial tx, and\n"
            "re-runs the real ZSLP parse + conservation check + a live-UTXO check\n"
            "on vin[0]. A forged or edited offer FAILS here with clear reasons.\n"
            "\nArguments:\n"
            "1. \"params\" (object, required) { \"offerBlob\":\"base64 or znftoffer:...\" }\n"
            "\nResult:\n"
            "{ \"ok\":true|false, \"tokenId\":\"hex\", \"priceZat\":n,\n"
            "  \"payoutAddr\":\"t1..\", \"buyerNftAddr\":\"t1..\",\n"
            "  \"expiryHeight\":n, \"reasons\":[...] }\n"
            "\nExamples:\n"
            + HelpExampleCli("nft_verifyoffer", "'{\"offerBlob\":\"znftoffer:...\"}'"));

    CZSLPStore* store = NftGetStoreOrThrow();
    LOCK(cs_main);

    const UniValue& o = params[0].get_obj();
    const UniValue& vb = find_value(o, "offerBlob");
    if (!vb.isStr() || vb.get_str().empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offerBlob is required");

    CNftOfferBlob blob;
    std::string err;
    if (!blob.FromBase64(NftStripPrefix(vb.get_str()), err))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);

    NftVerifyResult r;
    NftVerify(store, blob, r);

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("ok", r.ok));
    ret.push_back(Pair("tokenId", r.tokenId.IsNull() ? blob.tokenId.GetHex()
                                                     : r.tokenId.GetHex()));
    ret.push_back(Pair("priceZat", r.priceZat));
    ret.push_back(Pair("payoutAddr", r.payoutAddr.empty() ? blob.payoutAddr
                                                          : r.payoutAddr));
    ret.push_back(Pair("buyerNftAddr", r.buyerNftAddr.empty() ? blob.buyerNftAddr
                                                             : r.buyerNftAddr));
    ret.push_back(Pair("expiryHeight", (int64_t)r.expiryHeight));
    UniValue reasons(UniValue::VARR);
    for (size_t i = 0; i < r.reasons.size(); ++i)
        reasons.push_back(r.reasons[i]);
    ret.push_back(Pair("reasons", reasons));
    return ret;
}

// Parse a "txid:n" outpoint string.
static bool NftParseOutpoint(const std::string& s, COutPoint& out)
{
    size_t colon = s.rfind(':');
    if (colon == std::string::npos) return false;
    std::string h = s.substr(0, colon);
    std::string nstr = s.substr(colon + 1);
    if (h.size() != 64 || !IsHex(h)) return false;
    for (size_t i = 0; i < nstr.size(); ++i)
        if (nstr[i] < '0' || nstr[i] > '9') return false;
    out.hash = uint256S(h);
    out.n = (uint32_t)atoi(nstr.c_str());
    return true;
}

// ── nft_takeoffer ───────────────────────────────────────────────────

UniValue nft_takeoffer(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "nft_takeoffer '{\"offerBlob\":\"...\",\"fundingInputs\":[\"txid:n\",..],"
            "\"changeAddr\":?,\"acknowledge\":?}'\n"
            "\nVerify, fund, and broadcast an NFT sell offer atomically. Verifies\n"
            "first (refuses if not ok), appends funding inputs that EXCLUDE every\n"
            "ZSLP-protected outpoint (anti-burn), adds NO new outputs (no buyer\n"
            "change is possible under ALL), signs the buyer inputs ALL|ANYONECANPAY,\n"
            "merges the seller's vin[0], self-validates, and sendrawtransaction.\n"
            "Any overshoot beyond price+dust+fee is donated to the miner.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"params\" (object, required)\n"
            "     offerBlob     (string, required) base64 or znftoffer: blob\n"
            "     fundingInputs (array, optional) explicit [\"txid:n\",..] funding outpoints\n"
            "     changeAddr    (string, optional) reserved for a pre-size prep tx (unused here)\n"
            "     acknowledge   (bool, optional) acknowledge the overshoot-to-fee\n"
            "\nResult:\n{ \"txid\":\"hex\", \"overshootZat\":n }\n"
            "\nExamples:\n"
            + HelpExampleCli("nft_takeoffer", "'{\"offerBlob\":\"znftoffer:...\"}'"));

    CZSLPStore* store = NftGetStoreOrThrow();
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const UniValue& o = params[0].get_obj();
    const UniValue& vb = find_value(o, "offerBlob");
    if (!vb.isStr() || vb.get_str().empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offerBlob is required");

    CNftOfferBlob blob;
    std::string derr;
    if (!blob.FromBase64(NftStripPrefix(vb.get_str()), derr))
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, derr);

    // The buyer's explicit consent to donate any overshoot beyond
    // price+dust+fee to miner fees (no change output is possible under ALL).
    bool acknowledge = false;
    { const UniValue& va = find_value(o, "acknowledge");
      if (va.isBool()) acknowledge = va.get_bool();
      else if (!va.isNull())
          throw JSONRPCError(RPC_TYPE_ERROR, "acknowledge must be a boolean"); }

    // (1) Verify first; refuse if not ok (TOCTOU is closed: this re-checks
    //     liveness right before we fund/sign).
    NftVerifyResult vr;
    NftVerify(store, blob, vr);
    if (!vr.ok) {
        std::string joined;
        for (size_t i = 0; i < vr.reasons.size(); ++i)
            joined += (i ? "; " : "") + vr.reasons[i];
        throw JSONRPCError(RPC_VERIFY_REJECTED, "offer failed verification: " + joined);
    }

    EnsureWalletIsUnlocked();

    CMutableTransaction mtx = vr.tx; // decoded partial (vin[0] seller-signed)

    // (2) Output value to cover + an estimated fee. No change output is possible
    //     under ALL, so the buyer funds exact (or honest overshoot -> fee).
    CAmount outValue = 0;
    for (size_t i = 0; i < mtx.vout.size(); ++i)
        outValue += mtx.vout[i].nValue;       // 0 + D + price
    CAmount vin0Value = vr.nftPrevValue;       // the NFT dust the seller spends
    // A 3-output, ~2-input tx is ~ a few hundred bytes; use the wallet's fee
    // estimator against a conservative size and refine after selection.
    CAmount feeEst = pwalletMain->GetMinimumFee(2000, nTxConfirmTarget, mempool);

    // (3) Funding selection (anti-burn). EXCLUDE every protected outpoint.
    std::vector<COutPoint> funding;
    CAmount fundIn = 0;
    const UniValue& vfi = find_value(o, "fundingInputs");
    if (vfi.isArray() && vfi.size() > 0) {
        for (size_t i = 0; i < vfi.size(); ++i) {
            COutPoint op;
            if (!NftParseOutpoint(vfi[i].get_str(), op))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "fundingInputs entry not in txid:n form: " + vfi[i].get_str());
            if (ZSLPIsProtectedTokenOutpoint(pwalletMain, store, op))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "anti-burn: funding input is a ZSLP token/baton UTXO: " + vfi[i].get_str());
            CCoins c;
            if (!pcoinsTip->GetCoins(op.hash, c) || !c.IsAvailable(op.n))
                throw JSONRPCError(RPC_INVALID_PARAMETER,
                    "funding input is not live: " + vfi[i].get_str());
            funding.push_back(op);
            fundIn += c.vout[op.n].nValue;
        }
    } else {
        // Auto-select: AvailableCoins with fExcludeZSLPTokens=true already drops
        // protected outpoints; greedy smallest-combo >= target.
        std::vector<COutput> coins;
        pwalletMain->AvailableCoins(coins, /*fOnlyConfirmed=*/true, NULL,
                                    /*fIncludeZeroValue=*/false,
                                    /*fIncludeCoinBase=*/false,
                                    /*fExcludeZSLPTokens=*/true);
        std::sort(coins.begin(), coins.end(),
                  [](const COutput& a, const COutput& b) {
                      return a.tx->vout[a.i].nValue < b.tx->vout[b.i].nValue;
                  });
        CAmount target = (outValue - vin0Value) + feeEst;
        for (size_t i = 0; i < coins.size() && fundIn < target; ++i) {
            if (!coins[i].fSpendable) continue;
            COutPoint op(coins[i].tx->GetHash(), coins[i].i);
            // Belt-and-suspenders: re-assert not protected.
            if (ZSLPIsProtectedTokenOutpoint(pwalletMain, store, op)) continue;
            funding.push_back(op);
            fundIn += coins[i].tx->vout[coins[i].i].nValue;
        }
    }

    CAmount target = (outValue - vin0Value) + feeEst;
    if (fundIn < target)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
            strprintf("Insufficient funds to fund the swap: have %d, need ~%d "
                      "(price+dust+fee, no change output is possible)",
                      fundIn, target));

    // Overshoot consent (§2.5: overshoot must NEVER be silent). With NO change
    // output possible under ALL, every zat of (funds in - outputs) is the miner
    // fee. The portion ABOVE the estimated fee is the buyer's accidental overpay.
    // If that exceeds a small dust threshold, REQUIRE acknowledge==true.
    CAmount overshootZat = (fundIn + vin0Value) - outValue; // total fee paid
    CAmount overpayZat = overshootZat - feeEst;             // beyond intended fee
    if (overpayZat < 0) overpayZat = 0;
    CAmount overshootDust = CTxOut(0, NftFreshWalletScript())
                                .GetDustThreshold(::minRelayTxFee);
    if (overpayZat > overshootDust && !acknowledge)
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf(
            "you would overpay %s ZCL to miner fees (overshoot %d zat, estimated "
            "fee %d zat); pass acknowledge:true to proceed",
            FormatMoney(overpayZat), overshootZat, feeEst));

    // Append funding inputs as vin[1..] ONLY (NO new outputs; fundrawtransaction
    // is forbidden — its random change insert breaks the ALL-pinned order).
    for (size_t i = 0; i < funding.size(); ++i)
        mtx.vin.push_back(CTxIn(funding[i], CScript(),
                                std::numeric_limits<unsigned int>::max()));

    // (4) Sign the buyer's inputs (vin[1..]) with ALL|ANYONECANPAY; leave vin[0]
    //     untouched and merge it via CombineSignatures.
    uint32_t branchId = CurrentEpochBranchId(chainActive.Height() + 1,
                                             Params().GetConsensus());
    CMutableTransaction sellerVariant = vr.tx; // carries vin[0]'s scriptSig
    {
        CTransaction txConst(mtx);
        for (size_t i = 1; i < mtx.vin.size(); ++i) {
            const COutPoint& op = mtx.vin[i].prevout;
            CCoins c;
            if (!pcoinsTip->GetCoins(op.hash, c) || !c.IsAvailable(op.n))
                throw JSONRPCError(RPC_WALLET_ERROR, "funding input vanished mid-sign");
            const CScript& spk = c.vout[op.n].scriptPubKey;
            CAmount amt = c.vout[op.n].nValue;
            SignatureData sigdata;
            if (!ProduceSignature(
                    TransactionSignatureCreator(pwalletMain, &txConst, i, amt,
                        SigHashType(SIGHASH_ALL | SIGHASH_ANYONECANPAY)),
                    spk, sigdata, branchId))
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("failed to sign funding input %d", (int)i));
            UpdateTransaction(mtx, i, sigdata);
        }
        // Merge the seller's pre-existing vin[0] scriptSig (CombineSignatures).
        {
            const CScript& spk0 = vr.nftPrevScript;
            CAmount amt0 = vr.nftPrevValue;
            SignatureData merged = CombineSignatures(
                spk0, TransactionSignatureChecker(&txConst, 0, amt0),
                DataFromTransaction(mtx, 0), DataFromTransaction(sellerVariant, 0),
                branchId);
            UpdateTransaction(mtx, 0, merged);
        }
    }

    // (5) Verify every input now signs cleanly (incl. the seller's ALL pin).
    {
        CTransaction txConst(mtx);
        for (size_t i = 0; i < mtx.vin.size(); ++i) {
            const COutPoint& op = mtx.vin[i].prevout;
            CCoins c;
            if (!pcoinsTip->GetCoins(op.hash, c) || !c.IsAvailable(op.n))
                throw JSONRPCError(RPC_WALLET_ERROR, "an input is no longer live");
            const CScript& spk = c.vout[op.n].scriptPubKey;
            CAmount amt = c.vout[op.n].nValue;
            ScriptError serr = SCRIPT_ERR_OK;
            if (!VerifyScript(mtx.vin[i].scriptSig, spk,
                              STANDARD_SCRIPT_VERIFY_FLAGS,
                              TransactionSignatureChecker(&txConst, i, amt),
                              branchId, &serr))
                throw JSONRPCError(RPC_WALLET_ERROR,
                    strprintf("input %d failed VerifyScript: %s", (int)i,
                              ScriptErrorString(serr)));
        }
    }

    // (6) Final self-validate (real parse + conservation) + anti-burn post-check.
    CTransaction finalTx(mtx);
    {
        std::vector<COutPoint> vin;
        for (size_t k = 0; k < finalTx.vin.size(); ++k) {
            vin.push_back(finalTx.vin[k].prevout);
            if (k >= 1 && ZSLPIsProtectedTokenOutpoint(pwalletMain, store,
                                                        finalTx.vin[k].prevout))
                throw JSONRPCError(RPC_WALLET_ERROR,
                    "anti-burn post-check: a funding input is a live token UTXO");
        }
        CZSLPParsedMsg parsed; CZSLPToken gm; bool haveGm = false;
        if (!CZSLPIndexer::ParseTx(finalTx, chainActive.Height() + 1, parsed,
                                   gm, haveGm))
            throw JSONRPCError(RPC_WALLET_ERROR, "self-validate: no SLP message at vout[0]");
        std::string why;
        if (!store->WouldBeValid(vin, &parsed, finalTx.GetHash(),
                                 haveGm ? &gm : NULL,
                                 (int32_t)finalTx.vout.size(), why))
            throw JSONRPCError(RPC_WALLET_ERROR,
                "self-validate: final tx would not be valid in the token ledger (" + why + ")");
    }

    // (7) Broadcast (mirror sendrawtransaction: ATMP + relay).
    {
        CValidationState state;
        bool fMissingInputs = false;
        if (!AcceptToMemoryPool(mempool, state, finalTx, false, &fMissingInputs, false)) {
            if (state.IsInvalid())
                throw JSONRPCError(RPC_TRANSACTION_REJECTED,
                    strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            if (fMissingInputs)
                throw JSONRPCError(RPC_TRANSACTION_ERROR, "Missing inputs");
            throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
        }
        RelayTransaction(finalTx);
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", finalTx.GetHash().GetHex()));
    ret.push_back(Pair("overshootZat", overshootZat)); // = the network fee donated
    return ret;
}

// ── nft_listoffers ──────────────────────────────────────────────────

UniValue nft_listoffers(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 0)
        throw std::runtime_error(
            "nft_listoffers\n"
            "\nList offers from the local store; status recomputed live against\n"
            "the UTXO set (open / filled / expired / canceled). Every record in\n"
            "the local store is yours (sent), so there is no filter.\n"
            "\nResult:\n"
            "[ { \"offerId\", \"tokenId\", \"priceZat\", \"expiryHeight\",\n"
            "    \"role\", \"status\" }, ... ]\n");

    NftGetStoreOrThrow(); // fail CLOSED if the index is off
    LOCK(cs_main);

    int tip = chainActive.Height();
    UniValue arr = NftLoadStore();
    UniValue out(UniValue::VARR);
    for (size_t i = 0; i < arr.size(); ++i) {
        const UniValue& rec = arr[i];
        std::string status = "open";
        std::string stored = find_value(rec, "status").get_str();
        int64_t expiry = find_value(rec, "expiryHeight").get_int64();

        // Live recompute against vin[0]'s prevout (the NFT outpoint).
        COutPoint nftOp;
        bool haveOp = NftParseOutpoint(find_value(rec, "nftOutpoint").get_str(), nftOp);
        bool nftLive = false;
        if (haveOp) {
            CCoins c;
            nftLive = pcoinsTip->GetCoins(nftOp.hash, c) && c.IsAvailable(nftOp.n);
        }
        if (stored == "canceled" || stored == "filled") {
            status = stored; // terminal states are sticky (we broadcast them)
        } else if (!nftLive) {
            // The NFT outpoint is spent but we did not record a terminal state:
            // someone filled/canceled it elsewhere.
            status = "filled";
        } else if (tip > expiry) {
            status = "expired";
        } else {
            status = "open";
        }

        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("offerId", find_value(rec, "offerId").get_str()));
        o.push_back(Pair("tokenId", find_value(rec, "tokenId").get_str()));
        o.push_back(Pair("priceZat", find_value(rec, "priceZat").get_int64()));
        o.push_back(Pair("expiryHeight", expiry));
        o.push_back(Pair("role", find_value(rec, "role").get_str()));
        o.push_back(Pair("status", status));
        out.push_back(o);
    }
    return out;
}

// ── nft_canceloffer ─────────────────────────────────────────────────

UniValue nft_canceloffer(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "nft_canceloffer '{\"offerId\":\"...\"}'\n"
            "\nCancel an outstanding sell offer by self-spending its NFT UTXO\n"
            "(a 1-output ZSLP SEND to a fresh own address). This voids any offer\n"
            "referencing that outpoint and unlocks it.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"params\" (object, required) { \"offerId\":\"hex\" }\n"
            "\nResult:\n{ \"txid\":\"hex\" }\n");

    CZSLPStore* store = NftGetStoreOrThrow();
    (void)store;
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const UniValue& o = params[0].get_obj();
    const UniValue& vid = find_value(o, "offerId");
    if (!vid.isStr() || vid.get_str().empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offerId is required");
    std::string offerId = vid.get_str();

    UniValue rec;
    if (!NftFindOffer(offerId, rec))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "offerId not found in the local store");

    uint256 tokenId = uint256S(find_value(rec, "tokenId").get_str());
    COutPoint nftOp;
    if (!NftParseOutpoint(find_value(rec, "nftOutpoint").get_str(), nftOp))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "stored nftOutpoint is malformed");

    EnsureWalletIsUnlocked();

    // Unlock so BuildAndCommitZSLP can spend it, then self-send the NFT (1-output
    // SEND to a fresh own address) — reuses the whole proven builder (DRY).
    { COutPoint tmp = nftOp; pwalletMain->UnlockCoin(tmp); }

    uint8_t tidBE[32]; ZSLPTokenIdToBE(tokenId, tidBE);
    std::vector<uint64_t> quantities; quantities.push_back(1);
    std::vector<unsigned char> opret = ZSLPBuildSend(tidBE, quantities);
    if (opret.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "failed to build cancel SEND OP_RETURN");

    ZSLPBuildReq req;
    req.opret = CScript(opret.begin(), opret.end());
    ZSLPTokenOut recip; recip.dest = NftFreshWalletScript(); recip.dustSats = SLP_TOKEN_DUST;
    req.tokenOuts.push_back(recip);
    req.tokenInputs.push_back(nftOp);
    req.selfValidateTokenId = tokenId;
    req.isGenesis = false;

    CWalletTx wtx;
    std::string err;
    if (!BuildAndCommitZSLP(pwalletMain, req, wtx, err)) {
        // Re-lock on failure so a transient error doesn't leave the NFT exposed.
        { COutPoint tmp = nftOp; pwalletMain->LockCoin(tmp); }
        throw JSONRPCError(RPC_WALLET_ERROR, err);
    }

    // Mark canceled in the store.
    {
        UniValue nrec = rec;
        nrec.pushKV("status", "canceled");
        nrec.pushKV("cancelTxid", wtx.GetHash().GetHex());
        NftUpsertOffer(nrec);
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("txid", wtx.GetHash().GetHex()));
    return ret;
}

// ── nft_requestbuy ──────────────────────────────────────────────────

UniValue nft_requestbuy(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "nft_requestbuy '{\"tokenId\":\"...\"}'\n"
            "\nProduce a fresh buyer NFT receive address + a request blob for the\n"
            "buyer-address handshake (so the seller can seal an offer to it).\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"params\" (object, required) { \"tokenId\":\"hex\" } (or \"offerId\")\n"
            "\nResult:\n{ \"buyerNftAddr\":\"t1..\", \"requestBlob\":\"base64\" }\n");

    NftGetStoreOrThrow();
    LOCK2(cs_main, pwalletMain->cs_wallet);

    const UniValue& o = params[0].get_obj();
    uint256 tokenId;
    const UniValue& vt = find_value(o, "tokenId");
    const UniValue& voi = find_value(o, "offerId");
    if (vt.isStr() && !vt.get_str().empty()) {
        tokenId = ParseHashV(vt, "tokenId");
    } else if (voi.isStr() && !voi.get_str().empty()) {
        UniValue rec;
        if (!NftFindOffer(voi.get_str(), rec))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "offerId not found");
        tokenId = uint256S(find_value(rec, "tokenId").get_str());
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "tokenId or offerId is required");
    }

    EnsureWalletIsUnlocked();

    CScript script = NftFreshWalletScript();
    std::string addr = NftAddrFromScript(script);

    // Request blob: versioned base64 { magic ZNFTREQ1, tokenId, buyerNftAddr }.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    const char rqmagic[8] = { 'Z','N','F','T','R','E','Q','1' };
    ss.write(rqmagic, 8);
    ss << tokenId;
    ss << addr;
    std::string requestBlob = EncodeBase64((const unsigned char*)&ss[0], ss.size());

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("buyerNftAddr", addr));
    ret.push_back(Pair("requestBlob", "znftreq:" + requestBlob));
    return ret;
}

#endif // ENABLE_WALLET

static const CRPCCommand commands[] =
{ //  category   name              actor (function)   okSafeMode
    { "nft",     "nft_verifyoffer", &nft_verifyoffer, true  },
    { "nft",     "nft_listoffers",  &nft_listoffers,  true  },
#ifdef ENABLE_WALLET
    { "nft",     "nft_makeoffer",   &nft_makeoffer,   false },
    { "nft",     "nft_takeoffer",   &nft_takeoffer,   false },
    { "nft",     "nft_canceloffer", &nft_canceloffer, false },
    { "nft",     "nft_requestbuy",  &nft_requestbuy,  false },
#endif
};

void RegisterNFTOfferRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
