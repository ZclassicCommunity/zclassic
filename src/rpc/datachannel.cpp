// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SHIELD pillar — PRIVATE file/data transfer over the Sapling shielded pool.
//
//   z_senddatafile      {from,to,filepath|hexdata,acknowledge_permanent,...}
//                         -> {transfer_id, fingerprint, ...}
//   z_listdatatransfers -> [ {transfer_id, fingerprint, direction, frames,
//                             status, height} ]
//   z_getdatatransfer   {transfer_id|fingerprint}
//                         -> reassemble + VERIFY-BEFORE-DECRYPT
//
// NON-CONSENSUS overlay. The data rides inside ordinary Sapling output MEMOs as
// ZDC1 frames (one 512-byte frame per memo; 512 == ZC_MEMO_SIZE exactly). Old
// nodes relay + mine these txs unchanged. No validation/PoW/consensus is touched.
//
// SAFETY GATES (all enforced in the daemon, not the GUI):
//   * default OFF behind -datachannel; when off the RPCs are NOT registered, so
//     the dispatcher returns RPC_METHOD_NOT_FOUND (-32601) — indistinguishable
//     from a nonexistent method.
//   * PERMANENCE CONSENT: z_senddatafile REQUIRES acknowledge_permanent=true.
//   * transfer_id is RANDOM (8 bytes from libsodium); the on-chain ANCHOR is the
//     ciphertext fingerprint (= what a ZSLP NFT document_hash would commit to).
//   * DoS caps: per-file size cap (ZDC_MAX_FILE_BYTES = 40000 bytes; derived
//     from the single-tx frame budget below), inflight TTL (72h), max inflight
//     transfers (256), and a basic per-call rate guard.
//   * VERIFY-BEFORE-DECRYPT: z_getdatatransfer confirms the on-chain ciphertext
//     fingerprint matches the recorded anchor BEFORE any AEAD decrypt, and
//     surfaces the distinct codec errors honestly.
//   * KEYS NEVER LEAVE THE WALLET: the only secret returned to the caller is the
//     per-transfer ZDC1 key it asked us to create; no ivk/spending key is exported.

#include "rpc/server.h"

#include "rpc/datachannel.h"   // E-2 test seams (de-hidden registry/DoS guards)
#include "datachannel/zdc.h"
#include "key_io.h"
#include "rpc/protocol.h"
#include "util.h"
#include "utilstrencodings.h"
#include "utiltime.h"

#include <sodium.h>

#ifdef ENABLE_WALLET
#include "init.h"          // pwalletMain
#include "main.h"          // cs_main
#include "wallet/wallet.h"
#include "wallet/asyncrpcoperation_senddatafile.h"
#include "asyncrpcqueue.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "transaction_builder.h"
extern bool EnsureWalletIsAvailable(bool avoidException);
// EnsureWalletIsUnlocked + getAsyncRPCQueue are declared in rpc/server.h.
#endif

#include <fstream>
#include <map>
#include <stdint.h>
#include <univalue.h>

// ── DoS / responsibility caps (POLICY, not consensus) ────────────────────────
//
// SINGLE-TX BROADCASTABILITY (the file-cap is derived, not wished for):
//   This transfer is ONE shielded tx. Every ZDC1 frame becomes one Sapling
//   OutputDescription = 948 bytes on the wire (cv32+cm32+ephemeralKey32+
//   encCiphertext580+outCiphertext80+zkproof192). A SpendDescription is 384B.
//   Consensus rejects any tx over MAX_TX_SIZE_AFTER_SAPLING (102000, see
//   consensus/consensus.h) at AcceptToMemoryPool/sendrawtransaction — AFTER all
//   Groth proofs are computed. So an honest file-cap MUST guarantee the worst-
//   case tx still fits. We budget conservatively:
//
//     reserve = envelope(~200) + change output(948) + spends(reserve ~16 * 384)
//             ≈ 7300 bytes  (rounded to ZDC_TX_OVERHEAD_RESERVE below)
//     output budget = 102000 - 7300 = 94700
//     max frames    = 94700 / 948 ≈ 99  → capped at ZDC_MAX_FRAMES_PER_TX (90)
//
//   90 frames includes 3 control frames (START, END, KEY), so 87 DATA frames *
//   464 plaintext bytes/frame = 40368 usable bytes. We advertise a clean 40000.
//   This is PROVABLY broadcastable: 90 * 948 + 7300 = 92620 < 102000, with
//   margin for many small input notes. A pre-build guard in the async op
//   double-checks the ACTUAL projected size (incl. real spend count) before any
//   proving, so an unusual UTXO set never produces a late "bad-txns-oversize".
static const size_t   ZDC_MAX_FILE_BYTES   = 40000;        // see derivation above
static const size_t   ZDC_MAX_FRAMES_PER_TX = 90;          // hard single-tx frame ceiling
static const size_t   ZDC_MAX_INFLIGHT     = 256;           // tracked transfers
static const int64_t  ZDC_INFLIGHT_TTL_SEC = 72 * 60 * 60;  // 72 hours
static const int64_t  ZDC_RATE_WINDOW_SEC  = 1;             // basic rate guard
static const int      ZDC_RATE_MAX_PER_WIN = 4;             // calls per window

// ── In-memory transfer registry (the disclosure + verify-before-decrypt hook) ─
//
// A z_senddatafile records the per-transfer SECRET (key) + the on-chain ANCHOR
// (ciphertext fingerprint) here, keyed by the RANDOM transfer_id. z_getdatatransfer
// reads it to (a) know the authoritative anchor for verify-before-decrypt and
// (b) hold the key needed to decrypt. This never persists to disk and never
// leaves the process; the only thing returned to a caller is its OWN key.
struct ZdcTransferRecord {
    uint64_t              transferId;
    std::string           fingerprintHex;   // 64 hex (the on-chain anchor)
    std::vector<uint8_t>  key;              // 32B per-transfer key
    std::string           fromAddress;
    std::string           toAddress;
    std::string           direction;        // "sent"
    uint32_t              frames;
    std::string           filename;
    int64_t               createdAt;        // GetTime()
};

static CCriticalSection cs_zdc;
static std::map<uint64_t, ZdcTransferRecord> g_zdcTransfers;  // by transfer_id
static int64_t g_zdcRateWindowStart = 0;
static int     g_zdcRateCount = 0;

static void ZdcExpireOld()  // caller holds cs_zdc
{
    int64_t now = GetTime();
    for (std::map<uint64_t, ZdcTransferRecord>::iterator it = g_zdcTransfers.begin();
         it != g_zdcTransfers.end(); ) {
        if (now - it->second.createdAt > ZDC_INFLIGHT_TTL_SEC) {
            // wipe the key before dropping the record
            if (!it->second.key.empty())
                sodium_memzero(&it->second.key[0], it->second.key.size());
            g_zdcTransfers.erase(it++);
        } else {
            ++it;
        }
    }
}

static void ZdcRateGuard()  // caller holds cs_zdc
{
    int64_t now = GetTime();
    if (now - g_zdcRateWindowStart >= ZDC_RATE_WINDOW_SEC) {
        g_zdcRateWindowStart = now;
        g_zdcRateCount = 0;
    }
    if (++g_zdcRateCount > ZDC_RATE_MAX_PER_WIN) {
        throw JSONRPCError(RPC_INVALID_REQUEST,
            "Data channel rate limit exceeded; slow down");
    }
}

static std::string BytesToHex(const uint8_t* p, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += h[p[i] >> 4]; s += h[p[i] & 0xF]; }
    return s;
}

// ── E-2 test seams (declared in rpc/datachannel.h) ───────────────────────────
//
// These call the REAL ZdcExpireOld/ZdcRateGuard and touch the REAL file-static
// registry + rate globals — so the gtest gates the exact production decision
// logic. They acquire cs_zdc the same way the RPCs do. No production code path
// changes; these are only reachable from the test binary.
void ZdcTestExpireOld()
{
    LOCK(cs_zdc);
    ZdcExpireOld();
}

bool ZdcTestRateGuardAdmits()
{
    LOCK(cs_zdc);
    try {
        ZdcRateGuard();
        return true;
    } catch (const UniValue&) {
        return false; // JSONRPCError throws a UniValue
    }
}

void ZdcTestSeedTransfer(uint64_t transferId, int64_t createdAt)
{
    LOCK(cs_zdc);
    ZdcTransferRecord rec;
    rec.transferId = transferId;
    rec.createdAt  = createdAt;
    rec.frames     = 0;
    g_zdcTransfers[transferId] = rec;
}

size_t ZdcTestTransferCount()
{
    LOCK(cs_zdc);
    return g_zdcTransfers.size();
}

bool ZdcTestHasTransfer(uint64_t transferId)
{
    LOCK(cs_zdc);
    return g_zdcTransfers.find(transferId) != g_zdcTransfers.end();
}

void ZdcTestReset()
{
    LOCK(cs_zdc);
    for (std::map<uint64_t, ZdcTransferRecord>::iterator it = g_zdcTransfers.begin();
         it != g_zdcTransfers.end(); ++it) {
        if (!it->second.key.empty())
            sodium_memzero(&it->second.key[0], it->second.key.size());
    }
    g_zdcTransfers.clear();
    g_zdcRateWindowStart = 0;
    g_zdcRateCount = 0;
}

#ifdef ENABLE_WALLET

// ── z_senddatafile ───────────────────────────────────────────────────────────
UniValue z_senddatafile(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "z_senddatafile '{\"fromaddress\":\"zs..\",\"toaddress\":\"zs..\","
            "\"filepath\":\"/path\"|\"hexdata\":\"hex\",\"acknowledge_permanent\":true,"
            "\"filename\":?,\"content_type\":?}'\n"
            "\nSend a PRIVATE file/data transfer over the Sapling shielded pool. The\n"
            "bytes are encrypted with a fresh per-transfer key, chunked into ZDC1\n"
            "frames, and emitted as N Sapling output memos in ONE shielded tx.\n"
            "\nPERMANENCE: the encrypted bytes are stored by every full node FOREVER\n"
            "and are public ciphertext. You MUST pass acknowledge_permanent=true.\n"
            + HelpRequiringPassphrase() +
            "\nSIZE: a transfer is ONE shielded tx; the per-file cap (40000 bytes) is\n"
            "chosen so the tx is always broadcastable (each frame is a Sapling output;\n"
            "the consensus tx-size limit caps how many fit). Larger files are rejected\n"
            "UP FRONT, before any proving work — never with a late consensus error.\n"
            "\nArguments:\n"
            "1. \"params\" (object, required)\n"
            "     fromaddress           (string, required) a Sapling z-addr in this wallet\n"
            "     toaddress             (string, required) recipient Sapling z-addr\n"
            "     filepath              (string) path to the file to send (<=40000 bytes), OR\n"
            "     hexdata               (string) raw bytes as hex (<=40000 bytes), one of the two\n"
            "     acknowledge_permanent (bool, required) must be true\n"
            "     filename              (string, optional) recorded in the transfer metadata\n"
            "     content_type          (string, optional) MIME type recorded in metadata\n"
            "\nResult:\n"
            "{\n"
            "  \"operationid\": \"opid\",   (async; poll with z_getoperationresult)\n"
            "  \"transfer_id\": \"hex\",    (RANDOM 64-bit id)\n"
            "  \"fingerprint\": \"hex\",    (32-byte ciphertext anchor = NFT document_hash)\n"
            "  \"frames\": n,\n"
            "  \"key\": \"hex\"             (the per-transfer key, for selective disclosure)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_senddatafile",
                "'{\"fromaddress\":\"zs1..\",\"toaddress\":\"zs1..\",\"filepath\":\"/tmp/secret.bin\",\"acknowledge_permanent\":true}'"));

    LOCK(cs_zdc);
    ZdcRateGuard();
    ZdcExpireOld();
    if (g_zdcTransfers.size() >= ZDC_MAX_INFLIGHT)
        throw JSONRPCError(RPC_INVALID_REQUEST,
            strprintf("Too many tracked transfers (max %u); wait for old ones to expire", (unsigned)ZDC_MAX_INFLIGHT));

    const UniValue& o = params[0].get_obj();

    // PERMANENCE CONSENT — enforced at the daemon, never the GUI.
    bool ack = false;
    { const UniValue& v = find_value(o, "acknowledge_permanent");
      if (!v.isNull()) ack = v.get_bool(); }
    if (!ack)
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            "Refusing: the encrypted bytes are PERMANENT and public-ciphertext on-chain "
            "forever. Pass acknowledge_permanent=true to proceed.");

    std::string fromAddress, toAddress;
    { const UniValue& v = find_value(o, "fromaddress"); if (v.isStr()) fromAddress = v.get_str(); }
    { const UniValue& v = find_value(o, "toaddress");   if (v.isStr()) toAddress   = v.get_str(); }
    if (fromAddress.empty() || toAddress.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "fromaddress and toaddress are required");

    std::string filename, contentType;
    { const UniValue& v = find_value(o, "filename");     if (v.isStr()) filename    = v.get_str(); }
    { const UniValue& v = find_value(o, "content_type"); if (v.isStr()) contentType = v.get_str(); }

    // Read the plaintext from filepath OR hexdata (exactly one).
    std::vector<uint8_t> plaintext;
    const UniValue& vfile = find_value(o, "filepath");
    const UniValue& vhex  = find_value(o, "hexdata");
    bool haveFile = vfile.isStr() && !vfile.get_str().empty();
    bool haveHex  = vhex.isStr()  && !vhex.get_str().empty();
    if (haveFile == haveHex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "provide exactly one of filepath or hexdata");

    if (haveFile) {
        std::string path = vfile.get_str();
        std::ifstream f(path.c_str(), std::ios::binary);
        if (!f.good())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "cannot open filepath: " + path);
        f.seekg(0, std::ios::end);
        std::streamoff sz = f.tellg();
        if (sz < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "cannot size file: " + path);
        if ((size_t)sz > ZDC_MAX_FILE_BYTES)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("file too large (%lld bytes); the data channel cap is %u bytes",
                          (long long)sz, (unsigned)ZDC_MAX_FILE_BYTES));
        f.seekg(0, std::ios::beg);
        plaintext.resize((size_t)sz);
        if (sz > 0) f.read((char*)&plaintext[0], sz);
        if (!f && sz > 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "failed reading file: " + path);
        if (filename.empty()) {
            size_t slash = path.find_last_of("/\\");
            filename = (slash == std::string::npos) ? path : path.substr(slash + 1);
        }
    } else {
        std::string h = vhex.get_str();
        if (!IsHex(h))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "hexdata is not valid hex");
        std::vector<unsigned char> raw = ParseHex(h);
        if (raw.size() > ZDC_MAX_FILE_BYTES)
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                strprintf("hexdata too large (%u bytes); the data channel cap is %u bytes",
                          (unsigned)raw.size(), (unsigned)ZDC_MAX_FILE_BYTES));
        plaintext.assign(raw.begin(), raw.end());
    }

    // Fresh per-transfer key + RANDOM transfer_id (NOT the txid, NOT a token id).
    std::vector<uint8_t> key;
    if (zdc::ZdcAead::generate_key(key) != zdc::OK)
        throw JSONRPCError(RPC_INTERNAL_ERROR, "failed to generate transfer key");
    uint64_t transferId = 0;
    randombytes_buf(&transferId, sizeof(transferId));
    // Avoid an in-flight collision (astronomically unlikely, but cheap to check).
    while (g_zdcTransfers.count(transferId))
        randombytes_buf(&transferId, sizeof(transferId));

    // Encode -> ZDC1 frames. include_key_frame=true puts the KEY frame on-chain
    // so the recipient z-addr (who holds the ivk) can decrypt directly; the key
    // is ALSO returned to the sender for out-of-band / selective disclosure.
    zdc::TransferMeta meta;
    meta.filename = filename;
    meta.content_type = contentType;
    meta.total_plaintext_size = plaintext.size();
    meta.chunk_count = 0; // filled by encoder
    std::vector<std::vector<uint8_t> > frames;
    zdc::Status es = zdc::Encoder::encode(transferId, key, plaintext, meta,
                                          /*include_key_frame=*/true, frames);
    if (es != zdc::OK) {
        if (!key.empty()) sodium_memzero(&key[0], key.size());
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            std::string("encode failed: ") + zdc::status_str(es));
    }

    // The on-chain ANCHOR = SHA-256 over the DATA-frame ciphertexts.
    uint8_t fp[zdc::CONTENT_HASH_LEN];
    if (zdc::ciphertext_fingerprint(frames, fp) != zdc::OK) {
        if (!key.empty()) sodium_memzero(&key[0], key.size());
        throw JSONRPCError(RPC_INTERNAL_ERROR, "fingerprint computation failed");
    }
    std::string fingerprintHex = BytesToHex(fp, zdc::CONTENT_HASH_LEN);

    // SINGLE-TX FRAME GUARD (reject BEFORE proving, never after).
    // The 40000-byte file cap already bounds DATA frames, but guard the total
    // frame count explicitly so the invariant is enforced at the point that
    // matters and a future cap change can't silently exceed one tx. The async op
    // re-checks the ACTUAL projected serialized size (incl. real spend count)
    // before Build(); this is the cheap up-front gate.
    if (frames.size() > ZDC_MAX_FRAMES_PER_TX) {
        if (!key.empty()) sodium_memzero(&key[0], key.size());
        throw JSONRPCError(RPC_INVALID_PARAMETER,
            strprintf("transfer needs %u frames but a single shielded tx holds at "
                      "most %u; reduce the file size (cap is %u bytes)",
                      (unsigned)frames.size(), (unsigned)ZDC_MAX_FRAMES_PER_TX,
                      (unsigned)ZDC_MAX_FILE_BYTES));
    }

    // Convert frames to unsigned char vectors for the async op.
    std::vector<std::vector<unsigned char> > ucFrames;
    ucFrames.reserve(frames.size());
    for (size_t i = 0; i < frames.size(); ++i)
        ucFrames.push_back(std::vector<unsigned char>(frames[i].begin(), frames[i].end()));

    EnsureWalletIsUnlocked();

    // Build the dedicated async op (N same-recipient outputs in one tx).
    int nextBlockHeight;
    {
        LOCK(cs_main);
        nextBlockHeight = chainActive.Height() + 1;
    }
    TransactionBuilder builder(Params().GetConsensus(), nextBlockHeight, pwalletMain);
    CMutableTransaction contextualTx =
        CreateNewContextualCMutableTransaction(Params().GetConsensus(), nextBlockHeight);

    UniValue ctx(UniValue::VOBJ);
    ctx.push_back(Pair("fromaddress", fromAddress));
    ctx.push_back(Pair("toaddress", toAddress));
    ctx.push_back(Pair("frames", (int)ucFrames.size()));
    ctx.push_back(Pair("fingerprint", fingerprintHex));

    std::shared_ptr<AsyncRPCQueue> q = getAsyncRPCQueue();
    std::shared_ptr<AsyncRPCOperation> operation(new AsyncRPCOperation_senddatafile(
        builder, contextualTx, fromAddress, toAddress, ucFrames,
        transferId, fingerprintHex, /*minDepth=*/1, /*fee=*/SENDDATAFILE_DEFAULT_MINERS_FEE, ctx));
    q->addOperation(operation);
    AsyncRPCOperationId operationId = operation->getId();

    // Record the transfer (key + anchor) for list/get + disclosure.
    ZdcTransferRecord rec;
    rec.transferId = transferId;
    rec.fingerprintHex = fingerprintHex;
    rec.key = key;            // held in-process only; never persisted
    rec.fromAddress = fromAddress;
    rec.toAddress = toAddress;
    rec.direction = "sent";
    rec.frames = (uint32_t)ucFrames.size();
    rec.filename = filename;
    rec.createdAt = GetTime();
    g_zdcTransfers[transferId] = rec;

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("operationid", operationId));
    ret.push_back(Pair("transfer_id", strprintf("%016x", transferId)));
    ret.push_back(Pair("fingerprint", fingerprintHex));
    ret.push_back(Pair("frames", (int)ucFrames.size()));
    ret.push_back(Pair("key", BytesToHex(&key[0], key.size())));
    return ret;
}

// ── z_listdatatransfers ──────────────────────────────────────────────────────
UniValue z_listdatatransfers(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() > 0)
        throw std::runtime_error(
            "z_listdatatransfers\n"
            "\nList the data transfers this node knows about (sent this session).\n"
            "\nIn this build \"direction\" is ALWAYS \"sent\" and \"status\" is ALWAYS\n"
            "\"recorded\": only the send path is built. The values \"received\" and\n"
            "\"complete\" are reserved for the unbuilt receive path and never appear\n"
            "here yet.\n"
            "\nResult: [ { \"transfer_id\", \"fingerprint\", \"direction\",\n"
            "             \"frames\", \"status\", \"toaddress\", \"filename\" }, ... ]\n"
            "\nExamples:\n"
            + HelpExampleCli("z_listdatatransfers", ""));

    LOCK(cs_zdc);
    ZdcExpireOld();

    UniValue arr(UniValue::VARR);
    for (std::map<uint64_t, ZdcTransferRecord>::const_iterator it = g_zdcTransfers.begin();
         it != g_zdcTransfers.end(); ++it) {
        const ZdcTransferRecord& r = it->second;
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("transfer_id", strprintf("%016x", r.transferId)));
        obj.push_back(Pair("fingerprint", r.fingerprintHex));
        // direction is always "sent" and status always "recorded" in this build
        // (the receive path is not built; see the help). No identity wrapper.
        obj.push_back(Pair("direction", r.direction.c_str()));
        obj.push_back(Pair("frames", (int)r.frames));
        obj.push_back(Pair("status", "recorded"));
        obj.push_back(Pair("fromaddress", r.fromAddress));
        obj.push_back(Pair("toaddress", r.toAddress));
        obj.push_back(Pair("filename", r.filename));
        arr.push_back(obj);
    }
    return arr;
}

// ── z_getdatatransfer ────────────────────────────────────────────────────────
UniValue z_getdatatransfer(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "z_getdatatransfer '{\"transfer_id\":\"hex\"|\"fingerprint\":\"hex\",\"address\":\"zs..\"}'\n"
            "\nReassemble a data transfer from the on-chain Sapling memos held by\n"
            "this wallet, VERIFY-BEFORE-DECRYPT (confirm the ciphertext fingerprint\n"
            "matches the recorded anchor BEFORE attempting decryption), then decrypt.\n"
            "\nArguments:\n"
            "1. \"params\" (object, required)\n"
            "     transfer_id  (string) the 16-hex transfer id, OR\n"
            "     fingerprint  (string) the 64-hex ciphertext anchor\n"
            "     address      (string, optional) the z-addr that received the frames\n"
            "                  (default: the recorded toaddress)\n"
            "     verify_fingerprint (string, optional) a 64-hex anchor known OUT OF\n"
            "                  BAND (e.g. a published NFT document_hash). If given, the\n"
            "                  on-chain ciphertext MUST hash to THIS value or the call\n"
            "                  refuses to decrypt (ERR_HASH_MISMATCH, no plaintext),\n"
            "                  even when the local registry anchor matches.\n"
            "\nResult:\n"
            "{\n"
            "  \"transfer_id\": \"hex\",\n"
            "  \"fingerprint\": \"hex\",\n"
            "  \"verified\": true|false,    (on-chain anchor == recorded anchor)\n"
            "  \"complete\": true|false,\n"
            "  \"frames_received\": n,\n"
            "  \"hexdata\": \"hex\",        (plaintext, only if verified+decrypted)\n"
            "  \"filename\": \"...\",\n"
            "  \"error\": \"...\"           (honest codec error if any)\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("z_getdatatransfer", "'{\"transfer_id\":\"0123456789abcdef\"}'"));

    const UniValue& o = params[0].get_obj();

    std::string transferIdHex, fingerprintHex, address, verifyFingerprintHex;
    { const UniValue& v = find_value(o, "transfer_id"); if (v.isStr()) transferIdHex = v.get_str(); }
    { const UniValue& v = find_value(o, "fingerprint"); if (v.isStr()) fingerprintHex = v.get_str(); }
    { const UniValue& v = find_value(o, "address");     if (v.isStr()) address = v.get_str(); }
    // OPTIONAL caller-asserted anchor (the verify-before-decrypt expectation a
    // recipient obtained OUT OF BAND, e.g. a published ZSLP NFT document_hash).
    // When supplied, the on-chain ciphertext MUST hash to THIS value or we refuse
    // to decrypt — even if the in-process registry anchor matches. This is the
    // real-world gate: trust the independently-known anchor, not just our own record.
    { const UniValue& v = find_value(o, "verify_fingerprint"); if (v.isStr()) verifyFingerprintHex = v.get_str(); }
    if (transferIdHex.empty() && fingerprintHex.empty())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "provide transfer_id or fingerprint");
    if (!verifyFingerprintHex.empty() &&
        (verifyFingerprintHex.size() != 64 || !IsHex(verifyFingerprintHex)))
        throw JSONRPCError(RPC_INVALID_PARAMETER, "verify_fingerprint must be 64 hex chars");

    // ── (A) FAST-PATH: a registry record from THIS session (sender) ─────────
    // The record holds the authoritative anchor + the per-transfer key, so we can
    // serve verify-before-decrypt even when (rarely) no KEY frame rode on chain.
    ZdcTransferRecord rec;
    bool haveRec = false;
    uint64_t wantId = 0;
    if (!transferIdHex.empty()) {
        if (transferIdHex.size() != 16 || !IsHex(transferIdHex))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "transfer_id must be 16 hex chars");
        wantId = strtoull(transferIdHex.c_str(), NULL, 16);
        LOCK(cs_zdc);
        ZdcExpireOld();
        std::map<uint64_t, ZdcTransferRecord>::const_iterator it = g_zdcTransfers.find(wantId);
        if (it != g_zdcTransfers.end()) { rec = it->second; haveRec = true; }
    } else {
        if (fingerprintHex.size() != 64 || !IsHex(fingerprintHex))
            throw JSONRPCError(RPC_INVALID_PARAMETER, "fingerprint must be 64 hex chars");
        LOCK(cs_zdc);
        ZdcExpireOld();
        for (std::map<uint64_t, ZdcTransferRecord>::const_iterator it = g_zdcTransfers.begin();
             it != g_zdcTransfers.end(); ++it) {
            if (it->second.fingerprintHex == fingerprintHex) {
                rec = it->second; haveRec = true; wantId = it->first; break;
            }
        }
    }

    // The address to scan: explicit param > recorded toaddress > all in-wallet
    // z-addrs (empty string => GetFilteredNotes scans every address we can view).
    if (address.empty() && haveRec) address = rec.toAddress;

    // Pull the wallet's Sapling notes. requireSpendingKey=false so a VIEWING-KEY-
    // ONLY wallet (the recipient with only an ivk) still sees its frames; the ivk
    // path inside GetFilteredNotes decrypts each Sapling memo to plaintext for us.
    // No spending key / ivk ever leaves the wallet; we only read decrypted memos.
    std::vector<SaplingNoteEntry> saplingEntries;
    std::vector<CSproutNotePlaintextEntry> sproutEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, address,
                                      /*minDepth=*/0, /*ignoreSpent=*/false,
                                      /*requireSpendingKey=*/false);
    }

    // ── (B) REGISTRY-MISS FALLBACK: reconstruct purely from chain ────────────
    // No session record for this id/fingerprint (a cross-wallet recipient, or the
    // sender after a restart). We resolve wantId from the on-chain frames alone:
    //   * transfer_id query  -> wantId already parsed above.
    //   * fingerprint query  -> group in-wallet ZDC frames by transfer_id, recompute
    //                           each group's ciphertext fingerprint, pick the match.
    // Everything after this point is identical to the fast-path; the ONLY secret we
    // ever rely on is the on-chain KEY frame (decrypted to us by our own ivk), which
    // the Decoder consumes automatically in add_frame — we never need rec.key.
    if (!haveRec && transferIdHex.empty()) {
        // fingerprint-only, no record: find the transfer_id whose DATA frames hash
        // to the requested fingerprint. (Bounded by this wallet's note count.)
        std::map<uint64_t, std::vector<std::vector<uint8_t> > > byId;
        for (size_t i = 0; i < saplingEntries.size(); ++i) {
            std::vector<uint8_t> memo(saplingEntries[i].memo.begin(), saplingEntries[i].memo.end());
            zdc::FrameHeader h;
            if (zdc::parse_header(&memo[0], h) != zdc::OK) continue; // skip non-ZDC memos
            byId[h.transfer_id].push_back(memo);
        }
        bool foundId = false;
        for (std::map<uint64_t, std::vector<std::vector<uint8_t> > >::const_iterator
                 it = byId.begin(); it != byId.end(); ++it) {
            uint8_t fp[zdc::CONTENT_HASH_LEN];
            if (zdc::ciphertext_fingerprint(it->second, fp) != zdc::OK) continue;
            if (BytesToHex(fp, zdc::CONTENT_HASH_LEN) == fingerprintHex) {
                wantId = it->first; foundId = true; break;
            }
        }
        if (!foundId)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY,
                "transfer not found: no in-wallet Sapling frames hash to that fingerprint "
                "(this wallet is not the recipient, or the frames have not arrived)");
    }

    // Feed matching frames to the decoder (it locks to the first transfer_id it
    // accepts; the on-chain KEY frame, if visible to our ivk, populates the key).
    zdc::Decoder dec;
    uint32_t fed = 0;
    for (size_t i = 0; i < saplingEntries.size(); ++i) {
        std::vector<uint8_t> memo(saplingEntries[i].memo.begin(), saplingEntries[i].memo.end());
        zdc::FrameHeader h;
        if (zdc::parse_header(&memo[0], h) != zdc::OK) continue; // foreign/text memo
        if (h.transfer_id != wantId) continue;
        if (dec.add_frame(memo) == zdc::OK) ++fed;
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("transfer_id", strprintf("%016x", wantId)));
    // Authoritative anchor: registry record if we have one, else the on-chain
    // recomputed fingerprint (filled below once frames are complete).
    if (haveRec) ret.push_back(Pair("fingerprint", rec.fingerprintHex));
    ret.push_back(Pair("frames_received", (int)fed));
    ret.push_back(Pair("complete", dec.is_complete()));

    // VERIFY-BEFORE-DECRYPT: recompute the anchor over the DATA frames we hold and
    // compare to the EXPECTED anchor BEFORE any decrypt. Expected =
    //   verify_fingerprint (caller out-of-band) if supplied;
    //   else rec.fingerprintHex if we have a record;
    //   else (cross-wallet, no record) the on-chain recompute IS the anchor — there
    //   is nothing independent to compare to, so "verified" means the frames form a
    //   self-consistent transfer; a caller wanting a trust anchor passes
    //   verify_fingerprint (e.g. the published NFT document_hash).
    bool verified = false;
    std::string onchain;
    if (dec.is_complete()) {
        std::vector<std::vector<uint8_t> > frames;
        for (size_t i = 0; i < saplingEntries.size(); ++i) {
            std::vector<uint8_t> memo(saplingEntries[i].memo.begin(), saplingEntries[i].memo.end());
            zdc::FrameHeader h;
            if (zdc::parse_header(&memo[0], h) != zdc::OK) continue;
            if (h.transfer_id != wantId) continue;
            frames.push_back(memo);
        }
        uint8_t fp[zdc::CONTENT_HASH_LEN];
        if (zdc::ciphertext_fingerprint(frames, fp) == zdc::OK) {
            onchain = BytesToHex(fp, zdc::CONTENT_HASH_LEN);
            if (!verifyFingerprintHex.empty())
                verified = (onchain == verifyFingerprintHex);
            else if (haveRec)
                verified = (onchain == rec.fingerprintHex);
            else
                verified = true; // no independent anchor to compare against
            ret.push_back(Pair("onchain_fingerprint", onchain));
            if (!haveRec) ret.push_back(Pair("fingerprint", onchain));
            if (!verifyFingerprintHex.empty())
                ret.push_back(Pair("expected_fingerprint", verifyFingerprintHex));
        }
    }
    ret.push_back(Pair("verified", verified));

    if (!dec.is_complete()) {
        ret.push_back(Pair("error",
            std::string(zdc::status_str(zdc::ERR_INCOMPLETE)) + " (frames still missing)"));
        return ret;
    }
    if (!verified) {
        // VERIFY-BEFORE-DECRYPT refusal: NEVER decrypt or return plaintext when the
        // on-chain anchor does not match the expected fingerprint.
        ret.push_back(Pair("error",
            std::string(zdc::status_str(zdc::ERR_HASH_MISMATCH)) +
            (!verifyFingerprintHex.empty()
                ? " (on-chain fingerprint != caller-asserted verify_fingerprint; refusing to decrypt)"
                : " (on-chain fingerprint != recorded anchor; refusing to decrypt)")));
        return ret;
    }

    // Anchor verified. The key comes from the on-chain KEY frame the Decoder already
    // consumed (cross-wallet recipient, or sender-after-restart via its own ovk-
    // decrypted outgoing memo). If we ALSO hold a registry key, set it as a belt-and-
    // suspenders authoritative source; assemble() then AEAD-decrypts. No key is ever
    // returned or logged.
    if (haveRec && !rec.key.empty())
        dec.set_key(rec.key);

    std::vector<uint8_t> out;
    zdc::TransferMeta gotMeta;
    zdc::Status ds = dec.assemble(out, gotMeta);
    if (ds != zdc::OK) {
        // Distinct codec error, honestly surfaced (never plaintext on failure):
        //   ERR_NO_KEY      -> no KEY frame visible to this wallet (not the recipient)
        //   ERR_AEAD_FAIL   -> tamper / wrong key
        //   ERR_HASH_MISMATCH -> reassembled plaintext != END content hash
        ret.push_back(Pair("error", zdc::status_str(ds)));
        return ret;
    }

    ret.push_back(Pair("hexdata", BytesToHex(out.empty() ? (const uint8_t*)"" : &out[0], out.size())));
    ret.push_back(Pair("size", (int)out.size()));
    ret.push_back(Pair("filename", gotMeta.filename));
    ret.push_back(Pair("content_type", gotMeta.content_type));
    return ret;
}

#endif // ENABLE_WALLET

// ── Registration (default OFF -> RPC_METHOD_NOT_FOUND when -datachannel off) ──
static const CRPCCommand commands[] =
{ //  category        name                   actor (function)      okSafeMode
#ifdef ENABLE_WALLET
    { "datachannel",  "z_senddatafile",      &z_senddatafile,      false },
    { "datachannel",  "z_listdatatransfers", &z_listdatatransfers, true  },
    { "datachannel",  "z_getdatatransfer",   &z_getdatatransfer,   true  },
#endif
};

void RegisterDataChannelRPCCommands(CRPCTable& tableRPC)
{
    // GATE: only register when -datachannel is on. When off, the methods are
    // ABSENT, so rpc/server.cpp's dispatcher throws RPC_METHOD_NOT_FOUND
    // (-32601) — indistinguishable from a nonexistent method. (Default OFF.)
    if (!GetBoolArg("-datachannel", false))
        return;
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
