// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zslp/zslpindex.h"

#include "base58.h"
#include "dbwrapper.h"
#include "hash.h"
#include "key_io.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "util.h"
#include "utilstrencodings.h"

#include "c23/services/glue/zcl_slp_index.h"

#include <algorithm>
#include <memory>
#include <string.h>

namespace zslp {

// ---- stores ---------------------------------------------------------------

bool MemKV::Get(const std::string& key, std::string& value) const
{
    std::map<std::string, std::string>::const_iterator it = m.find(key);
    if (it == m.end())
        return false;
    value = it->second;
    return true;
}

bool MemKV::WriteBatch(const std::vector<Op>& ops, bool)
{
    for (size_t i = 0; i < ops.size(); i++) {
        if (ops[i].erase)
            m.erase(ops[i].key);
        else
            m[ops[i].key] = ops[i].value;
    }
    nBatches++;
    return true;
}

void MemKV::Scan(const std::string& prefix,
                 const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    for (std::map<std::string, std::string>::const_iterator it = m.lower_bound(prefix); it != m.end(); ++it) {
        if (it->first.compare(0, prefix.size(), prefix) != 0)
            break;
        if (!fn(it->first, it->second))
            break;
    }
}

namespace {
/** Raw bytes as a CDBWrapper key or value: no length prefix, so prefix iteration works. */
struct RawBytes {
    std::string d;
    RawBytes() {}
    explicit RawBytes(const std::string& s) : d(s) {}
    template <typename Stream> void Serialize(Stream& s) const { if (!d.empty()) s.write(d.data(), d.size()); }
    template <typename Stream> void Unserialize(Stream& s)
    {
        d.resize(s.size());
        if (!d.empty())
            s.read(&d[0], d.size());
    }
};
} // namespace

LevelKV::LevelKV(const std::string& path, size_t nCacheBytes, bool fMemory, bool fWipe)
    : db(new CDBWrapper(path, nCacheBytes, fMemory, fWipe))
{
}

LevelKV::~LevelKV() { delete db; }

bool LevelKV::Get(const std::string& key, std::string& value) const
{
    RawBytes v;
    if (!db->Read(RawBytes(key), v))
        return false;
    value = v.d;
    return true;
}

bool LevelKV::WriteBatch(const std::vector<Op>& ops, bool fSync)
{
    CDBBatch batch(*db);
    for (size_t i = 0; i < ops.size(); i++) {
        if (ops[i].erase)
            batch.Erase(RawBytes(ops[i].key));
        else
            batch.Write(RawBytes(ops[i].key), RawBytes(ops[i].value));
    }
    return db->WriteBatch(batch, fSync);
}

void LevelKV::Scan(const std::string& prefix,
                   const std::function<bool(const std::string&, const std::string&)>& fn) const
{
    std::unique_ptr<CDBIterator> it(db->NewIterator());
    it->Seek(RawBytes(prefix));
    while (it->Valid()) {
        RawBytes k, v;
        if (!it->GetKey(k) || k.d.compare(0, prefix.size(), prefix) != 0)
            break;
        if (!it->GetValue(v))
            break;
        if (!fn(k.d, v.d))
            break;
        it->Next();
    }
}

bool WipeKV(KV* kv, const std::string& keepKey, std::string& err)
{
    std::vector<KV::Op> ops;
    kv->Scan("", [&](const std::string& k, const std::string&) {
        if (k != keepKey) {
            KV::Op op;
            op.key = k;
            op.erase = true;
            ops.push_back(op);
        }
        return true;
    });
    if (ops.empty())
        return true;
    if (!kv->WriteBatch(ops, true)) {
        err = "the index store is not writable";
        return false;
    }
    return true;
}

// ---- encoding -------------------------------------------------------------

namespace {

struct Enc {
    std::string s;
    void U8(unsigned int v) { s.push_back((char)(v & 0xff)); }
    void U32(uint32_t v) { for (int i = 3; i >= 0; i--) s.push_back((char)((v >> (8 * i)) & 0xff)); }
    void U64(uint64_t v) { for (int i = 7; i >= 0; i--) s.push_back((char)((v >> (8 * i)) & 0xff)); }
    void Raw(const void* p, size_t n) { s.append((const char*)p, n); }
    void H(const uint256& h) { Raw(h.begin(), 32); }
    void Str(const std::string& x) { U32((uint32_t)x.size()); s += x; }
};

struct Dec {
    const std::string& s;
    size_t p;
    bool ok;
    explicit Dec(const std::string& str) : s(str), p(0), ok(true) {}
    bool Need(size_t n) { if (!ok || s.size() - p < n) { ok = false; return false; } return true; }
    unsigned int U8() { if (!Need(1)) return 0; return (unsigned char)s[p++]; }
    uint32_t U32() { if (!Need(4)) return 0; uint32_t v = 0; for (int i = 0; i < 4; i++) v = (v << 8) | (unsigned char)s[p++]; return v; }
    uint64_t U64() { if (!Need(8)) return 0; uint64_t v = 0; for (int i = 0; i < 8; i++) v = (v << 8) | (unsigned char)s[p++]; return v; }
    uint256 H() { uint256 h; if (Need(32)) { memcpy(h.begin(), s.data() + p, 32); p += 32; } return h; }
    std::string Str()
    {
        uint32_t n = U32();
        if (!Need(n)) return std::string();
        std::string r = s.substr(p, n);
        p += n;
        return r;
    }
    std::string Fixed(size_t n)
    {
        if (!Need(n)) return std::string();
        std::string r = s.substr(p, n);
        p += n;
        return r;
    }
};

const std::string kBestKey = "mbest";
const std::string kStatKey = "mstat";
const std::string kVerKey = "mver";
const unsigned int kVersion = 1;

std::string BE32(uint32_t v)
{
    std::string r;
    for (int i = 3; i >= 0; i--) r.push_back((char)((v >> (8 * i)) & 0xff));
    return r;
}

std::string HStr(const uint256& h) { return std::string((const char*)h.begin(), 32); }

std::string KeyOut(const uint256& txid, unsigned int n) { return "o" + HStr(txid) + BE32(n); }
std::string KeyTok(const uint256& id) { return "t" + HStr(id); }
std::string KeyTx(const uint256& txid) { return "x" + HStr(txid); }
std::string KeyAddrBal(const std::string& addr, const uint256& token) { return "a" + addr + HStr(token); }
std::string KeyTokBal(const uint256& token, const std::string& addr) { return "h" + HStr(token) + addr; }
std::string KeyUndo(const uint256& h) { return "u" + HStr(h); }
std::string KeyTokenTx(const uint256& token, int height, const uint256& txid)
{
    return "y" + HStr(token) + BE32((uint32_t)height) + HStr(txid);
}

std::string EncodeToken(const TokenInfo& t)
{
    Enc e;
    e.Str(t.ticker); e.Str(t.name); e.Str(t.documentUrl);
    e.U8(t.hasDocumentHash ? 1 : 0); e.H(t.documentHash);
    e.U8(t.decimals); e.U32((uint32_t)t.genesisHeight);
    e.U64(t.minted); e.U64(t.sendBurned); e.U64(t.spentBurned);
    e.U8(t.supplyOverflow ? 1 : 0);
    e.U8(t.hasBaton ? 1 : 0); e.H(t.batonTx); e.U32(t.batonVout);
    e.U32(t.nTx);
    return e.s;
}

bool DecodeToken(const uint256& id, const std::string& v, TokenInfo& t)
{
    Dec d(v);
    t.id = id;
    t.ticker = d.Str(); t.name = d.Str(); t.documentUrl = d.Str();
    t.hasDocumentHash = d.U8() != 0; t.documentHash = d.H();
    t.decimals = d.U8(); t.genesisHeight = (int)d.U32();
    t.minted = d.U64(); t.sendBurned = d.U64(); t.spentBurned = d.U64();
    t.supplyOverflow = d.U8() != 0;
    t.hasBaton = d.U8() != 0; t.batonTx = d.H(); t.batonVout = d.U32();
    t.nTx = d.U32();
    return d.ok;
}

std::string EncodeOut(const OutInfo& o)
{
    Enc e;
    e.H(o.token); e.U64(o.amount); e.U8(o.role); e.Raw(o.addr.data(), 21); e.U32((uint32_t)o.height);
    return e.s;
}

bool DecodeOut(const std::string& v, OutInfo& o)
{
    Dec d(v);
    o.token = d.H(); o.amount = d.U64(); o.role = (int)d.U8(); o.addr = d.Fixed(21); o.height = (int)d.U32();
    return d.ok;
}

std::string EncodeTx(const TxInfo& t)
{
    Enc e;
    e.U8(t.type); e.U8(t.status); e.Str(t.reason); e.H(t.token); e.U32((uint32_t)t.height);
    e.U64(t.inputUnits); e.U64(t.outputUnits); e.U64(t.mintedUnits); e.U64(t.burnedUnits);
    e.U32((uint32_t)t.inputs.size());
    for (size_t i = 0; i < t.inputs.size(); i++) {
        const TxInput& in = t.inputs[i];
        e.H(in.txid); e.U32(in.vout); e.H(in.token); e.U64(in.amount); e.U8(in.role);
    }
    e.U32((uint32_t)t.outputs.size());
    for (size_t i = 0; i < t.outputs.size(); i++) {
        const TxOutput& o = t.outputs[i];
        e.U32(o.vout); e.H(o.token); e.U64(o.amount); e.U8(o.role); e.Raw(o.addr.data(), 21);
    }
    return e.s;
}

bool DecodeTx(const std::string& v, TxInfo& t)
{
    Dec d(v);
    t.type = (int)d.U8(); t.status = (int)d.U8(); t.reason = d.Str(); t.token = d.H(); t.height = (int)d.U32();
    t.inputUnits = d.U64(); t.outputUnits = d.U64(); t.mintedUnits = d.U64(); t.burnedUnits = d.U64();
    uint32_t n = d.U32();
    t.inputs.clear();
    for (uint32_t i = 0; i < n && d.ok; i++) {
        TxInput in;
        in.txid = d.H(); in.vout = d.U32(); in.token = d.H(); in.amount = d.U64(); in.role = (int)d.U8();
        t.inputs.push_back(in);
    }
    n = d.U32();
    t.outputs.clear();
    for (uint32_t i = 0; i < n && d.ok; i++) {
        TxOutput o;
        o.vout = d.U32(); o.token = d.H(); o.amount = d.U64(); o.role = (int)d.U8(); o.addr = d.Fixed(21);
        t.outputs.push_back(o);
    }
    return d.ok;
}

std::string EncodeStats(const IndexStats& s)
{
    Enc e;
    e.U64(s.tokens); e.U64(s.txValid); e.U64(s.txInvalid); e.U64(s.txUnknown); e.U64(s.txBurn); e.U64(s.unspentOutputs);
    e.U64(s.nGenesis); e.U64(s.nMint); e.U64(s.nSend); e.U64(s.nUnrepresentable); e.U64(s.nOverflow);
    return e.s;
}

bool DecodeStats(const std::string& v, IndexStats& s)
{
    Dec d(v);
    s.tokens = d.U64(); s.txValid = d.U64(); s.txInvalid = d.U64(); s.txUnknown = d.U64(); s.txBurn = d.U64();
    s.unspentOutputs = d.U64();
    s.nGenesis = d.U64(); s.nMint = d.U64(); s.nSend = d.U64(); s.nUnrepresentable = d.U64(); s.nOverflow = d.U64();
    return d.ok;
}

// ---- write journal --------------------------------------------------------

/** Reads through to the store, collects writes, and remembers the first-seen original of every key it
 *  changes: that is exactly the undo record. Nothing reaches the store until Commit. */
class Journal
{
public:
    explicit Journal(const KV* kv) : kvp(kv) {}

    bool Get(const std::string& key, std::string& v) const
    {
        std::map<std::string, Pend>::const_iterator it = pending.find(key);
        if (it != pending.end()) {
            if (!it->second.present)
                return false;
            v = it->second.value;
            return true;
        }
        return kvp->Get(key, v);
    }
    void Put(const std::string& key, const std::string& v) { Touch(key); Pend p; p.present = true; p.value = v; pending[key] = p; }
    void Erase(const std::string& key) { Touch(key); Pend p; p.present = false; pending[key] = p; }

    struct Pend { bool present; std::string value; Pend() : present(false) {} };
    struct Orig { bool exists; std::string value; Orig() : exists(false) {} };
    std::map<std::string, Pend> pending;
    std::map<std::string, Orig> orig;

private:
    const KV* kvp;
    void Touch(const std::string& key)
    {
        if (orig.count(key))
            return;
        Orig o;
        o.exists = kvp->Get(key, o.value);
        orig[key] = o;
    }
};

std::string EncodeUndo(const Journal& j)
{
    Enc e;
    e.U32((uint32_t)j.orig.size());
    for (std::map<std::string, Journal::Orig>::const_iterator it = j.orig.begin(); it != j.orig.end(); ++it) {
        e.Str(it->first);
        e.U8(it->second.exists ? 1 : 0);
        e.Str(it->second.value);
    }
    return e.s;
}

bool ApplyUndo(const std::string& v, std::vector<KV::Op>& ops)
{
    Dec d(v);
    uint32_t n = d.U32();
    for (uint32_t i = 0; i < n && d.ok; i++) {
        KV::Op op;
        op.key = d.Str();
        op.erase = d.U8() == 0;
        op.value = d.Str();
        ops.push_back(op);
    }
    return d.ok;
}

bool BestRead(const KV* kv, uint256& hash, int& height)
{
    std::string v;
    if (!kv->Get(kBestKey, v))
        return false;
    Dec d(v);
    hash = d.H();
    height = (int)d.U32();
    return d.ok;
}

// ---- helpers over a journal ----------------------------------------------

bool AddU64(uint64_t& acc, uint64_t add)
{
    if (add > UINT64_MAX - acc) {
        acc = UINT64_MAX;
        return false;
    }
    acc += add;
    return true;
}

/** A holder balance is kept exact. Every token output holds at most 2^63-1 units, but a token whose supply
 *  passed 2^64-1 (supplyOverflow) can give one holder more than 64 bits hold: a saturated 64-bit balance would
 *  then underflow when those outputs are spent and stop the index for good. So the value is 8 bytes (the low
 *  word) while the high word is zero, which is every balance on mainnet, and 16 bytes (high word first) above. */
bool DecodeBalance(const std::string& v, uint64_t& hi, uint64_t& lo)
{
    Dec d(v);
    hi = v.size() == 16 ? d.U64() : 0;
    lo = d.U64();
    return d.ok && (v.size() == 8 || v.size() == 16);
}

std::string EncodeBalance(uint64_t hi, uint64_t lo)
{
    Enc e;
    if (hi)
        e.U64(hi);
    e.U64(lo);
    return e.s;
}

/** A balance as the readers report it: saturated at 2^64-1 (the token record carries supplyOverflow). */
uint64_t ReportedBalance(uint64_t hi, uint64_t lo) { return hi ? UINT64_MAX : lo; }

/** Adjust a holder balance in both indexes. false only on an underflow, which means a corrupt store. */
bool AdjustBalance(Journal& j, const std::string& addr, const uint256& token, uint64_t amount, bool add)
{
    if (amount == 0)
        return true;
    const std::string ka = KeyAddrBal(addr, token), kh = KeyTokBal(token, addr);
    uint64_t hi = 0, lo = 0;
    std::string v;
    if (j.Get(ka, v) && !DecodeBalance(v, hi, lo))
        return false;
    if (add) {
        lo += amount;
        if (lo < amount)
            hi++; // cannot wrap: that would take 2^64 outputs
    } else {
        if (hi == 0 && amount > lo)
            return false;
        if (amount > lo)
            hi--;
        lo -= amount;
    }
    if (hi == 0 && lo == 0) {
        j.Erase(ka);
        j.Erase(kh);
    } else {
        j.Put(ka, EncodeBalance(hi, lo));
        j.Put(kh, EncodeBalance(hi, lo));
    }
    return true;
}

bool LoadToken(const Journal& j, const uint256& id, TokenInfo& t)
{
    std::string v;
    return j.Get(KeyTok(id), v) && DecodeToken(id, v, t);
}

void SaveToken(Journal& j, const TokenInfo& t) { j.Put(KeyTok(t.id), EncodeToken(t)); }

void ReverseTokenId(const uint8_t wire[32], uint256& out)
{
    for (int i = 0; i < 32; i++)
        out.begin()[i] = wire[31 - i];
}

} // namespace

// ---- addresses and amounts ------------------------------------------------

std::string AddrKeyForScript(const std::vector<unsigned char>& scriptPubKey)
{
    std::string key(21, '\0');
    CScript script(scriptPubKey.begin(), scriptPubKey.end());
    CTxDestination dest;
    if (ExtractDestination(script, dest)) {
        if (const CKeyID* id = boost::get<CKeyID>(&dest)) {
            key[0] = ADDR_P2PKH;
            memcpy(&key[1], id->begin(), 20);
            return key;
        }
        if (const CScriptID* id = boost::get<CScriptID>(&dest)) {
            key[0] = ADDR_P2SH;
            memcpy(&key[1], id->begin(), 20);
            return key;
        }
    }
    uint160 h = Hash160(scriptPubKey);
    key[0] = ADDR_SCRIPT;
    memcpy(&key[1], h.begin(), 20);
    return key;
}

std::string AddrKeyToString(const std::string& k)
{
    if (k.size() != 21 || k[0] == ADDR_NONE)
        return "";
    uint160 h;
    memcpy(h.begin(), k.data() + 1, 20);
    if (k[0] == ADDR_P2PKH)
        return EncodeDestination(CKeyID(h));
    if (k[0] == ADDR_P2SH)
        return EncodeDestination(CScriptID(h));
    return "script:" + HexStr(h.begin(), h.end());
}

bool AddrKeyFromString(const std::string& s, std::string& keyOut)
{
    if (s.compare(0, 7, "script:") == 0) {
        std::string hex = s.substr(7);
        if (hex.size() != 40 || !IsHex(hex))
            return false;
        std::vector<unsigned char> b = ParseHex(hex);
        keyOut.assign(1, (char)ADDR_SCRIPT);
        keyOut.append((const char*)&b[0], 20);
        return true;
    }
    CTxDestination dest = DecodeDestination(s);
    if (const CKeyID* id = boost::get<CKeyID>(&dest)) {
        keyOut.assign(1, (char)ADDR_P2PKH);
        keyOut.append((const char*)id->begin(), 20);
        return true;
    }
    if (const CScriptID* id = boost::get<CScriptID>(&dest)) {
        keyOut.assign(1, (char)ADDR_P2SH);
        keyOut.append((const char*)id->begin(), 20);
        return true;
    }
    return false;
}

std::string FormatAmount(uint64_t amount, unsigned int decimals)
{
    std::string digits = std::to_string((unsigned long long)amount);
    if (decimals == 0)
        return digits;
    if (digits.size() <= decimals)
        digits = std::string(decimals - digits.size() + 1, '0') + digits;
    return digits.substr(0, digits.size() - decimals) + "." + digits.substr(digits.size() - decimals);
}

// ---- the index ------------------------------------------------------------

ZslpIndex::ZslpIndex(KV* kvIn) : kv(kvIn) {}

bool ZslpIndex::Load(std::string& err)
{
    LOCK(cs);
    std::string v;
    if (kv->Get(kVerKey, v)) {
        Dec d(v);
        unsigned int ver = d.U8();
        if (!d.ok || ver != kVersion) {
            err = strprintf("zslp index store has format version %u, this build reads %u: delete the zslpindex directory to rebuild it", ver, kVersion);
            return false;
        }
    } else {
        Enc e;
        e.U8(kVersion);
        KV::Op op;
        op.key = kVerKey; op.erase = false; op.value = e.s;
        std::vector<KV::Op> ops(1, op);
        if (!kv->WriteBatch(ops, true)) {
            err = "zslp index store is not writable";
            return false;
        }
    }
    return true;
}

bool ZslpIndex::Reset(std::string& err)
{
    LOCK(cs);
    return WipeKV(kv, kVerKey, err);
}

bool ZslpIndex::GetBest(uint256& hash, int& height) const
{
    LOCK(cs);
    return BestRead(kv, hash, height);
}

IndexStats ZslpIndex::GetStats() const
{
    LOCK(cs);
    IndexStats s;
    std::string v;
    if (kv->Get(kStatKey, v))
        DecodeStats(v, s);
    return s;
}

namespace {

struct Spent {
    COutPoint op;
    OutInfo rec;
};

/** Rule ZSLP-VOUT0 (token-name-rules, shared with Z23; the SLP specification's own rule): the candidate message is
 *  vout[0] and only vout[0], and only when its script starts with OP_RETURN. An SLP message in any other output (for
 *  instance behind a payment output) is not a message, and so is one behind another OP_RETURN. On mainnet no
 *  message was ever outside vout[0] (census to block 3,323,972: none of 4,302), so the rule applies from genesis.
 *  The wallet token guard still protects the outputs of a message at the first OP_RETURN wherever it is (a superset:
 *  it can only withhold more coins, never fewer). */
int MessageOutput(const CTransaction& tx)
{
    if (tx.vout.empty())
        return -1;
    const CScript& s = tx.vout[0].scriptPubKey;
    return (!s.empty() && s[0] == OP_RETURN) ? 0 : -1;
}

bool ProcessTx(Journal& j, IndexStats& st, const CTransaction& tx, int height, std::string& err)
{
    const uint256 txid = tx.GetHash();
    const bool coinbase = tx.IsCoinBase();

    std::vector<Spent> spent;
    // while no token output is unspent (the whole chain before the first token) nothing can be spent: no lookups
    if (!coinbase && st.unspentOutputs > 0) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            std::string v;
            if (!j.Get(KeyOut(tx.vin[i].prevout.hash, tx.vin[i].prevout.n), v))
                continue;
            Spent s;
            s.op = tx.vin[i].prevout;
            if (!DecodeOut(v, s.rec)) {
                err = "corrupt token output record";
                return false;
            }
            spent.push_back(s);
        }
    }

    zcl_slp_parsed msg;
    bool isSlp = false;
    const int nMsg = MessageOutput(tx);
    if (nMsg >= 0) {
        const CScript& s = tx.vout[nMsg].scriptPubKey;
        isSlp = zcl_slp_parse_message(&s[0], s.size(), &msg) != 0;
    }
    if (!isSlp && spent.empty())
        return true;

    TxInfo info;
    info.height = height;
    uint256 target;
    zcl_slp_eval ev;
    memset(&ev, 0, sizeof(ev));
    if (isSlp) {
        info.type = msg.type;
        if (msg.type == ZCL_SLP_TX_GENESIS)
            target = txid;
        else
            ReverseTokenId(msg.token_id_wire, target);
        info.token = target;

        // Each spent record and each parent record is looked up once per transaction: many inputs from one
        // parent must not decode that parent's record (which lists all its own inputs) once per input.
        std::map<COutPoint, const OutInfo*> spentAt;
        for (size_t k = 0; k < spent.size(); k++)
            spentAt[spent[k].op] = &spent[k].rec;
        std::map<uint256, int> parentStatus; // prev txid -> its status for this token, -1 when not an SLP tx of it
        std::vector<zcl_slp_input> in(tx.vin.size());
        for (size_t i = 0; i < tx.vin.size(); i++) {
            memset(&in[i], 0, sizeof(in[i]));
            if (coinbase)
                continue;
            std::map<COutPoint, const OutInfo*>::const_iterator sp = spentAt.find(tx.vin[i].prevout);
            if (sp != spentAt.end()) {
                in[i].has_ledger = 1;
                in[i].role = sp->second->role;
                memcpy(in[i].token_id, sp->second->token.begin(), 32);
                in[i].amount = sp->second->amount;
            }
            const uint256& prevHash = tx.vin[i].prevout.hash;
            std::map<uint256, int>::iterator ps = parentStatus.find(prevHash);
            if (ps == parentStatus.end()) {
                std::string pv;
                TxInfo parent;
                const bool same = j.Get(KeyTx(prevHash), pv) && DecodeTx(pv, parent) && parent.type != 0 &&
                                  parent.token == target;
                ps = parentStatus.insert(std::make_pair(prevHash, same ? parent.status : -1)).first;
            }
            if (ps->second >= 0) {
                in[i].parent_same_token = 1;
                in[i].parent_status = ps->second;
            }
        }
        zcl_slp_evaluate(&msg, target.begin(), tx.vout.size(), in.empty() ? NULL : &in[0], in.size(), &ev);
        info.status = ev.status;
        info.reason = ev.reason ? ev.reason : "";
        info.inputUnits = ev.input_units;
    } else {
        info.type = 0;
        info.status = STATUS_UNKNOWN;
        info.reason = "token_outputs_spent_by_ordinary_transaction";
    }
    const bool valid = isSlp && ev.status == ZCL_SLP_STATUS_VALID;
    const bool carries = valid && msg.type == ZCL_SLP_TX_SEND;

    // 1. every spent token or baton output leaves the unspent set; token units that no valid SEND carries forward are burned
    std::map<uint256, TokenInfo> tokens;
    uint64_t burnedHere = 0;
    for (size_t i = 0; i < spent.size(); i++) {
        const OutInfo& o = spent[i].rec;
        TxInput ti;
        ti.txid = spent[i].op.hash; ti.vout = spent[i].op.n; ti.token = o.token; ti.amount = o.amount; ti.role = o.role;
        info.inputs.push_back(ti);
        j.Erase(KeyOut(spent[i].op.hash, spent[i].op.n));
        if (st.unspentOutputs)
            st.unspentOutputs--;

        if (!tokens.count(o.token) && !LoadToken(j, o.token, tokens[o.token])) {
            err = "token record missing for an indexed output";
            return false;
        }
        TokenInfo& t = tokens[o.token];
        if (o.role == ROLE_TOKEN) {
            if (!AdjustBalance(j, o.addr, o.token, o.amount, false)) {
                err = "token balance underflow";
                return false;
            }
            if (!carries) {
                if (!AddU64(t.spentBurned, o.amount))
                    t.supplyOverflow = true;
                AddU64(burnedHere, o.amount);
            }
        } else if (o.role == ROLE_BATON) {
            if (t.hasBaton && t.batonTx == spent[i].op.hash && t.batonVout == spent[i].op.n)
                t.hasBaton = false;
        }
    }
    if (carries)
        burnedHere = ev.burned_units;

    // 2. a VALID message creates its outputs and moves the token record
    if (valid) {
        if (msg.type != ZCL_SLP_TX_GENESIS && !tokens.count(target) && !LoadToken(j, target, tokens[target])) {
            // MINT/SEND of a token with no record cannot be VALID (it has no inputs of it), so this is unreachable
            err = "valid token message for an unknown token";
            return false;
        }
        TokenInfo& t = tokens[target];
        if (msg.type == ZCL_SLP_TX_GENESIS) {
            t = TokenInfo();
            t.id = txid;
            t.ticker = msg.ticker; t.name = msg.name; t.documentUrl = msg.document_url;
            t.hasDocumentHash = msg.has_document_hash != 0;
            if (t.hasDocumentHash)
                memcpy(t.documentHash.begin(), msg.document_hash, 32);
            t.decimals = msg.decimals;
            t.genesisHeight = height;
            st.tokens++;
        }
        t.nTx++;
        if (msg.type == ZCL_SLP_TX_SEND) {
            if (!AddU64(t.sendBurned, ev.burned_units))
                t.supplyOverflow = true;
        } else if (!AddU64(t.minted, ev.minted_units)) {
            t.supplyOverflow = true;
        }
        info.outputUnits = ev.output_units;
        info.mintedUnits = ev.minted_units;

        std::vector<std::pair<unsigned int, std::pair<uint64_t, int> > > outs; // vout -> (amount, role)
        if (msg.type == ZCL_SLP_TX_SEND) {
            for (int i = 0; i < msg.num_outputs; i++)
                if (msg.output_quantities[i] > 0)
                    outs.push_back(std::make_pair((unsigned int)i + 1, std::make_pair(msg.output_quantities[i], (int)ROLE_TOKEN)));
        } else {
            if (msg.quantity > 0)
                outs.push_back(std::make_pair(1u, std::make_pair(msg.quantity, (int)ROLE_TOKEN)));
            if (msg.mint_baton_vout)
                outs.push_back(std::make_pair((unsigned int)msg.mint_baton_vout, std::make_pair((uint64_t)0, (int)ROLE_BATON)));
        }
        for (size_t i = 0; i < outs.size(); i++) {
            OutInfo o;
            o.token = target; o.amount = outs[i].second.first; o.role = outs[i].second.second; o.height = height;
            const std::vector<unsigned char> script(tx.vout[outs[i].first].scriptPubKey.begin(),
                                                    tx.vout[outs[i].first].scriptPubKey.end());
            o.addr = AddrKeyForScript(script);
            j.Put(KeyOut(txid, outs[i].first), EncodeOut(o));
            st.unspentOutputs++;
            if (o.role == ROLE_TOKEN) {
                if (!AdjustBalance(j, o.addr, target, o.amount, true)) {
                    err = "token balance update failed";
                    return false;
                }
            } else {
                t.hasBaton = true; t.batonTx = txid; t.batonVout = outs[i].first;
            }
            TxOutput to;
            to.vout = outs[i].first; to.token = target; to.amount = o.amount; to.role = o.role; to.addr = o.addr;
            info.outputs.push_back(to);
        }
    }
    info.burnedUnits = burnedHere;

    for (std::map<uint256, TokenInfo>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
        SaveToken(j, it->second);

    if (isSlp) {
        if (info.status == STATUS_VALID) st.txValid++;
        else if (info.status == STATUS_INVALID) st.txInvalid++;
        else st.txUnknown++;
        if (msg.type == ZCL_SLP_TX_GENESIS) st.nGenesis++;
        else if (msg.type == ZCL_SLP_TX_MINT) st.nMint++;
        else st.nSend++;
        if (info.reason == "quantity_unrepresentable" || info.reason == "input_quantity_unrepresentable")
            st.nUnrepresentable++;
        else if (info.reason == "output_quantity_overflow" || info.reason == "input_quantity_overflow")
            st.nOverflow++;
        Enc ref;
        ref.U8(info.type); ref.U8(info.status);
        j.Put(KeyTokenTx(target, height, txid), ref.s);
    } else {
        st.txBurn++;
        // an ordinary transaction that spent token outputs shows up in the history of each token it burned
        Enc ref;
        ref.U8(0); ref.U8(STATUS_UNKNOWN);
        for (std::map<uint256, TokenInfo>::const_iterator it = tokens.begin(); it != tokens.end(); ++it)
            j.Put(KeyTokenTx(it->first, height, txid), ref.s);
    }
    j.Put(KeyTx(txid), EncodeTx(info));
    return true;
}

} // namespace

bool ZslpIndex::ApplyBlock(const CBlock& block, const uint256& hash, int height, bool fSync, std::string& err)
{
    LOCK(cs);
    uint256 best;
    int bestHeight = -1;
    if (BestRead(kv, best, bestHeight) && best != block.hashPrevBlock) {
        err = strprintf("block %s does not extend the index tip %s", hash.GetHex(), best.GetHex());
        return false;
    }

    Journal j(kv);
    IndexStats st;
    {
        std::string v;
        if (kv->Get(kStatKey, v))
            DecodeStats(v, st);
    }
    const IndexStats before = st;

    for (size_t i = 0; i < block.vtx.size(); i++)
        if (!ProcessTx(j, st, block.vtx[i], height, err))
            return false;

    std::vector<KV::Op> ops;
    const bool changed = !j.orig.empty();
    if (changed) {
        if (memcmp(&before, &st, sizeof(st)) != 0 || !j.orig.count(kStatKey))
            j.Put(kStatKey, EncodeStats(st));
        for (std::map<std::string, Journal::Pend>::const_iterator it = j.pending.begin(); it != j.pending.end(); ++it) {
            KV::Op op;
            op.key = it->first; op.erase = !it->second.present; op.value = it->second.value;
            ops.push_back(op);
        }
        KV::Op u;
        u.key = KeyUndo(hash); u.erase = false; u.value = EncodeUndo(j);
        ops.push_back(u);
    }
    KV::Op b;
    Enc e;
    e.H(hash); e.U32((uint32_t)height);
    b.key = kBestKey; b.erase = false; b.value = e.s;
    ops.push_back(b);
    if (!kv->WriteBatch(ops, fSync)) {
        err = "zslp index write failed";
        return false;
    }
    return true;
}

bool ZslpIndex::DisconnectBlock(const uint256& hash, const uint256& prevHash, int prevHeight, std::string& err)
{
    LOCK(cs);
    uint256 best;
    int bestHeight = -1;
    if (!BestRead(kv, best, bestHeight) || best != hash) {
        err = strprintf("cannot disconnect %s: it is not the index tip", hash.GetHex());
        return false;
    }
    std::vector<KV::Op> ops;
    std::string undo;
    if (kv->Get(KeyUndo(hash), undo)) {
        if (!ApplyUndo(undo, ops)) {
            err = "corrupt undo record";
            return false;
        }
        KV::Op u;
        u.key = KeyUndo(hash); u.erase = true;
        ops.push_back(u);
    }
    KV::Op b;
    Enc e;
    e.H(prevHash); e.U32((uint32_t)prevHeight);
    b.key = kBestKey; b.erase = false; b.value = e.s;
    ops.push_back(b);
    if (!kv->WriteBatch(ops, true)) {
        err = "zslp index write failed";
        return false;
    }
    return true;
}

bool ZslpIndex::GetToken(const uint256& id, TokenInfo& out) const
{
    LOCK(cs);
    std::string v;
    return kv->Get(KeyTok(id), v) && DecodeToken(id, v, out);
}

std::vector<TokenInfo> ZslpIndex::ListTokens(size_t skip, size_t count) const
{
    LOCK(cs);
    std::vector<TokenInfo> r;
    size_t seen = 0;
    kv->Scan("t", [&](const std::string& k, const std::string& v) {
        if (k.size() != 33)
            return true;
        if (seen++ < skip)
            return true;
        TokenInfo t;
        uint256 id;
        memcpy(id.begin(), k.data() + 1, 32);
        if (DecodeToken(id, v, t))
            r.push_back(t);
        return r.size() < count;
    });
    return r;
}

bool ZslpIndex::GetTx(const uint256& txid, TxInfo& out) const
{
    LOCK(cs);
    std::string v;
    return kv->Get(KeyTx(txid), v) && DecodeTx(v, out);
}

std::vector<TxRef> ZslpIndex::ListTokenTransactions(const uint256& token, size_t skip, size_t count) const
{
    LOCK(cs);
    std::vector<TxRef> r;
    size_t seen = 0;
    kv->Scan("y" + HStr(token), [&](const std::string& k, const std::string& v) {
        if (k.size() != 1 + 32 + 4 + 32)
            return true;
        if (seen++ < skip)
            return true;
        TxRef t;
        const std::string hbytes = k.substr(33, 4);
        Dec hd(hbytes);
        t.height = (int)hd.U32();
        memcpy(t.txid.begin(), k.data() + 37, 32);
        Dec d(v);
        t.type = (int)d.U8();
        t.status = (int)d.U8();
        if (d.ok)
            r.push_back(t);
        return r.size() < count;
    });
    return r;
}

bool ZslpIndex::GetOutput(const uint256& txid, unsigned int vout, OutInfo& out) const
{
    LOCK(cs);
    std::string v;
    return kv->Get(KeyOut(txid, vout), v) && DecodeOut(v, out);
}

std::vector<HolderBalance> ZslpIndex::GetBalances(const std::string& addrKey) const
{
    LOCK(cs);
    std::vector<HolderBalance> r;
    kv->Scan("a" + addrKey, [&](const std::string& k, const std::string& v) {
        if (k.size() != 1 + 21 + 32)
            return true;
        HolderBalance hb;
        hb.addr = addrKey;
        memcpy(hb.token.begin(), k.data() + 22, 32);
        uint64_t hi, lo;
        if (DecodeBalance(v, hi, lo)) {
            hb.amount = ReportedBalance(hi, lo);
            r.push_back(hb);
        }
        return true;
    });
    return r;
}

std::vector<HolderBalance> ZslpIndex::GetHolders(const uint256& token, size_t skip, size_t count) const
{
    LOCK(cs);
    std::vector<HolderBalance> r;
    size_t seen = 0;
    kv->Scan("h" + HStr(token), [&](const std::string& k, const std::string& v) {
        if (k.size() != 1 + 32 + 21)
            return true;
        if (seen++ < skip)
            return true;
        HolderBalance hb;
        hb.addr = k.substr(33, 21);
        hb.token = token;
        uint64_t hi, lo;
        if (DecodeBalance(v, hi, lo)) {
            hb.amount = ReportedBalance(hi, lo);
            r.push_back(hb);
        }
        return r.size() < count;
    });
    return r;
}

bool ZslpIndex::SumUnspent(const uint256& token, uint64_t& out) const
{
    LOCK(cs);
    bool overflow = false;
    out = 0;
    kv->Scan("h" + HStr(token), [&](const std::string&, const std::string& v) {
        uint64_t hi = 0, lo = 0;
        if (!DecodeBalance(v, hi, lo) || hi || !AddU64(out, lo))
            overflow = true;
        return true;
    });
    return !overflow;
}

bool ZslpIndex::EvaluateTx(const CTransaction& tx, Evaluation& out, std::string& err) const
{
    out = Evaluation();
    LOCK(cs);
    const uint256 txid = tx.GetHash();
    const bool coinbase = tx.IsCoinBase();

    // Same lookups as ProcessTx, read-only: the unspent token/baton records among the inputs.
    std::map<COutPoint, OutInfo> spentAt;
    if (!coinbase) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            std::string v;
            if (!kv->Get(KeyOut(tx.vin[i].prevout.hash, tx.vin[i].prevout.n), v))
                continue;
            OutInfo rec;
            if (!DecodeOut(v, rec)) {
                err = "corrupt token output record";
                return false;
            }
            spentAt[tx.vin[i].prevout] = rec;
            TxInput ti;
            ti.txid = tx.vin[i].prevout.hash; ti.vout = tx.vin[i].prevout.n;
            ti.token = rec.token; ti.amount = rec.amount; ti.role = rec.role;
            out.spent.push_back(ti);
        }
    }

    zcl_slp_parsed msg;
    const int nMsg = MessageOutput(tx);
    if (nMsg >= 0) {
        const CScript& s = tx.vout[nMsg].scriptPubKey;
        out.isSlp = zcl_slp_parse_message(&s[0], s.size(), &msg) != 0;
    }

    if (!out.isSlp) {
        out.type = 0;
        out.reason = "token_outputs_spent_by_ordinary_transaction";
        for (size_t i = 0; i < out.spent.size(); i++)
            if (out.spent[i].role == ROLE_TOKEN && !AddU64(out.burnedUnits, out.spent[i].amount))
                out.burnedUnits = UINT64_MAX;
        return true;
    }

    out.type = msg.type;
    uint256 target;
    if (msg.type == ZCL_SLP_TX_GENESIS)
        target = txid;
    else
        ReverseTokenId(msg.token_id_wire, target);
    out.token = target;

    std::map<uint256, int> parentStatus; // prev txid -> its status for this token, -1 when not an SLP tx of it
    std::vector<zcl_slp_input> in(tx.vin.size());
    for (size_t i = 0; i < tx.vin.size(); i++) {
        memset(&in[i], 0, sizeof(in[i]));
        if (coinbase)
            continue;
        std::map<COutPoint, OutInfo>::const_iterator sp = spentAt.find(tx.vin[i].prevout);
        if (sp != spentAt.end()) {
            in[i].has_ledger = 1;
            in[i].role = sp->second.role;
            memcpy(in[i].token_id, sp->second.token.begin(), 32);
            in[i].amount = sp->second.amount;
        }
        const uint256& prevHash = tx.vin[i].prevout.hash;
        std::map<uint256, int>::iterator ps = parentStatus.find(prevHash);
        if (ps == parentStatus.end()) {
            std::string pv;
            TxInfo parent;
            const bool same = kv->Get(KeyTx(prevHash), pv) && DecodeTx(pv, parent) && parent.type != 0 &&
                              parent.token == target;
            ps = parentStatus.insert(std::make_pair(prevHash, same ? parent.status : -1)).first;
        }
        if (ps->second >= 0) {
            in[i].parent_same_token = 1;
            in[i].parent_status = ps->second;
        }
    }
    zcl_slp_eval ev;
    memset(&ev, 0, sizeof(ev));
    zcl_slp_evaluate(&msg, target.begin(), tx.vout.size(), in.empty() ? NULL : &in[0], in.size(), &ev);
    out.status = ev.status;
    out.reason = ev.reason ? ev.reason : "";
    out.inputUnits = ev.input_units;

    const bool valid = ev.status == ZCL_SLP_STATUS_VALID;
    const bool carries = valid && msg.type == ZCL_SLP_TX_SEND;
    if (carries) {
        out.burnedUnits = ev.burned_units;
    } else {
        for (size_t i = 0; i < out.spent.size(); i++)
            if (out.spent[i].role == ROLE_TOKEN && !AddU64(out.burnedUnits, out.spent[i].amount))
                out.burnedUnits = UINT64_MAX;
    }
    if (!valid)
        return true;

    out.outputUnits = ev.output_units;
    out.mintedUnits = ev.minted_units;
    std::vector<std::pair<unsigned int, std::pair<uint64_t, int> > > outs;
    if (msg.type == ZCL_SLP_TX_SEND) {
        for (int i = 0; i < msg.num_outputs; i++)
            if (msg.output_quantities[i] > 0)
                outs.push_back(std::make_pair((unsigned int)i + 1, std::make_pair(msg.output_quantities[i], (int)ROLE_TOKEN)));
    } else {
        if (msg.quantity > 0)
            outs.push_back(std::make_pair(1u, std::make_pair(msg.quantity, (int)ROLE_TOKEN)));
        if (msg.mint_baton_vout)
            outs.push_back(std::make_pair((unsigned int)msg.mint_baton_vout, std::make_pair((uint64_t)0, (int)ROLE_BATON)));
    }
    for (size_t i = 0; i < outs.size(); i++) {
        TxOutput to;
        to.vout = outs[i].first; to.token = target; to.amount = outs[i].second.first; to.role = outs[i].second.second;
        const CScript& spk = tx.vout[outs[i].first].scriptPubKey;
        to.addr = AddrKeyForScript(std::vector<unsigned char>(spk.begin(), spk.end()));
        out.created.push_back(to);
    }
    return true;
}

} // namespace zslp
