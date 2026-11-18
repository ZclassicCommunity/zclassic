// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "znam/znamindex.h"

#include "key_io.h"
#include "script/script.h"
#include "uint256.h"
#include "util.h"

#include "c23/services/glue/zcl_znam_index.h"

#include <map>
#include <string.h>

namespace znam {

const char* TypeName(unsigned int type)
{
    switch (type) {
    case TYPE_ONION: return "onion";
    case TYPE_ZADDR: return "z-address";
    case TYPE_TADDR: return "t-address";
    case TYPE_BTC: return "bitcoin";
    case TYPE_LTC: return "litecoin";
    case TYPE_DOGE: return "dogecoin";
    case TYPE_CONTENT: return "content";
    default: return "unknown";
    }
}

unsigned int TypeFromName(const std::string& s)
{
    if (s == "onion") return TYPE_ONION;
    if (s == "zaddr" || s == "z-address") return TYPE_ZADDR;
    if (s == "taddr" || s == "t-address") return TYPE_TADDR;
    if (s == "btc" || s == "bitcoin") return TYPE_BTC;
    if (s == "ltc" || s == "litecoin") return TYPE_LTC;
    if (s == "doge" || s == "dogecoin") return TYPE_DOGE;
    if (s == "content" || s == "content-hash") return TYPE_CONTENT;
    return 0;
}

const char* CommandName(int cmd)
{
    switch (cmd) {
    case CMD_REGISTER: return "REGISTER";
    case CMD_UPDATE: return "UPDATE";
    case CMD_TRANSFER: return "TRANSFER";
    case CMD_RENEW: return "RENEW";
    case CMD_SET_RECORD: return "SET_RECORD";
    case CMD_SET_TEXT: return "SET_TEXT";
    default: return "UNKNOWN";
    }
}

std::string OwnerFromHash160(const unsigned char hash160[20])
{
    uint160 h;
    memcpy(h.begin(), hash160, 20);
    return EncodeDestination(CKeyID(h));
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

// Names contain only a-z 0-9 '-', so a NUL separates a name from what follows it unambiguously. An owner
// is a C string (Z23 stores it as one), so it has no NUL either.
std::string KeyName(const std::string& name) { return "n" + name; }
std::string KeyOwner(const std::string& owner, const std::string& name) { return "o" + owner + std::string(1, '\0') + name; }
std::string KeyOwnerPrefix(const std::string& owner) { return "o" + owner + std::string(1, '\0'); }
std::string KeyAddr(const std::string& name, unsigned int type) { return "r" + name + std::string(1, '\0') + std::string(1, (char)type); }
std::string KeyAddrPrefix(const std::string& name) { return "r" + name + std::string(1, '\0'); }
std::string KeyText(const std::string& name, const std::string& key) { return "t" + name + std::string(1, '\0') + key; }
std::string KeyTextPrefix(const std::string& name) { return "t" + name + std::string(1, '\0'); }
std::string KeyEvent(const std::string& name, int height, uint32_t txIndex)
{
    return "e" + name + std::string(1, '\0') + BE32((uint32_t)height) + BE32(txIndex);
}
std::string KeyEventPrefix(const std::string& name) { return "e" + name + std::string(1, '\0'); }
std::string KeyUndo(const uint256& h) { return "u" + HStr(h); }

std::string EncodeEntry(const Entry& e)
{
    Enc x;
    x.Str(e.owner);
    x.U8(e.type);
    x.Str(e.value);
    x.U32((uint32_t)e.regHeight);
    x.H(e.regTxid);
    x.H(e.lastUpdateTxid);
    x.U32((uint32_t)e.expiryHeight);
    x.U32((uint32_t)e.changeHeight);
    x.H(e.changeTxid);
    x.U8(e.changeCommand);
    return x.s;
}

bool DecodeEntry(const std::string& name, const std::string& v, Entry& e)
{
    Dec d(v);
    e.name = name;
    e.owner = d.Str();
    e.type = d.U8();
    e.value = d.Str();
    e.regHeight = (int)d.U32();
    e.regTxid = d.H();
    e.lastUpdateTxid = d.H();
    e.expiryHeight = (int)d.U32();
    e.changeHeight = (int)d.U32();
    e.changeTxid = d.H();
    e.changeCommand = (int)d.U8();
    return d.ok;
}

std::string EncodeAddr(const AddrRecord& r)
{
    Enc x;
    x.Str(r.value); x.U32((uint32_t)r.height); x.H(r.txid);
    return x.s;
}

bool DecodeAddr(unsigned int type, const std::string& v, AddrRecord& r)
{
    Dec d(v);
    r.type = type;
    r.value = d.Str();
    r.height = (int)d.U32();
    r.txid = d.H();
    return d.ok;
}

std::string EncodeText(const TextRecord& r)
{
    Enc x;
    x.Str(r.value); x.U32((uint32_t)r.height); x.H(r.txid);
    return x.s;
}

bool DecodeText(const std::string& key, const std::string& v, TextRecord& r)
{
    Dec d(v);
    r.key = key;
    r.value = d.Str();
    r.height = (int)d.U32();
    r.txid = d.H();
    return d.ok;
}

std::string EncodeEvent(const Event& e)
{
    Enc x;
    x.H(e.txid);
    x.U8(e.command);
    x.Str(e.owner);
    x.U8(e.type);
    x.Str(e.value);
    x.Str(e.key);
    x.U32((uint32_t)e.expiryHeight);
    x.Str(e.actor);
    return x.s;
}

bool DecodeEvent(int height, uint32_t txIndex, const std::string& v, Event& e)
{
    Dec d(v);
    e.height = height;
    e.txIndex = txIndex;
    e.txid = d.H();
    e.command = (int)d.U8();
    e.owner = d.Str();
    e.type = d.U8();
    e.value = d.Str();
    e.key = d.Str();
    e.expiryHeight = (int)d.U32();
    e.actor = d.Str();
    return d.ok;
}

std::string EncodeStats(const IndexStats& s)
{
    Enc x;
    x.U64(s.names); x.U64(s.messages); x.U64(s.applied); x.U64(s.ignored);
    for (int i = 1; i < 7; i++) x.U64(s.byCommand[i]);
    return x.s;
}

bool DecodeStats(const std::string& v, IndexStats& s)
{
    Dec d(v);
    s.names = d.U64(); s.messages = d.U64(); s.applied = d.U64(); s.ignored = d.U64();
    for (int i = 1; i < 7; i++) s.byCommand[i] = d.U64();
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

// ---- one message ------------------------------------------------------------

/** The first output whose script starts with OP_RETURN, as Z23 takes the transaction's one message
 *  (explorer_index.c:499-508). */
const CTxOut* FirstOpReturn(const CTransaction& tx)
{
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript& s = tx.vout[i].scriptPubKey;
        if (!s.empty() && s[0] == OP_RETURN)
            return &tx.vout[i];
    }
    return NULL;
}

Entry ToEntry(const std::string& name, const zcl_znam_entry& z, const Entry* old)
{
    Entry e;
    if (old)
        e = *old;
    e.name = name;
    e.owner = z.owner;
    e.type = z.target_type;
    e.value = z.target_value;
    e.regHeight = z.reg_height;
    e.expiryHeight = z.expiry_height;
    return e;
}

zcl_znam_entry ToZ(const Entry& e)
{
    zcl_znam_entry z;
    memset(&z, 0, sizeof(z));
    strncpy(z.owner, e.owner.c_str(), ZCL_ZNAM_OWNER_MAX);
    z.target_type = (uint8_t)e.type;
    strncpy(z.target_value, e.value.c_str(), ZCL_ZNAM_VALUE_MAX);
    z.reg_height = e.regHeight;
    z.expiry_height = e.expiryHeight;
    return z;
}

/** Fold one parsed message into the journal. Returns false only when a store read fails. */
void ApplyMessage(Journal& j, IndexStats& st, const zcl_znam_parsed& m, bool haveOwner, const std::string& owner,
                  const uint256& txid, uint32_t txIndex, int height)
{
    st.messages++;
    const std::string name = m.name;
    Entry cur;
    bool have = false;
    {
        std::string v;
        if (j.Get(KeyName(name), v))
            have = DecodeEntry(name, v, cur);
    }
    zcl_znam_entry zc = ToZ(cur);
    zcl_znam_result res;
    zcl_znam_evaluate(&m, have ? 1 : 0, have ? &zc : NULL, haveOwner ? 1 : 0, owner.c_str(), height, &res);
    if (res.effect == ZCL_ZNAM_EFFECT_NONE) {
        st.ignored++;
        return;
    }

    Event ev;
    ev.height = height;
    ev.txIndex = txIndex;
    ev.txid = txid;
    ev.command = m.command;
    ev.actor = haveOwner ? owner : std::string();

    switch (res.effect) {
    case ZCL_ZNAM_EFFECT_REGISTER: {
        Entry e = ToEntry(name, res.entry, NULL);
        e.regTxid = txid;
        e.lastUpdateTxid = txid;
        e.changeHeight = height;
        e.changeTxid = txid;
        e.changeCommand = CMD_REGISTER;
        j.Put(KeyName(name), EncodeEntry(e));
        j.Put(KeyOwner(e.owner, name), std::string());
        st.names++;
        ev.owner = e.owner;
        ev.type = e.type;
        ev.value = e.value;
        ev.expiryHeight = e.expiryHeight;
        break;
    }
    case ZCL_ZNAM_EFFECT_SET_TARGET: {
        Entry e = ToEntry(name, res.entry, &cur);
        e.lastUpdateTxid = txid;
        e.changeHeight = height;
        e.changeTxid = txid;
        e.changeCommand = CMD_UPDATE;
        j.Put(KeyName(name), EncodeEntry(e));
        ev.type = e.type;
        ev.value = e.value;
        break;
    }
    case ZCL_ZNAM_EFFECT_SET_OWNER: {
        Entry e = ToEntry(name, res.entry, &cur);
        e.lastUpdateTxid = txid;
        e.changeHeight = height;
        e.changeTxid = txid;
        e.changeCommand = CMD_TRANSFER;
        if (e.owner != cur.owner) {
            j.Erase(KeyOwner(cur.owner, name));
            j.Put(KeyOwner(e.owner, name), std::string());
        }
        j.Put(KeyName(name), EncodeEntry(e));
        ev.owner = e.owner;
        break;
    }
    case ZCL_ZNAM_EFFECT_EXTEND: {
        Entry e = ToEntry(name, res.entry, &cur);
        e.lastUpdateTxid = txid; // Z23 sets last_update_txid on RENEW too
        j.Put(KeyName(name), EncodeEntry(e));
        ev.expiryHeight = e.expiryHeight;
        break;
    }
    case ZCL_ZNAM_EFFECT_SET_RECORD: {
        AddrRecord r;
        r.type = res.record_type;
        r.value = res.record_value;
        r.height = height;
        r.txid = txid;
        j.Put(KeyAddr(name, r.type), EncodeAddr(r));
        ev.type = r.type;
        ev.value = r.value;
        break;
    }
    case ZCL_ZNAM_EFFECT_SET_TEXT: {
        TextRecord r;
        r.key = res.text_key;
        r.value = res.text_value;
        r.height = height;
        r.txid = txid;
        j.Put(KeyText(name, r.key), EncodeText(r));
        ev.key = r.key;
        ev.value = r.value;
        break;
    }
    default:
        st.ignored++;
        return;
    }
    st.applied++;
    if (m.command >= 1 && m.command <= 6)
        st.byCommand[m.command]++;
    j.Put(KeyEvent(name, height, txIndex), EncodeEvent(ev));
}

} // namespace

// ---- the index ------------------------------------------------------------

ZnamIndex::ZnamIndex(KV* kvIn) : kv(kvIn) {}

bool ZnamIndex::Load(std::string& err)
{
    LOCK(cs);
    std::string v;
    if (kv->Get(kVerKey, v)) {
        Dec d(v);
        unsigned int ver = d.U8();
        if (!d.ok || ver != kVersion) {
            err = strprintf("znam index store has format version %u, this build reads %u: delete the znamindex directory to rebuild it", ver, kVersion);
            return false;
        }
    } else {
        Enc e;
        e.U8(kVersion);
        KV::Op op;
        op.key = kVerKey; op.erase = false; op.value = e.s;
        std::vector<KV::Op> ops(1, op);
        if (!kv->WriteBatch(ops, true)) {
            err = "znam index store is not writable";
            return false;
        }
    }
    return true;
}

bool ZnamIndex::GetBest(uint256& hash, int& height) const
{
    LOCK(cs);
    return BestRead(kv, hash, height);
}

IndexStats ZnamIndex::GetStats() const
{
    LOCK(cs);
    IndexStats s;
    std::string v;
    if (kv->Get(kStatKey, v))
        DecodeStats(v, s);
    return s;
}

bool ZnamIndex::ApplyBlock(const CBlock& block, const OwnerFn& ownerOf, const uint256& hash, int height, bool fSync, std::string& err)
{
    // First, without any lock of the index: find the messages and learn their owners. `ownerOf` reads the undo file
    // and takes cs_main, and a thread that holds cs_main may be waiting for the index's own lock (an RPC), so the
    // index lock must not be held while it runs.
    struct Found {
        size_t txIndex;
        zcl_znam_parsed msg;
        bool haveOwner;
        std::string owner;
        uint256 txid;
    };
    std::vector<Found> found;
    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        const CTxOut* out = FirstOpReturn(tx);
        if (!out)
            continue;
        Found f;
        const std::vector<unsigned char> script(out->scriptPubKey.begin(), out->scriptPubKey.end());
        if (!zcl_znam_parse_message(script.data(), script.size(), &f.msg))
            continue;
        f.txIndex = i;
        f.haveOwner = false;
        int rc = ownerOf ? ownerOf(i, f.owner) : 0;
        if (rc < 0) {
            err = strprintf("cannot learn the owner of transaction %s in block %d (the undo data of the block is not readable)",
                            tx.GetHash().GetHex(), height);
            return false;
        }
        f.haveOwner = rc > 0;
        f.txid = tx.GetHash();
        found.push_back(f);
    }

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

    // Messages are folded in block order: that order IS the first-come-first-served rule.
    for (size_t k = 0; k < found.size(); k++)
        ApplyMessage(j, st, found[k].msg, found[k].haveOwner, found[k].owner, found[k].txid, (uint32_t)found[k].txIndex, height);

    std::vector<KV::Op> ops;
    const bool changed = !j.orig.empty() || memcmp(&before, &st, sizeof(st)) != 0;
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
        err = "znam index write failed";
        return false;
    }
    return true;
}

bool ZnamIndex::DisconnectBlock(const uint256& hash, const uint256& prevHash, int prevHeight, std::string& err)
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
        err = "znam index write failed";
        return false;
    }
    return true;
}

bool ZnamIndex::GetName(const std::string& name, Entry& out) const
{
    LOCK(cs);
    std::string v;
    return kv->Get(KeyName(name), v) && DecodeEntry(name, v, out);
}

std::vector<AddrRecord> ZnamIndex::GetAddrRecords(const std::string& name) const
{
    LOCK(cs);
    std::vector<AddrRecord> r;
    const std::string prefix = KeyAddrPrefix(name);
    kv->Scan(prefix, [&](const std::string& k, const std::string& v) {
        AddrRecord a;
        if (k.size() == prefix.size() + 1 && DecodeAddr((unsigned char)k[prefix.size()], v, a))
            r.push_back(a);
        return true;
    });
    return r;
}

bool ZnamIndex::GetAddrRecord(const std::string& name, unsigned int type, AddrRecord& out) const
{
    LOCK(cs);
    std::string v;
    return kv->Get(KeyAddr(name, type), v) && DecodeAddr(type, v, out);
}

std::vector<TextRecord> ZnamIndex::GetTextRecords(const std::string& name) const
{
    LOCK(cs);
    std::vector<TextRecord> r;
    const std::string prefix = KeyTextPrefix(name);
    kv->Scan(prefix, [&](const std::string& k, const std::string& v) {
        TextRecord t;
        if (DecodeText(k.substr(prefix.size()), v, t))
            r.push_back(t);
        return true;
    });
    return r;
}

std::vector<Event> ZnamIndex::GetHistory(const std::string& name) const
{
    LOCK(cs);
    std::vector<Event> r;
    const std::string prefix = KeyEventPrefix(name);
    kv->Scan(prefix, [&](const std::string& k, const std::string& v) {
        if (k.size() != prefix.size() + 8)
            return true;
        uint32_t h = 0, t = 0;
        for (int i = 0; i < 4; i++) h = (h << 8) | (unsigned char)k[prefix.size() + i];
        for (int i = 0; i < 4; i++) t = (t << 8) | (unsigned char)k[prefix.size() + 4 + i];
        Event e;
        if (DecodeEvent((int)h, t, v, e))
            r.push_back(e);
        return true;
    });
    return r;
}

std::vector<Entry> ZnamIndex::ListByOwner(const std::string& owner, size_t skip, size_t count) const
{
    LOCK(cs);
    std::vector<Entry> r;
    const std::string prefix = KeyOwnerPrefix(owner);
    size_t seen = 0;
    kv->Scan(prefix, [&](const std::string& k, const std::string&) {
        if (seen++ < skip)
            return true;
        if (r.size() >= count)
            return false;
        const std::string name = k.substr(prefix.size());
        std::string v;
        Entry e;
        if (kv->Get(KeyName(name), v) && DecodeEntry(name, v, e))
            r.push_back(e);
        return true;
    });
    return r;
}

std::vector<Entry> ZnamIndex::ListNames(size_t skip, size_t count) const
{
    LOCK(cs);
    std::vector<Entry> r;
    size_t seen = 0;
    kv->Scan("n", [&](const std::string& k, const std::string& v) {
        if (seen++ < skip)
            return true;
        if (r.size() >= count)
            return false;
        Entry e;
        if (DecodeEntry(k.substr(1), v, e))
            r.push_back(e);
        return true;
    });
    return r;
}

} // namespace znam
