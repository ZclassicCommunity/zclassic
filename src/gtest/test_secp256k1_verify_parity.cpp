// Result-identity corpus for libsecp256k1 ECDSA verification and recovery.
//
// configure.ac decides how src/secp256k1 is built (for example whether the
// GLV endomorphism splits the scalar inside secp256k1_ecmult). Such a build
// choice must not move a single accept/reject decision, because CPubKey::Verify
// is on the consensus path. Each test below runs a fixed corpus, folds every
// input and every outcome into one SHA-256 digest and compares it with a
// golden value recorded on the base build of 8ee9727e7 (endomorphism off).
// A mismatch is a divergence: never regenerate the golden to make it pass.
//
// The corpus is driven by a fixed 64-bit LCG, never the system RNG, and
// signing is RFC 6979 deterministic, so the digest depends only on the
// library's results. See doc/perf/secp256k1-endomorphism.md.

#include <gtest/gtest.h>

#include "consensus/upgrades.h"
#include "core_io.h"
#include "crypto/sha256.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/script_error.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include "test/data/script_invalid.json.h"
#include "test/data/script_valid.json.h"

#include <univalue.h>

#include <stdint.h>
#include <string.h>

#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

typedef std::vector<unsigned char> Bytes;

// Golden digests recorded on the base build (src/secp256k1 without
// --enable-endomorphism). See the header comment before touching them.
const char* const GOLDEN_ECDSA = "0807f5dc888c55016e20c9c5cdab2ee870b5f174b0daee3baae9635c6cb06d7a";
const char* const GOLDEN_SCRIPT = "38706f04d0dcca7432ec1216fb5532378a17513c7d6aeab343a88418143ba0e6";

const int ECDSA_CASES = 20000;

// secp256k1 group order n, big-endian.
const unsigned char ORDER_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41};

// Knuth MMIX 64-bit LCG; the top byte of each state is the output.
class Lcg
{
    uint64_t state;

public:
    explicit Lcg(uint64_t seed) : state(seed) {}
    unsigned char Byte()
    {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        return (unsigned char)(state >> 56);
    }
    void Fill(unsigned char* p, size_t n)
    {
        for (size_t i = 0; i < n; i++) p[i] = Byte();
    }
    uint32_t Below(uint32_t n)
    {
        uint32_t v = 0;
        for (int i = 0; i < 4; i++) v = (v << 8) | Byte();
        return v % n;
    }
};

// Running SHA-256 over every input and outcome of a corpus.
class Digest
{
    CSHA256 sha;

public:
    void Raw(const unsigned char* p, size_t n) { sha.Write(p, n); }
    void U32(uint32_t v)
    {
        unsigned char b[4] = {(unsigned char)v, (unsigned char)(v >> 8), (unsigned char)(v >> 16), (unsigned char)(v >> 24)};
        Raw(b, 4);
    }
    void Vec(const unsigned char* p, size_t n)
    {
        U32((uint32_t)n);
        Raw(p, n);
    }
    void Vec(const Bytes& v) { Vec(v.data(), v.size()); }
    void Flag(bool b)
    {
        unsigned char c = b ? 1 : 0;
        Raw(&c, 1);
    }
    std::string Hex()
    {
        unsigned char out[CSHA256::OUTPUT_SIZE];
        sha.Finalize(out);
        return HexStr(out, out + sizeof(out));
    }
};

struct Scalars {
    unsigned char r[32];
    unsigned char s[32];
};

// Reads one DER INTEGER at der[pos] into a right-aligned 32-byte value.
bool ReadDerInt(const Bytes& der, size_t& pos, unsigned char out[32])
{
    if (pos + 2 > der.size() || der[pos] != 0x02) return false;
    size_t len = der[pos + 1];
    pos += 2;
    if (pos + len > der.size()) return false;
    size_t skip = (len == 33 && der[pos] == 0x00) ? 1 : 0;
    if (len - skip > 32) return false;
    memset(out, 0, 32);
    memcpy(out + 32 - (len - skip), &der[pos + skip], len - skip);
    pos += len;
    return true;
}

// Splits a strict DER signature, as CKey::Sign writes it, into r and s.
bool SplitDer(const Bytes& der, Scalars& out)
{
    if (der.size() < 8 || der[0] != 0x30 || der[1] + 2u != der.size()) return false;
    size_t pos = 2;
    return ReadDerInt(der, pos, out.r) && ReadDerInt(der, pos, out.s) && pos == der.size();
}

void AppendDerInt(Bytes& out, const unsigned char v[32])
{
    size_t i = 0;
    while (i < 31 && v[i] == 0) i++;
    bool pad = (v[i] & 0x80) != 0;
    out.push_back(0x02);
    out.push_back((unsigned char)(32 - i + (pad ? 1 : 0)));
    if (pad) out.push_back(0x00);
    out.insert(out.end(), v + i, v + 32);
}

Bytes JoinDer(const Scalars& rs)
{
    Bytes body;
    AppendDerInt(body, rs.r);
    AppendDerInt(body, rs.s);
    Bytes der;
    der.push_back(0x30);
    der.push_back((unsigned char)body.size());
    der.insert(der.end(), body.begin(), body.end());
    return der;
}

// out = a - b over 256-bit big-endian values (mod 2^256).
void Sub256(const unsigned char a[32], const unsigned char b[32], unsigned char out[32])
{
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int d = (int)a[i] - (int)b[i] - borrow;
        borrow = d < 0 ? 1 : 0;
        out[i] = (unsigned char)(d & 0xFF);
    }
}

// v += 1 over a 256-bit big-endian value (mod 2^256).
void Inc256(unsigned char v[32])
{
    for (int i = 31; i >= 0; i--) {
        if (++v[i] != 0) return;
    }
}

void FlipBit(Lcg& g, unsigned char* p, size_t n)
{
    p[g.Below((uint32_t)n)] ^= (unsigned char)(1u << g.Below(8));
}

bool VerifyRs(const CPubKey& pub, const uint256& hash, const Scalars& rs, Digest& d)
{
    Bytes der = JoinDer(rs);
    bool ok = pub.Verify(hash, der);
    d.Vec(der);
    d.Flag(ok);
    return ok;
}

struct Case {
    CKey key;
    CPubKey pub;
    uint256 hash;
    Bytes sig;
    Scalars rs;
};

// Builds case i. Every 5000th key is all zero, an invalid secret, so the
// skip path is part of the corpus.
bool MakeCase(Lcg& g, int i, Case& c)
{
    unsigned char secret[32];
    g.Fill(secret, sizeof(secret));
    if (i % 5000 == 0) memset(secret, 0, sizeof(secret));
    c.key.Set(secret, secret + sizeof(secret), (i & 1) == 0);
    g.Fill(c.hash.begin(), 32);
    if (!c.key.IsValid()) return false;
    c.pub = c.key.GetPubKey();
    return c.key.Sign(c.hash, c.sig) && SplitDer(c.sig, c.rs);
}

// The valid signature, its high-S twin and one-bit flips of r, s, the hash
// and the public key.
void FoldMutations(Lcg& g, const Case& c, Digest& d)
{
    d.Vec(c.pub.begin(), c.pub.size());
    d.Raw(c.hash.begin(), 32);
    d.Vec(c.sig);
    bool ok = c.pub.Verify(c.hash, c.sig);
    d.Flag(ok);
    EXPECT_TRUE(ok);

    Scalars high = c.rs;
    Sub256(ORDER_N, c.rs.s, high.s);
    EXPECT_TRUE(VerifyRs(c.pub, c.hash, high, d)); // CPubKey::Verify normalizes S
    d.Flag(CPubKey::CheckLowS(JoinDer(high)));

    Scalars rflip = c.rs;
    FlipBit(g, rflip.r, 32);
    VerifyRs(c.pub, c.hash, rflip, d);
    Scalars sflip = c.rs;
    FlipBit(g, sflip.s, 32);
    VerifyRs(c.pub, c.hash, sflip, d);

    uint256 hflip = c.hash;
    FlipBit(g, hflip.begin(), 32);
    d.Flag(c.pub.Verify(hflip, c.sig));

    Bytes pk(c.pub.begin(), c.pub.end());
    FlipBit(g, pk.data(), pk.size());
    CPubKey pflip(pk);
    d.Vec(pk);
    d.Flag(pflip.Verify(c.hash, c.sig));
}

// r or s set to 0, n, n + 1 and 2^256 - 1.
void FoldSpecials(const Case& c, Digest& d)
{
    unsigned char zero[32] = {0};
    unsigned char n1[32];
    memcpy(n1, ORDER_N, 32);
    Inc256(n1);
    unsigned char ones[32];
    memset(ones, 0xFF, 32);
    const unsigned char* values[4] = {zero, ORDER_N, n1, ones};
    for (int v = 0; v < 4; v++) {
        Scalars rs = c.rs;
        memcpy(rs.r, values[v], 32);
        EXPECT_FALSE(VerifyRs(c.pub, c.hash, rs, d));
        rs = c.rs;
        memcpy(rs.s, values[v], 32);
        EXPECT_FALSE(VerifyRs(c.pub, c.hash, rs, d));
    }
}

void FoldRecover(const uint256& hash, const Bytes& csig, Digest& d)
{
    CPubKey rec;
    bool ok = rec.RecoverCompact(hash, csig);
    d.Vec(csig);
    d.Flag(ok);
    if (ok) d.Vec(rec.begin(), rec.size());
}

// Compact signature round trip, then recovery from a flipped hash and a
// flipped recovery id (both recover some other key or fail).
void FoldRecovery(Lcg& g, const Case& c, Digest& d)
{
    Bytes csig;
    ASSERT_TRUE(c.key.SignCompact(c.hash, csig));
    CPubKey rec;
    EXPECT_TRUE(rec.RecoverCompact(c.hash, csig));
    EXPECT_TRUE(rec == c.pub);
    FoldRecover(c.hash, csig, d);

    uint256 hflip = c.hash;
    FlipBit(g, hflip.begin(), 32);
    FoldRecover(hflip, csig, d);

    Bytes idflip = csig;
    idflip[0] ^= 1;
    FoldRecover(c.hash, idflip, d);
}

unsigned int ParseFlags(const std::string& text)
{
    static const struct {
        const char* name;
        unsigned int flag;
    } names[] = {
        {"NONE", SCRIPT_VERIFY_NONE},
        {"P2SH", SCRIPT_VERIFY_P2SH},
        {"STRICTENC", SCRIPT_VERIFY_STRICTENC},
        {"LOW_S", SCRIPT_VERIFY_LOW_S},
        {"SIGPUSHONLY", SCRIPT_VERIFY_SIGPUSHONLY},
        {"MINIMALDATA", SCRIPT_VERIFY_MINIMALDATA},
        {"NULLDUMMY", SCRIPT_VERIFY_NULLDUMMY},
        {"DISCOURAGE_UPGRADABLE_NOPS", SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS},
        {"CLEANSTACK", SCRIPT_VERIFY_CLEANSTACK},
        {"CHECKLOCKTIMEVERIFY", SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY},
        {"NULLFAIL", SCRIPT_VERIFY_NULLFAIL},
        {"CHECKDATASIG", SCRIPT_VERIFY_CHECKDATASIG_SIGOPS},
    };
    unsigned int flags = 0;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find(',', start);
        if (end == std::string::npos) end = text.size();
        std::string word = text.substr(start, end - start);
        bool known = false;
        for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
            if (word == names[i].name) {
                flags |= names[i].flag;
                known = true;
            }
        }
        EXPECT_TRUE(known) << "unknown verification flag " << word;
        start = end + 1;
    }
    return flags;
}

// Same transaction shape as script_tests.cpp.
bool RunScript(const CScript& scriptSig, const CScript& scriptPubKey, unsigned int flags, uint32_t branchId, ScriptError& err)
{
    CMutableTransaction credit;
    credit.nVersion = 1;
    credit.vin.resize(1);
    credit.vout.resize(1);
    credit.vin[0].prevout.SetNull();
    credit.vin[0].scriptSig = CScript() << CScriptNum(0) << CScriptNum(0);
    credit.vin[0].nSequence = std::numeric_limits<unsigned int>::max();
    credit.vout[0].scriptPubKey = scriptPubKey;
    credit.vout[0].nValue = 0;

    CMutableTransaction spend;
    spend.nVersion = 1;
    spend.vin.resize(1);
    spend.vout.resize(1);
    spend.vin[0].prevout.hash = credit.GetHash();
    spend.vin[0].prevout.n = 0;
    spend.vin[0].scriptSig = scriptSig;
    spend.vin[0].nSequence = std::numeric_limits<unsigned int>::max();
    spend.vout[0].nValue = 0;
    return VerifyScript(scriptSig, scriptPubKey, flags, MutableTransactionSignatureChecker(&spend, 0, credit.vout[0].nValue), branchId, &err);
}

// Runs every [scriptSig, scriptPubKey, flags, ...] row of one JSON file under
// every network upgrade's branch id; returns the number of rows.
size_t FoldScriptFile(const unsigned char* data, size_t size, bool expect, Digest& d)
{
    UniValue rows;
    EXPECT_TRUE(rows.read(std::string(data, data + size)) && rows.isArray());
    size_t count = 0;
    for (size_t idx = 0; idx < rows.size(); idx++) {
        const UniValue& row = rows[idx];
        if (row.size() < 3) continue;
        CScript scriptSig = ParseScript(row[0].get_str());
        CScript scriptPubKey = ParseScript(row[1].get_str());
        unsigned int flags = ParseFlags(row[2].get_str());
        for (int up = 0; up < (int)Consensus::MAX_NETWORK_UPGRADES; up++) {
            ScriptError err = SCRIPT_ERR_OK;
            bool ok = RunScript(scriptSig, scriptPubKey, flags, NetworkUpgradeInfo[up].nBranchId, err);
            EXPECT_EQ(expect, ok) << row.write();
            d.Flag(ok);
            d.U32((uint32_t)err);
        }
        count++;
    }
    return count;
}

} // namespace

TEST(Secp256k1VerifyParity, EcdsaCorpus)
{
    Lcg g(0x5A434C2D53454350ULL); // "ZCL-SECP"
    Digest d;
    Case prev;
    int valid = 0;
    for (int i = 0; i < ECDSA_CASES; i++) {
        Case c;
        bool made = MakeCase(g, i, c);
        d.Flag(made);
        if (!made) continue;
        valid++;
        FoldMutations(g, c, d);
        FoldSpecials(c, d);
        FoldRecovery(g, c, d);
        if (prev.pub.IsValid()) d.Flag(prev.pub.Verify(c.hash, c.sig)); // wrong key
        prev = c;
    }
    std::string hex = d.Hex();
    std::cerr << "secp256k1 ECDSA parity digest " << hex << " over " << valid << " of " << ECDSA_CASES << " cases" << std::endl;
    EXPECT_EQ(ECDSA_CASES - ECDSA_CASES / 5000, valid);
    EXPECT_EQ(std::string(GOLDEN_ECDSA), hex);
}

TEST(Secp256k1VerifyParity, ScriptJsonCorpus)
{
    Digest d;
    size_t good = FoldScriptFile(json_tests::script_valid, sizeof(json_tests::script_valid), true, d);
    size_t bad = FoldScriptFile(json_tests::script_invalid, sizeof(json_tests::script_invalid), false, d);
    std::string hex = d.Hex();
    std::cerr << "script JSON parity digest " << hex << " over " << good << " valid and " << bad << " invalid rows" << std::endl;
    EXPECT_GT(good, 0u);
    EXPECT_GT(bad, 0u);
    EXPECT_EQ(std::string(GOLDEN_SCRIPT), hex);
}
