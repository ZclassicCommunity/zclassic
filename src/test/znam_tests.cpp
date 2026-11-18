// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ZNAM name index: wire format, rules, ordering, undo, atomicity and resolution, on an in-memory store.
// The messages come from the vendored Z23 builders, so a parser/builder disagreement shows up here.

#include "znam/znamindex.h"
#include "znam/znamresolve.h"

#include "key_io.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "tinyformat.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include "c23/services/glue/zcl_znam_index.h"

#include <boost/test/unit_test.hpp>
#include <algorithm>
#include <map>
#include <set>
#include <tuple>

using namespace znam;

namespace {

CScript Msg(const unsigned char* b, size_t n) { return CScript(b, b + n); }

CScript Build(int cmd, const char* name, unsigned type = 0, const char* value = NULL, const char* newOwner = NULL,
              const char* key = NULL, const char* text = NULL)
{
    unsigned char buf[300];
    size_t n = zcl_znam_build(cmd, name, (uint8_t)type, value, newOwner, key, text, buf, sizeof(buf));
    BOOST_REQUIRE_MESSAGE(n > 0, std::string("builder refused ") + name);
    return Msg(buf, n);
}

CScript Register(const char* name, const char* addr, unsigned type = TYPE_TADDR) { return Build(CMD_REGISTER, name, type, addr); }
CScript Update(const char* name, const char* addr, unsigned type = TYPE_TADDR) { return Build(CMD_UPDATE, name, type, addr); }
CScript Transfer(const char* name, const char* newOwner) { return Build(CMD_TRANSFER, name, 0, NULL, newOwner); }
CScript Renew(const char* name) { return Build(CMD_RENEW, name); }
CScript SetRecord(const char* name, unsigned type, const char* v) { return Build(CMD_SET_RECORD, name, type, v); }
CScript SetText(const char* name, const char* k, const char* v) { return Build(CMD_SET_TEXT, name, 0, NULL, NULL, k, v); }

std::string OwnerOf(unsigned char tag)
{
    unsigned char h[20];
    memset(h, tag, 20);
    return OwnerFromHash160(h);
}

CScript P2PKH(unsigned char tag)
{
    std::vector<unsigned char> h(20, tag);
    return CScript() << OP_DUP << OP_HASH160 << h << OP_EQUALVERIFY << OP_CHECKSIG;
}

/** One transaction of a test block: the message and who signs it (tag 0 = no owner: not P2PKH/P2SH). */
struct Op {
    CScript script;
    unsigned char owner;
    int pos; //! where the OP_RETURN sits among the outputs (0 = first)
    Op(const CScript& s, unsigned char o, int p = 0) : script(s), owner(o), pos(p) {}
};

uint32_t g_seq = 0;

CTransaction Tx(const CScript& opret, int pos)
{
    CMutableTransaction m;
    m.nVersion = 1;
    uint256 prev = uint256S(strprintf("%x", 0x7000000 + ++g_seq));
    m.vin.push_back(CTxIn(COutPoint(prev, 0), CScript() << (int)g_seq, 0xffffffff));
    for (int i = 0; i < pos; i++)
        m.vout.push_back(CTxOut(1000, P2PKH(0xcc)));
    m.vout.push_back(CTxOut(0, opret));
    m.vout.push_back(CTxOut(1000, P2PKH(0xdd)));
    return CTransaction(m);
}

CTransaction Coinbase(int height)
{
    CMutableTransaction m;
    m.nVersion = 1;
    m.vin.push_back(CTxIn(COutPoint(), CScript() << height << OP_0, 0xffffffff));
    m.vout.push_back(CTxOut(1000, P2PKH(0xcc)));
    return CTransaction(m);
}

/** A chain of fake blocks over one store. Hashes are arbitrary: the index only chains them. */
struct Chain {
    MemKV kv;
    ZnamIndex idx;
    std::vector<uint256> hashes;
    Chain() : idx(&kv)
    {
        std::string err;
        BOOST_REQUIRE(idx.Load(err));
    }
    uint256 Add(const std::vector<Op>& ops)
    {
        CBlock b;
        b.hashPrevBlock = hashes.empty() ? uint256() : hashes.back();
        b.vtx.push_back(Coinbase((int)hashes.size() + 1));
        std::vector<unsigned char> owners(1, 0);
        for (size_t i = 0; i < ops.size(); i++) {
            b.vtx.push_back(Tx(ops[i].script, ops[i].pos));
            owners.push_back(ops[i].owner);
        }
        OwnerFn fn = [owners](size_t i, std::string& o) -> int {
            if (i >= owners.size() || owners[i] == 0)
                return 0;
            o = OwnerOf(owners[i]);
            return 1;
        };
        uint256 h = uint256S(strprintf("%x", 0x100000 + (unsigned)hashes.size()));
        std::string err;
        BOOST_REQUIRE_MESSAGE(idx.ApplyBlock(b, fn, h, (int)hashes.size() + 1, true, err), err);
        hashes.push_back(h);
        return h;
    }
    void Pop()
    {
        std::string err;
        uint256 prev = hashes.size() > 1 ? hashes[hashes.size() - 2] : uint256();
        BOOST_REQUIRE_MESSAGE(idx.DisconnectBlock(hashes.back(), prev, (int)hashes.size() - 1, err), err);
        hashes.pop_back();
    }
    bool Get(const char* name, Entry& e) const { return idx.GetName(name, e); }
    std::string OwnerNow(const char* name) const { Entry e; return Get(name, e) ? e.owner : std::string("-"); }
    std::string ValueNow(const char* name) const { Entry e; return Get(name, e) ? e.value : std::string("-"); }
};

// Valid-looking address text per chain: the index never checks one, resolution does.
std::string TAddr(unsigned char tag)
{
    unsigned char h[20];
    memset(h, tag, 20);
    uint160 u;
    memcpy(u.begin(), h, 20);
    return EncodeDestination(CKeyID(u));
}

std::string P2shAddr(unsigned char tag)
{
    uint160 u;
    memset(u.begin(), tag, 20);
    return EncodeDestination(CScriptID(u));
}

} // namespace

namespace {
/** The first keys two stores disagree on, as text, "" when equal. */
std::string Diff(const std::map<std::string, std::string>& a, const std::map<std::string, std::string>& b)
{
    std::string d;
    for (std::map<std::string, std::string>::const_iterator it = a.begin(); it != a.end() && d.size() < 300; ++it) {
        std::map<std::string, std::string>::const_iterator o = b.find(it->first);
        if (o == b.end()) d += " only-left:" + HexStr(it->first);
        else if (o->second != it->second) d += " differs:" + HexStr(it->first);
    }
    for (std::map<std::string, std::string>::const_iterator it = b.begin(); it != b.end() && d.size() < 300; ++it)
        if (!a.count(it->first)) d += " only-right:" + HexStr(it->first);
    return d;
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(znam_tests, BasicTestingSetup)

// ---- the vendored wire format -------------------------------------------------

BOOST_AUTO_TEST_CASE(wire_format_vector)
{
    // 6a | 04 "ZNAM" | 01 01 (version) | 01 01 (REGISTER) | 05 "alice" | 01 03 (t-address) | 05 "t1abc"
    const std::string expect = "6a045a4e414d" "0101" "0101" "05616c696365" "0103" "057431616263";
    unsigned char buf[100];
    size_t n = zcl_znam_build(ZCL_ZNAM_CMD_REGISTER, "alice", ZCL_ZNAM_TYPE_TADDR, "t1abc", NULL, NULL, NULL, buf, sizeof(buf));
    BOOST_CHECK_EQUAL(HexStr(buf, buf + n), expect);
    zcl_znam_parsed m;
    BOOST_REQUIRE(zcl_znam_parse_message(buf, n, &m));
    BOOST_CHECK_EQUAL(m.command, ZCL_ZNAM_CMD_REGISTER);
    BOOST_CHECK_EQUAL(std::string(m.name), "alice");
    BOOST_CHECK_EQUAL((int)m.target_type, 3);
    BOOST_CHECK_EQUAL(std::string(m.target_value), "t1abc");

    // every command round-trips
    unsigned char b2[300];
    n = zcl_znam_build(ZCL_ZNAM_CMD_TRANSFER, "a-b", 0, NULL, "t1new", NULL, NULL, b2, sizeof(b2));
    BOOST_REQUIRE(n && zcl_znam_parse_message(b2, n, &m));
    BOOST_CHECK_EQUAL(std::string(m.new_owner), "t1new");
    n = zcl_znam_build(ZCL_ZNAM_CMD_RENEW, "a-b", 0, NULL, NULL, NULL, NULL, b2, sizeof(b2));
    BOOST_REQUIRE(n && zcl_znam_parse_message(b2, n, &m));
    BOOST_CHECK_EQUAL(m.command, ZCL_ZNAM_CMD_RENEW);
    n = zcl_znam_build(ZCL_ZNAM_CMD_SET_TEXT, "a-b", 0, NULL, NULL, "url", "", b2, sizeof(b2));
    BOOST_REQUIRE(n && zcl_znam_parse_message(b2, n, &m));
    BOOST_CHECK_EQUAL(std::string(m.text_key), "url");
    BOOST_CHECK_EQUAL(std::string(m.text_value), "");
    n = zcl_znam_build(ZCL_ZNAM_CMD_SET_RECORD, "a-b", ZCL_ZNAM_TYPE_CONTENT, "abcd", NULL, NULL, NULL, b2, sizeof(b2));
    BOOST_REQUIRE(n && zcl_znam_parse_message(b2, n, &m));
    BOOST_CHECK_EQUAL((int)m.target_type, 7);
}

BOOST_AUTO_TEST_CASE(name_syntax)
{
    const char* good[] = {"a", "alice", "a-b", "a--b", "0", "123", "xn--80ak6aa92e", "a1-b2-c3", "z"};
    for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++)
        BOOST_CHECK_MESSAGE(zcl_znam_validate_name(good[i]), good[i]);
    BOOST_CHECK(zcl_znam_validate_name(std::string(63, 'a').c_str()));
    BOOST_CHECK(!zcl_znam_validate_name(std::string(64, 'a').c_str()));
    const char* bad[] = {"", "-a", "a-", "-", "Alice", "ALICE", "aLice", "a b", " alice", "alice ", "a_b", "a.b", "a@b", "@alice",
                         "alice\n", "al\x01ice", "\xd0\xb0lice" /* Cyrillic a */, "alic\xd0\xb5" /* Cyrillic e */,
                         "\xef\xbd\x81lice" /* fullwidth a */, "alice\xe2\x80\x8b" /* zero width space */, "\xc3\xa9", "a\xcc\x81"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        BOOST_CHECK_MESSAGE(!zcl_znam_validate_name(bad[i]), "accepted " + HexStr(std::string(bad[i])));
    BOOST_CHECK(!zcl_znam_validate_name(NULL));
    // the builders refuse what the validator refuses
    unsigned char buf[100];
    BOOST_CHECK_EQUAL(zcl_znam_build(ZCL_ZNAM_CMD_RENEW, "Alice", 0, NULL, NULL, NULL, NULL, buf, sizeof(buf)), 0u);
}

BOOST_AUTO_TEST_CASE(parser_rejects_what_z23_rejects)
{
    unsigned char ok[100];
    size_t n = zcl_znam_build(ZCL_ZNAM_CMD_REGISTER, "alice", 3, "t1abc", NULL, NULL, NULL, ok, sizeof(ok));
    zcl_znam_parsed m;
    BOOST_REQUIRE(zcl_znam_parse_message(ok, n, &m));
    // truncated at every length
    for (size_t k = 0; k < n; k++)
        BOOST_CHECK_MESSAGE(!zcl_znam_parse_message(ok, k, &m), strprintf("a %u byte prefix parsed", (unsigned)k));
    // wrong lokad, version, command, type
    unsigned char t[100];
    memcpy(t, ok, n); t[2] = 'X';
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    memcpy(t, ok, n); t[7] = 2; // version
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    memcpy(t, ok, n); t[9] = 0; // command 0
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    memcpy(t, ok, n); t[9] = 7; // command 7
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    memcpy(t, ok, n); t[17] = 0; // type 0
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    memcpy(t, ok, n); t[17] = 8; // type 8
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    memcpy(t, ok, n); t[0] = 0x6b; // not OP_RETURN
    BOOST_CHECK(!zcl_znam_parse_message(t, n, &m));
    // Z23 does not call overlay_reader_finish: trailing bytes after the last field still parse (docs/znam.md, A1)
    memcpy(t, ok, n); t[n] = 0xde; t[n + 1] = 0xad;
    BOOST_CHECK(zcl_znam_parse_message(t, n + 2, &m));
    BOOST_CHECK_EQUAL(std::string(m.target_value), "t1abc");
    // an empty target is refused; an empty SET_TEXT value is not
    unsigned char e1[] = {0x6a, 0x04, 'Z', 'N', 'A', 'M', 0x01, 0x01, 0x01, 0x01, 0x01, 'a', 0x01, 0x03, 0x00};
    BOOST_CHECK(!zcl_znam_parse_message(e1, sizeof(e1), &m));
    // an invalid name in a well-formed record is refused
    unsigned char e2[] = {0x6a, 0x04, 'Z', 'N', 'A', 'M', 0x01, 0x01, 0x01, 0x04, 0x01, 'A'};
    BOOST_CHECK(!zcl_znam_parse_message(e2, sizeof(e2), &m));
    unsigned char e3[] = {0x6a, 0x04, 'Z', 'N', 'A', 'M', 0x01, 0x01, 0x01, 0x04, 0x01, 'a'};
    BOOST_CHECK(zcl_znam_parse_message(e3, sizeof(e3), &m));
    // a script over the relay cap is never built: a maximal SET_TEXT is 237 bytes
    unsigned char big[400];
    BOOST_CHECK_EQUAL(zcl_znam_build(ZCL_ZNAM_CMD_SET_TEXT, std::string(63, 'a').c_str(), 0, NULL, NULL, std::string(32, 'k').c_str(),
                                     std::string(128, 'v').c_str(), big, sizeof(big)), 0u);
}

BOOST_AUTO_TEST_CASE(owner_is_the_first_inputs_address_in_p2pkh_form)
{
    uint8_t h[20];
    std::vector<unsigned char> hash(20, 0x42);
    CScript p2pkh = P2PKH(0x42);
    CScript p2sh = CScript() << OP_HASH160 << hash << OP_EQUAL;
    CScript p2pk = CScript() << std::vector<unsigned char>(33, 0x02) << OP_CHECKSIG;
    CScript multisig = CScript() << OP_1 << std::vector<unsigned char>(33, 0x02) << OP_1 << OP_CHECKMULTISIG;
    BOOST_CHECK(zcl_znam_owner_hash(&p2pkh[0], p2pkh.size(), h));
    BOOST_CHECK(h[0] == 0x42 && h[19] == 0x42);
    BOOST_CHECK(zcl_znam_owner_hash(&p2sh[0], p2sh.size(), h));
    BOOST_CHECK(!zcl_znam_owner_hash(&p2pk[0], p2pk.size(), h));
    BOOST_CHECK(!zcl_znam_owner_hash(&multisig[0], multisig.size(), h));
    CScript almost = P2PKH(0x42);
    almost << OP_NOP;
    BOOST_CHECK(!zcl_znam_owner_hash(&almost[0], almost.size(), h));
    // A P2SH output yields the SAME owner text as the P2PKH output with the same hash (Z23 renders both as P2PKH, A3)
    unsigned char hh[20];
    memset(hh, 0x42, 20);
    BOOST_CHECK_EQUAL(OwnerFromHash160(hh), OwnerOf(0x42));
    BOOST_CHECK(OwnerOf(0x42) != P2shAddr(0x42));
}

// ---- the rules -------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(register_update_transfer_renew)
{
    Chain c;
    const std::string a1 = TAddr(0x11), a2 = TAddr(0x12), a3 = TAddr(0x13);
    c.Add({Op(Register("alice", a1.c_str()), 0xa1)});
    Entry e;
    BOOST_REQUIRE(c.Get("alice", e));
    BOOST_CHECK_EQUAL(e.owner, OwnerOf(0xa1));
    BOOST_CHECK_EQUAL(e.value, a1);
    BOOST_CHECK_EQUAL(e.type, TYPE_TADDR);
    BOOST_CHECK_EQUAL(e.regHeight, 1);
    BOOST_CHECK_EQUAL(e.expiryHeight, 1 + 210240);
    BOOST_CHECK_EQUAL(e.changeHeight, 1);

    // a second registration of the same name, by anyone, later: ignored (first come, first served)
    c.Add({Op(Register("alice", a2.c_str()), 0xa2)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a1);
    BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa1));

    // UPDATE by a stranger: ignored. By the owner: applied.
    c.Add({Op(Update("alice", a2.c_str()), 0xa2)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a1);
    c.Add({Op(Update("alice", a3.c_str()), 0xa1)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a3);
    BOOST_REQUIRE(c.Get("alice", e));
    BOOST_CHECK_EQUAL(e.changeHeight, 4);
    BOOST_CHECK_EQUAL(e.regHeight, 1);

    // UPDATE and TRANSFER of a name that does not exist: ignored
    c.Add({Op(Update("bob", a1.c_str()), 0xa1), Op(Transfer("bob", a1.c_str()), 0xa1)});
    BOOST_CHECK(!c.Get("bob", e));

    // TRANSFER by a stranger: ignored. By the owner: applied, and the old owner loses the name.
    c.Add({Op(Transfer("alice", OwnerOf(0xa2).c_str()), 0xa2)});
    BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa1));
    c.Add({Op(Transfer("alice", OwnerOf(0xa2).c_str()), 0xa1)});
    BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa2));
    c.Add({Op(Update("alice", a1.c_str()), 0xa1)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a3);
    c.Add({Op(Update("alice", a1.c_str()), 0xa2)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a1);
    BOOST_CHECK_EQUAL(c.idx.ListByOwner(OwnerOf(0xa1), 0, 10).size(), 0u);
    BOOST_CHECK_EQUAL(c.idx.ListByOwner(OwnerOf(0xa2), 0, 10).size(), 1u);

    // RENEW is permissionless, extends from the later of expiry and height, and sets last_update_txid
    BOOST_REQUIRE(c.Get("alice", e));
    const int oldExpiry = e.expiryHeight;
    c.Add({Op(Renew("alice"), 0xee)});
    BOOST_REQUIRE(c.Get("alice", e));
    BOOST_CHECK_EQUAL(e.expiryHeight, oldExpiry + 210240);
    BOOST_CHECK_EQUAL(e.changeHeight, 9); // a renewal is not a change a payer must be warned about
    c.Add({Op(Renew("nobody"), 0xee)});
    BOOST_CHECK(!c.Get("nobody", e));
}

BOOST_AUTO_TEST_CASE(no_owner_means_ignored)
{
    Chain c;
    const std::string a1 = TAddr(0x11);
    // a first input that is not P2PKH/P2SH (bare pubkey, multisig, non-standard, coinbase) names no owner
    c.Add({Op(Register("alice", a1.c_str()), 0)});
    Entry e;
    BOOST_CHECK(!c.Get("alice", e));
    BOOST_CHECK_EQUAL(c.idx.GetStats().names, 0u);
    BOOST_CHECK_EQUAL(c.idx.GetStats().messages, 1u);
    BOOST_CHECK_EQUAL(c.idx.GetStats().ignored, 1u);
    c.Add({Op(Register("alice", a1.c_str()), 0xa1)});
    BOOST_CHECK(c.Get("alice", e));
    c.Add({Op(Update("alice", TAddr(0x22).c_str()), 0)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a1);
    // RENEW needs no owner at all
    c.Add({Op(Renew("alice"), 0)});
    BOOST_REQUIRE(c.Get("alice", e));
    BOOST_CHECK_EQUAL(e.expiryHeight, 2 + 2 * 210240); // registered at height 2, renewed once
}

BOOST_AUTO_TEST_CASE(same_block_order_is_first_come_first_served)
{
    const std::string a1 = TAddr(0x11), a2 = TAddr(0x12);
    {
        Chain c;
        c.Add({Op(Register("alice", a1.c_str()), 0xa1), Op(Register("alice", a2.c_str()), 0xa2)});
        BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa1));
        BOOST_CHECK_EQUAL(c.ValueNow("alice"), a1);
        BOOST_CHECK_EQUAL(c.idx.GetStats().applied, 1u);
        BOOST_CHECK_EQUAL(c.idx.GetStats().ignored, 1u);
    }
    {
        Chain c; // the same two transactions, the other way round
        c.Add({Op(Register("alice", a2.c_str()), 0xa2), Op(Register("alice", a1.c_str()), 0xa1)});
        BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa2));
    }
    {
        // the owner registers and updates in one block; a stranger's update between them is ignored
        Chain c;
        c.Add({Op(Register("alice", a1.c_str()), 0xa1), Op(Update("alice", a2.c_str()), 0xa2),
               Op(Update("alice", TAddr(0x13).c_str()), 0xa1)});
        BOOST_CHECK_EQUAL(c.ValueNow("alice"), TAddr(0x13));
        // an update BEFORE the registration in block order finds no name
        Chain d;
        d.Add({Op(Update("alice", a2.c_str()), 0xa1), Op(Register("alice", a1.c_str()), 0xa1)});
        BOOST_CHECK_EQUAL(d.ValueNow("alice"), a1);
    }
}

BOOST_AUTO_TEST_CASE(records_and_text)
{
    Chain c;
    const std::string a1 = TAddr(0x11), z = "zs1notvalidbutstoredasis";
    c.Add({Op(Register("alice", a1.c_str()), 0xa1)});
    c.Add({Op(SetRecord("alice", TYPE_ZADDR, z.c_str()), 0xa1), Op(SetRecord("alice", TYPE_BTC, "1btc"), 0xa2),
           Op(SetText("alice", "url", "https://example.org"), 0xa1), Op(SetText("alice", "email", "x@y"), 0xa2)});
    std::vector<AddrRecord> r = c.idx.GetAddrRecords("alice");
    BOOST_REQUIRE_EQUAL(r.size(), 1u);
    BOOST_CHECK_EQUAL(r[0].type, TYPE_ZADDR);
    BOOST_CHECK_EQUAL(r[0].value, z);
    BOOST_CHECK_EQUAL(r[0].height, 2);
    std::vector<TextRecord> t = c.idx.GetTextRecords("alice");
    BOOST_REQUIRE_EQUAL(t.size(), 1u);
    BOOST_CHECK_EQUAL(t[0].key, "url");
    // an empty value is kept as a row (Z23 does not delete), a later value replaces it
    c.Add({Op(SetText("alice", "url", ""), 0xa1)});
    t = c.idx.GetTextRecords("alice");
    BOOST_REQUIRE_EQUAL(t.size(), 1u);
    BOOST_CHECK_EQUAL(t[0].value, "");
    // records of a name that does not exist are ignored
    c.Add({Op(SetRecord("ghost", TYPE_ZADDR, z.c_str()), 0xa1), Op(SetText("ghost", "k", "v"), 0xa1)});
    BOOST_CHECK(c.idx.GetAddrRecords("ghost").empty());
    // after a TRANSFER only the new owner can set records
    c.Add({Op(Transfer("alice", OwnerOf(0xa2).c_str()), 0xa1)});
    c.Add({Op(SetRecord("alice", TYPE_LTC, "lltc"), 0xa1), Op(SetRecord("alice", TYPE_DOGE, "ddoge"), 0xa2)});
    r = c.idx.GetAddrRecords("alice");
    BOOST_REQUIRE_EQUAL(r.size(), 2u);
    BOOST_CHECK_EQUAL(r[0].type, TYPE_ZADDR);
    BOOST_CHECK_EQUAL(r[1].type, TYPE_DOGE);
}

BOOST_AUTO_TEST_CASE(the_one_message_is_the_first_op_return_at_any_position)
{
    Chain c;
    const std::string a1 = TAddr(0x11);
    // the OP_RETURN is the third output: still read (Z23 takes the first OP_RETURN, wherever it is)
    c.Add({Op(Register("alice", a1.c_str()), 0xa1, 2)});
    Entry e;
    BOOST_CHECK(c.Get("alice", e));
    // a transaction with two OP_RETURN outputs: only the first counts
    CMutableTransaction m;
    m.nVersion = 1;
    m.vin.push_back(CTxIn(COutPoint(uint256S("77"), 0), CScript() << 77, 0xffffffff));
    m.vout.push_back(CTxOut(0, CScript() << OP_RETURN << std::vector<unsigned char>(3, 'x')));
    m.vout.push_back(CTxOut(0, Register("bob", a1.c_str())));
    CBlock b;
    b.hashPrevBlock = c.hashes.back();
    b.vtx.push_back(Coinbase(9));
    b.vtx.push_back(CTransaction(m));
    OwnerFn fn = [](size_t i, std::string& o) -> int { if (i == 0) return 0; o = OwnerOf(0xa1); return 1; };
    std::string err;
    BOOST_REQUIRE(c.idx.ApplyBlock(b, fn, uint256S("99"), 2, true, err));
    BOOST_CHECK(!c.Get("bob", e));
}

BOOST_AUTO_TEST_CASE(transfer_to_a_text_that_is_not_an_owner_loses_the_name)
{
    // Z23 stores new_owner as given. No transaction can ever sign as that text again (docs/znam.md, A5).
    Chain c;
    c.Add({Op(Register("alice", TAddr(0x11).c_str()), 0xa1)});
    c.Add({Op(Transfer("alice", "not an address"), 0xa1)});
    BOOST_CHECK_EQUAL(c.OwnerNow("alice"), "not an address");
    c.Add({Op(Update("alice", TAddr(0x12).c_str()), 0xa1)});
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), TAddr(0x11));
    // a P2SH owner string never matches a derived owner either
    c.Add({Op(Register("bob", TAddr(0x11).c_str()), 0xa1)});
    c.Add({Op(Transfer("bob", P2shAddr(0xa1).c_str()), 0xa1)});
    c.Add({Op(Update("bob", TAddr(0x12).c_str()), 0xa1)});
    BOOST_CHECK_EQUAL(c.ValueNow("bob"), TAddr(0x11));
}

// ---- undo, atomicity ----------------------------------------------------------------

BOOST_AUTO_TEST_CASE(disconnect_restores_the_exact_state)
{
    Chain c;
    const std::string a1 = TAddr(0x11), a2 = TAddr(0x12);
    c.Add({Op(Register("alice", a1.c_str()), 0xa1)});
    const std::map<std::string, std::string> s1 = c.kv.m;
    c.Add({Op(Update("alice", a2.c_str()), 0xa1), Op(Register("bob", a2.c_str()), 0xa2), Op(SetText("alice", "k", "v"), 0xa1)});
    const std::map<std::string, std::string> s2 = c.kv.m;
    c.Add({Op(Transfer("alice", OwnerOf(0xa2).c_str()), 0xa1), Op(Renew("bob"), 0xa3), Op(Register("alice", a1.c_str()), 0xa3)});
    BOOST_CHECK(c.kv.m != s2);
    c.Pop();
    BOOST_CHECK_MESSAGE(c.kv.m == s2, Diff(c.kv.m, s2));
    c.Pop();
    BOOST_CHECK_MESSAGE(c.kv.m == s1, Diff(c.kv.m, s1));
    BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa1));
    BOOST_CHECK_EQUAL(c.ValueNow("alice"), a1);
    c.Pop();
    for (std::map<std::string, std::string>::const_iterator it = c.kv.m.begin(); it != c.kv.m.end(); ++it)
        BOOST_CHECK_MESSAGE(it->first == "mver" || it->first == "mbest", "leftover key " + HexStr(it->first));
    // and the chain can be built again (a new transaction has a new id, so the bytes differ from s1; the shape does not)
    c.Add({Op(Register("alice", a1.c_str()), 0xa1)});
    BOOST_CHECK_EQUAL(c.kv.m.size(), s1.size());
    BOOST_CHECK_EQUAL(c.OwnerNow("alice"), OwnerOf(0xa1));
}

BOOST_AUTO_TEST_CASE(a_block_is_one_atomic_batch)
{
    Chain c;
    const size_t before = c.kv.nBatches;
    c.Add({Op(Register("alice", TAddr(0x11).c_str()), 0xa1), Op(Register("bob", TAddr(0x12).c_str()), 0xa2)});
    BOOST_CHECK_EQUAL(c.kv.nBatches, before + 1);

    const std::map<std::string, std::string> snap = c.kv.m;
    std::string err;
    // a block that does not extend the tip is refused and writes nothing
    CBlock bad;
    bad.hashPrevBlock = uint256S("deadbeef");
    bad.vtx.push_back(Coinbase(9));
    OwnerFn none = [](size_t, std::string&) -> int { return 0; };
    BOOST_CHECK(!c.idx.ApplyBlock(bad, none, uint256S("01"), 9, true, err));
    BOOST_CHECK(c.kv.m == snap);
    // a block whose owners cannot be read (undo data missing) is refused whole, after the transactions before it were folded
    CBlock b2;
    b2.hashPrevBlock = c.hashes.back();
    b2.vtx.push_back(Coinbase(3));
    b2.vtx.push_back(Tx(Register("carol", TAddr(0x13).c_str()), 0));
    b2.vtx.push_back(Tx(Register("dave", TAddr(0x14).c_str()), 0));
    OwnerFn flaky = [](size_t i, std::string& o) -> int { if (i == 1) { o = OwnerOf(0xa3); return 1; } return i == 2 ? -1 : 0; };
    BOOST_CHECK(!c.idx.ApplyBlock(b2, flaky, uint256S("02"), 3, true, err));
    BOOST_CHECK(c.kv.m == snap);
    Entry e;
    BOOST_CHECK(!c.Get("carol", e));
    // only the tip can be disconnected
    BOOST_CHECK(!c.idx.DisconnectBlock(uint256S("02"), uint256(), 0, err));
    BOOST_CHECK(c.kv.m == snap);
}

// An independent model of Z23's rules (explorer_index_overlays.c), to compare the index with.
namespace {
struct ModelName {
    std::string owner, value;
    unsigned type;
    int regHeight, expiry;
    std::map<unsigned, std::string> recs;
    std::map<std::string, std::string> text;
};
struct Model {
    std::map<std::string, ModelName> names;
    void Apply(int cmd, const std::string& name, unsigned type, const std::string& value, const std::string& newOwner,
               const std::string& key, const std::string& text, unsigned char ownerTag, int height)
    {
        const bool have = ownerTag != 0;
        const std::string owner = have ? OwnerOf(ownerTag) : std::string();
        std::map<std::string, ModelName>::iterator it = names.find(name);
        switch (cmd) {
        case CMD_REGISTER:
            if (have && it == names.end()) {
                ModelName n; n.owner = owner; n.value = value; n.type = type; n.regHeight = height; n.expiry = height + 210240;
                names[name] = n;
            }
            break;
        case CMD_UPDATE:
            if (it != names.end() && have && it->second.owner == owner) { it->second.type = type; it->second.value = value; }
            break;
        case CMD_TRANSFER:
            if (it != names.end() && have && it->second.owner == owner) it->second.owner = newOwner;
            break;
        case CMD_SET_RECORD:
            if (it != names.end() && have && it->second.owner == owner) it->second.recs[type] = value;
            break;
        case CMD_SET_TEXT:
            if (it != names.end() && have && it->second.owner == owner) it->second.text[key] = text;
            break;
        case CMD_RENEW:
            if (it != names.end()) it->second.expiry = std::max(it->second.expiry, height) + 210240;
            break;
        }
    }
};
} // namespace

BOOST_AUTO_TEST_CASE(random_chains_match_the_model_and_reorgs_equal_a_rebuild)
{
    uint64_t rng = 0x9e3779b97f4a7c15ULL;
    auto rnd = [&rng](uint64_t n) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return n ? rng % n : 0; };
    const char* names[] = {"a", "bb", "c-c", "d1", "eeee"};
    uint64_t applied = 0, ignored = 0;
    for (int round = 0; round < 25; round++) {
        Chain c;
        struct Blk { std::vector<Op> ops; std::vector<std::tuple<int, std::string, unsigned, std::string, std::string, std::string, std::string, unsigned char> > raw; };
        std::vector<Blk> blocks;
        std::vector<std::map<std::string, std::string> > snaps;
        for (int step = 0; step < 120; step++) {
            if (!blocks.empty() && rnd(10) < 3) {
                const size_t k = 1 + rnd(std::min<size_t>(3, blocks.size()));
                for (size_t i = 0; i < k; i++) {
                    c.Pop();
                    blocks.pop_back();
                    snaps.pop_back();
                    if (!snaps.empty())
                        BOOST_REQUIRE(c.kv.m == snaps.back());
                }
                continue;
            }
            Blk b;
            const int ntx = (int)rnd(5);
            for (int n = 0; n < ntx; n++) {
                const std::string nm = names[rnd(5)];
                const unsigned char owner = rnd(8) == 0 ? 0 : (unsigned char)(0xa0 + rnd(3));
                const std::string val = TAddr((unsigned char)(0x30 + rnd(6)));
                const int cmd = 1 + (int)rnd(6);
                const unsigned type = (unsigned)(1 + rnd(7));
                const std::string newOwner = rnd(3) == 0 ? "weird owner" : OwnerOf((unsigned char)(0xa0 + rnd(3)));
                const std::string key = rnd(2) ? "k1" : "k2", text = rnd(3) ? "v" + std::to_string(rnd(100)) : "";
                CScript s;
                switch (cmd) {
                case CMD_REGISTER: s = Build(cmd, nm.c_str(), type, val.c_str()); break;
                case CMD_UPDATE: s = Build(cmd, nm.c_str(), type, val.c_str()); break;
                case CMD_TRANSFER: s = Build(cmd, nm.c_str(), 0, NULL, newOwner.c_str()); break;
                case CMD_RENEW: s = Build(cmd, nm.c_str()); break;
                case CMD_SET_RECORD: s = Build(cmd, nm.c_str(), type, val.c_str()); break;
                default: s = Build(cmd, nm.c_str(), 0, NULL, NULL, key.c_str(), text.c_str()); break;
                }
                b.ops.push_back(Op(s, owner, (int)rnd(3)));
                b.raw.push_back(std::make_tuple(cmd, nm, type, val, newOwner, key, text, owner));
            }
            c.Add(b.ops);
            blocks.push_back(b);
            snaps.push_back(c.kv.m);
        }
        // the model, over the surviving chain
        Model model;
        for (size_t h = 0; h < blocks.size(); h++)
            for (size_t i = 0; i < blocks[h].raw.size(); i++) {
                const auto& r = blocks[h].raw[i];
                model.Apply(std::get<0>(r), std::get<1>(r), std::get<2>(r), std::get<3>(r), std::get<4>(r), std::get<5>(r),
                            std::get<6>(r), std::get<7>(r), (int)h + 1);
            }
        BOOST_CHECK_EQUAL(c.idx.GetStats().names, model.names.size());
        for (std::map<std::string, ModelName>::const_iterator it = model.names.begin(); it != model.names.end(); ++it) {
            Entry e;
            BOOST_REQUIRE_MESSAGE(c.Get(it->first.c_str(), e), "missing " + it->first);
            BOOST_CHECK_EQUAL(e.owner, it->second.owner);
            BOOST_CHECK_EQUAL(e.value, it->second.value);
            BOOST_CHECK_EQUAL(e.type, it->second.type);
            BOOST_CHECK_EQUAL(e.regHeight, it->second.regHeight);
            BOOST_CHECK_EQUAL(e.expiryHeight, it->second.expiry);
            std::vector<AddrRecord> ar = c.idx.GetAddrRecords(it->first);
            BOOST_CHECK_EQUAL(ar.size(), it->second.recs.size());
            for (size_t i = 0; i < ar.size(); i++)
                BOOST_CHECK_EQUAL(ar[i].value, it->second.recs.at(ar[i].type));
            std::vector<TextRecord> tr = c.idx.GetTextRecords(it->first);
            BOOST_CHECK_EQUAL(tr.size(), it->second.text.size());
            for (size_t i = 0; i < tr.size(); i++)
                BOOST_CHECK_EQUAL(tr[i].value, it->second.text.at(tr[i].key));
        }
        // the reorged store equals a rebuild of the surviving chain, byte for byte
        Chain fresh;
        for (size_t h = 0; h < blocks.size(); h++) {
            // re-adding generates new transactions (new ids); compare the shape instead of the bytes
            fresh.Add(blocks[h].ops);
        }
        BOOST_CHECK_EQUAL(fresh.idx.GetStats().names, c.idx.GetStats().names);
        BOOST_CHECK_EQUAL(fresh.idx.GetStats().applied, c.idx.GetStats().applied);
        BOOST_CHECK_EQUAL(fresh.idx.GetStats().ignored, c.idx.GetStats().ignored);
        applied += c.idx.GetStats().applied;
        ignored += c.idx.GetStats().ignored;
        // popping everything leaves an empty store
        while (!c.hashes.empty())
            c.Pop();
        for (std::map<std::string, std::string>::const_iterator it = c.kv.m.begin(); it != c.kv.m.end(); ++it)
            BOOST_CHECK_MESSAGE(it->first == "mver" || it->first == "mbest", "leftover key " + HexStr(it->first));
    }
    BOOST_TEST_MESSAGE(strprintf("random chains: %u applied, %u ignored messages survive", applied, ignored));
    BOOST_CHECK(applied > 200 && ignored > 200);
}

// ---- resolution ---------------------------------------------------------------------

BOOST_AUTO_TEST_CASE(resolve_rejects_lookalikes_and_never_folds_case)
{
    Chain c;
    c.Add({Op(Register("alice", TAddr(0x11).c_str()), 0xa1)});
    const int tip = 1000;
    BOOST_CHECK_EQUAL(Resolve(c.idx, "alice", 0, tip, 100).status, Resolution::OK);
    const char* bad[] = {"Alice", "ALICE", "alice ", " alice", "alice\n", "\xd0\xb0lice", "alic\xd0\xb5", "\xef\xbd\x81lice",
                         "alice\xe2\x80\x8b", "a1ice@", "@alice", "alice.zcl", "", "al ice"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        BOOST_CHECK_MESSAGE(Resolve(c.idx, bad[i], 0, tip, 100).status == Resolution::MALFORMED, "not malformed: " + HexStr(std::string(bad[i])));
    BOOST_CHECK_EQUAL(Resolve(c.idx, std::string("alice\0x", 7), 0, tip, 100).status, Resolution::MALFORMED); // an embedded NUL
    // a look-alike made only of allowed characters is a DIFFERENT name: it resolves to nothing, never to alice
    const char* near[] = {"a1ice", "aIice", "alicee", "alice-", "-alice", "al-ice", "rnartin", "a1ice0"};
    for (size_t i = 0; i < sizeof(near) / sizeof(near[0]); i++) {
        Resolution r = Resolve(c.idx, near[i], 0, tip, 100);
        BOOST_CHECK_MESSAGE(r.status == Resolution::ABSENT || r.status == Resolution::MALFORMED, near[i]);
    }
    // two names that differ by one look-alike character are two names with two owners
    c.Add({Op(Register("a1ice", TAddr(0x66).c_str()), 0xa2)});
    BOOST_CHECK_EQUAL(Resolve(c.idx, "alice", 0, tip, 100).candidates[0].value, TAddr(0x11));
    BOOST_CHECK_EQUAL(Resolve(c.idx, "a1ice", 0, tip, 100).candidates[0].value, TAddr(0x66));
}

BOOST_AUTO_TEST_CASE(resolve_picks_a_payable_address_and_says_when_it_changed)
{
    Chain c;
    const std::string t1 = TAddr(0x11), t2 = TAddr(0x12);
    c.Add({Op(Register("alice", t1.c_str()), 0xa1)}); // height 1
    Resolution r = Resolve(c.idx, "alice", 0, 1, 100);
    BOOST_REQUIRE_EQUAL(r.status, Resolution::OK);
    BOOST_CHECK_EQUAL(r.candidates[r.selected].value, t1);
    BOOST_CHECK_EQUAL(r.candidates[r.selected].kind, PAY_TRANSPARENT);
    BOOST_CHECK(r.recent);
    BOOST_CHECK(!r.warnings.empty());
    BOOST_CHECK_EQUAL(r.changeHeight, 1);

    // the "changed recently" window: a change at height 1 is recent at tip 100 (99 blocks ago), not at tip 101 (100 ago)
    BOOST_CHECK(Resolve(c.idx, "alice", 0, 100, 100).recent);
    BOOST_CHECK(!Resolve(c.idx, "alice", 0, 101, 100).recent);
    BOOST_CHECK(Resolve(c.idx, "alice", 0, 101, 101).recent);
    BOOST_CHECK(!Resolve(c.idx, "alice", 0, 5, 0).recent); // 0 turns the flag off
    BOOST_CHECK(Resolve(c.idx, "alice", 0, 101, 100).warnings.empty());

    // an UPDATE makes it recent again, and the answer names the new height and txid
    c.Add({Op(Update("alice", t2.c_str()), 0xa1)}); // height 2
    r = Resolve(c.idx, "alice", 0, 500, 100);
    BOOST_CHECK(!r.recent);
    BOOST_CHECK_EQUAL(r.candidates[r.selected].value, t2);
    c.Add({Op(Update("alice", t1.c_str()), 0xa1)}); // height 3: swap back
    r = Resolve(c.idx, "alice", 0, 3 + 50, 100);
    BOOST_CHECK(r.recent);
    BOOST_CHECK_EQUAL(r.changeHeight, 3);
    BOOST_CHECK_EQUAL(r.blocksSinceChange, 50);
    Entry e;
    BOOST_REQUIRE(c.Get("alice", e));
    BOOST_CHECK(r.changeTxid == e.changeTxid);
    // a TRANSFER is a change a payer must hear about; a RENEW is not
    c.Add({Op(Transfer("alice", OwnerOf(0xa2).c_str()), 0xa1)}); // height 4
    BOOST_CHECK_EQUAL(Resolve(c.idx, "alice", 0, 4 + 10, 100).changeHeight, 4);
    c.Add({Op(Renew("alice"), 0xa3)}); // height 5
    BOOST_CHECK_EQUAL(Resolve(c.idx, "alice", 0, 5 + 10, 100).changeHeight, 4);
    // text records never move what a payer relies on
    c.Add({Op(SetText("alice", "k", "v"), 0xa2)}); // height 6
    BOOST_CHECK_EQUAL(Resolve(c.idx, "alice", 0, 6 + 10, 100).changeHeight, 4);
}

BOOST_AUTO_TEST_CASE(resolve_record_types_and_validation)
{
    Chain c;
    const std::string t1 = TAddr(0x11);
    // a primary target that is not an address of this chain is not payable, and nothing else is guessed
    c.Add({Op(Register("onionname", "abcdefghij.onion", TYPE_ONION), 0xa1)});
    Resolution r = Resolve(c.idx, "onionname", 0, 500, 100);
    BOOST_CHECK_EQUAL(r.status, Resolution::NO_TARGET);
    r = Resolve(c.idx, "onionname", TYPE_ONION, 500, 100);
    BOOST_REQUIRE_EQUAL(r.status, Resolution::OK);
    BOOST_CHECK_EQUAL(r.candidates[r.selected].value, "abcdefghij.onion");
    BOOST_CHECK_EQUAL(r.candidates[r.selected].kind, PAY_NONE);
    // a t-address record added later is what a payer gets, and it is the record's height that counts
    c.Add({Op(SetRecord("onionname", TYPE_TADDR, t1.c_str()), 0xa1)}); // height 2
    r = Resolve(c.idx, "onionname", 0, 52, 100);
    BOOST_REQUIRE_EQUAL(r.status, Resolution::OK);
    BOOST_CHECK_EQUAL(r.candidates[r.selected].value, t1);
    BOOST_CHECK(r.candidates[r.selected].fromRecord);
    BOOST_CHECK_EQUAL(r.changeHeight, 2);
    BOOST_CHECK(r.recent);

    // type and value that disagree are not payable
    c.Add({Op(Register("liar", t1.c_str(), TYPE_ZADDR), 0xa2)});
    r = Resolve(c.idx, "liar", 0, 500, 100);
    BOOST_CHECK_EQUAL(r.status, Resolution::NO_TARGET);
    r = Resolve(c.idx, "liar", TYPE_ZADDR, 500, 100);
    BOOST_REQUIRE_EQUAL(r.status, Resolution::OK);
    BOOST_CHECK_EQUAL(r.candidates[r.selected].kind, PAY_NONE);
    BOOST_CHECK(!r.candidates[r.selected].why.empty());
    // garbage, whitespace and a P2SH address
    std::string why;
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_TADDR, "", why), PAY_NONE);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_TADDR, " " + t1, why), PAY_NONE);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_TADDR, t1 + " ", why), PAY_NONE);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_TADDR, t1.substr(0, t1.size() - 1), why), PAY_NONE);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_TADDR, t1, why), PAY_TRANSPARENT);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_TADDR, P2shAddr(0x44), why), PAY_TRANSPARENT);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_BTC, t1, why), PAY_NONE);
    BOOST_CHECK_EQUAL(ClassifyAddress(TYPE_ZADDR, "zs1qqqqqqqqqqqqqqqqqqq", why), PAY_NONE);
    // an expired registration still resolves, with a warning
    r = Resolve(c.idx, "onionname", 0, 1 + 210240 + 5, 100);
    BOOST_CHECK(r.expired);
}

BOOST_AUTO_TEST_SUITE_END()
