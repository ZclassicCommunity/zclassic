// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ZSLP token transaction builder: exact amount parsing, the OP_RETURN bytes and the output
// order, against real mainnet transactions (made by Z23 and other wallets) and against the
// validity rules of the index (the vendored Z23 rule set), including a long run of varied
// transactions that are laid out by the builder, judged by ZslpIndex::EvaluateTx and then applied.

#include "zslp/zslpbuild.h"
#include "zslp/zslpindex.h"

#include "data/zslp_mainnet.json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "tinyformat.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "version.h"

#include "c23/services/glue/zcl_slp_index.h"
#include "c23/services/glue/zcl_token_guard.h"

#include <boost/test/unit_test.hpp>
#include <map>
#include <set>
#include <string>
#include <univalue.h>
#include <vector>

using namespace zslp;

namespace {

CScript P2PKHTag(unsigned char tag)
{
    return CScript() << OP_DUP << OP_HASH160 << std::vector<unsigned char>(20, tag) << OP_EQUALVERIFY << OP_CHECKSIG;
}

std::string Parse(const std::string& text, unsigned dec)
{
    uint64_t u = 0;
    std::string err;
    if (!ParseUnits(text, dec, u, err))
        return "ERR";
    return strprintf("%llu", (unsigned long long)u);
}

std::string ParsePos(const std::string& text, unsigned dec)
{
    uint64_t u = 0;
    std::string err;
    if (!ParsePositiveQuantity(text, dec, u, err))
        return "ERR";
    return strprintf("%llu", (unsigned long long)u);
}

CTransaction MakeTx(const std::vector<COutPoint>& ins, const std::vector<CTxOut>& outs, int tag = 0)
{
    CMutableTransaction m;
    m.nVersion = 1;
    for (size_t i = 0; i < ins.size(); i++)
        m.vin.push_back(CTxIn(ins[i], CScript() << (tag + (int)i + 1), 0xffffffff));
    m.vout = outs;
    return CTransaction(m);
}

CTransaction Coinbase(int height)
{
    CMutableTransaction m;
    m.nVersion = 1;
    m.vin.push_back(CTxIn(COutPoint(), CScript() << height << OP_0, 0xffffffff));
    m.vout.push_back(CTxOut(1000, P2PKHTag(0xcc)));
    return CTransaction(m);
}

struct Chain {
    MemKV kv;
    ZslpIndex idx;
    unsigned n;
    uint256 prev;
    Chain() : idx(&kv), n(0)
    {
        std::string err;
        BOOST_REQUIRE(idx.Load(err));
    }
    void Add(const std::vector<CTransaction>& txs)
    {
        CBlock b;
        b.hashPrevBlock = prev;
        b.vtx.push_back(Coinbase((int)n + 1));
        for (size_t i = 0; i < txs.size(); i++)
            b.vtx.push_back(txs[i]);
        uint256 h = uint256S(strprintf("%x", 0x300000 + ++n));
        std::string err;
        BOOST_REQUIRE_MESSAGE(idx.ApplyBlock(b, h, (int)n, true, err), err);
        prev = h;
    }
};

uint256 FromWire(const uint8_t wire[32])
{
    uint256 r;
    for (int i = 0; i < 32; i++)
        r.begin()[i] = wire[31 - i];
    return r;
}

// a small deterministic generator, so the run is the same everywhere
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed) {}
    uint64_t Next()
    {
        s = s * 6364136223846793005ULL + 1442695040888963407ULL;
        return s >> 11;
    }
    uint64_t Below(uint64_t n) { return n ? Next() % n : 0; }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(zslpbuild_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(parse_units_is_exact)
{
    BOOST_CHECK_EQUAL(Parse("0", 2), "0");
    BOOST_CHECK_EQUAL(Parse("1", 2), "100");
    BOOST_CHECK_EQUAL(Parse("1.5", 2), "150");
    BOOST_CHECK_EQUAL(Parse("1.50", 2), "150");
    BOOST_CHECK_EQUAL(Parse("0.01", 2), "1");
    BOOST_CHECK_EQUAL(Parse("0.00000001", 8), "1");
    BOOST_CHECK_EQUAL(Parse("00012.5", 1), "125");
    BOOST_CHECK_EQUAL(Parse("7", 0), "7");
    BOOST_CHECK_EQUAL(Parse("12.0", 0), "ERR"); // a fraction on a token with no decimals, even a zero one
    // never rounded
    BOOST_CHECK_EQUAL(Parse("1.234", 2), "ERR");
    BOOST_CHECK_EQUAL(Parse("0.000000001", 8), "ERR");
    BOOST_CHECK_EQUAL(Parse("0.5", 0), "ERR");
    // shapes that are not plain decimals
    const char* bad[] = {"", ".", ".5", "5.", "-1", "+1", "1e3", "1E3", " 1", "1 ", "1,000", "1_000", "0x10", "1.2.3", "٣", "NaN", "inf", "1.5f", "--1", "0.-1"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        BOOST_CHECK_MESSAGE(Parse(bad[i], 2) == "ERR", "accepted \"" << bad[i] << "\"");
    // the 64-bit edges
    BOOST_CHECK_EQUAL(Parse("184467440737095516.15", 2), "18446744073709551615");
    BOOST_CHECK_EQUAL(Parse("184467440737095516.16", 2), "ERR");
    BOOST_CHECK_EQUAL(Parse("18446744073709551615", 0), "18446744073709551615");
    BOOST_CHECK_EQUAL(Parse("18446744073709551616", 0), "ERR");
    BOOST_CHECK_EQUAL(Parse("99999999999999999999999999", 0), "ERR");
    // a transferable quantity is positive and at most 2^63-1
    BOOST_CHECK_EQUAL(ParsePos("0", 2), "ERR");
    BOOST_CHECK_EQUAL(ParsePos("0.00", 2), "ERR");
    BOOST_CHECK_EQUAL(ParsePos("0.01", 2), "1");
    BOOST_CHECK_EQUAL(ParsePos("9223372036854775807", 0), "9223372036854775807");
    BOOST_CHECK_EQUAL(ParsePos("9223372036854775808", 0), "ERR");
    BOOST_CHECK_EQUAL(ParsePos("92233720368547758.07", 2), "9223372036854775807");
    BOOST_CHECK_EQUAL(ParsePos("92233720368547758.08", 2), "ERR");
    // it is the inverse of the index's formatter, for every size
    Rng r(7);
    for (int i = 0; i < 2000; i++) {
        const unsigned dec = (unsigned)r.Below(9);
        const uint64_t v = r.Next() >> r.Below(60);
        uint64_t back = 0;
        std::string err;
        BOOST_REQUIRE_MESSAGE(ParseUnits(FormatAmount(v, dec), dec, back, err), err);
        BOOST_CHECK_EQUAL(back, v);
    }
}

BOOST_AUTO_TEST_CASE(dust_follows_policy)
{
    BOOST_CHECK_EQUAL(TokenDust(CFeeRate(1000)), 546);
    BOOST_CHECK_EQUAL(TokenDust(CFeeRate(0)), 546);
    BOOST_CHECK(TokenDust(CFeeRate(5000)) > 546);
    // never below what the policy calls dust, so the output relays
    const CFeeRate rates[] = {CFeeRate(1000), CFeeRate(2000), CFeeRate(10000)};
    for (size_t i = 0; i < 3; i++)
        BOOST_CHECK(!CTxOut(TokenDust(rates[i]), P2PKHTag(1)).IsDust(rates[i]));
    // and 546 is exactly the P2PKH dust threshold at the default rate
    BOOST_CHECK(CTxOut(545, P2PKHTag(1)).IsDust(CFeeRate(1000)));
    BOOST_CHECK(!CTxOut(546, P2PKHTag(1)).IsDust(CFeeRate(1000)));
}

BOOST_AUTO_TEST_CASE(genesis_rules_are_z23s)
{
    GenesisParams p;
    p.ticker = "TST";
    p.name = "Test token";
    p.decimals = 2;
    p.quantity = 100000;
    std::string err;
    BOOST_CHECK(ValidateGenesis(p, err));
    { GenesisParams q = p; q.ticker = ""; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.ticker = "ABCDEFGHIJK"; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.ticker = "A B"; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.ticker = "AB-"; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.name = ""; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.name = std::string(65, 'a'); BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.name = std::string(64, 'a'); BOOST_CHECK(ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.name = "bad<name>"; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.name = "Fine name-1_2.3/4"; BOOST_CHECK(ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.decimals = 9; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.decimals = 8; BOOST_CHECK(ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.quantity = 0; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.quantity = MAX_GENESIS_SUPPLY; BOOST_CHECK(ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.quantity = MAX_GENESIS_SUPPLY + 1; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.documentUrl = std::string(256, 'a'); BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.documentUrl = "https://exa mple"; BOOST_CHECK(!ValidateGenesis(q, err)); }
    { GenesisParams q = p; q.documentUrl = "https://example.org/a.json"; BOOST_CHECK(ValidateGenesis(q, err)); }
}

// What Z23 itself writes: ticker/name only, no document, a baton at vout[2]. The bytes are pinned,
// and they are the vendored builder's: nothing here encodes SLP by hand.
BOOST_AUTO_TEST_CASE(genesis_message_bytes)
{
    GenesisParams p;
    p.ticker = "AAA";
    p.name = "Alpha";
    p.decimals = 2;
    p.quantity = 100000;
    CScript s;
    std::string err;
    BOOST_REQUIRE(BuildGenesisScript(p, s, err));
    BOOST_CHECK_EQUAL(HexStr(s.begin(), s.end()),
        "6a04534c500001010747454e455349530341414105416c7068614c004c00010201020800000000000186a0");
    p.baton = false;
    BOOST_REQUIRE(BuildGenesisScript(p, s, err));
    // no baton: an empty push in place of the baton index
    BOOST_CHECK_EQUAL(HexStr(s.begin(), s.end()),
        "6a04534c500001010747454e455349530341414105416c7068614c004c000102" "4c00" "0800000000000186a0");
}

BOOST_AUTO_TEST_CASE(layout_send)
{
    const uint256 token = uint256S("40f47139acb5c3088aa282a48c58324a43177ec2704d5aa748f03c3d09828568");
    std::vector<Recipient> to(1);
    to[0].script = P2PKHTag(0x11);
    to[0].units = 1234;
    TokenLayout l;
    std::string err;
    // one recipient, change returns
    BOOST_REQUIRE(LayoutSend(token, to, 100000, P2PKHTag(0x22), 546, l, err));
    BOOST_REQUIRE_EQUAL(l.vout.size(), 3u);
    BOOST_CHECK(l.vout[0].scriptPubKey[0] == OP_RETURN && l.vout[0].nValue == 0);
    BOOST_CHECK(l.vout[1].scriptPubKey == P2PKHTag(0x11) && l.vout[1].nValue == 546);
    BOOST_CHECK(l.vout[2].scriptPubKey == P2PKHTag(0x22) && l.vout[2].nValue == 546);
    BOOST_CHECK_EQUAL(l.tokenChange, 100000u - 1234u);
    BOOST_REQUIRE_EQUAL(l.quantities.size(), 2u);
    BOOST_CHECK_EQUAL(l.quantities[0], 1234u);
    BOOST_CHECK_EQUAL(l.quantities[1], 100000u - 1234u);
    // the message is the vendored builder's, for the same quantities
    unsigned char id[32], buf[300];
    WireTokenId(token, id);
    const size_t n = zcl_token_guard_build_send(buf, sizeof(buf), id, &l.quantities[0], 2);
    BOOST_CHECK(l.vout[0].scriptPubKey == CScript(buf, buf + n));
    // an exact amount has no change output
    BOOST_REQUIRE(LayoutSend(token, to, 1234, P2PKHTag(0x22), 546, l, err));
    BOOST_CHECK_EQUAL(l.vout.size(), 2u);
    BOOST_CHECK_EQUAL(l.tokenChange, 0u);
    // many recipients keep their order
    std::vector<Recipient> many(3);
    for (int i = 0; i < 3; i++) { many[i].script = P2PKHTag(0x30 + i); many[i].units = 10 + i; }
    BOOST_REQUIRE(LayoutSend(token, many, 100, P2PKHTag(0x22), 546, l, err));
    BOOST_REQUIRE_EQUAL(l.vout.size(), 5u);
    BOOST_CHECK_EQUAL(l.quantities[0], 10u); BOOST_CHECK_EQUAL(l.quantities[1], 11u); BOOST_CHECK_EQUAL(l.quantities[2], 12u);
    BOOST_CHECK_EQUAL(l.quantities[3], 100u - 33u);
    // refusals
    BOOST_CHECK(!LayoutSend(token, to, 1233, P2PKHTag(0x22), 546, l, err));          // more than the inputs
    to[0].units = 0;
    BOOST_CHECK(!LayoutSend(token, to, 100, P2PKHTag(0x22), 546, l, err));           // zero amount
    to[0].units = 5;
    to[0].script = CScript() << OP_TRUE;
    BOOST_CHECK(!LayoutSend(token, to, 100, P2PKHTag(0x22), 546, l, err));           // not an address
    BOOST_CHECK(!LayoutSend(token, std::vector<Recipient>(), 100, P2PKHTag(0x22), 546, l, err));
    std::vector<Recipient> twenty(20);
    for (int i = 0; i < 20; i++) { twenty[i].script = P2PKHTag(1); twenty[i].units = 1; }
    BOOST_CHECK(!LayoutSend(token, twenty, 20, P2PKHTag(0x22), 546, l, err));        // 20 outputs: too many
    std::vector<Recipient> nineteen(twenty.begin(), twenty.begin() + 19);
    BOOST_CHECK(LayoutSend(token, nineteen, 19, P2PKHTag(0x22), 546, l, err));       // 19 and no change
    BOOST_CHECK(!LayoutSend(token, nineteen, 20, P2PKHTag(0x22), 546, l, err));      // 19 and a change: 20
    std::vector<Recipient> big(2);
    big[0].script = big[1].script = P2PKHTag(1);
    big[0].units = MAX_QUANTITY; big[1].units = 1;
    BOOST_CHECK(!LayoutSend(token, big, UINT64_MAX, P2PKHTag(0x22), 546, l, err));   // a sum above 2^63-1
}

BOOST_AUTO_TEST_CASE(layout_burn_keeps_the_zcl_change_out_of_a_token_slot)
{
    const uint256 token = uint256S("40f47139acb5c3088aa282a48c58324a43177ec2704d5aa748f03c3d09828568");
    TokenLayout l;
    std::string err;
    BOOST_REQUIRE(LayoutBurn(token, 40, 100, P2PKHTag(0x22), 546, l, err));
    BOOST_CHECK_EQUAL(l.burned, 40u);
    BOOST_CHECK_EQUAL(l.tokenChange, 60u);
    BOOST_REQUIRE_EQUAL(l.vout.size(), 2u);
    BOOST_REQUIRE_EQUAL(l.quantities.size(), 1u);
    BOOST_CHECK_EQUAL(l.quantities[0], 60u);
    // the whole selection: the message still has one quantity (0) and vout[1] is a real dust output
    BOOST_REQUIRE(LayoutBurn(token, 100, 100, P2PKHTag(0x22), 546, l, err));
    BOOST_CHECK_EQUAL(l.tokenChange, 0u);
    BOOST_REQUIRE_EQUAL(l.vout.size(), 2u);
    BOOST_CHECK_EQUAL(l.quantities[0], 0u);
    BOOST_CHECK(l.vout[1].nValue == 546);
    BOOST_CHECK(!LayoutBurn(token, 101, 100, P2PKHTag(0x22), 546, l, err));
    BOOST_CHECK(!LayoutBurn(token, 0, 100, P2PKHTag(0x22), 546, l, err));
}

// Real mainnet transactions: every message re-built from its parsed fields is byte for byte the
// message on the chain, and a one-recipient transfer re-laid-out is the same outputs.
BOOST_AUTO_TEST_CASE(rebuild_mainnet_messages)
{
    UniValue root;
    BOOST_REQUIRE(root.read(std::string(json_tests::zslp_mainnet, json_tests::zslp_mainnet + sizeof(json_tests::zslp_mainnet))));
    const UniValue& tokens = root["tokens"].get_array();
    std::set<std::string> seen;
    unsigned nGenesis = 0, nMint = 0, nSend = 0, nLayout = 0, nGenesisRules = 0;
    for (size_t i = 0; i < tokens.size(); i++) {
        const UniValue& txs = tokens[i]["txs"].get_array();
        for (size_t k = 0; k < txs.size(); k++) {
            const std::string txid = txs[k]["txid"].get_str();
            if (!seen.insert(txid).second)
                continue;
            CTransaction tx;
            CDataStream ss(ParseHex(txs[k]["hex"].get_str()), SER_NETWORK, PROTOCOL_VERSION);
            ss >> tx;
            if (txs[k]["type"].get_str() == "NONE")
                continue; // an ordinary transaction that burned tokens: no message
            const CScript& script = tx.vout[0].scriptPubKey;
            zcl_slp_parsed msg;
            BOOST_REQUIRE_MESSAGE(zcl_slp_parse_message(&script[0], script.size(), &msg) == 1, txid);
            unsigned char buf[600];
            size_t n = 0;
            CScript rebuilt;
            std::string err;
            if (msg.type == ZCL_SLP_TX_GENESIS) {
                nGenesis++;
                n = zcl_token_guard_build_genesis(buf, sizeof(buf), msg.ticker, msg.name, msg.document_url,
                                                  msg.has_document_hash ? msg.document_hash : NULL, msg.decimals,
                                                  msg.mint_baton_vout, msg.quantity);
                rebuilt = CScript(buf, buf + n);
                // and through the wallet's own entry point, when the fields satisfy Z23's creation rules
                GenesisParams p;
                p.ticker = msg.ticker; p.name = msg.name; p.documentUrl = msg.document_url;
                p.hasDocumentHash = msg.has_document_hash != 0;
                memcpy(p.documentHash, msg.document_hash, 32);
                p.decimals = msg.decimals; p.quantity = msg.quantity; p.baton = msg.mint_baton_vout == 2;
                CScript viaWallet;
                if (msg.mint_baton_vout <= 2 && ValidateGenesis(p, err)) {
                    nGenesisRules++;
                    BOOST_REQUIRE_MESSAGE(BuildGenesisScript(p, viaWallet, err), err);
                    BOOST_CHECK_MESSAGE(viaWallet == script, txid << ": BuildGenesisScript differs from the mainnet message");
                }
            } else if (msg.type == ZCL_SLP_TX_MINT) {
                nMint++;
                const uint256 token = FromWire(msg.token_id_wire);
                if (msg.quantity > 0 && msg.quantity <= MAX_QUANTITY && (msg.mint_baton_vout == 0 || msg.mint_baton_vout == 2)) {
                    BOOST_REQUIRE_MESSAGE(BuildMintScript(token, msg.quantity, msg.mint_baton_vout == 2, rebuilt, err), err);
                } else {
                    unsigned char id[32];
                    WireTokenId(token, id);
                    n = zcl_token_guard_build_mint(buf, sizeof(buf), id, msg.mint_baton_vout, msg.quantity);
                    rebuilt = CScript(buf, buf + n);
                }
            } else {
                nSend++;
                const uint256 token = FromWire(msg.token_id_wire);
                std::vector<uint64_t> q(msg.output_quantities, msg.output_quantities + msg.num_outputs);
                BOOST_REQUIRE_MESSAGE(BuildSendScript(token, q, rebuilt, err), err);
                // the same logical transfer: the first quantity to vout[1], the second (if any) back to vout[2]
                if (msg.num_outputs <= 2 && tx.vout.size() >= (size_t)msg.num_outputs + 1 &&
                    tx.vout[1].nValue == 546 && (msg.num_outputs == 1 || tx.vout[2].nValue == 546)) {
                    std::vector<Recipient> to(1);
                    to[0].script = tx.vout[1].scriptPubKey;
                    to[0].units = q[0];
                    TokenLayout l;
                    const CScript change = msg.num_outputs == 2 ? tx.vout[2].scriptPubKey : P2PKHTag(1);
                    if (LayoutSend(token, to, q[0] + (msg.num_outputs == 2 ? q[1] : 0), change, 546, l, err)) {
                        nLayout++;
                        BOOST_CHECK_MESSAGE(l.vout[0].scriptPubKey == script, txid << ": layout message differs");
                        for (size_t o = 1; o < l.vout.size(); o++)
                            BOOST_CHECK_MESSAGE(l.vout[o] == tx.vout[o], txid << ": output " << o << " differs");
                    }
                }
            }
            BOOST_CHECK_MESSAGE(rebuilt == script, txid << ": rebuilt message is not the mainnet message\n  chain  " << HexStr(script.begin(), script.end()) << "\n  rebuilt " << HexStr(rebuilt.begin(), rebuilt.end()));
        }
    }
    BOOST_TEST_MESSAGE(strprintf("rebuilt %u GENESIS (%u through Z23's creation rules), %u MINT, %u SEND messages; %u transfers re-laid-out",
                                 nGenesis, nGenesisRules, nMint, nSend, nLayout));
    BOOST_CHECK(nGenesis >= 5 && nMint >= 2 && nSend >= 5);
}

// Varied transactions, laid out by the builder, judged by EvaluateTx, then applied: the dry run
// agrees with the chain on every one, the created outputs are exactly the planned ones, and the
// totals stay exact.
BOOST_AUTO_TEST_CASE(evaluate_agrees_with_apply)
{
    struct Utxo { COutPoint op; uint64_t units; unsigned char tag; };
    struct Tok { uint256 id; unsigned dec; std::vector<Utxo> utxos; bool baton; COutPoint batonOp; unsigned char batonTag; uint64_t supply; };
    Chain c;
    Rng r(20260101);
    std::vector<Tok> toks;
    unsigned nTx = 0, nGenesis = 0, nMint = 0, nSend = 0, nBurn = 0;
    unsigned char nextTag = 1;

    for (int step = 0; step < 120; step++) {
        const unsigned op = toks.empty() ? 0 : (unsigned)r.Below(10);
        std::vector<COutPoint> ins;
        TokenLayout layout;
        std::string err;
        int tokIdx = -1;
        std::vector<Utxo> spentUtxos;
        bool spendsBaton = false;
        uint64_t sentTotal = 0;
        int want = 0; // 1 genesis 2 mint 3 send
        uint64_t wantMint = 0, wantBurn = 0, wantCreatedUnits = 0;
        unsigned wantBatons = 0;
        bool genesisBaton = false;
        uint64_t genesisQty = 0;
        unsigned genesisDec = 0;

        if (op <= 1) { // GENESIS
            want = 1;
            GenesisParams p;
            p.ticker = strprintf("T%d", step);
            p.name = strprintf("Token %d", step);
            p.decimals = (unsigned)r.Below(9);
            p.quantity = 1 + r.Below(1000000);
            p.baton = r.Below(3) != 0;
            layout.vout.clear();
            BOOST_REQUIRE(LayoutGenesis(p, P2PKHTag(nextTag), P2PKHTag((unsigned char)(nextTag + 1)), 546, layout, err));
            genesisBaton = p.baton; genesisQty = p.quantity; genesisDec = p.decimals;
            wantMint = p.quantity; wantCreatedUnits = p.quantity; wantBatons = p.baton ? 1 : 0;
        } else {
            // pick a token that has something to spend
            std::vector<int> cand;
            for (size_t t = 0; t < toks.size(); t++)
                if (!toks[t].utxos.empty() || toks[t].baton)
                    cand.push_back((int)t);
            if (cand.empty()) { step--; continue; }
            tokIdx = cand[r.Below(cand.size())];
            Tok& tk = toks[tokIdx];
            if (op == 2 && tk.baton) { // MINT
                want = 2;
                const uint64_t q = 1 + r.Below(5000);
                const bool newBaton = r.Below(3) != 0;
                BOOST_REQUIRE(LayoutMint(tk.id, q, P2PKHTag(nextTag), newBaton, P2PKHTag((unsigned char)(nextTag + 1)), 546, layout, err));
                ins.push_back(tk.batonOp);
                spendsBaton = true;
                wantMint = q; wantCreatedUnits = q; wantBatons = newBaton ? 1 : 0;
            } else if (!tk.utxos.empty()) {
                // pick 1..3 inputs
                const size_t k = 1 + r.Below(std::min<size_t>(3, tk.utxos.size()));
                uint64_t have = 0;
                std::set<size_t> pick;
                while (pick.size() < k) pick.insert(r.Below(tk.utxos.size()));
                for (std::set<size_t>::const_iterator it = pick.begin(); it != pick.end(); ++it) {
                    ins.push_back(tk.utxos[*it].op);
                    spentUtxos.push_back(tk.utxos[*it]);
                    have += tk.utxos[*it].units;
                }
                want = 3;
                if (op >= 8 && have > 1) { // BURN
                    wantBurn = 1 + r.Below(have);
                    BOOST_REQUIRE(LayoutBurn(tk.id, wantBurn, have, P2PKHTag(nextTag), 546, layout, err));
                    wantCreatedUnits = have - wantBurn;
                    nBurn++;
                } else {
                    const size_t nr = 1 + r.Below(std::min<uint64_t>(4, have));
                    std::vector<Recipient> to;
                    uint64_t left = have;
                    for (size_t i = 0; i < nr && left > 1; i++) {
                        Recipient rc;
                        rc.script = P2PKHTag((unsigned char)(nextTag + i));
                        rc.units = 1 + r.Below(left / 2 + 1);
                        if (rc.units > left) rc.units = left;
                        left -= rc.units;
                        sentTotal += rc.units;
                        to.push_back(rc);
                    }
                    if (to.empty()) { Recipient rc; rc.script = P2PKHTag(nextTag); rc.units = have; sentTotal = have; to.push_back(rc); }
                    BOOST_REQUIRE_MESSAGE(LayoutSend(tk.id, to, have, P2PKHTag(0xee), 546, layout, err), err);
                    wantCreatedUnits = have; // recipients plus change: every input unit is carried
                }
            } else { step--; continue; }
        }

        // ZCL change last, as the wallet does
        std::vector<CTxOut> outs = layout.vout;
        outs.push_back(CTxOut(100000, P2PKHTag(0xf0)));
        if (ins.empty())
            ins.push_back(COutPoint(uint256S(strprintf("%x", 0x70000 + step)), 0)); // an ordinary ZCL input
        else if (r.Below(2))
            ins.push_back(COutPoint(uint256S(strprintf("%x", 0x70000 + step)), 1));
        const CTransaction tx = MakeTx(ins, outs, step * 3);

        Evaluation ev;
        std::string err2;
        BOOST_REQUIRE_MESSAGE(c.idx.EvaluateTx(tx, ev, err2), err2);
        BOOST_REQUIRE_MESSAGE(ev.isSlp && ev.status == STATUS_VALID, strprintf("step %d: %s", step, ev.reason));
        BOOST_CHECK_EQUAL(ev.type, want);
        BOOST_CHECK(ev.token == (want == 1 ? tx.GetHash() : toks[tokIdx].id));
        BOOST_CHECK_EQUAL(ev.burnedUnits, wantBurn);
        BOOST_CHECK_EQUAL(ev.mintedUnits, wantMint);
        uint64_t createdUnits = 0;
        unsigned createdBatons = 0;
        for (size_t i = 0; i < ev.created.size(); i++) {
            if (ev.created[i].role == ROLE_TOKEN) createdUnits += ev.created[i].amount; else createdBatons++;
            // every token output sits where the layout put it, never on the ZCL change (the last output)
            BOOST_CHECK(ev.created[i].vout >= 1 && ev.created[i].vout < outs.size() - 1);
        }
        BOOST_CHECK_EQUAL(createdUnits, wantCreatedUnits);
        BOOST_CHECK_EQUAL(createdBatons, wantBatons);
        // exactly the intended token outputs would be spent, nothing else
        std::set<COutPoint> spentWant(ins.begin(), ins.end());
        for (size_t i = 0; i < ev.spent.size(); i++)
            BOOST_CHECK(spentWant.count(COutPoint(ev.spent[i].txid, ev.spent[i].vout)));
        BOOST_CHECK_EQUAL(ev.spent.size(), (spendsBaton ? 1u : 0u) + spentUtxos.size());
        // the dry run did not change the store
        { TxInfo pre; BOOST_CHECK(!c.idx.GetTx(tx.GetHash(), pre)); }

        c.Add(std::vector<CTransaction>(1, tx));
        nTx++;
        TxInfo ti;
        BOOST_REQUIRE(c.idx.GetTx(tx.GetHash(), ti));
        BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
        BOOST_CHECK_EQUAL(ti.burnedUnits, wantBurn);

        // model update
        if (want == 1) {
            nGenesis++;
            Tok t;
            t.id = tx.GetHash(); t.dec = genesisDec; t.baton = genesisBaton; t.supply = genesisQty; t.batonTag = (unsigned char)(nextTag + 1);
            Utxo u; u.op = COutPoint(tx.GetHash(), 1); u.units = genesisQty; u.tag = nextTag;
            t.utxos.push_back(u);
            if (genesisBaton) t.batonOp = COutPoint(tx.GetHash(), 2);
            toks.push_back(t);
        } else if (want == 2) {
            nMint++;
            Tok& tk = toks[tokIdx];
            tk.supply += wantMint;
            Utxo u; u.op = COutPoint(tx.GetHash(), 1); u.units = wantMint; u.tag = nextTag;
            tk.utxos.push_back(u);
            tk.baton = wantBatons > 0;
            if (tk.baton) tk.batonOp = COutPoint(tx.GetHash(), 2);
        } else {
            nSend++;
            Tok& tk = toks[tokIdx];
            std::set<COutPoint> gone;
            for (size_t i = 0; i < spentUtxos.size(); i++) gone.insert(spentUtxos[i].op);
            std::vector<Utxo> keep;
            for (size_t i = 0; i < tk.utxos.size(); i++) if (!gone.count(tk.utxos[i].op)) keep.push_back(tk.utxos[i]);
            tk.utxos = keep;
            tk.supply -= wantBurn;
            // the created outputs of the transaction itself (nonzero quantities)
            for (size_t i = 0; i < ev.created.size(); i++) {
                Utxo u; u.op = COutPoint(tx.GetHash(), ev.created[i].vout); u.units = ev.created[i].amount; u.tag = 0;
                tk.utxos.push_back(u);
            }
            // a send moves tokens; units the recipients did not take are burned only by BURN
            (void)sentTotal;
        }
        nextTag = (unsigned char)(nextTag + 7);
    }
    BOOST_CHECK(nTx >= 100);
    BOOST_TEST_MESSAGE(strprintf("%u transactions: %u GENESIS, %u MINT, %u SEND (%u of them BURN)", nTx, nGenesis, nMint, nSend, nBurn));

    // the store agrees with the model for every token: unspent units == supply, every modelled output is indexed
    for (size_t t = 0; t < toks.size(); t++) {
        uint64_t sum = 0;
        BOOST_REQUIRE(c.idx.SumUnspent(toks[t].id, sum));
        uint64_t model = 0;
        for (size_t i = 0; i < toks[t].utxos.size(); i++) {
            OutInfo oi;
            BOOST_REQUIRE_MESSAGE(c.idx.GetOutput(toks[t].utxos[i].op.hash, toks[t].utxos[i].op.n, oi), "a modelled output is not indexed");
            BOOST_CHECK_EQUAL(oi.amount, toks[t].utxos[i].units);
            model += toks[t].utxos[i].units;
        }
        BOOST_CHECK_EQUAL(sum, model);
        BOOST_CHECK_EQUAL(sum, toks[t].supply);
        TokenInfo ti;
        BOOST_REQUIRE(c.idx.GetToken(toks[t].id, ti));
        BOOST_CHECK_EQUAL(ti.hasBaton, toks[t].baton);
        BOOST_CHECK_EQUAL(ti.spentBurned, 0u); // the builder never burns by spending: every burn above was asked for
    }
}

// What the dry run says about transactions the wallet must never send.
BOOST_AUTO_TEST_CASE(evaluate_catches_what_would_burn_or_fail)
{
    Chain c;
    GenesisParams p;
    p.ticker = "TST"; p.name = "Test"; p.decimals = 0; p.quantity = 100; p.baton = true;
    TokenLayout gl;
    std::string err;
    BOOST_REQUIRE(LayoutGenesis(p, P2PKHTag(1), P2PKHTag(2), 546, gl, err));
    const CTransaction g = MakeTx(std::vector<COutPoint>(1, COutPoint(uint256S("77"), 0)), gl.vout);
    c.Add(std::vector<CTransaction>(1, g));
    const uint256 tok = g.GetHash();

    // an ordinary transaction that spends the token output: not a message, burns it all
    {
        const CTransaction t = MakeTx(std::vector<COutPoint>(1, COutPoint(tok, 1)), std::vector<CTxOut>(1, CTxOut(300, P2PKHTag(5))));
        Evaluation ev; std::string e;
        BOOST_REQUIRE(c.idx.EvaluateTx(t, ev, e));
        BOOST_CHECK(!ev.isSlp);
        BOOST_CHECK_EQUAL(ev.burnedUnits, 100u);
        BOOST_CHECK_EQUAL(ev.spent.size(), 1u);
    }
    // a SEND that names more than the inputs hold: invalid
    {
        std::vector<Recipient> to(1);
        to[0].script = P2PKHTag(5); to[0].units = 101;
        TokenLayout l;
        BOOST_CHECK(!LayoutSend(tok, to, 100, P2PKHTag(1), 546, l, err)); // the builder refuses it
        // forced through the raw builder: the rules still say invalid
        std::vector<uint64_t> q(1, 101);
        CScript m;
        BOOST_REQUIRE(BuildSendScript(tok, q, m, err));
        const CTransaction t = MakeTx(std::vector<COutPoint>(1, COutPoint(tok, 1)), {CTxOut(0, m), CTxOut(546, P2PKHTag(5))});
        Evaluation ev; std::string e;
        BOOST_REQUIRE(c.idx.EvaluateTx(t, ev, e));
        BOOST_CHECK(ev.isSlp && ev.status == STATUS_INVALID);
        BOOST_CHECK(ev.created.empty());
        BOOST_CHECK_EQUAL(ev.burnedUnits, 100u); // an invalid message burns what it spends
    }
    // a SEND of a token the inputs do not hold: invalid
    {
        std::vector<uint64_t> q(1, 5);
        CScript m;
        BOOST_REQUIRE(BuildSendScript(uint256S("abcd"), q, m, err));
        const CTransaction t = MakeTx(std::vector<COutPoint>(1, COutPoint(tok, 1)), {CTxOut(0, m), CTxOut(546, P2PKHTag(5))});
        Evaluation ev; std::string e;
        BOOST_REQUIRE(c.idx.EvaluateTx(t, ev, e));
        BOOST_CHECK(ev.isSlp && ev.status == STATUS_INVALID);
    }
    // spending the baton in a SEND: the baton is destroyed, the message still judged on its token inputs
    {
        std::vector<uint64_t> q(1, 100);
        CScript m;
        BOOST_REQUIRE(BuildSendScript(tok, q, m, err));
        const CTransaction t = MakeTx({COutPoint(tok, 1), COutPoint(tok, 2)}, {CTxOut(0, m), CTxOut(546, P2PKHTag(5))});
        Evaluation ev; std::string e;
        BOOST_REQUIRE(c.idx.EvaluateTx(t, ev, e));
        // the builder never selects a baton as a SEND input; if it did, EvaluateTx lists it among the spent outputs
        BOOST_CHECK_EQUAL(ev.spent.size(), 2u);
    }
    // a MINT without the baton: invalid
    {
        CScript m;
        BOOST_REQUIRE(BuildMintScript(tok, 10, true, m, err));
        const CTransaction t = MakeTx(std::vector<COutPoint>(1, COutPoint(uint256S("88"), 0)), {CTxOut(0, m), CTxOut(546, P2PKHTag(5)), CTxOut(546, P2PKHTag(6))});
        Evaluation ev; std::string e;
        BOOST_REQUIRE(c.idx.EvaluateTx(t, ev, e));
        BOOST_CHECK(ev.isSlp && ev.status == STATUS_INVALID);
    }
    // the evaluation changed nothing
    uint64_t sum = 0;
    BOOST_REQUIRE(c.idx.SumUnspent(tok, sum));
    BOOST_CHECK_EQUAL(sum, 100u);
    BOOST_CHECK_EQUAL(c.idx.GetStats().unspentOutputs, 2u);
}

BOOST_AUTO_TEST_SUITE_END()
