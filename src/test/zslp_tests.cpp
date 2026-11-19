// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// ZSLP token index: rules, undo, atomicity and arithmetic, on an in-memory store.
// The messages come from the vendored Z23 builders, so a parser/builder disagreement shows up here.

#include "zslp/zslpindex.h"
#include "zslp/zslpservice.h"

#include "data/zslp_mainnet.json.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "streams.h"
#include "version.h"
#include "script/script.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "tinyformat.h"
#include "utilstrencodings.h"

#include "c23/services/glue/zcl_slp_index.h"
#include "c23/services/glue/zcl_token_guard.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <set>
#include <univalue.h>

using namespace zslp;

namespace {

CScript Msg(const std::vector<unsigned char>& raw) { return CScript(raw.begin(), raw.end()); }

void Wire(const uint256& internal, unsigned char out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = internal.begin()[31 - i];
}

CScript P2PKH(unsigned char tag)
{
    std::vector<unsigned char> h(20, tag);
    return CScript() << OP_DUP << OP_HASH160 << h << OP_EQUALVERIFY << OP_CHECKSIG;
}

CScript GenesisMsg(uint64_t qty, unsigned baton, const char* ticker = "TST", unsigned decimals = 2)
{
    unsigned char buf[600];
    size_t n = zcl_token_guard_build_genesis(buf, sizeof(buf), ticker, "Test Token", "https://example.org", NULL, decimals, baton, qty);
    BOOST_REQUIRE(n > 0);
    return Msg(std::vector<unsigned char>(buf, buf + n));
}

CScript MintMsg(const uint256& token, uint64_t qty, unsigned baton)
{
    unsigned char id[32], buf[600];
    Wire(token, id);
    size_t n = zcl_token_guard_build_mint(buf, sizeof(buf), id, baton, qty);
    BOOST_REQUIRE(n > 0);
    return Msg(std::vector<unsigned char>(buf, buf + n));
}

CScript SendMsg(const uint256& token, std::vector<uint64_t> q)
{
    unsigned char id[32], buf[600];
    Wire(token, id);
    size_t n = zcl_token_guard_build_send(buf, sizeof(buf), id, &q[0], (int)q.size());
    BOOST_REQUIRE(n > 0);
    return Msg(std::vector<unsigned char>(buf, buf + n));
}

CTransaction Tx(const std::vector<COutPoint>& ins, const std::vector<CScript>& outs, int tag = 0)
{
    CMutableTransaction m;
    m.nVersion = 1;
    for (size_t i = 0; i < ins.size(); i++)
        m.vin.push_back(CTxIn(ins[i], CScript() << (tag + (int)i + 1), 0xffffffff));
    for (size_t i = 0; i < outs.size(); i++)
        m.vout.push_back(CTxOut(i == 0 && outs[i].size() && outs[i][0] == OP_RETURN ? 0 : 546, outs[i]));
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
    ZslpIndex idx;
    std::vector<uint256> hashes;
    Chain() : idx(&kv)
    {
        std::string err;
        BOOST_REQUIRE(idx.Load(err));
    }
    uint256 Add(const std::vector<CTransaction>& txs)
    {
        CBlock b;
        b.hashPrevBlock = hashes.empty() ? uint256() : hashes.back();
        b.vtx.push_back(Coinbase((int)hashes.size() + 1));
        for (size_t i = 0; i < txs.size(); i++)
            b.vtx.push_back(txs[i]);
        uint256 h = uint256S(strprintf("%x", 0x100000 + (unsigned)hashes.size()));
        std::string err;
        BOOST_REQUIRE_MESSAGE(idx.ApplyBlock(b, h, (int)hashes.size() + 1, true, err), err);
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
    uint64_t Bal(unsigned char tag, const uint256& token) const
    {
        std::string key(21, '\0');
        key[0] = ADDR_P2PKH;
        for (int i = 1; i < 21; i++)
            key[i] = (char)tag;
        std::vector<HolderBalance> v = idx.GetBalances(key);
        for (size_t i = 0; i < v.size(); i++)
            if (v[i].token == token)
                return v[i].amount;
        return 0;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(zslp_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(default_start_height)
{
    // BasicTestingSetup selects the main chain: a new index skips the 650,000 blocks before the first ZSLP message
    BOOST_CHECK_EQUAL(DefaultStartHeight(), 650000);
}

BOOST_AUTO_TEST_CASE(format_amount_is_exact)
{
    BOOST_CHECK_EQUAL(FormatAmount(0, 0), "0");
    BOOST_CHECK_EQUAL(FormatAmount(5, 3), "0.005");
    BOOST_CHECK_EQUAL(FormatAmount(12345, 2), "123.45");
    BOOST_CHECK_EQUAL(FormatAmount(100, 2), "1.00");
    BOOST_CHECK_EQUAL(FormatAmount(UINT64_MAX, 0), "18446744073709551615");
    BOOST_CHECK_EQUAL(FormatAmount(UINT64_MAX, 9), "18446744073.709551615");
    BOOST_CHECK_EQUAL(FormatAmount(9223372036854775808ULL, 9), "9223372036.854775808");
}

BOOST_AUTO_TEST_CASE(genesis_send_mint_flow)
{
    Chain c;
    // GENESIS: 1000 units to A, baton to B
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(1000, 2), P2PKH(0xa1), P2PKH(0xb1)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.ticker, "TST");
    BOOST_CHECK_EQUAL(t.decimals, 2u);
    BOOST_CHECK_EQUAL(t.minted, 1000u);
    BOOST_CHECK(t.hasBaton);
    BOOST_CHECK(t.batonTx == tok && t.batonVout == 2);
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 1000u);
    BOOST_CHECK_EQUAL(c.idx.GetStats().unspentOutputs, 2u);

    // SEND 600 to C, 300 back to A, 100 burned
    CTransaction s = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {600, 300}), P2PKH(0xc1), P2PKH(0xa1)});
    c.Add(std::vector<CTransaction>(1, s));
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 300u);
    BOOST_CHECK_EQUAL(c.Bal(0xc1, tok), 600u);
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.sendBurned, 100u);
    BOOST_CHECK_EQUAL(t.spentBurned, 0u);
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(s.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    BOOST_CHECK_EQUAL(ti.reason, "valid_send");
    BOOST_CHECK_EQUAL(ti.inputUnits, 1000u);
    BOOST_CHECK_EQUAL(ti.outputUnits, 900u);
    BOOST_CHECK_EQUAL(ti.burnedUnits, 100u);

    // MINT 50 more, baton moves to a new output
    CTransaction m = Tx({COutPoint(tok, 2)}, {MintMsg(tok, 50, 2), P2PKH(0xd1), P2PKH(0xd2)});
    c.Add(std::vector<CTransaction>(1, m));
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.minted, 1050u);
    BOOST_CHECK(t.hasBaton && t.batonTx == m.GetHash());
    BOOST_CHECK_EQUAL(c.Bal(0xd1, tok), 50u);

    // the token's transactions, oldest first, and the per-type counters
    std::vector<TxRef> refs = c.idx.ListTokenTransactions(tok, 0, 100);
    BOOST_REQUIRE_EQUAL(refs.size(), 3u);
    BOOST_CHECK(refs[0].txid == tok && refs[0].type == 1 && refs[0].status == STATUS_VALID);
    BOOST_CHECK(refs[1].txid == s.GetHash() && refs[1].type == 3);
    BOOST_CHECK(refs[2].txid == m.GetHash() && refs[2].type == 2);
    BOOST_CHECK_EQUAL(c.idx.ListTokenTransactions(tok, 1, 1).size(), 1u);
    IndexStats st = c.idx.GetStats();
    BOOST_CHECK_EQUAL(st.nGenesis, 1u);
    BOOST_CHECK_EQUAL(st.nSend, 1u);
    BOOST_CHECK_EQUAL(st.nMint, 1u);
    BOOST_CHECK_EQUAL(st.txValid, 3u);

    // invariant: unspent == minted - burned, and the holders list sums to it
    uint64_t sum = 0;
    BOOST_CHECK(c.idx.SumUnspent(tok, sum));
    BOOST_CHECK_EQUAL(sum, t.minted - t.sendBurned - t.spentBurned);
    BOOST_CHECK_EQUAL(sum, 950u);
}

BOOST_AUTO_TEST_CASE(invalid_sends_burn_their_inputs)
{
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(100, 0), P2PKH(0xa1)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));

    // over-spend: outputs exceed inputs
    CTransaction over = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {101}), P2PKH(0xb1)});
    c.Add(std::vector<CTransaction>(1, over));
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(over.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "send_output_exceeds_input");
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 0u);
    BOOST_CHECK_EQUAL(c.Bal(0xb1, tok), 0u);
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.spentBurned, 100u);
    uint64_t sum = 1;
    BOOST_CHECK(c.idx.SumUnspent(tok, sum));
    BOOST_CHECK_EQUAL(sum, 0u);
}

BOOST_AUTO_TEST_CASE(wrong_token_and_mixed_inputs)
{
    Chain c;
    CTransaction ga = Tx(std::vector<COutPoint>(), {GenesisMsg(100, 0, "AAA"), P2PKH(0xa1)});
    CTransaction gb = Tx(std::vector<COutPoint>(), {GenesisMsg(200, 0, "BBB"), P2PKH(0xa2)}, 10);
    const uint256 A = ga.GetHash(), B = gb.GetHash();
    std::vector<CTransaction> v;
    v.push_back(ga); v.push_back(gb);
    c.Add(v);

    // SEND names token B but spends only an A output: no B inputs at all
    CTransaction wrong = Tx({COutPoint(A, 1)}, {SendMsg(B, {100}), P2PKH(0xb1)});
    c.Add(std::vector<CTransaction>(1, wrong));
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(wrong.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "send_ancestry_invalid");
    BOOST_CHECK_EQUAL(c.Bal(0xb1, B), 0u);

    // SEND of B spending B and A outputs together: mixed
    CTransaction mixed = Tx({COutPoint(B, 1), COutPoint(wrong.GetHash(), 1)}, {SendMsg(B, {200}), P2PKH(0xb2)}, 20);
    c.Add(std::vector<CTransaction>(1, mixed));
    BOOST_REQUIRE(c.idx.GetTx(mixed.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(c.Bal(0xb2, B), 0u);
    TokenInfo tb;
    BOOST_REQUIRE(c.idx.GetToken(B, tb));
    BOOST_CHECK_EQUAL(tb.spentBurned, 200u);
}

BOOST_AUTO_TEST_CASE(ordinary_spend_burns)
{
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(100, 2), P2PKH(0xa1), P2PKH(0xa2)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    // spends the token output and the baton in an ordinary transaction
    CTransaction burn = Tx({COutPoint(tok, 1), COutPoint(tok, 2)}, {P2PKH(0xee)});
    c.Add(std::vector<CTransaction>(1, burn));
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(burn.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.type, 0);
    BOOST_CHECK_EQUAL(ti.burnedUnits, 100u);
    BOOST_CHECK_EQUAL(ti.inputs.size(), 2u);
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK(!t.hasBaton);
    BOOST_CHECK_EQUAL(t.spentBurned, 100u);
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 0u);
    BOOST_CHECK_EQUAL(c.idx.GetStats().unspentOutputs, 0u);
    BOOST_CHECK_EQUAL(c.idx.GetStats().txBurn, 1u);
    // the burn is part of the token's history
    std::vector<TxRef> refs = c.idx.ListTokenTransactions(tok, 0, 10);
    BOOST_REQUIRE_EQUAL(refs.size(), 2u);
    BOOST_CHECK(refs[0].type == 1 && refs[1].type == 0 && refs[1].txid == burn.GetHash());
    // the baton is gone: a MINT now has no baton input
    CTransaction mint = Tx({COutPoint(burn.GetHash(), 0)}, {MintMsg(tok, 5, 0), P2PKH(0xa3)}, 5);
    c.Add(std::vector<CTransaction>(1, mint));
    BOOST_REQUIRE(c.idx.GetTx(mint.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "mint_baton_lineage_invalid");
}

BOOST_AUTO_TEST_CASE(zero_quantity)
{
    Chain c;
    // GENESIS of zero units with a baton and no token output
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(0, 2), P2PKH(0xa1), P2PKH(0xa2)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.minted, 0u);
    BOOST_CHECK(t.hasBaton);
    OutInfo o;
    BOOST_CHECK(!c.idx.GetOutput(tok, 1, o)); // nothing minted: vout 1 carries nothing
    BOOST_CHECK(c.idx.GetOutput(tok, 2, o) && o.role == ROLE_BATON);
    // MINT 500 then SEND with a zero slot: zero slots create no output
    CTransaction m = Tx({COutPoint(tok, 2)}, {MintMsg(tok, 500, 2), P2PKH(0xb1), P2PKH(0xb2)});
    c.Add(std::vector<CTransaction>(1, m));
    CTransaction s = Tx({COutPoint(m.GetHash(), 1)}, {SendMsg(tok, {0, 500}), P2PKH(0xc1), P2PKH(0xc2)});
    c.Add(std::vector<CTransaction>(1, s));
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(s.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    BOOST_CHECK(!c.idx.GetOutput(s.GetHash(), 1, o));
    BOOST_CHECK_EQUAL(c.Bal(0xc2, tok), 500u);
    BOOST_CHECK_EQUAL(c.Bal(0xc1, tok), 0u);
    // a SEND whose total is zero needs token inputs: it has none
    CTransaction z = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {0}), P2PKH(0xd1)}, 7);
    c.Add(std::vector<CTransaction>(1, z));
    BOOST_REQUIRE(c.idx.GetTx(z.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
}

BOOST_AUTO_TEST_CASE(quantities_at_and_above_2_63)
{
    Chain c;
    const uint64_t big = 9223372036854775808ULL; // 2^63
    // GENESIS above INT64_MAX: UNKNOWN, no token, no outputs
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(big, 2), P2PKH(0xa1), P2PKH(0xa2)});
    c.Add(std::vector<CTransaction>(1, g));
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(g.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_UNKNOWN);
    BOOST_CHECK_EQUAL(ti.reason, "quantity_unrepresentable");
    TokenInfo t;
    BOOST_CHECK(!c.idx.GetToken(g.GetHash(), t));
    BOOST_CHECK_EQUAL(c.idx.GetStats().unspentOutputs, 0u);
    // a SEND naming that token: the parent is UNKNOWN, so the child is UNKNOWN (not INVALID)
    CTransaction s = Tx({COutPoint(g.GetHash(), 1)}, {SendMsg(g.GetHash(), {1}), P2PKH(0xb1)}, 3);
    c.Add(std::vector<CTransaction>(1, s));
    BOOST_REQUIRE(c.idx.GetTx(s.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_UNKNOWN);

    // INT64_MAX itself is representable
    CTransaction g2 = Tx(std::vector<COutPoint>(), {GenesisMsg(9223372036854775807ULL, 0, "MAX"), P2PKH(0xa3)}, 9);
    c.Add(std::vector<CTransaction>(1, g2));
    BOOST_REQUIRE(c.idx.GetToken(g2.GetHash(), t));
    BOOST_CHECK_EQUAL(t.minted, 9223372036854775807ULL);
    // splitting it exactly is valid; the outputs sum to INT64_MAX
    CTransaction s2 = Tx({COutPoint(g2.GetHash(), 1)},
                         {SendMsg(g2.GetHash(), {9223372036854775800ULL, 7}), P2PKH(0xb2), P2PKH(0xb3)}, 11);
    c.Add(std::vector<CTransaction>(1, s2));
    BOOST_REQUIRE(c.idx.GetTx(s2.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    BOOST_CHECK_EQUAL(c.Bal(0xb2, g2.GetHash()), 9223372036854775800ULL);
    BOOST_CHECK_EQUAL(c.Bal(0xb3, g2.GetHash()), 7u);
    // a SEND whose outputs sum above INT64_MAX is UNKNOWN; one that overflows uint64 is INVALID
    CTransaction s3 = Tx({COutPoint(s2.GetHash(), 1)}, {SendMsg(g2.GetHash(), {big, 1}), P2PKH(0xb4), P2PKH(0xb5)}, 13);
    c.Add(std::vector<CTransaction>(1, s3));
    BOOST_REQUIRE(c.idx.GetTx(s3.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_UNKNOWN);
    CTransaction s4 = Tx({COutPoint(s2.GetHash(), 2)}, {SendMsg(g2.GetHash(), {UINT64_MAX, 1}), P2PKH(0xb6), P2PKH(0xb7)}, 15);
    c.Add(std::vector<CTransaction>(1, s4));
    BOOST_REQUIRE(c.idx.GetTx(s4.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "output_quantity_overflow");
}

BOOST_AUTO_TEST_CASE(mint_rules)
{
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(10, 2), P2PKH(0xa1), P2PKH(0xa2)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    TxInfo ti;
    // a MINT without the baton input (spends the token output instead)
    CTransaction nob = Tx({COutPoint(tok, 1)}, {MintMsg(tok, 5, 0), P2PKH(0xb1)});
    c.Add(std::vector<CTransaction>(1, nob));
    BOOST_REQUIRE(c.idx.GetTx(nob.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "mint_baton_lineage_invalid");
    // a MINT that ends the baton (no baton output): valid, token has no baton afterwards
    CTransaction last = Tx({COutPoint(tok, 2)}, {MintMsg(tok, 5, 0), P2PKH(0xb2)}, 4);
    c.Add(std::vector<CTransaction>(1, last));
    BOOST_REQUIRE(c.idx.GetTx(last.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK(!t.hasBaton);
    BOOST_CHECK_EQUAL(t.minted, 15u);
}

BOOST_AUTO_TEST_CASE(same_block_chain_of_spends)
{
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(100, 0), P2PKH(0xa1)});
    const uint256 tok = g.GetHash();
    CTransaction s1 = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {100}), P2PKH(0xb1)});
    CTransaction s2 = Tx({COutPoint(s1.GetHash(), 1)}, {SendMsg(tok, {60, 40}), P2PKH(0xc1), P2PKH(0xc2)}, 8);
    std::vector<CTransaction> v;
    v.push_back(g); v.push_back(s1); v.push_back(s2);
    c.Add(v); // one block
    BOOST_CHECK_EQUAL(c.Bal(0xc1, tok), 60u);
    BOOST_CHECK_EQUAL(c.Bal(0xc2, tok), 40u);
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 0u);
    BOOST_CHECK_EQUAL(c.Bal(0xb1, tok), 0u);
}

BOOST_AUTO_TEST_CASE(disconnect_restores_the_exact_state)
{
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(1000, 2), P2PKH(0xa1), P2PKH(0xb1)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    const std::map<std::string, std::string> afterGenesis = c.kv.m;

    CTransaction s = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {400, 500}), P2PKH(0xc1), P2PKH(0xc2)});
    c.Add(std::vector<CTransaction>(1, s));
    const std::map<std::string, std::string> afterSend = c.kv.m;
    CTransaction burn = Tx({COutPoint(s.GetHash(), 1), COutPoint(tok, 2)}, {P2PKH(0xee)}, 6);
    CTransaction g2 = Tx(std::vector<COutPoint>(), {GenesisMsg(7, 0, "TWO"), P2PKH(0xd1)}, 12);
    std::vector<CTransaction> v;
    v.push_back(burn); v.push_back(g2);
    c.Add(v);
    BOOST_CHECK(c.kv.m != afterSend);

    // a reorg that removes the burn block, then the SEND block, then the GENESIS block
    c.Pop();
    BOOST_CHECK(c.kv.m == afterSend);
    c.Pop();
    BOOST_CHECK(c.kv.m == afterGenesis);
    c.Pop();
    // back to the empty store: only the format version and the best pointer (to the null block) remain
    std::map<std::string, std::string>::const_iterator it = c.kv.m.begin();
    for (; it != c.kv.m.end(); ++it)
        BOOST_CHECK_MESSAGE(it->first == "mver" || it->first == "mbest", "leftover key " + HexStr(it->first));
    TokenInfo t;
    BOOST_CHECK(!c.idx.GetToken(tok, t));

    // and the same blocks apply again to the same result
    c.Add(std::vector<CTransaction>(1, g));
    BOOST_CHECK(c.kv.m == afterGenesis);
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 1000u);
}

BOOST_AUTO_TEST_CASE(reset_forgets_everything_and_the_blocks_apply_again)
{
    // An index whose tip is on no chain this node knows is wiped and rebuilt (ZslpService::Step).
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(1000, 2), P2PKH(0xa1), P2PKH(0xb1)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    const std::map<std::string, std::string> afterGenesis = c.kv.m;
    CTransaction s = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {400, 500}), P2PKH(0xc1), P2PKH(0xc2)});
    c.Add(std::vector<CTransaction>(1, s));
    uint256 best;
    int height = -1;
    BOOST_REQUIRE(c.idx.GetBest(best, height));

    std::string err;
    BOOST_REQUIRE_MESSAGE(c.idx.Reset(err), err);
    BOOST_CHECK(!c.idx.GetBest(best, height));
    BOOST_CHECK_EQUAL(c.kv.m.size(), 1u);
    BOOST_CHECK(c.kv.m.count("mver") == 1);
    TokenInfo t;
    BOOST_CHECK(!c.idx.GetToken(tok, t));
    BOOST_CHECK(c.idx.Reset(err)); // an empty index resets too
    BOOST_CHECK(c.idx.Load(err));

    // the chain is applied again from the start and gives the same store as before
    c.hashes.clear();
    c.Add(std::vector<CTransaction>(1, g));
    BOOST_CHECK(c.kv.m == afterGenesis);
}


BOOST_AUTO_TEST_CASE(a_block_is_one_atomic_batch)
{
    Chain c;
    const size_t before = c.kv.nBatches;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(1000, 2), P2PKH(0xa1), P2PKH(0xb1)});
    CTransaction s = Tx({COutPoint(g.GetHash(), 1)}, {SendMsg(g.GetHash(), {400, 600}), P2PKH(0xc1), P2PKH(0xc2)});
    std::vector<CTransaction> v;
    v.push_back(g); v.push_back(s);
    c.Add(v);
    BOOST_CHECK_EQUAL(c.kv.nBatches, before + 1);

    // a block that does not extend the tip is refused and writes nothing
    CBlock bad;
    bad.hashPrevBlock = uint256S("deadbeef");
    bad.vtx.push_back(Coinbase(9));
    const std::map<std::string, std::string> snap = c.kv.m;
    std::string err;
    BOOST_CHECK(!c.idx.ApplyBlock(bad, uint256S("01"), 9, true, err));
    BOOST_CHECK(c.kv.m == snap);
    // only the tip can be disconnected
    BOOST_CHECK(!c.idx.DisconnectBlock(uint256S("02"), uint256(), 0, err));
    BOOST_CHECK(c.kv.m == snap);
}

BOOST_AUTO_TEST_CASE(holders_and_balances_agree)
{
    Chain c;
    CTransaction g = Tx(std::vector<COutPoint>(), {GenesisMsg(90, 0), P2PKH(0xa1)});
    const uint256 tok = g.GetHash();
    c.Add(std::vector<CTransaction>(1, g));
    CTransaction s = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {10, 20, 30}), P2PKH(0xb1), P2PKH(0xb2), P2PKH(0xb3)});
    c.Add(std::vector<CTransaction>(1, s));
    std::vector<HolderBalance> h = c.idx.GetHolders(tok, 0, 100);
    BOOST_CHECK_EQUAL(h.size(), 3u);
    uint64_t sum = 0;
    for (size_t i = 0; i < h.size(); i++)
        sum += h[i].amount;
    BOOST_CHECK_EQUAL(sum, 60u);
    BOOST_CHECK_EQUAL(c.idx.GetHolders(tok, 1, 1).size(), 1u);
    BOOST_CHECK_EQUAL(c.idx.ListTokens(0, 10).size(), 1u);
    BOOST_CHECK_EQUAL(c.idx.ListTokens(1, 10).size(), 0u);
}

// Real mainnet transactions (src/test/data/zslp_mainnet.json, made by qa/zslp/make_fixtures.sh from
// a full-chain run): parsed from their raw bytes, applied in chain order, and every transaction's
// validity and reason, every token's supply and every holder must match what the index answered on the chain.
BOOST_AUTO_TEST_CASE(mainnet_fixtures)
{
    UniValue root;
    BOOST_REQUIRE(root.read(std::string(json_tests::zslp_mainnet, json_tests::zslp_mainnet + sizeof(json_tests::zslp_mainnet))));
    const UniValue& tokens = root["tokens"].get_array();
    BOOST_REQUIRE(tokens.size() > 0);

    struct Row { int height, pos; std::string txid, hex, validity, reason, type; };
    std::map<std::string, Row> uniq;
    for (size_t i = 0; i < tokens.size(); i++) {
        const UniValue& txs = tokens[i]["txs"].get_array();
        for (size_t k = 0; k < txs.size(); k++) {
            Row r;
            r.height = txs[k]["height"].get_int();
            r.pos = txs[k]["pos"].get_int();
            r.txid = txs[k]["txid"].get_str();
            r.hex = txs[k]["hex"].get_str();
            r.validity = txs[k]["validity"].get_str();
            r.reason = txs[k]["reason"].get_str();
            r.type = txs[k]["type"].get_str();
            uniq[r.txid] = r;
        }
    }
    std::map<int, std::map<int, Row> > byHeight;
    for (std::map<std::string, Row>::const_iterator it = uniq.begin(); it != uniq.end(); ++it)
        byHeight[it->second.height][it->second.pos] = it->second;

    MemKV kv;
    ZslpIndex idx(&kv);
    std::string err;
    BOOST_REQUIRE(idx.Load(err));
    uint256 prev;
    unsigned nBlocks = 0;
    for (std::map<int, std::map<int, Row> >::const_iterator hb = byHeight.begin(); hb != byHeight.end(); ++hb) {
        CBlock b;
        b.hashPrevBlock = prev;
        for (std::map<int, Row>::const_iterator rb = hb->second.begin(); rb != hb->second.end(); ++rb) {
            CTransaction tx;
            CDataStream ss(ParseHex(rb->second.hex), SER_NETWORK, PROTOCOL_VERSION);
            ss >> tx;
            BOOST_REQUIRE_EQUAL(tx.GetHash().GetHex(), rb->second.txid);
            b.vtx.push_back(tx);
        }
        uint256 h = uint256S(strprintf("%x", 0x200000 + ++nBlocks));
        BOOST_REQUIRE_MESSAGE(idx.ApplyBlock(b, h, hb->first, true, err), err);
        prev = h;
    }

    for (std::map<std::string, Row>::const_iterator it = uniq.begin(); it != uniq.end(); ++it) {
        TxInfo ti;
        BOOST_REQUIRE_MESSAGE(idx.GetTx(uint256S(it->first), ti), "no record of " + it->first);
        const std::string validity = ti.type == 0 ? "burn" : ti.status == STATUS_VALID ? "valid" : ti.status == STATUS_INVALID ? "invalid" : "unknown";
        BOOST_CHECK_MESSAGE(validity == it->second.validity && ti.reason == it->second.reason,
                            it->first << ": " << validity << "/" << ti.reason << " expected " << it->second.validity << "/" << it->second.reason);
    }
    for (size_t i = 0; i < tokens.size(); i++) {
        const UniValue& tj = tokens[i];
        TokenInfo t;
        const uint256 id = uint256S(tj["tokenid"].get_str());
        if (tj["token"].isNull()) {
            BOOST_CHECK(!idx.GetToken(id, t));
            continue;
        }
        BOOST_REQUIRE_MESSAGE(idx.GetToken(id, t), "no token " + tj["tokenid"].get_str());
        const UniValue& e = tj["token"];
        const unsigned dec = (unsigned)e["decimals"].get_int();
        BOOST_CHECK_EQUAL(t.decimals, dec);
        BOOST_CHECK_EQUAL(FormatAmount(t.minted, dec), e["totalminted"].get_str());
        BOOST_CHECK_EQUAL(FormatAmount(t.sendBurned, dec), e["burnedinsends"].get_str());
        BOOST_CHECK_EQUAL(FormatAmount(t.spentBurned, dec), e["burnedbyspending"].get_str());
        BOOST_CHECK_EQUAL(FormatAmount(t.minted - t.sendBurned - t.spentBurned, dec), e["circulating"].get_str());
        BOOST_CHECK_EQUAL(t.hasBaton, !e["mintbaton"].isNull());
        // the holders: every address and amount
        const UniValue& holders = tj["holders"].get_array();
        std::vector<HolderBalance> got = idx.GetHolders(id, 0, 100000);
        BOOST_CHECK_EQUAL(got.size(), holders.size());
        for (size_t k = 0; k < holders.size(); k++) {
            const std::string addr = holders[k]["address"].get_str();
            bool found = false;
            for (size_t m = 0; m < got.size(); m++)
                if (AddrKeyToString(got[m].addr) == addr) {
                    found = true;
                    BOOST_CHECK_EQUAL(FormatAmount(got[m].amount, dec), holders[k]["amount"].get_str());
                }
            BOOST_CHECK_MESSAGE(found, "holder " + addr + " missing");
        }
    }
}


// ---- independent review: adversarial cases and a randomised reorg check --------------------------

namespace {
const std::vector<COutPoint> kNoInputs;
std::vector<CTransaction> One(const CTransaction& tx) { return std::vector<CTransaction>(1, tx); }
}

// A holder can own more than 2^64-1 units of a token whose supply overflowed (three MINTs of 2^63-1 to one
// address). Spending those outputs must neither stop the index (a saturated 64-bit balance used to underflow
// here) nor leave a wrong balance behind, and every block must still disconnect.
BOOST_AUTO_TEST_CASE(review_holder_balance_above_2_64)
{
    Chain c;
    const uint64_t max = 9223372036854775807ULL;
    CTransaction g = Tx(kNoInputs, {GenesisMsg(max, 2, "BIG", 0), P2PKH(0xa1), P2PKH(0xa2)});
    const uint256 tok = g.GetHash();
    c.Add(One(g));
    const std::map<std::string, std::string> afterGenesis = c.kv.m;
    CTransaction m1 = Tx({COutPoint(tok, 2)}, {MintMsg(tok, max, 2), P2PKH(0xa1), P2PKH(0xa2)}, 20);
    c.Add(One(m1));
    CTransaction m2 = Tx({COutPoint(m1.GetHash(), 2)}, {MintMsg(tok, max, 2), P2PKH(0xa1), P2PKH(0xa2)}, 40);
    c.Add(One(m2));
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK(t.supplyOverflow);
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), UINT64_MAX); // shown saturated: 3 * (2^63-1) does not fit
    uint64_t sum = 0;
    BOOST_CHECK(!c.idx.SumUnspent(tok, sum));          // and the sum says it does not fit
    c.Add(One(Tx({COutPoint(tok, 1)}, {P2PKH(0xee)}, 60)));
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), UINT64_MAX - 1); // 2 * (2^63-1), exact
    c.Add(One(Tx({COutPoint(m1.GetHash(), 1)}, {P2PKH(0xee)}, 61)));
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), max);
    c.Add(One(Tx({COutPoint(m2.GetHash(), 1)}, {P2PKH(0xee)}, 62)));
    BOOST_CHECK_EQUAL(c.Bal(0xa1, tok), 0u);
    BOOST_CHECK(c.idx.GetHolders(tok, 0, 10).empty());
    for (int i = 0; i < 5; i++)
        c.Pop();
    BOOST_CHECK(c.kv.m == afterGenesis);
}

// Z23 (zslp_validity.c, ZSLP_VALIDITY_MAX_INPUTS) does not judge an SLP transaction with more than 4096
// inputs: it is UNKNOWN "input_limit_exceeded". 4096 inputs are still judged.
BOOST_AUTO_TEST_CASE(review_input_limit_matches_z23)
{
    Chain c;
    CTransaction g = Tx(kNoInputs, {GenesisMsg(100, 0), P2PKH(0xa1), P2PKH(0xa2)});
    const uint256 tok = g.GetHash();
    CTransaction split = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {50, 50}), P2PKH(0xa1), P2PKH(0xa2)}, 3);
    std::vector<CTransaction> v;
    v.push_back(g); v.push_back(split);
    c.Add(v);
    std::vector<COutPoint> at(1, COutPoint(split.GetHash(), 1)), over(1, COutPoint(split.GetHash(), 2));
    for (int i = 0; i < 4095; i++)
        at.push_back(COutPoint(uint256S(strprintf("%x", 0x700000 + i)), 0));
    for (int i = 0; i < 4096; i++)
        over.push_back(COutPoint(uint256S(strprintf("%x", 0x800000 + i)), 0));
    CTransaction sAt = Tx(at, {SendMsg(tok, {50}), P2PKH(0xb1)}, 100000);
    CTransaction sOver = Tx(over, {SendMsg(tok, {50}), P2PKH(0xb2)}, 200000);
    BOOST_REQUIRE_EQUAL(sAt.vin.size(), 4096u);
    BOOST_REQUIRE_EQUAL(sOver.vin.size(), 4097u);
    v.clear();
    v.push_back(sAt); v.push_back(sOver);
    c.Add(v);
    TxInfo ti;
    BOOST_REQUIRE(c.idx.GetTx(sAt.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    BOOST_REQUIRE(c.idx.GetTx(sOver.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_UNKNOWN);
    BOOST_CHECK_EQUAL(ti.reason, "input_limit_exceeded");
    BOOST_CHECK_EQUAL(c.Bal(0xb1, tok), 50u);
    BOOST_CHECK_EQUAL(c.Bal(0xb2, tok), 0u);
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.spentBurned, 50u); // the UNKNOWN transaction carries nothing: its token input is burned
}

// Z23's rules on adversarial SENDs, MINTs and batons, case by case.
BOOST_AUTO_TEST_CASE(review_adversarial_rules)
{
    Chain c;
    CTransaction g = Tx(kNoInputs, {GenesisMsg(100, 2), P2PKH(0xa1), P2PKH(0xa2)});
    const uint256 tok = g.GetHash();
    CTransaction g2 = Tx(kNoInputs, {GenesisMsg(9, 0, "OTH"), P2PKH(0xa3)}, 5);
    const uint256 oth = g2.GetHash();
    CTransaction split = Tx({COutPoint(tok, 1)}, {SendMsg(tok, {60, 40}), P2PKH(0xa1), P2PKH(0xa1)}, 7);
    std::vector<CTransaction> v;
    v.push_back(g); v.push_back(g2); v.push_back(split);
    c.Add(v);
    TxInfo ti;

    // over-spend across two inputs: 60 + 40 = 100 < 101
    CTransaction over = Tx({COutPoint(split.GetHash(), 1), COutPoint(split.GetHash(), 2)},
                           {SendMsg(tok, {51, 50}), P2PKH(0xb1), P2PKH(0xb2)}, 9);
    c.Add(One(over));
    BOOST_REQUIRE(c.idx.GetTx(over.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "send_output_exceeds_input");
    BOOST_CHECK_EQUAL(ti.inputUnits, 100u);
    c.Pop();
    // the exact amount across two inputs is valid
    CTransaction exact = Tx({COutPoint(split.GetHash(), 1), COutPoint(split.GetHash(), 2)},
                            {SendMsg(tok, {50, 50}), P2PKH(0xb1), P2PKH(0xb2)}, 11);
    c.Add(One(exact));
    BOOST_REQUIRE(c.idx.GetTx(exact.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    c.Pop();
    // mixed token inputs: invalid, and BOTH tokens' inputs burn
    CTransaction mixed = Tx({COutPoint(split.GetHash(), 1), COutPoint(oth, 1)},
                            {SendMsg(tok, {60}), P2PKH(0xb1)}, 13);
    c.Add(One(mixed));
    BOOST_REQUIRE(c.idx.GetTx(mixed.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "mixed_token_inputs");
    TokenInfo t;
    BOOST_REQUIRE(c.idx.GetToken(oth, t));
    BOOST_CHECK_EQUAL(t.spentBurned, 9u);
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK_EQUAL(t.spentBurned, 60u);
    c.Pop();
    // a valid SEND that also spends the baton: the baton is destroyed, the tokens move
    CTransaction withBaton = Tx({COutPoint(split.GetHash(), 1), COutPoint(tok, 2)},
                                {SendMsg(tok, {60}), P2PKH(0xb1)}, 15);
    c.Add(One(withBaton));
    BOOST_REQUIRE(c.idx.GetTx(withBaton.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK(!t.hasBaton);
    BOOST_CHECK_EQUAL(c.Bal(0xb1, tok), 60u);
    c.Pop();
    // a SEND with only the baton as input has no token input
    CTransaction batonOnly = Tx({COutPoint(tok, 2)}, {SendMsg(tok, {1}), P2PKH(0xb1)}, 17);
    c.Add(One(batonOnly));
    BOOST_REQUIRE(c.idx.GetTx(batonOnly.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "send_ancestry_invalid");
    c.Pop();
    // a MINT of the other token's id with this token's baton: no baton of the target token
    CTransaction wrongMint = Tx({COutPoint(tok, 2)}, {MintMsg(oth, 5, 2), P2PKH(0xb1), P2PKH(0xb2)}, 19);
    c.Add(One(wrongMint));
    BOOST_REQUIRE(c.idx.GetTx(wrongMint.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "mint_baton_lineage_invalid");
    BOOST_REQUIRE(c.idx.GetToken(tok, t));
    BOOST_CHECK(!t.hasBaton); // spending it in a non-MINT of its token ends it
    c.Pop();
    // Z23 rule: one input whose parent is an INVALID transaction of the same token makes the SEND invalid,
    // even next to a good token input (stricter than "invalid inputs count zero")
    CTransaction bad = Tx({COutPoint(split.GetHash(), 2)}, {SendMsg(tok, {41}), P2PKH(0xc1), P2PKH(0xc2)}, 21);
    c.Add(One(bad));
    BOOST_REQUIRE(c.idx.GetTx(bad.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    CTransaction child = Tx({COutPoint(split.GetHash(), 1), COutPoint(bad.GetHash(), 2)},
                            {SendMsg(tok, {60}), P2PKH(0xc3)}, 23);
    c.Add(One(child));
    BOOST_REQUIRE(c.idx.GetTx(child.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "send_ancestry_invalid");
    c.Pop();
    c.Pop();
    // a SEND naming a vout the transaction does not have
    CTransaction missing = Tx({COutPoint(split.GetHash(), 1)}, {SendMsg(tok, {30, 30}), P2PKH(0xb1)}, 25);
    c.Add(One(missing));
    BOOST_REQUIRE(c.idx.GetTx(missing.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_INVALID);
    BOOST_CHECK_EQUAL(ti.reason, "send_output_missing");
    c.Pop();
    // a zero slot may name a vout that does not exist
    CTransaction zeroSlot = Tx({COutPoint(split.GetHash(), 1)}, {SendMsg(tok, {60, 0}), P2PKH(0xb1)}, 27);
    c.Add(One(zeroSlot));
    BOOST_REQUIRE(c.idx.GetTx(zeroSlot.GetHash(), ti));
    BOOST_CHECK_EQUAL(ti.status, STATUS_VALID);
    c.Pop();
}

// Which output carries the message: the FIRST OP_RETURN output, wherever it is, as Z23.s ledger reads it
// (explorer_index.c index_op_return) and as the wallet token guard reads it (tokenguard.cpp, reading B).
// The SLP Token Type 1 spec puts the message at vout[0] only. This pins the current choice.
BOOST_AUTO_TEST_CASE(review_message_position)
{
    Chain c;
    CTransaction g = Tx(kNoInputs, {GenesisMsg(10, 0), P2PKH(0xa1)});
    c.Add(One(g));
    // message at vout[1] after a P2PKH vout[0]: indexed (tokens go to vout 1 = the OP_RETURN itself)
    CTransaction late = Tx(kNoInputs, {P2PKH(0xa2), GenesisMsg(5, 0, "LATE"), P2PKH(0xa3)}, 31);
    // a non-SLP OP_RETURN first, then an SLP one: not indexed
    CTransaction second = Tx(kNoInputs, {CScript() << OP_RETURN << std::vector<unsigned char>(4, 0x41),
                                         GenesisMsg(5, 0, "SEC"), P2PKH(0xa4)}, 33);
    std::vector<CTransaction> v;
    v.push_back(late); v.push_back(second);
    c.Add(v);
    TxInfo ti;
    BOOST_CHECK(c.idx.GetTx(late.GetHash(), ti));
    BOOST_CHECK(!c.idx.GetTx(second.GetHash(), ti));
}

// Random connect/disconnect sequences: after every disconnect the store equals the snapshot taken when
// that height was the tip, and at the end it equals a from-scratch build of the surviving chain.
BOOST_AUTO_TEST_CASE(review_random_reorgs_equal_rebuild)
{
    uint64_t rng = 0x9e3779b97f4a7c15ULL;
    auto rnd = [&rng](uint64_t n) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        return n ? rng % n : 0;
    };
    int tagSeq = 1000;
    uint64_t nValid = 0, nInvalid = 0, nUnknown = 0, nBurn = 0;
    std::map<uint256, uint256> tokOf; // txid -> the token its message names (generator hint only)
    for (int round = 0; round < 20; round++) {
        Chain c;
        std::vector<std::vector<CTransaction> > blocks;     // the current branch
        std::vector<std::map<std::string, std::string> > snaps; // store after each block
        for (int step = 0; step < 150; step++) {
            if (!blocks.empty() && rnd(10) < 3) {
                const size_t k = 1 + rnd(std::min<size_t>(4, blocks.size()));
                for (size_t i = 0; i < k; i++) {
                    c.Pop();
                    blocks.pop_back();
                    snaps.pop_back();
                    if (!snaps.empty())
                        BOOST_REQUIRE(c.kv.m == snaps.back());
                }
                continue;
            }
            // outputs and tokens of the current branch
            std::vector<COutPoint> pool;
            std::vector<uint256> toks;
            std::set<COutPoint> spent;
            for (size_t b = 0; b < blocks.size(); b++)
                for (size_t t = 0; t < blocks[b].size(); t++) {
                    const CTransaction& tx = blocks[b][t];
                    for (size_t i = 0; i < tx.vin.size(); i++)
                        spent.insert(tx.vin[i].prevout);
                    for (size_t i = 1; i < tx.vout.size(); i++)
                        pool.push_back(COutPoint(tx.GetHash(), i));
                    if (tokOf.count(tx.GetHash()) && tokOf[tx.GetHash()] == tx.GetHash())
                        toks.push_back(tx.GetHash());
                }
            std::vector<COutPoint> unspent;
            for (size_t i = 0; i < pool.size(); i++)
                if (!spent.count(pool[i]))
                    unspent.push_back(pool[i]);
            std::vector<CTransaction> blk;
            const int ntx = (int)rnd(5);
            for (int n = 0; n < ntx; n++) {
                const unsigned char a = (unsigned char)(0xa0 + rnd(4));
                const uint256 tok = toks.empty() ? uint256() : toks[rnd(toks.size())];
                const uint64_t qs[] = {0, 1, 7, 50, 100, 300, 9223372036854775807ULL, 9223372036854775808ULL};
                std::vector<CScript> outs;
                const uint64_t kind = toks.empty() ? 0 : rnd(5);
                // inputs: mostly outputs of transactions that named the chosen token, sometimes any output
                std::vector<COutPoint> ins;
                const int nin = unspent.empty() ? 0 : 1 + (int)rnd(3);
                for (int i = 0; i < nin && !unspent.empty(); i++) {
                    size_t p = rnd(unspent.size());
                    if ((kind == 1 || kind == 2 || kind == 3) && rnd(5) != 0) {
                        for (size_t tries = 0; tries < unspent.size(); tries++) {
                            const size_t qp = (p + tries) % unspent.size();
                            if (tokOf.count(unspent[qp].hash) && tokOf[unspent[qp].hash] == tok) {
                                p = qp;
                                break;
                            }
                        }
                    }
                    ins.push_back(unspent[p]);
                    unspent.erase(unspent.begin() + p);
                }
                if (kind == 0) {
                    outs.push_back(GenesisMsg(qs[rnd(8)], rnd(2) ? 2 : 0, "R", (unsigned)rnd(3)));
                    outs.push_back(P2PKH(a)); outs.push_back(P2PKH(a + 1));
                } else if (kind == 1) {
                    outs.push_back(MintMsg(tok, qs[rnd(6)], rnd(2) ? 2 : 0));
                    outs.push_back(P2PKH(a)); outs.push_back(P2PKH(a + 1));
                } else if (kind == 2 || kind == 3) {
                    std::vector<uint64_t> q;
                    const int nout = 1 + (int)rnd(3);
                    for (int i = 0; i < nout; i++)
                        q.push_back(qs[rnd(rnd(8) == 0 ? 8 : 5)]);
                    outs.push_back(SendMsg(tok, q));
                    for (int i = 0; i < nout - (rnd(6) == 0 ? 1 : 0); i++)
                        outs.push_back(P2PKH((unsigned char)(a + i)));
                } else {
                    outs.push_back(P2PKH(a));
                }
                CTransaction tx = Tx(ins, outs, tagSeq);
                tagSeq += 10;
                blk.push_back(tx);
                for (size_t i = 1; i < tx.vout.size(); i++)
                    unspent.push_back(COutPoint(tx.GetHash(), i));
                if (kind == 0) {
                    tokOf[tx.GetHash()] = tx.GetHash();
                    toks.push_back(tx.GetHash());
                } else if (kind != 4) {
                    tokOf[tx.GetHash()] = tok;
                }
            }
            c.Add(blk);
            blocks.push_back(blk);
            snaps.push_back(c.kv.m);
        }
        Chain fresh;
        for (size_t b = 0; b < blocks.size(); b++)
            fresh.Add(blocks[b]);
        std::map<std::string, std::string> got = c.kv.m;
        if (blocks.empty())
            got.erase("mbest"); // a store popped back to nothing keeps a best pointer to the null block
        BOOST_CHECK_MESSAGE(fresh.kv.m == got, strprintf("round %d: reorged store differs from a rebuild", round));
        BOOST_CHECK(fresh.idx.GetStats().unspentOutputs == c.idx.GetStats().unspentOutputs);
        const IndexStats fs = fresh.idx.GetStats();
        nValid += fs.txValid; nInvalid += fs.txInvalid; nUnknown += fs.txUnknown; nBurn += fs.txBurn;
    }
    BOOST_TEST_MESSAGE(strprintf("random reorgs: %u valid, %u invalid, %u unknown, %u burn transactions survive", nValid, nInvalid, nUnknown, nBurn));
    // the sequences must exercise every outcome, or the comparison proves little
    BOOST_CHECK(nValid > 100 && nInvalid > 100 && nUnknown > 10 && nBurn > 10);
}

// The LevelDB-backed store must take empty values and an empty scan prefix:
// the ZNAM index writes records whose value is empty. A build with the checked
// standard library (--enable-debug) aborted here in CDBBatch::Write, which
// took &ss[0] of an empty stream.
BOOST_AUTO_TEST_CASE(leveldb_store_accepts_empty_values_and_prefix)
{
    const boost::filesystem::path dir = boost::filesystem::temp_directory_path() / UniquePath();
    {
        LevelKV kv(dir.string(), 1 << 20, true, false);
        std::vector<KV::Op> ops;
        KV::Op a; a.key = "a"; a.erase = false; a.value = "";
        KV::Op b; b.key = "b"; b.erase = false; b.value = "x";
        ops.push_back(a);
        ops.push_back(b);
        BOOST_CHECK(kv.WriteBatch(ops, false));

        std::string v = "sentinel";
        BOOST_CHECK(kv.Get("a", v));
        BOOST_CHECK(v.empty());
        BOOST_CHECK(kv.Get("b", v));
        BOOST_CHECK_EQUAL(v, "x");

        std::vector<std::pair<std::string, std::string> > seen;
        kv.Scan("", [&](const std::string& k, const std::string& val) {
            seen.push_back(std::make_pair(k, val));
            return true;
        });
        BOOST_REQUIRE_EQUAL(seen.size(), (size_t)2);
        BOOST_CHECK(seen[0] == std::make_pair(std::string("a"), std::string()));
        BOOST_CHECK(seen[1] == std::make_pair(std::string("b"), std::string("x")));

        std::vector<KV::Op> del;
        KV::Op e; e.key = "a"; e.erase = true;
        del.push_back(e);
        BOOST_CHECK(kv.WriteBatch(del, false));
        BOOST_CHECK(!kv.Get("a", v));
    }
    boost::filesystem::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
