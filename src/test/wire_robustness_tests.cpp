// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//
// Deterministic mutation tests for the P2P deserializers.
//
// Seeds are valid serializations built in code. Each seed is mutated a fixed
// number of times with a fixed-seed PRNG and fed to the matching decoder. The
// only allowed outcomes are success or std::ios_base::failure; anything else
// (another exception type, a crash, a sanitizer report) is a bug. No fuzzer
// engine is needed, and the run is reproducible: a failure prints the PRNG
// seed, the seed object and the case number.
//

#include "bloom.h"
#include "crypto/common.h"
#include "crypto/sha256.h"
#include "chainparams.h"
#include "merkleblock.h"
#include "netbase.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "protocol.h"
#include "script/script.h"
#include "serialize.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "univalue.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "version.h"

#include "data/tx_valid.json.h"

#include <algorithm>
#include <initializer_list>
#include <stdint.h>
#include <string.h>
#include <string>
#include <typeinfo>
#include <vector>

#include <boost/test/unit_test.hpp>

extern UniValue read_json(const std::string& jsondata);

namespace {

typedef std::vector<unsigned char> Bytes;

static const uint64_t WIRE_PRNG_SEED = 0x5a43326e65743233ULL;
static const int MUTATIONS_PER_SEED = 2000;

/** xorshift64*, fixed seed: same cases on every run and platform. */
struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed ? seed : 1) {}
    uint64_t Next()
    {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        return s * 2685821657736338717ULL;
    }
    size_t Below(size_t n) { return n ? (size_t)(Next() % n) : 0; }
};

enum Kind { K_HEADER, K_BLOCK, K_TX, K_LOCATOR, K_INV, K_ADDR, K_BLOOM, K_MERKLE };

struct Seed {
    std::string name;
    Kind kind;
    Bytes bytes;
};

template <typename T>
Bytes Ser(const T& obj)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << obj;
    return Bytes(ss.begin(), ss.end());
}

CDataStream StreamOf(const Bytes& b)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    if (!b.empty())
        ss.write((const char*)&b[0], b.size());
    return ss;
}

/** Decode into T, then serialize the result again. Throws whatever the decoder throws. */
template <typename T>
void Decode(const Bytes& b)
{
    CDataStream ss = StreamOf(b);
    T obj;
    ss >> obj;
    // a decoded object must serialize again without throwing
    CDataStream out(SER_NETWORK, PROTOCOL_VERSION);
    out << obj;
}

void DecodeKind(Kind k, const Bytes& b)
{
    switch (k) {
    case K_HEADER:  Decode<CBlockHeader>(b); break;
    case K_BLOCK:   Decode<CBlock>(b); break;
    case K_TX:      Decode<CTransaction>(b); break;
    case K_LOCATOR: Decode<CBlockLocator>(b); break;
    case K_INV:     Decode<std::vector<CInv> >(b); break;
    case K_ADDR:    Decode<std::vector<CAddress> >(b); break;
    case K_BLOOM:   Decode<CBloomFilter>(b); break;
    case K_MERKLE:  Decode<CMerkleBlock>(b); break;
    }
}

/** Returns "" when the outcome is allowed, otherwise a description. */
std::string Outcome(Kind k, const Bytes& b, bool* pDecoded = NULL)
{
    try {
        DecodeKind(k, b);
        if (pDecoded) *pDecoded = true;
    } catch (const std::ios_base::failure&) {
        // allowed
    } catch (const std::exception& e) {
        return std::string("forbidden exception ") + typeid(e).name() + ": " + e.what();
    } catch (...) {
        return "forbidden non-std exception";
    }
    return "";
}

// The six mutation kinds. Each draws from rng in the same order the single
// switch did, so a PRNG seed still names the same cases.

void MutateBitFlip(Rng& rng, Bytes& r)
{
    if (!r.empty())
        r[rng.Below(r.size())] ^= (unsigned char)(1u << rng.Below(8));
}

void MutateByteSet(Rng& rng, Bytes& r)
{
    if (!r.empty()) {
        static const unsigned char interesting[] = {0x00, 0x01, 0x7f, 0x80, 0xfc, 0xfd, 0xfe, 0xff};
        r[rng.Below(r.size())] = (rng.Below(2) ? interesting[rng.Below(sizeof(interesting))]
                                                : (unsigned char)rng.Next());
    }
}

void MutateTruncate(Rng& rng, Bytes& r)
{
    r.resize(rng.Below(r.size() + 1));
}

void MutateInsert(Rng& rng, Bytes& r)
{
    // insert 1..8 random bytes
    size_t pos = rng.Below(r.size() + 1);
    size_t n = 1 + rng.Below(8);
    Bytes ins(n);
    for (size_t i = 0; i < n; i++)
        ins[i] = (unsigned char)rng.Next();
    r.insert(r.begin() + pos, ins.begin(), ins.end());
}

void MutateSplice(Rng& rng, Bytes& r, const std::vector<Seed>& seeds)
{
    // splice a prefix of this seed onto a suffix of another
    const Bytes& o = seeds[rng.Below(seeds.size())].bytes;
    size_t cut1 = rng.Below(r.size() + 1);
    size_t cut2 = rng.Below(o.size() + 1);
    r.resize(cut1);
    r.insert(r.end(), o.begin() + cut2, o.end());
}

void MutateCompactSize(Rng& rng, Bytes& r)
{
    // inject a 0xFD/0xFE/0xFF compact size, overwriting or inserting
    static const unsigned char marks[] = {0xfd, 0xfe, 0xff};
    unsigned char m = marks[rng.Below(3)];
    size_t n = m == 0xfd ? 2 : (m == 0xfe ? 4 : 8);
    Bytes inj(1, m);
    for (size_t i = 0; i < n; i++) {
        // favour huge claimed lengths
        inj.push_back(rng.Below(3) ? (unsigned char)0xff : (unsigned char)rng.Next());
    }
    size_t pos = rng.Below(r.size() + 1);
    if (rng.Below(2) && pos + inj.size() <= r.size())
        std::copy(inj.begin(), inj.end(), r.begin() + pos);
    else
        r.insert(r.begin() + pos, inj.begin(), inj.end());
}

Bytes Mutate(Rng& rng, const Bytes& a, const std::vector<Seed>& seeds, int& mode)
{
    Bytes r = a;
    mode = (int)rng.Below(6);
    switch (mode) {
    case 0: MutateBitFlip(rng, r); break;
    case 1: MutateByteSet(rng, r); break;
    case 2: MutateTruncate(rng, r); break;
    case 3: MutateInsert(rng, r); break;
    case 4: MutateSplice(rng, r, seeds); break;
    case 5: MutateCompactSize(rng, r); break;
    }
    return r;
}

CAddress MakeAddr(uint32_t ipv4, uint16_t port, uint32_t nTime)
{
    struct in_addr s;
    s.s_addr = ipv4;
    CAddress a(CService(CNetAddr(s), port));
    a.nTime = nTime;
    a.nServices = NODE_NETWORK;
    return a;
}

std::vector<Seed> BuildSeeds()
{
    std::vector<Seed> seeds;
    const CBaseChainParams::Network nets[] = {CBaseChainParams::MAIN, CBaseChainParams::REGTEST};
    const char* netnames[] = {"main", "regtest"};
    for (int i = 0; i < 2; i++) {
        const CBlock& g = Params(nets[i]).GenesisBlock();
        seeds.push_back(Seed{std::string("header-") + netnames[i], K_HEADER, Ser((const CBlockHeader&)g)});
        seeds.push_back(Seed{std::string("block-") + netnames[i], K_BLOCK, Ser(g)});
    }

    // transactions from tx_valid.json: a deterministic spread of the vectors
    UniValue tests = read_json(std::string(json_tests::tx_valid, json_tests::tx_valid + sizeof(json_tests::tx_valid)));
    size_t taken = 0, seen = 0;
    for (size_t i = 0; i < tests.size() && taken < 6; i++) {
        const UniValue& t = tests[i];
        if (!t.isArray() || t.size() < 3 || !t[0].isArray() || !t[1].isStr())
            continue;
        if (seen++ % 9 != 0)
            continue;
        try {
            CDataStream ss(ParseHex(t[1].get_str()), SER_NETWORK, PROTOCOL_VERSION);
            CTransaction tx;
            ss >> tx;
            seeds.push_back(Seed{"tx_valid#" + std::to_string(i), K_TX, Ser(tx)});
            taken++;
        } catch (const std::exception&) {
            // a vector this tree cannot parse is not a seed
        }
    }
    BOOST_REQUIRE_GT(taken, 0u);

    // an overwinter v3 and a sapling v4 transaction, built in code
    {
        CMutableTransaction m;
        m.fOverwintered = true;
        m.nVersionGroupId = OVERWINTER_VERSION_GROUP_ID;
        m.nVersion = OVERWINTER_TX_VERSION;
        m.nExpiryHeight = 1000;
        m.vin.push_back(CTxIn(COutPoint(uint256S("11"), 0), CScript() << OP_1));
        m.vout.push_back(CTxOut(1234, CScript() << OP_TRUE));
        seeds.push_back(Seed{"tx-overwinter-v3", K_TX, Ser(CTransaction(m))});

        m.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
        m.nVersion = SAPLING_TX_VERSION;
        m.valueBalance = 0;
        seeds.push_back(Seed{"tx-sapling-v4", K_TX, Ser(CTransaction(m))});
    }

    // locator, inv, addr
    {
        std::vector<uint256> have;
        for (int i = 1; i <= 10; i++)
            have.push_back(uint256S(strprintf("%x", i * 0x1111)));
        seeds.push_back(Seed{"locator", K_LOCATOR, Ser(CBlockLocator(have))});

        std::vector<CInv> invs;
        for (int i = 0; i < 20; i++)
            invs.push_back(CInv(i % 2 ? MSG_TX : MSG_BLOCK, uint256S(strprintf("%x", i + 1))));
        seeds.push_back(Seed{"inv-vector", K_INV, Ser(invs)});

        std::vector<CAddress> addrs;
        for (int i = 0; i < 20; i++)
            addrs.push_back(MakeAddr(0x08080808u + (uint32_t)i * 0x01010101u, 8033, 1700000000 + i));
        seeds.push_back(Seed{"addr-vector", K_ADDR, Ser(addrs)});
    }

    // bloom filter and merkle block (genesis block, filter matching its coinbase)
    {
        CBloomFilter bf(10, 0.000001, 7, BLOOM_UPDATE_ALL);
        const CBlock& g = Params(CBaseChainParams::MAIN).GenesisBlock();
        bf.insert(g.vtx[0].GetHash());
        seeds.push_back(Seed{"bloom-filter", K_BLOOM, Ser(bf)});
        seeds.push_back(Seed{"merkle-block", K_MERKLE, Ser(CMerkleBlock(g, bf))});
    }
    return seeds;
}

uint64_t ReadCS(const Bytes& b)
{
    CDataStream ss = StreamOf(b);
    return ReadCompactSize(ss);
}

Bytes B(std::initializer_list<unsigned> l)
{
    Bytes b;
    for (unsigned v : l)
        b.push_back((unsigned char)v);
    return b;
}

template <typename T>
int64_t TimedClaimedLengthDecode(uint64_t claimed)
{
    // claimed length, then a body far too short to hold even one element
    Bytes b;
    {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        WriteCompactSize(ss, claimed);
        for (int i = 0; i < 10; i++)
            ss << (unsigned char)0xab;
        b.assign(ss.begin(), ss.end());
    }
    int64_t best = -1;
    for (int attempt = 0; attempt < 5; attempt++) {
        CDataStream ss = StreamOf(b);
        std::vector<T> v;
        int64_t t0 = GetTimeMicros();
        bool threw = false;
        try {
            ss >> v;
        } catch (const std::ios_base::failure&) {
            threw = true;
        }
        int64_t dt = GetTimeMicros() - t0;
        BOOST_REQUIRE_MESSAGE(threw, "decode of a " << claimed << "-element claim over a 10-byte body must throw");
        if (best < 0 || dt < best)
            best = dt;
    }
    return best;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(wire_robustness_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(seeds_are_valid)
{
    // every seed must decode cleanly, otherwise the mutations prove nothing
    std::vector<Seed> seeds = BuildSeeds();
    BOOST_REQUIRE_GE(seeds.size(), 15u); // 12 fixed + tx_valid vectors
    for (const Seed& s : seeds) {
        try {
            DecodeKind(s.kind, s.bytes);
        } catch (const std::exception& e) {
            BOOST_ERROR("seed " << s.name << " does not decode: " << e.what());
        }
    }
}

BOOST_AUTO_TEST_CASE(mutated_inputs_only_fail_with_ios_failure)
{
    std::vector<Seed> seeds = BuildSeeds();
    Rng rng(WIRE_PRNG_SEED);
    size_t total = 0, accepted = 0, failures = 0;
    int64_t t0 = GetTimeMicros();
    for (size_t si = 0; si < seeds.size(); si++) {
        for (int c = 0; c < MUTATIONS_PER_SEED; c++) {
            int mode = -1;
            Bytes m = Mutate(rng, seeds[si].bytes, seeds, mode);
            bool decoded = false;
            std::string o = Outcome(seeds[si].kind, m, &decoded);
            total++;
            if (!o.empty()) {
                if (failures++ < 20)
                    BOOST_ERROR("PRNG seed 0x" << std::hex << WIRE_PRNG_SEED << std::dec << " seed-object "
                                << seeds[si].name << " case " << c << " mutation " << mode << " input "
                                << HexStr(m.begin(), m.end()).substr(0, 400) << ": " << o);
            } else {
                if (decoded) accepted++;
            }
        }
    }
    int64_t elapsed = GetTimeMicros() - t0;
    BOOST_TEST_MESSAGE("wire_robustness: " << total << " mutations, " << accepted << " decoded, "
                       << (total - accepted) << " rejected, " << elapsed / 1000 << " ms");
    BOOST_CHECK_EQUAL(failures, 0u);
}

BOOST_AUTO_TEST_CASE(mutation_stream_is_pinned)
{
    // The PRNG seed names the cases: the same seed must keep giving the same
    // mutated inputs, mode by mode, whatever shape Mutate takes. SHA256 over
    // (mode, length, bytes) of the first 200 mutations of every seed.
    std::vector<Seed> seeds = BuildSeeds();
    Rng rng(WIRE_PRNG_SEED);
    CSHA256 h;
    size_t modes[6] = {0, 0, 0, 0, 0, 0};
    for (size_t si = 0; si < seeds.size(); si++) {
        for (int c = 0; c < 200; c++) {
            int mode = -1;
            Bytes m = Mutate(rng, seeds[si].bytes, seeds, mode);
            BOOST_REQUIRE(mode >= 0 && mode < 6);
            modes[mode]++;
            unsigned char hdr[9];
            hdr[0] = (unsigned char)mode;
            WriteLE64(hdr + 1, (uint64_t)m.size());
            h.Write(hdr, sizeof(hdr));
            if (!m.empty())
                h.Write(&m[0], m.size());
        }
    }
    uint256 digest;
    h.Finalize(digest.begin());
    BOOST_TEST_MESSAGE("mutation stream: " << seeds.size() << " seeds, modes " << modes[0] << "/" << modes[1] << "/"
                       << modes[2] << "/" << modes[3] << "/" << modes[4] << "/" << modes[5] << ", sha256 "
                       << digest.GetHex());
    BOOST_CHECK_EQUAL(digest.GetHex(), "96f88a2bc55d2b2a60c98afc2ec76330b185d6dc0a5a993c5c376362be5c469b");
}

BOOST_AUTO_TEST_CASE(compact_size_bounds)
{
    // values above MAX_SIZE throw
    BOOST_CHECK_THROW(ReadCS(B({0xfe, 0x01, 0x00, 0x00, 0x02})), std::ios_base::failure); // MAX_SIZE + 1
    BOOST_CHECK_THROW(ReadCS(B({0xfe, 0xff, 0xff, 0xff, 0xff})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xff, 0, 0, 0, 0, 1, 0, 0, 0})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})), std::ios_base::failure);
    // MAX_SIZE itself is the largest accepted value
    BOOST_CHECK_EQUAL(ReadCS(B({0xfe, 0x00, 0x00, 0x00, 0x02})), (uint64_t)MAX_SIZE);
    // non-canonical encodings throw
    BOOST_CHECK_THROW(ReadCS(B({0xfd, 0x00, 0x00})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xfd, 0xfc, 0x00})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xfe, 0xff, 0xff, 0x00, 0x00})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xfe, 0x00, 0x00, 0x00, 0x00})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xff, 0, 0, 0, 0, 0, 0, 0, 0})), std::ios_base::failure);
    // a truncated compact size throws too
    BOOST_CHECK_THROW(ReadCS(B({0xfd, 0x01})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({0xfe, 0x01, 0x00})), std::ios_base::failure);
    BOOST_CHECK_THROW(ReadCS(B({})), std::ios_base::failure);
    // the smallest canonical form of each width is accepted
    BOOST_CHECK_EQUAL(ReadCS(B({0xfc})), 252u);
    BOOST_CHECK_EQUAL(ReadCS(B({0xfd, 0xfd, 0x00})), 253u);
    BOOST_CHECK_EQUAL(ReadCS(B({0xfe, 0x00, 0x00, 0x01, 0x00})), 65536u);
}

BOOST_AUTO_TEST_CASE(claimed_length_does_not_allocate_up_front)
{
    // 33,554,432 == MAX_SIZE: accepted by ReadCompactSize, so the vector reader
    // must not trust it. Allocating the claimed length up front would cost over
    // a gigabyte and far more than 50 ms. Best of five tries, to ride out scheduler noise.
    const uint64_t claimed = 33554432;
    BOOST_REQUIRE_EQUAL(claimed, (uint64_t)MAX_SIZE);
    int64_t invUs = TimedClaimedLengthDecode<CInv>(claimed);
    int64_t addrUs = TimedClaimedLengthDecode<CAddress>(claimed);
    BOOST_TEST_MESSAGE("claimed-length decode: vector<CInv> " << invUs << " us, vector<CAddress> " << addrUs << " us");
    BOOST_CHECK_LT(invUs, 50 * 1000);
    BOOST_CHECK_LT(addrUs, 50 * 1000);
}

BOOST_AUTO_TEST_SUITE_END()
