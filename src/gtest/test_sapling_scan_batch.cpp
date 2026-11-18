// Differential tests for the batched Sapling trial decryption
// (c23/glue/zcl_c23_sapling_scan.c, SaplingIvkBatchAgreement,
// SaplingNotePlaintext::decryptWithFirstMatchingIvk).
//
// The reference is always the original one-at-a-time path:
//   librustzcash_sapling_ka_agree(epk, ivk)            for key agreement,
//   SaplingNotePlaintext::decrypt(ct, ivk, epk, cmu)   for whole-output decryption
// and the batched results must be bit-identical for every input, valid or not.
//
//   ZCL_MAINNET_BLK_FILES=/path/blk00049.dat:/path/blk00050.dat \
//   ZCL_MAINNET_SCAN_MAXOUT=200000 ./zcash-gtest --gtest_filter='SaplingScanBatch.Mainnet*'
//
// runs the same comparison over the Sapling outputs of real mainnet blocks
// (read from COPIES of blk*.dat) and reports the measured cost per
// (ivk, output) pair for the old and the new path.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>
#include <vector>

#include "chainparams.h"
#include "clientversion.h"
#include "compat/endian.h"
#include "librustzcash.h"
#include "main.h"
#include "primitives/block.h"
#include "random.h"
#include "streams.h"
#include "uint256.h"
#include "zcash/Address.hpp"
#include "zcash/Note.hpp"
#include "zcash/NoteEncryption.hpp"

using namespace libzcash;

namespace {

// Jubjub group order r (Fs modulus), little-endian.
const unsigned char kOrderLE[32] = {
    0xb7, 0x2c, 0xf7, 0xd6, 0x5e, 0x0e, 0x97, 0xd0, 0x82, 0x10, 0xc8, 0xcc, 0x93, 0x20, 0x68, 0xa6,
    0x00, 0x3b, 0x34, 0x01, 0x01, 0x3b, 0x67, 0x06, 0xa9, 0xaf, 0x33, 0x65, 0xea, 0xb4, 0x7d, 0x0e};
// BLS12-381 scalar field modulus q (Fr, the Jubjub base field), little-endian.
const unsigned char kFieldLE[32] = {
    0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0x02, 0xa4, 0xbd, 0x53,
    0x05, 0xd8, 0xa1, 0x09, 0x08, 0xd8, 0x39, 0x33, 0x48, 0x7d, 0x9d, 0x29, 0x53, 0xa7, 0xed, 0x73};

uint256 FromBytes(const unsigned char* b)
{
    uint256 u;
    memcpy(u.begin(), b, 32);
    return u;
}

// small helpers on 32-byte little-endian integers
uint256 AddSmall(const unsigned char* le, int delta)
{
    unsigned char b[32];
    memcpy(b, le, 32);
    int carry = delta;
    for (int i = 0; i < 32 && carry != 0; i++) {
        int v = b[i] + carry;
        carry = (v >> 8);
        if (v < 0) { v += 256; carry = -1; }
        b[i] = (unsigned char)(v & 0xff);
    }
    return FromBytes(b);
}

SaplingIncomingViewingKey RandomIvk()
{
    return SaplingSpendingKey::random().full_viewing_key().in_viewing_key();
}

diversifier_t RandomValidDiversifier(const SaplingIncomingViewingKey& ivk)
{
    for (;;) {
        diversifier_t d;
        GetRandBytes(d.data(), d.size());
        if (ivk.address(d)) return d;
    }
}

// A random valid epk (a point of the prime-order subgroup, as produced by
// honest senders).
uint256 RandomEpk()
{
    SaplingIncomingViewingKey ivk = RandomIvk();
    diversifier_t d = RandomValidDiversifier(ivk);
    uint256 esk = random_uint256();
    esk.begin()[31] &= 0x07; // < 2^251 < r
    uint256 epk;
    EXPECT_TRUE(librustzcash_sapling_ka_derivepublic(d.data(), esk.begin(), epk.begin()));
    return epk;
}

// Reference: one librustzcash_sapling_ka_agree per key.
void RefAgree(const uint256& epk, const std::vector<uint256>& ivks,
              std::vector<uint256>& dh, std::vector<unsigned char>& ok)
{
    dh.assign(ivks.size(), uint256());
    ok.assign(ivks.size(), 0);
    for (size_t i = 0; i < ivks.size(); i++) {
        ok[i] = librustzcash_sapling_ka_agree(epk.begin(), ivks[i].begin(), dh[i].begin()) ? 1 : 0;
    }
}

void CheckAgreeEqual(const uint256& epk, const std::vector<uint256>& ivks, size_t expected,
                     const char* what)
{
    std::vector<uint256> refDh;
    std::vector<unsigned char> refOk;
    RefAgree(epk, ivks, refDh, refOk);

    std::vector<unsigned char> inBuf(ivks.size() * 32), dhBuf(ivks.size() * 32, 0), ok(ivks.size(), 7);
    for (size_t i = 0; i < ivks.size(); i++) memcpy(&inBuf[32 * i], ivks[i].begin(), 32);
    SaplingIvkBatchAgreement agree(epk, expected);
    agree.agree(inBuf.data(), ivks.size(), dhBuf.data(), ok.data());
    for (size_t i = 0; i < ivks.size(); i++) {
        ASSERT_EQ(refOk[i] != 0, ok[i] != 0) << what << " ivk#" << i << " epk=" << epk.GetHex()
                                             << " ivk=" << ivks[i].GetHex();
        if (refOk[i]) {
            ASSERT_EQ(0, memcmp(refDh[i].begin(), &dhBuf[32 * i], 32))
                << what << " ivk#" << i << " epk=" << epk.GetHex() << " ivk=" << ivks[i].GetHex()
                << " expected=" << expected;
        }
    }
}

std::vector<uint256> EdgeScalars()
{
    std::vector<uint256> v;
    v.push_back(uint256());                       // 0
    v.push_back(uint256S("01"));                  // 1  (uint256S is big-endian text; value 1)
    v.push_back(AddSmall(kOrderLE, -1));          // r-1
    v.push_back(FromBytes(kOrderLE));             // r   (rejected)
    v.push_back(AddSmall(kOrderLE, 1));           // r+1 (rejected)
    uint256 all_ff;
    memset(all_ff.begin(), 0xff, 32);
    v.push_back(all_ff);                          // 2^256-1 (rejected)
    uint256 p251;
    memset(p251.begin(), 0xff, 32);
    p251.begin()[31] = 0x07;
    v.push_back(p251);                            // 2^251-1 (largest ivk)
    uint256 p252;
    memset(p252.begin(), 0xff, 32);
    p252.begin()[31] = 0x0f;
    v.push_back(p252);                            // 2^252-1 (> r, rejected)
    uint256 two;
    two.begin()[0] = 2;
    v.push_back(two);
    uint256 hi;
    hi.begin()[31] = 0x08;
    v.push_back(hi);                              // 2^251
    uint256 nib;
    for (int i = 0; i < 32; i++) nib.begin()[i] = 0x88; // all digits 8 (recoding carries)
    nib.begin()[31] = 0x08;
    v.push_back(nib);
    for (int i = 0; i < 32; i++) nib.begin()[i] = 0x77;
    v.push_back(nib);
    for (int i = 0; i < 32; i++) nib.begin()[i] = 0x99;
    nib.begin()[31] = 0x09;
    v.push_back(nib);
    return v;
}

std::vector<uint256> EdgeEpks()
{
    std::vector<uint256> v;
    auto bytesY = [](const unsigned char* y, bool sign) {
        uint256 u = FromBytes(y);
        if (sign) u.begin()[31] |= 0x80;
        return u;
    };
    unsigned char y[32];
    // identity (0, 1): y = 1
    memset(y, 0, 32); y[0] = 1;
    v.push_back(bytesY(y, false));
    v.push_back(bytesY(y, true));       // sign bit set on x = 0
    // (0, -1): order 2, y = q - 1
    v.push_back(bytesY(AddSmall(kFieldLE, -1).begin(), false));
    v.push_back(bytesY(AddSmall(kFieldLE, -1).begin(), true));
    // y = 0: the order-4 points (+-sqrt(-1)... x^2 = -1), when -1 is a square
    memset(y, 0, 32);
    v.push_back(bytesY(y, false));
    v.push_back(bytesY(y, true));
    // non-canonical y (>= q)
    v.push_back(bytesY(kFieldLE, false));
    v.push_back(bytesY(AddSmall(kFieldLE, 1).begin(), false));
    memset(y, 0xff, 32); y[31] = 0x7f;
    v.push_back(bytesY(y, false));
    // arbitrary small y values (about half are not on the curve)
    for (int k = 2; k < 40; k++) {
        memset(y, 0, 32); y[0] = (unsigned char)k;
        v.push_back(bytesY(y, false));
        v.push_back(bytesY(y, true));
    }
    return v;
}

} // namespace

TEST(SaplingScanBatch, AgreeMatchesShimOnRandomAndEdgeInputs)
{
    // every table width the cost model can choose: vary the expected count
    const size_t expectedList[] = {1, 2, 3, 4, 5, 6, 8, 10, 14, 20, 32, 64, 150, 1000, 100000};

    std::vector<uint256> ivks = EdgeScalars();
    for (int i = 0; i < 70; i++) ivks.push_back(RandomIvk());
    for (int i = 0; i < 30; i++) { uint256 u = random_uint256(); ivks.push_back(u); } // mostly > r

    std::vector<uint256> epks = EdgeEpks();
    for (int i = 0; i < 12; i++) epks.push_back(RandomEpk());
    // torsion-translated points: P + small order point is NOT in the prime subgroup
    // (still a valid curve point; ka_agree takes no subgroup check, it multiplies by 8)
    for (const uint256& epk : epks) {
        for (size_t expected : expectedList) {
            CheckAgreeEqual(epk, ivks, expected, "edge/random");
            if (testing::Test::HasFatalFailure()) return;
        }
    }
}

TEST(SaplingScanBatch, AgreeMatchesShimForEveryBatchSize)
{
    std::vector<uint256> all;
    for (int i = 0; i < 300; i++) all.push_back(RandomIvk());
    const size_t sizes[] = {0, 1, 2, 3, 7, 8, 9, 31, 32, 33, 63, 64, 65, 127, 128, 129, 200, 300};
    for (int rep = 0; rep < 4; rep++) {
        uint256 epk = RandomEpk();
        for (size_t n : sizes) {
            std::vector<uint256> sub(all.begin(), all.begin() + n);
            CheckAgreeEqual(epk, sub, n ? n : 1, "sizes");
            // mismatched expectation: tables sized for far fewer / more keys
            CheckAgreeEqual(epk, sub, 1, "sizes-small-expected");
            CheckAgreeEqual(epk, sub, 5000, "sizes-large-expected");
            if (testing::Test::HasFatalFailure()) return;
        }
    }
}

namespace {

struct TestOutput {
    SaplingEncCiphertext ct;
    uint256 epk;
    uint256 cmu;
};

// Encrypt a note of `value` to (ivk, d).
bool MakeOutput(const SaplingIncomingViewingKey& ivk, const diversifier_t& d, uint64_t value, TestOutput& out)
{
    auto addr = ivk.address(d);
    if (!addr) return false;
    SaplingNote note(*addr, value);
    auto cmu = note.cm();
    if (!cmu) return false;
    std::array<unsigned char, ZC_MEMO_SIZE> memo;
    memo.fill(0xf6);
    SaplingNotePlaintext pt(note, memo);
    auto res = pt.encrypt(addr->pk_d);
    if (!res) return false;
    out.ct = res->first;
    out.epk = res->second.get_epk();
    out.cmu = *cmu;
    return true;
}

// Reference: the original serial loop (first match in order wins).
boost::optional<std::pair<size_t, SaplingNotePlaintext>>
RefFirstMatch(const TestOutput& o, const std::vector<SaplingIncomingViewingKey>& ivks)
{
    for (size_t i = 0; i < ivks.size(); i++) {
        auto r = SaplingNotePlaintext::decrypt(o.ct, ivks[i], o.epk, o.cmu);
        if (r) return std::make_pair(i, *r);
    }
    return boost::none;
}

void CheckDecryptEqual(const TestOutput& o, const std::vector<SaplingIncomingViewingKey>& ivks, const char* what)
{
    auto ref = RefFirstMatch(o, ivks);
    size_t idx = 12345;
    SaplingNotePlaintext got;
    uint256 pk_d;
    bool found = SaplingNotePlaintext::decryptWithFirstMatchingIvk(o.ct, ivks, o.epk, o.cmu, idx, got, pk_d);
    ASSERT_EQ(ref.is_initialized(), found) << what;
    if (!found) return;
    ASSERT_EQ(ref->first, idx) << what;
    ASSERT_EQ(ref->second.value(), got.value()) << what;
    ASSERT_TRUE(ref->second.d == got.d) << what;
    ASSERT_TRUE(ref->second.rcm == got.rcm) << what;
    ASSERT_TRUE(ref->second.memo() == got.memo()) << what;
    // pk_d must equal what ivk.address(d) yields (what the wallet used to store)
    auto addr = ivks[idx].address(got.d);
    ASSERT_TRUE(addr.is_initialized()) << what;
    ASSERT_TRUE(addr->pk_d == pk_d) << what;
}

} // namespace

TEST(SaplingScanBatch, DecryptFirstMatchEqualsSerialLoop)
{
    // A pool of keys; outputs go to: a key in the list (any position), a
    // diversified address of a key in the list, a key NOT in the list.
    std::vector<SaplingIncomingViewingKey> pool;
    for (int i = 0; i < 40; i++) pool.push_back(RandomIvk());
    std::vector<SaplingIncomingViewingKey> outsiders;
    for (int i = 0; i < 4; i++) outsiders.push_back(RandomIvk());

    const size_t listSizes[] = {1, 2, 3, 5, 16, 40};
    for (size_t n : listSizes) {
        std::vector<SaplingIncomingViewingKey> ivks(pool.begin(), pool.begin() + n);
        for (int round = 0; round < 6; round++) {
            // to a listed key, default and random diversified addresses
            const SaplingIncomingViewingKey& target = ivks[(size_t)GetRand(n)];
            diversifier_t d = RandomValidDiversifier(target);
            TestOutput o;
            ASSERT_TRUE(MakeOutput(target, d, 1000 + round, o));
            CheckDecryptEqual(o, ivks, "listed");
            if (testing::Test::HasFatalFailure()) return;

            // not for us
            TestOutput o2;
            ASSERT_TRUE(MakeOutput(outsiders[round % outsiders.size()], RandomValidDiversifier(outsiders[round % outsiders.size()]), 5, o2));
            CheckDecryptEqual(o2, ivks, "outsider");
            if (testing::Test::HasFatalFailure()) return;

            // duplicate keys in the list: the first occurrence wins in both paths
            std::vector<SaplingIncomingViewingKey> dup = ivks;
            dup.push_back(target);
            dup.insert(dup.begin(), outsiders[0]);
            CheckDecryptEqual(o, dup, "duplicate");
            if (testing::Test::HasFatalFailure()) return;

            // corrupted ciphertext (AEAD fails everywhere)
            TestOutput bad = o;
            bad.ct[(size_t)GetRand(bad.ct.size())] ^= 0x01;
            CheckDecryptEqual(bad, ivks, "bad ciphertext");
            // wrong cmu: AEAD succeeds, note validation fails -> no match, same in both
            TestOutput badcm = o;
            badcm.cmu = random_uint256();
            CheckDecryptEqual(badcm, ivks, "wrong cmu");
            // wrong epk (agreement differs, AEAD fails)
            TestOutput bade = o;
            bade.epk = RandomEpk();
            CheckDecryptEqual(bade, ivks, "wrong epk");
            // epk that is not a curve point / non-canonical / small order
            for (const uint256& weird : EdgeEpks()) {
                TestOutput w = o;
                w.epk = weird;
                CheckDecryptEqual(w, ivks, "weird epk");
                if (testing::Test::HasFatalFailure()) return;
            }
        }
    }
}

TEST(SaplingScanBatch, DecryptHandlesKeyListsBeyondOneChunk)
{
    // more than one 128-key chunk, match placed in the second chunk
    std::vector<SaplingIncomingViewingKey> ivks;
    for (int i = 0; i < 300; i++) ivks.push_back(RandomIvk());
    for (size_t pos : {size_t(0), size_t(127), size_t(128), size_t(255), size_t(256), size_t(299)}) {
        TestOutput o;
        ASSERT_TRUE(MakeOutput(ivks[pos], RandomValidDiversifier(ivks[pos]), 77, o));
        CheckDecryptEqual(o, ivks, "chunk boundary");
        if (testing::Test::HasFatalFailure()) return;
        size_t idx = 0;
        SaplingNotePlaintext got;
        uint256 pk_d;
        ASSERT_TRUE(SaplingNotePlaintext::decryptWithFirstMatchingIvk(o.ct, ivks, o.epk, o.cmu, idx, got, pk_d));
        ASSERT_EQ(pos, idx);
    }
    // empty key list
    TestOutput o;
    ASSERT_TRUE(MakeOutput(ivks[0], RandomValidDiversifier(ivks[0]), 1, o));
    std::vector<SaplingIncomingViewingKey> none;
    size_t idx;
    SaplingNotePlaintext got;
    uint256 pk_d;
    ASSERT_FALSE(SaplingNotePlaintext::decryptWithFirstMatchingIvk(o.ct, none, o.epk, o.cmu, idx, got, pk_d));
}

// --- Real mainnet blocks -----------------------------------------------------

namespace {

struct MainOut {
    uint256 epk;
    SaplingEncCiphertext ct;
    uint256 cmu;
};

bool ReadOutputs(const std::string& path, std::vector<MainOut>& out, uint64_t& nBlocks, uint64_t& nTx,
                 uint64_t maxOut, std::string& err)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) { err = "cannot open " + path; return false; }
    std::vector<char> buf;
    {
        char chunk[1 << 16];
        size_t n;
        while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0) buf.insert(buf.end(), chunk, chunk + n);
        fclose(f);
    }
    const unsigned char* magic = Params().MessageStart();
    size_t pos = 0;
    while (pos + 8 <= buf.size() && out.size() < maxOut) {
        if (memcmp(&buf[pos], magic, 4) != 0) { pos++; continue; }
        uint32_t nSize;
        memcpy(&nSize, &buf[pos + 4], 4);
        nSize = le32toh(nSize);
        if (nSize < 80 || nSize > GENEROUS_BLOCK_SIZE_LIMIT || pos + 8 + nSize > buf.size()) { pos++; continue; }
        CBlock block;
        try {
            CDataStream ss(&buf[pos + 8], &buf[pos + 8] + nSize, SER_DISK, CLIENT_VERSION);
            ss >> block;
        } catch (const std::exception& e) {
            err = path + ": block does not deserialize: " + e.what();
            return false;
        }
        pos += 8 + nSize;
        nBlocks++;
        for (const CTransaction& tx : block.vtx) {
            nTx++;
            for (const OutputDescription& od : tx.vShieldedOutput) {
                MainOut m;
                m.epk = od.ephemeralKey;
                m.ct = od.encCiphertext;
                m.cmu = od.cm;
                out.push_back(m);
            }
        }
    }
    return true;
}

double Now()
{
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

} // namespace

TEST(SaplingScanBatch, MainnetOutputsAgreeAndTiming)
{
    const char* env = getenv("ZCL_MAINNET_BLK_FILES");
    if (env == nullptr || env[0] == '\0') {
        printf("[  SKIPPED ] set ZCL_MAINNET_BLK_FILES=<blk file>[:<blk file>...] to run\n");
        return;
    }
    const char* me = getenv("ZCL_MAINNET_SCAN_MAXOUT");
    uint64_t maxOut = me ? strtoull(me, nullptr, 10) : 20000;
    SelectParams(CBaseChainParams::MAIN);

    std::vector<MainOut> outs;
    uint64_t nBlocks = 0, nTx = 0;
    std::string list(env);
    size_t start = 0;
    while (start <= list.size() && outs.size() < maxOut) {
        size_t end = list.find(':', start);
        if (end == std::string::npos) end = list.size();
        std::string path = list.substr(start, end - start);
        start = end + 1;
        if (path.empty()) continue;
        std::string err;
        const size_t outBefore = outs.size();
        const uint64_t blkBefore = nBlocks;
        ASSERT_TRUE(ReadOutputs(path, outs, nBlocks, nTx, maxOut, err)) << err;
        printf("[ INFO ] %s: %llu blocks, %zu sapling outputs (%.3f outputs/block)\n", path.c_str(),
               (unsigned long long)(nBlocks - blkBefore), outs.size() - outBefore,
               (nBlocks > blkBefore) ? (double)(outs.size() - outBefore) / (double)(nBlocks - blkBefore) : 0.0);
    }
    printf("[ INFO ] mainnet: %llu blocks, %llu transactions, %zu sapling outputs read\n",
           (unsigned long long)nBlocks, (unsigned long long)nTx, outs.size());
    ASSERT_GT(outs.size(), 0u);

    const char* te = getenv("ZCL_MAINNET_SCAN_TIMEMAX");
    const size_t timeMax = te ? (size_t)strtoull(te, nullptr, 10) : 6000;
    const std::vector<MainOut> timed(outs.begin(), outs.begin() + std::min(outs.size(), timeMax));
    std::vector<size_t> ivkCounts;
    {
        const char* ie = getenv("ZCL_MAINNET_SCAN_IVKS");
        std::string s = ie ? ie : "1,20,200";
        for (size_t p = 0; p < s.size();) {
            size_t q = s.find(',', p);
            if (q == std::string::npos) q = s.size();
            ivkCounts.push_back((size_t)strtoull(s.substr(p, q - p).c_str(), nullptr, 10));
            p = q + 1;
        }
    }
    for (size_t nIvk : ivkCounts) {
        std::vector<SaplingIncomingViewingKey> ivks;
        for (size_t i = 0; i < nIvk; i++) ivks.push_back(RandomIvk());

        // old path: the serial loop of SaplingNotePlaintext::decrypt
        double t0 = Now();
        size_t oldFound = 0;
        for (const MainOut& o : timed) {
            for (const auto& ivk : ivks) {
                if (SaplingNotePlaintext::decrypt(o.ct, ivk, o.epk, o.cmu)) oldFound++;
            }
        }
        double t1 = Now();
        // new path
        size_t newFound = 0;
        for (const MainOut& o : timed) {
            size_t idx;
            SaplingNotePlaintext got;
            uint256 pk_d;
            if (SaplingNotePlaintext::decryptWithFirstMatchingIvk(o.ct, ivks, o.epk, o.cmu, idx, got, pk_d)) newFound++;
        }
        double t2 = Now();
        ASSERT_EQ(oldFound, newFound);
        double pairs = (double)timed.size() * (double)nIvk;
        printf("[ INFO ] %zu ivk(s) x %zu outputs: old %.3f s (%.2f us/pair), new %.3f s (%.2f us/pair), speedup %.2fx, found old/new %zu/%zu\n",
               nIvk, timed.size(), t1 - t0, (t1 - t0) / pairs * 1e6, t2 - t1, (t2 - t1) / pairs * 1e6,
               (t1 - t0) / (t2 - t1), oldFound, newFound);
        if (timed.size() == outs.size() && nBlocks > 0) {
            printf("[ INFO ]   trial decryption only, over all %llu blocks read: old %.0f blocks/s, new %.0f blocks/s\n",
                   (unsigned long long)nBlocks, (double)nBlocks / (t1 - t0), (double)nBlocks / (t2 - t1));
        }
    }

    // exact dh equality on every real epk against a few keys, including edge scalars
    std::vector<uint256> keys = EdgeScalars();
    for (int i = 0; i < 6; i++) keys.push_back(RandomIvk());
    size_t checked = 0;
    for (const MainOut& o : outs) {
        CheckAgreeEqual(o.epk, keys, keys.size(), "mainnet epk");
        if (testing::Test::HasFatalFailure()) return;
        checked++;
    }
    printf("[ INFO ] key agreement identical on %zu real mainnet epks x %zu keys\n", checked, keys.size());
}

// Prints (does not assert) where the time of one (output, ivk-list) trial
// decryption goes, for tuning. Always runs; takes a couple of seconds.
TEST(SaplingScanBatch, PerOutputCostBreakdown)
{
    std::vector<uint256> epks;
    for (int i = 0; i < 200; i++) epks.push_back(RandomEpk());
    std::vector<unsigned char> ivkBuf(256 * 32), dh(256 * 32), ok(256);
    for (int i = 0; i < 256; i++) memcpy(&ivkBuf[32 * i], RandomIvk().begin(), 32);

    // The host may be shared: report the best of several repetitions per output.
    const int reps = 7;
    for (size_t n : {size_t(1), size_t(3), size_t(10), size_t(50), size_t(200)}) {
        double tBegin = 0, tAgree = 0;
        for (const uint256& epk : epks) {
            double bestBegin = 1e9, bestAgree = 1e9;
            for (int r = 0; r < reps; r++) {
                double a = Now();
                SaplingIvkBatchAgreement ag(epk, n);
                double b = Now();
                ag.agree(ivkBuf.data(), n, dh.data(), ok.data());
                double c = Now();
                bestBegin = std::min(bestBegin, b - a);
                bestAgree = std::min(bestAgree, c - b);
            }
            tBegin += bestBegin;
            tAgree += bestAgree;
        }
        double outs = (double)epks.size();
        printf("[ INFO ] n=%3zu: per output setup %.2f us, agree %.2f us (%.2f us/ivk); total %.2f us/output = %.2f us/pair\n",
               n, tBegin / outs * 1e6, tAgree / outs * 1e6, tAgree / outs / n * 1e6,
               (tBegin + tAgree) / outs * 1e6, (tBegin + tAgree) / outs / n * 1e6);
    }
    // the one-at-a-time reference
    double tRef = 0;
    for (const uint256& epk : epks) {
        double best = 1e9;
        for (int r = 0; r < reps; r++) {
            uint256 out;
            double t0 = Now();
            librustzcash_sapling_ka_agree(epk.begin(), &ivkBuf[0], out.begin());
            best = std::min(best, Now() - t0);
        }
        tRef += best;
    }
    printf("[ INFO ] reference librustzcash_sapling_ka_agree: %.2f us/call\n", tRef / epks.size() * 1e6);
}

// The inversion-free decompression inside the batch core must accept and
// reject exactly the encodings jub_from_bytes does, and resolve the sign bit
// to the same point. Probe with ivk = 1, whose agreement output is [8]epk.
TEST(SaplingScanBatch, DecompressionAcceptsExactlyWhatTheShimAccepts)
{
    std::vector<uint256> one(1);
    one[0].begin()[0] = 1;
    size_t accepted = 0, rejected = 0;
    auto probe = [&](const uint256& epk) {
        CheckAgreeEqual(epk, one, 1, "decompression");
        uint256 dh;
        if (librustzcash_sapling_ka_agree(epk.begin(), one[0].begin(), dh.begin())) accepted++; else rejected++;
    };
    // every small y, both sign bits
    for (unsigned y = 0; y < 3000; y++) {
        uint256 e;
        e.begin()[0] = (unsigned char)y;
        e.begin()[1] = (unsigned char)(y >> 8);
        probe(e);
        e.begin()[31] |= 0x80;
        probe(e);
        if (testing::Test::HasFatalFailure()) return;
    }
    // random 255-bit y (many >= q: non-canonical), random sign bit
    for (int i = 0; i < 6000; i++) {
        uint256 e = random_uint256();
        probe(e);
        if (testing::Test::HasFatalFailure()) return;
    }
    // y just below and above q
    for (int d = -4; d <= 4; d++) {
        uint256 e = AddSmall(kFieldLE, d);
        e.begin()[31] &= 0x7f;
        probe(e);
        e.begin()[31] |= 0x80;
        probe(e);
    }
    printf("[ INFO ] decompression probe: %zu accepted, %zu rejected encodings, all identical\n", accepted, rejected);
    EXPECT_GT(accepted, 1000u);
    EXPECT_GT(rejected, 1000u);
}

// Replays the Rust-oracle golden records of librustzcash_sapling_ka_agree
// (src/test/data/c23_golden/sapling_ka_agree.golden, produced by
// src/test/rust_oracle/gen_golden.cpp from librustzcash before Rust was
// removed; format in FORMAT.md next to it) through the batched core.
//   ZCL_C23_GOLDEN_DIR=/path/to/c23_golden ./zcash-gtest --gtest_filter=SaplingScanBatch.Golden*
TEST(SaplingScanBatch, GoldenKaAgreeRecordsFromRust)
{
    const char* dir = getenv("ZCL_C23_GOLDEN_DIR");
    if (dir == nullptr || dir[0] == '\0') {
        printf("[  SKIPPED ] set ZCL_C23_GOLDEN_DIR=<dir with sapling_ka_agree.golden> to run\n");
        return;
    }
    std::string path = std::string(dir) + "/sapling_ka_agree.golden";
    FILE* f = fopen(path.c_str(), "r");
    ASSERT_TRUE(f != nullptr) << "cannot open " << path;
    auto unhex = [](const std::string& s, unsigned char* out) {
        if (s.size() != 64) return false;
        for (size_t i = 0; i < 32; i++) {
            unsigned v;
            if (sscanf(s.substr(2 * i, 2).c_str(), "%2x", &v) != 1) return false;
            out[i] = (unsigned char)v;
        }
        return true;
    };
    char line[1024];
    size_t nRec = 0, nTrue = 0, nFalse = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != 'C') continue;
        std::vector<std::string> tok;
        for (char* p = strtok(line, " \n"); p; p = strtok(nullptr, " \n")) tok.push_back(p);
        ASSERT_GE(tok.size(), 6u);
        uint256 epk, sk, want;
        ASSERT_TRUE(unhex(tok[3], epk.begin())) << tok[1];
        ASSERT_TRUE(unhex(tok[4], sk.begin())) << tok[1];
        const bool wantOk = (tok[5] == "T");
        if (wantOk) ASSERT_TRUE(unhex(tok[6], want.begin())) << tok[1];
        std::vector<uint256> keys(1, sk);
        for (size_t expected : {size_t(1), size_t(7), size_t(200)}) {
            unsigned char dh[32] = {0}, ok[1] = {7};
            SaplingIvkBatchAgreement agree(epk, expected);
            agree.agree(sk.begin(), 1, dh, ok);
            ASSERT_EQ(wantOk, ok[0] != 0) << "golden record " << tok[1] << " (" << tok[2] << ")";
            if (wantOk) {
                ASSERT_EQ(0, memcmp(want.begin(), dh, 32)) << "golden record " << tok[1] << " (" << tok[2] << ")";
            }
        }
        nRec++;
        (wantOk ? nTrue : nFalse)++;
    }
    fclose(f);
    printf("[ INFO ] golden ka_agree: %zu Rust-oracle records identical (%zu accepted, %zu rejected)\n", nRec, nTrue, nFalse);
    ASSERT_GT(nRec, 1000u);
}
