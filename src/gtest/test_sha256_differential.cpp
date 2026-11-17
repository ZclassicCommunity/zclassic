// Differential test for the SHA-256 backend swap.
//
// CSHA256 now runs on the vendored Z23 C23 implementation with run-time
// dispatch (portable C, Intel SHA-NI, ARMv8 SHA). SHA-256 is consensus
// critical, so every backend the dispatcher can install on this host is forced
// in turn and compared, bit for bit, with the previous zclassicd C++
// implementation kept in gtest/sha256_reference.h, and with published vectors.
//
// The file also builds stand-alone (-DZCL_SHA256_DIFF_STANDALONE) so it can be
// run under ASan+UBSan without sanitising the whole daemon; see
// src/c23/test/sha256-diff-sanitize.sh.

#include <gtest/gtest.h>

#include "crypto/ripemd160.h"
#include "crypto/sha256.h"
#include "gtest/sha256_reference.h"

#ifndef ZCL_SHA256_DIFF_STANDALONE
#include "hash.h"
#include "uint256.h"
#include "zcash/IncrementalMerkleTree.hpp"
#endif

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

typedef std::vector<unsigned char> Bytes;

// Deterministic generator (xorshift64*), so a failure is reproducible.
class Rng
{
    uint64_t x;

public:
    explicit Rng(uint64_t seed) : x(seed ? seed : 0x9E3779B97F4A7C15ULL) {}
    uint64_t next()
    {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        return x * 0x2545F4914F6CDD1DULL;
    }
    size_t below(size_t n) { return n ? (size_t)(next() % n) : 0; }
    void fill(unsigned char* p, size_t n)
    {
        for (size_t i = 0; i < n; i++) {
            p[i] = (unsigned char)(next() >> 56);
        }
    }
};

std::string Hex(const unsigned char* p, size_t n)
{
    static const char d[] = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 15]);
    }
    return s;
}

std::string NewSha(const unsigned char* p, size_t n)
{
    unsigned char h[32];
    CSHA256().Write(p, n).Finalize(h);
    return Hex(h, 32);
}

std::string RefSha(const unsigned char* p, size_t n)
{
    unsigned char h[32];
    sha256_reference::CSHA256Ref().Write(p, n).Finalize(h);
    return Hex(h, 32);
}

std::string NewDouble(const unsigned char* p, size_t n)
{
    unsigned char h[32];
    CSHA256().Write(p, n).Finalize(h);
    CSHA256().Write(h, 32).Finalize(h);
    return Hex(h, 32);
}

std::string RefDouble(const unsigned char* p, size_t n)
{
    unsigned char h[32];
    sha256_reference::CSHA256Ref().Write(p, n).Finalize(h);
    sha256_reference::CSHA256Ref().Write(h, 32).Finalize(h);
    return Hex(h, 32);
}

// Feed [p, p+n) in random pieces; zero-length writes included on purpose.
template <typename Hasher>
std::string Streamed(Hasher hasher, const unsigned char* p, size_t n, Rng& rng)
{
    size_t off = 0;
    while (off < n) {
        size_t maxpiece;
        switch (rng.below(5)) {
        case 0: maxpiece = 1; break;
        case 1: maxpiece = 9; break;
        case 2: maxpiece = 70; break;
        case 3: maxpiece = 200; break;
        default: maxpiece = n; break;
        }
        size_t piece = rng.below(maxpiece + 1);
        if (piece > n - off) {
            piece = n - off;
        }
        hasher.Write(p + off, piece);
        off += piece;
    }
    unsigned char h[32];
    hasher.Finalize(h);
    return Hex(h, 32);
}

// A buffer whose payload starts at a chosen offset from a 64-byte boundary.
class Aligned
{
    Bytes store;
    unsigned char* base;

public:
    explicit Aligned(size_t max_len) : store(max_len + 192)
    {
        uintptr_t a = (uintptr_t)store.data();
        base = store.data() + ((64 - (a & 63)) & 63);
    }
    unsigned char* at(size_t align) { return base + align; }
};

// Back to the backend the test binary was started with (ZCL_SHA256_BACKEND,
// see gtest/main.cpp), so a forced whole-suite run stays forced.
void RestoreBackend()
{
    const char* env = getenv("ZCL_SHA256_BACKEND");
    SHA256SelectBackendForTesting(env ? env : "auto");
}

struct BackendCase {
    const char* request;
};

class Sha256Differential : public ::testing::TestWithParam<BackendCase>
{
protected:
    std::string installed;
    void SetUp() override
    {
        const std::string request(GetParam().request);
        const std::string portable("portable C");
        installed = SHA256SelectBackendForTesting(request);
        if (request == "portable") {
            ASSERT_EQ(portable, installed);
        }
        RecordProperty("installed_backend", installed);
        std::cout << "[ backend  ] requested=" << request << " installed=" << installed << std::endl;
        // Set ZCL_SHA256_REQUIRE_HARDWARE=1 on hosts known to have SHA-NI or
        // ARMv8 SHA so the hardware path cannot be skipped silently.
        const char* require = getenv("ZCL_SHA256_REQUIRE_HARDWARE");
        if (require && require[0] == '1' && request != "portable") {
            ASSERT_NE(portable, installed);
        }
    }
    void TearDown() override { RestoreBackend(); }
};

TEST_P(Sha256Differential, KnownVectors)
{
    // FIPS 180-4 / NIST example vectors.
    struct {
        const char* msg;
        const char* digest;
    } kat[] = {
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
        {"The quick brown fox jumps over the lazy dog",
         "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"},
    };
    for (size_t i = 0; i < sizeof(kat) / sizeof(kat[0]); i++) {
        const unsigned char* m = (const unsigned char*)kat[i].msg;
        size_t n = strlen(kat[i].msg);
        EXPECT_EQ(kat[i].digest, NewSha(m, n)) << "vector " << i;
        EXPECT_EQ(kat[i].digest, RefSha(m, n)) << "vector " << i;
    }

    // One million 'a', one-shot and in 1000-byte writes.
    Bytes a(1000000, 'a');
    const char* million = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";
    EXPECT_EQ(million, NewSha(a.data(), a.size()));
    EXPECT_EQ(million, RefSha(a.data(), a.size()));
    CSHA256 h;
    for (int i = 0; i < 1000; i++) {
        h.Write(a.data(), 1000);
    }
    unsigned char out[32];
    h.Finalize(out);
    EXPECT_EQ(million, Hex(out, 32));

    // Bitcoin genesis block header: double SHA-256 of an 80-byte input.
    static const unsigned char genesis[80] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x3b, 0xa3, 0xed, 0xfd, 0x7a, 0x7b, 0x12, 0xb2, 0x7a, 0xc7, 0x2c, 0x3e,
        0x67, 0x76, 0x8f, 0x61, 0x7f, 0xc8, 0x1b, 0xc3, 0x88, 0x8a, 0x51, 0x32, 0x3a, 0x9f, 0xb8, 0xaa,
        0x4b, 0x1e, 0x5e, 0x4a, 0x29, 0xab, 0x5f, 0x49, 0xff, 0xff, 0x00, 0x1d, 0x1d, 0xac, 0x2b, 0x7c};
    EXPECT_EQ("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", NewDouble(genesis, 80));
    EXPECT_EQ("6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000", RefDouble(genesis, 80));

    // SHA256Compress of 64 zero bytes: the Sprout empty-tree node one level
    // above the leaves.
    unsigned char zero[64] = {0};
    CSHA256().Write(zero, 64).FinalizeNoPadding(out);
    EXPECT_EQ("da5698be17b9b46962335799779fbeca8ce5d491c0d26243bafef9ea1837a9d8", Hex(out, 32));
}

TEST_P(Sha256Differential, EveryLength0To4096)
{
    Rng rng(0x5a17c1a551c0de01ULL);
    Bytes data(4096);
    rng.fill(data.data(), data.size());
    for (size_t len = 0; len <= 4096; len++) {
        const std::string want = RefSha(data.data(), len);
        ASSERT_EQ(want, NewSha(data.data(), len)) << "len " << len;
        ASSERT_EQ(RefDouble(data.data(), len), NewDouble(data.data(), len)) << "double, len " << len;
        ASSERT_EQ(want, Streamed(CSHA256(), data.data(), len, rng)) << "streamed, len " << len;
        // The tail of the buffer too, so the last byte abuts the end of the
        // allocation (an over-read shows up under ASan).
        const unsigned char* tail = data.data() + (data.size() - len);
        ASSERT_EQ(RefSha(tail, len), NewSha(tail, len)) << "tail, len " << len;
    }
}

TEST_P(Sha256Differential, EveryAlignment0To63)
{
    Rng rng(0xa11c0de5eedULL);
    const size_t kMax = 4096 + 64;
    Aligned buf(kMax);
    Aligned outbuf(32);
    for (size_t align = 0; align < 64; align++) {
        unsigned char* p = buf.at(align);
        rng.fill(p, kMax);
        for (size_t len = 0; len <= 320; len++) {
            ASSERT_EQ(RefSha(p, len), NewSha(p, len)) << "align " << align << " len " << len;
        }
        static const size_t big[] = {1487, 2048, 4095, 4096, 4097, 4096 + 64};
        for (size_t i = 0; i < sizeof(big) / sizeof(big[0]); i++) {
            ASSERT_EQ(RefSha(p, big[i]), NewSha(p, big[i])) << "align " << align << " len " << big[i];
            ASSERT_EQ(RefSha(p, big[i]), Streamed(CSHA256(), p, big[i], rng)) << "streamed, align " << align;
        }
        // The output buffer at every alignment as well.
        unsigned char ref[32];
        sha256_reference::CSHA256Ref().Write(p, 250).Finalize(ref);
        CSHA256().Write(p, 250).Finalize(outbuf.at(align));
        ASSERT_EQ(0, memcmp(ref, outbuf.at(align), 32)) << "output align " << align;
    }
}

TEST_P(Sha256Differential, RandomLengthsUpTo1MiBWithRandomSplits)
{
    Rng rng(0x1ee7f00dULL);
    const size_t kMax = 1024 * 1024;
    Aligned buf(kMax);
    rng.fill(buf.at(0), kMax + 64);
    for (int iter = 0; iter < 160; iter++) {
        size_t len = iter < 8 ? kMax - (size_t)iter : rng.below(kMax + 1);
        size_t align = rng.below(64);
        unsigned char* p = buf.at(align);
        // Refresh a random window so no two iterations hash the same bytes.
        size_t w = rng.below(len + 1);
        rng.fill(p + w, len - w > 4096 ? 4096 : len - w);
        const std::string want = RefSha(p, len);
        ASSERT_EQ(want, NewSha(p, len)) << "iter " << iter << " len " << len << " align " << align;
        ASSERT_EQ(want, Streamed(CSHA256(), p, len, rng)) << "streamed, iter " << iter << " len " << len;
        ASSERT_EQ(want, Streamed(sha256_reference::CSHA256Ref(), p, len, rng)) << "ref streamed, iter " << iter;
        ASSERT_EQ(RefDouble(p, len), NewDouble(p, len)) << "double, iter " << iter;
    }
}

TEST_P(Sha256Differential, ResetCopyAndReuse)
{
    Rng rng(0xc0b1e5ULL);
    Bytes data(777);
    rng.fill(data.data(), data.size());
    for (size_t cut = 0; cut <= data.size(); cut += 1 + rng.below(13)) {
        CSHA256 a;
        sha256_reference::CSHA256Ref r;
        a.Write(data.data(), cut);
        r.Write(data.data(), cut);
        CSHA256 b = a; // copy mid-stream, then diverge
        sha256_reference::CSHA256Ref rb = r;
        a.Write(data.data() + cut, data.size() - cut);
        r.Write(data.data() + cut, data.size() - cut);
        b.Write(data.data(), 5);
        rb.Write(data.data(), 5);
        unsigned char ha[32], hr[32], hb[32], hrb[32];
        a.Finalize(ha);
        r.Finalize(hr);
        b.Finalize(hb);
        rb.Finalize(hrb);
        ASSERT_EQ(Hex(hr, 32), Hex(ha, 32)) << "cut " << cut;
        ASSERT_EQ(Hex(hrb, 32), Hex(hb, 32)) << "copy, cut " << cut;
        // Reset() gives a fresh hasher.
        a.Reset().Write(data.data(), cut).Finalize(ha);
        ASSERT_EQ(RefSha(data.data(), cut), Hex(ha, 32)) << "reset, cut " << cut;
    }
    // A zero-length write with a null pointer is a no-op, as before.
    unsigned char h[32];
    CSHA256().Write(NULL, 0).Finalize(h);
    EXPECT_EQ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", Hex(h, 32));
}

// Sprout note-commitment tree node: SHA256Compress(left || right), the bare
// compression function on one 64-byte block with no padding.
TEST_P(Sha256Differential, SproutSha256Compress)
{
    Rng rng(0x5b207ULL);
    Aligned buf(64);
    for (int iter = 0; iter < 20000; iter++) {
        unsigned char* p = buf.at((size_t)iter % 64);
        rng.fill(p, 64);
        if (iter < 3) {
            memset(p, iter == 0 ? 0x00 : iter == 1 ? 0xff : 0x80, 64);
        }
        unsigned char want[32], got[32], got2[32];
        sha256_reference::CSHA256Ref().Write(p, 64).FinalizeNoPadding(want);
        CSHA256().Write(p, 64).FinalizeNoPadding(got);
        ASSERT_EQ(Hex(want, 32), Hex(got, 32)) << "iter " << iter;
        // Exactly as SHA256Compress::combine writes it: two 32-byte halves.
        CSHA256().Write(p, 32).Write(p + 32, 32).FinalizeNoPadding(got2);
        ASSERT_EQ(Hex(want, 32), Hex(got2, 32)) << "two halves, iter " << iter;
#ifndef ZCL_SHA256_DIFF_STANDALONE
        uint256 a, b;
        memcpy(a.begin(), p, 32);
        memcpy(b.begin(), p + 32, 32);
        const uint256 c = libzcash::SHA256Compress::combine(
            libzcash::SHA256Compress(a), libzcash::SHA256Compress(b), (size_t)iter % 29);
        ASSERT_EQ(Hex(want, 32), Hex(c.begin(), 32)) << "combine, iter " << iter;
#endif
    }

    // The length check (and its exception type) is unchanged.
    static const size_t bad[] = {0, 1, 32, 63, 65, 128};
    unsigned char block[128] = {0};
    unsigned char out[32];
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        EXPECT_THROW(CSHA256().Write(block, bad[i]).FinalizeNoPadding(out), std::length_error) << bad[i];
        EXPECT_THROW(sha256_reference::CSHA256Ref().Write(block, bad[i]).FinalizeNoPadding(out), std::length_error);
    }
}

// Merkle inner node shape: SHA256(SHA256(a || b)) over 64 bytes.
TEST_P(Sha256Differential, DoubleSha256Of64Bytes)
{
    Rng rng(0xd0b1e64ULL);
    Aligned buf(64);
    for (int iter = 0; iter < 20000; iter++) {
        unsigned char* p = buf.at((size_t)iter % 64);
        rng.fill(p, 64);
        const std::string want = RefDouble(p, 64);
        ASSERT_EQ(want, NewDouble(p, 64)) << "iter " << iter;
#ifndef ZCL_SHA256_DIFF_STANDALONE
        unsigned char h[32];
        CHash256().Write(p, 32).Write(p + 32, 32).Finalize(h);
        ASSERT_EQ(want, Hex(h, 32)) << "CHash256, iter " << iter;
        const uint256 m = Hash(p, p + 32, p + 32, p + 64); // as the merkle code does
        ASSERT_EQ(want, Hex(m.begin(), 32)) << "Hash(a,b), iter " << iter;
        const uint256 m1 = Hash(p, p + 64);
        ASSERT_EQ(want, Hex(m1.begin(), 32)) << "Hash(ab), iter " << iter;
#endif
    }
}

// Hash160 = RIPEMD160(SHA256(x)); RIPEMD160 itself is not replaced.
TEST_P(Sha256Differential, Hash160)
{
    Rng rng(0x160160ULL);
    Bytes data(130);
    for (int iter = 0; iter < 4000; iter++) {
        size_t len = iter % 3 == 0 ? 33 : iter % 3 == 1 ? 65 : rng.below(data.size() + 1);
        rng.fill(data.data(), len);
        unsigned char s[32], want[20], got[20];
        sha256_reference::CSHA256Ref().Write(data.data(), len).Finalize(s);
        CRIPEMD160().Write(s, 32).Finalize(want);
        CSHA256().Write(data.data(), len).Finalize(s);
        CRIPEMD160().Write(s, 32).Finalize(got);
        ASSERT_EQ(Hex(want, 20), Hex(got, 20)) << "iter " << iter;
#ifndef ZCL_SHA256_DIFF_STANDALONE
        const uint160 h = ::Hash160(data.data(), data.data() + len);
        ASSERT_EQ(Hex(want, 20), Hex(h.begin(), 20)) << "Hash160, iter " << iter;
#endif
    }
}

// Several threads hashing at once agree with the reference. The backend flag
// is read on every block, so an unsynchronised one would show under TSan.
TEST_P(Sha256Differential, ConcurrentHashing)
{
    std::vector<std::thread> threads;
    std::vector<int> failures(8, 0);
    for (int t = 0; t < 8; t++) {
        threads.emplace_back([t, &failures]() {
            Rng rng(0x7000 + (uint64_t)t);
            Bytes data(3000);
            for (int iter = 0; iter < 400; iter++) {
                size_t len = rng.below(data.size() + 1);
                rng.fill(data.data(), len);
                if (RefSha(data.data(), len) != NewSha(data.data(), len)) {
                    failures[t]++;
                }
            }
        });
    }
    for (size_t i = 0; i < threads.size(); i++) {
        threads[i].join();
    }
    for (int t = 0; t < 8; t++) {
        EXPECT_EQ(0, failures[t]) << "thread " << t;
    }
}

const BackendCase kBackends[] = {{"portable"}, {"hardware"}, {"auto"}};

std::string BackendName(const ::testing::TestParamInfo<BackendCase>& info)
{
    return info.param.request;
}

INSTANTIATE_TEST_CASE_P(Backends, Sha256Differential, ::testing::ValuesIn(kBackends), BackendName);

// The startup probe names a backend and is idempotent; a probe racing with
// hashing threads is safe.
TEST(Sha256Backend, AutoDetectIsStable)
{
    const std::string a = SHA256AutoDetect();
    const std::string b = SHA256AutoDetect();
    EXPECT_EQ(a, b);
    EXPECT_FALSE(a.empty());
    EXPECT_EQ("portable C", SHA256SelectBackendForTesting("portable"));
    EXPECT_EQ(a, SHA256SelectBackendForTesting("auto"));
    std::cout << "[ backend  ] auto-detected: " << a << std::endl;

    std::vector<std::thread> threads;
    std::vector<int> failures(8, 0);
    const unsigned char abc[3] = {'a', 'b', 'c'};
    for (int t = 0; t < 8; t++) {
        threads.emplace_back([t, &failures, &abc]() {
            for (int iter = 0; iter < 2000; iter++) {
                if (t == 0) {
                    SHA256AutoDetect();
                }
                if (NewSha(abc, 3) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") {
                    failures[t]++;
                }
            }
        });
    }
    for (size_t i = 0; i < threads.size(); i++) {
        threads[i].join();
    }
    for (int t = 0; t < 8; t++) {
        EXPECT_EQ(0, failures[t]) << "thread " << t;
    }
    RestoreBackend();
}

} // namespace

#ifdef ZCL_SHA256_DIFF_STANDALONE
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
#endif
