// Sprout PHGR13 ("BCTV14") JoinSplit verification through zclassicd's own entry
// point (JSDescription::Verify -> ZCJoinSplit::verify -> zcl_c23_phgr13_*).
//
// PHGR13 proofs can no longer be created, so the evidence here is real mainnet
// proofs (phgr13_vectors.h) and mutations of them. Every mutation below must be
// rejected exactly where libsnark rejected it; the exhaustive version of that
// claim (483,797 cases against a libsnark reference, all 432,407 distinct
// mainnet proofs) is the differential gate recorded in doc/c23-phgr13.md.
#include <gtest/gtest.h>

#include "phgr13_vectors.h"

#include "primitives/transaction.h"
#include "random.h"
#include "streams.h"
#include "util.h"
#include "utilstrencodings.h"
#include "version.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"
#include "zcl_c23_phgr13.h"

#include <boost/filesystem.hpp>

#include <atomic>
#include <fstream>
#include <memory>
#include <thread>
#include <vector>

using namespace libzcash;

extern ZCJoinSplit* params;

namespace {

// Byte offset of each point in the 296-byte wire proof, and its size.
struct PointSpan { size_t off; size_t len; bool g2; };
const PointSpan SPANS[8] = {
    {0, 33, false},   // g_A
    {33, 33, false},  // g_A'
    {66, 65, true},   // g_B
    {131, 33, false}, // g_B'
    {164, 33, false}, // g_C
    {197, 33, false}, // g_C'
    {230, 33, false}, // g_K
    {263, 33, false}, // g_H
};

// Fq modulus q as 32 big-endian bytes.
const char* Q_HEX = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

uint256 Raw32(const char* hex)
{
    std::vector<unsigned char> v = ParseHex(hex);
    EXPECT_EQ(v.size(), 32u);
    uint256 r;
    memcpy(r.begin(), v.data(), 32);
    return r;
}

struct Fixture {
    int height;
    JSDescription js;
    uint256 pubKey;
    std::vector<unsigned char> wire; // 296 proof bytes
};

PHGRProof ProofFromWire(const std::vector<unsigned char>& wire)
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.write((const char*)wire.data(), wire.size());
    PHGRProof p;
    ss >> p;
    return p;
}

Fixture Make(const PhgrVector& v)
{
    Fixture f;
    f.height = v.height;
    f.pubKey = Raw32(v.joinSplitPubKey);
    f.wire = ParseHex(v.proof);
    EXPECT_EQ(f.wire.size(), (size_t)PHGR_PROOF_SIZE);
    f.js.vpub_old = v.vpub_old;
    f.js.vpub_new = v.vpub_new;
    f.js.anchor = Raw32(v.anchor);
    for (int i = 0; i < 2; i++) {
        f.js.nullifiers[i] = Raw32(v.nf[i]);
        f.js.commitments[i] = Raw32(v.cm[i]);
        f.js.macs[i] = Raw32(v.mac[i]);
    }
    f.js.randomSeed = Raw32(v.randomSeed);
    f.js.proof = ProofFromWire(f.wire);
    return f;
}

std::vector<Fixture> All()
{
    std::vector<Fixture> r;
    for (const PhgrVector& v : PHGR_VECTORS) r.push_back(Make(v));
    return r;
}

bool Strict(const Fixture& f)
{
    auto verifier = ProofVerifier::Strict();
    return f.js.Verify(*params, verifier, f.pubKey);
}

bool Disabled(const Fixture& f)
{
    auto verifier = ProofVerifier::Disabled();
    return f.js.Verify(*params, verifier, f.pubKey);
}

// The same JoinSplit with the proof replaced by (mutated) wire bytes. Throws
// ios_base::failure when a lead byte is not a valid point prefix, as the
// transaction deserializer does.
Fixture WithWire(Fixture f, const std::vector<unsigned char>& wire)
{
    f.js.proof = ProofFromWire(wire);
    return f;
}

} // namespace

TEST(phgr13, vectors_present)
{
    ASSERT_GE(sizeof(PHGR_VECTORS) / sizeof(PHGR_VECTORS[0]), 10u);
    EXPECT_EQ(PHGR_VECTORS[0].height, 241);
}

TEST(phgr13, wire_roundtrip_is_exact)
{
    for (const Fixture& f : All()) {
        unsigned char out[PHGR_PROOF_SIZE];
        boost::get<PHGRProof>(f.js.proof).ToBytes(out);
        EXPECT_EQ(std::vector<unsigned char>(out, out + PHGR_PROOF_SIZE), f.wire) << "height " << f.height;
    }
}

TEST(phgr13, mainnet_proofs_verify)
{
    for (const Fixture& f : All()) {
        EXPECT_TRUE(Strict(f)) << "height " << f.height;
        EXPECT_TRUE(Disabled(f)) << "height " << f.height;
    }
}

TEST(phgr13, changed_public_inputs_are_rejected)
{
    for (const Fixture& f0 : All()) {
        std::vector<Fixture> bad;
        { Fixture f = f0; f.js.vpub_old += 1; bad.push_back(f); }
        { Fixture f = f0; f.js.vpub_new += 1; bad.push_back(f); }
        { Fixture f = f0; f.js.anchor.begin()[0] ^= 1; bad.push_back(f); }
        { Fixture f = f0; f.js.randomSeed.begin()[31] ^= 0x80; bad.push_back(f); }
        { Fixture f = f0; f.pubKey.begin()[7] ^= 4; bad.push_back(f); }
        for (int i = 0; i < 2; i++) {
            { Fixture f = f0; f.js.nullifiers[i].begin()[0] ^= 1; bad.push_back(f); }
            { Fixture f = f0; f.js.commitments[i].begin()[31] ^= 1; bad.push_back(f); }
            { Fixture f = f0; f.js.macs[i].begin()[16] ^= 0x10; bad.push_back(f); }
        }
        { Fixture f = f0; std::swap(f.js.macs[0], f.js.macs[1]); bad.push_back(f); }
        { Fixture f = f0; std::swap(f.js.nullifiers[0], f.js.nullifiers[1]); bad.push_back(f); }
        { Fixture f = f0; std::swap(f.js.commitments[0], f.js.commitments[1]); bad.push_back(f); }
        for (size_t i = 0; i < bad.size(); i++) {
            EXPECT_FALSE(Strict(bad[i])) << "height " << f0.height << " mutation " << i;
            // Public inputs are not looked at when proofs are not checked.
            EXPECT_TRUE(Disabled(bad[i])) << "height " << f0.height << " mutation " << i;
        }
    }
}

TEST(phgr13, mutated_proof_bytes_are_rejected)
{
    for (const Fixture& f : All()) {
        for (const PointSpan& s : SPANS) {
            // x bytes: first, middle, last; and the y-parity bit of the lead byte.
            const size_t offsets[] = {s.off + 1, s.off + 1 + (s.len - 1) / 2, s.off + s.len - 1};
            for (size_t o : offsets) {
                for (unsigned char mask : {0x01, 0x80}) {
                    std::vector<unsigned char> w = f.wire;
                    w[o] ^= mask;
                    EXPECT_FALSE(Strict(WithWire(f, w))) << "height " << f.height << " byte " << o;
                }
            }
            std::vector<unsigned char> w = f.wire;
            w[s.off] ^= 1; // other y root
            EXPECT_FALSE(Strict(WithWire(f, w))) << "height " << f.height << " lead " << s.off;
        }
    }
}

TEST(phgr13, swapped_points_are_rejected)
{
    for (const Fixture& f : All()) {
        // g_A <-> g_A', g_C <-> g_C', g_K <-> g_H (same size, so the wire stays valid).
        const size_t pairs[][2] = {{0, 33}, {164, 197}, {230, 263}, {33, 131}};
        for (const auto& pr : pairs) {
            std::vector<unsigned char> w = f.wire;
            for (size_t i = 0; i < 33; i++) std::swap(w[pr[0] + i], w[pr[1] + i]);
            EXPECT_FALSE(Strict(WithWire(f, w))) << "height " << f.height << " swap " << pr[0] << "," << pr[1];
        }
    }
}

TEST(phgr13, lead_bytes_are_refused_at_deserialization)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    for (const PointSpan& s : SPANS) {
        const unsigned char good = s.g2 ? 0x0a : 0x02;
        const unsigned char bad[] = {0x00, 0x01, 0x04, (unsigned char)(good ^ 0x10), (unsigned char)(good ^ 0x80),
                                     (unsigned char)(good ^ 0x04), (unsigned char)(s.g2 ? 0x02 : 0x0a), 0xff};
        for (unsigned char b : bad) {
            std::vector<unsigned char> w = f.wire;
            w[s.off] = b;
            EXPECT_THROW(ProofFromWire(w), std::ios_base::failure) << "offset " << s.off << " lead 0x" << HexStr(&b, &b + 1);
        }
        // The valid prefixes (either parity bit) do deserialize.
        for (unsigned char b : {good, (unsigned char)(good | 1)}) {
            std::vector<unsigned char> w = f.wire;
            w[s.off] = b;
            EXPECT_NO_THROW(ProofFromWire(w));
        }
    }
}

TEST(phgr13, noncanonical_encodings_are_rejected_even_when_not_checking)
{
    const std::vector<unsigned char> q = ParseHex(Q_HEX);
    ASSERT_EQ(q.size(), 32u);
    for (const Fixture& f : All()) {
        for (const PointSpan& s : SPANS) {
            const size_t xlen = s.len - 1;
            auto check = [&](const std::vector<unsigned char>& x, const char* what) {
                std::vector<unsigned char> w = f.wire;
                std::copy(x.begin(), x.end(), w.begin() + s.off + 1);
                Fixture m = WithWire(f, w);
                EXPECT_FALSE(Strict(m)) << what << " height " << f.height << " off " << s.off;
                // libsnark decompressed the proof before consulting the
                // verifier, so these fail even under ProofVerifier::Disabled().
                EXPECT_FALSE(Disabled(m)) << what << " height " << f.height << " off " << s.off;
            };
            check(std::vector<unsigned char>(xlen, 0xff), "x=all ones");
            if (!s.g2) {
                check(q, "x=q");
                std::vector<unsigned char> qp1 = q;
                qp1[31] += 1; // q+1 (q ends in 0x47)
                check(qp1, "x=q+1");
            } else {
                // FE2IP integer c1*q + c0 with c1 = q (needs c1 < q) and c0 = 0:
                // q*q is the smallest rejected value (>= q^2).
                std::vector<unsigned char> x(64, 0);
                // q^2 as 64 big-endian bytes via schoolbook multiply of the bytes of q.
                unsigned acc[64] = {0};
                for (int i = 0; i < 32; i++)
                    for (int j = 0; j < 32; j++)
                        acc[63 - (i + j)] += (unsigned)q[31 - i] * q[31 - j];
                unsigned carry = 0;
                for (int k = 63; k >= 0; k--) {
                    unsigned v = acc[k] + carry;
                    x[k] = v & 0xff;
                    carry = v >> 8;
                }
                check(x, "X=q^2");
            }
        }
    }
}

TEST(phgr13, x_not_on_curve_is_rejected_even_when_not_checking)
{
    // For the first G1 point, walk x upward until x^3 + 3 is a non-square.
    const Fixture f = Make(PHGR_VECTORS[0]);
    int rejected = 0;
    for (int i = 1; i <= 64; i++) {
        std::vector<unsigned char> w = f.wire;
        w[32] ^= (unsigned char)(i * 7); // low byte of g_A.x
        Fixture m = WithWire(f, w);
        EXPECT_FALSE(Strict(m));
        if (!Disabled(m)) rejected++;
    }
    // About half of all x are not on the curve; not one of 64 would be a
    // decoder that never checks.
    EXPECT_GT(rejected, 8);
}

TEST(phgr13, default_and_random_proofs_are_rejected)
{
    Fixture f = Make(PHGR_VECTORS[0]);
    f.js.proof = PHGRProof();
    EXPECT_FALSE(Strict(f));
    for (int i = 0; i < 16; i++) {
        f.js.proof = PHGRProof::random_invalid();
        EXPECT_FALSE(Strict(f));
        // It round-trips through the wire format.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << boost::get<PHGRProof>(f.js.proof);
        EXPECT_EQ(ss.size(), (size_t)PHGR_PROOF_SIZE);
        PHGRProof back;
        ss >> back;
        EXPECT_TRUE(back == boost::get<PHGRProof>(f.js.proof));
    }
}

TEST(phgr13, a_groth_proof_is_not_a_phgr_proof)
{
    // The proof variant decides the verifier; a Groth16 JoinSplit never reaches
    // the PHGR13 verifier and a PHGR13 JoinSplit never reaches Groth16.
    Fixture f = Make(PHGR_VECTORS[0]);
    GrothProof g;
    g.fill(0);
    f.js.proof = g;
    EXPECT_FALSE(Strict(f));
}

TEST(phgr13, phgr_proofs_can_no_longer_be_created)
{
    std::array<JSInput, 2> inputs = {JSInput(), JSInput()};
    std::array<JSOutput, 2> outputs = {JSOutput(), JSOutput()};
    std::array<SproutNote, 2> notes;
    std::array<ZCNoteEncryption::Ciphertext, 2> ct;
    uint256 epk, seed, pk = random_uint256(), rt;
    std::array<uint256, 2> macs, nfs, cms;

    // Without a proof (the fee-estimation path) nothing changes.
    SproutProof p = params->prove(false, inputs, outputs, notes, ct, epk, pk, seed, macs, nfs, cms,
                                  0, 0, rt, false);
    EXPECT_TRUE(boost::get<PHGRProof>(&p) != nullptr);

    // With one, there is an explicit error that names the reason.
    try {
        params->prove(false, inputs, outputs, notes, ct, epk, pk, seed, macs, nfs, cms, 0, 0, rt, true);
        FAIL() << "a PHGR13 proof was created";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("PHGR13"), std::string::npos) << e.what();
    }
}

TEST(phgr13, concurrent_verification)
{
    const std::vector<Fixture> fx = All();
    std::atomic<int> failures(0);
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; t++) {
        threads.emplace_back([&, t]() {
            for (size_t i = 0; i < fx.size(); i++) {
                const Fixture& f = fx[(i + t) % fx.size()];
                if (!Strict(f)) failures++;
                Fixture bad = f;
                bad.js.vpub_new += 1 + t;
                if (Strict(bad)) failures++;
                if (!Disabled(f)) failures++;
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(failures.load(), 0);
}

TEST(phgr13, off_subgroup_g2_is_rejected_even_when_not_checking)
{
    // x = 2 + 1*u (FE2IP integer q + 2) is on the twist y^2 = x^3 + 3/(9+u) but the
    // point is not in the order-r subgroup: libsnark's to_libsnark_g2 threw "point is
    // not in G2" for both signs (checked against the base Proof.cpp + libsnark).
    // x = 1 + 1*u is not on the curve. Each replaces g_B of every vector.
    const char* OFF_SUBGROUP[] = {
        "0a000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd49",
        "0b000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd49",
        "0a000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd48",
    };
    for (const Fixture& f : All()) {
        for (const char* hex : OFF_SUBGROUP) {
            const std::vector<unsigned char> g = ParseHex(hex);
            ASSERT_EQ(g.size(), 65u);
            std::vector<unsigned char> w = f.wire;
            std::copy(g.begin(), g.end(), w.begin() + SPANS[2].off);
            Fixture m = WithWire(f, w);
            EXPECT_FALSE(Strict(m)) << "height " << f.height << " g_B " << hex;
            EXPECT_FALSE(Disabled(m)) << "height " << f.height << " g_B " << hex;
        }
    }
}

TEST(phgr13, a_verifying_key_that_does_not_load_is_refused_and_leaves_the_key)
{
    // ZC_LoadParams checks the SHA-256 pin first; this is the loader below it.
    // A file that cannot be read or parsed throws (startup fails, as with
    // libsnark's loadFromFile for a missing file) and must not replace the
    // installed key.
    const boost::filesystem::path dir =
        boost::filesystem::temp_directory_path() / UniquePath("phgr13-vk-%%%%%%%%");
    boost::filesystem::create_directories(dir);
    const boost::filesystem::path real = ZC_GetParamsDir() / "sprout-verifying.key";
    std::ifstream in(real.string(), std::ios::binary);
    std::vector<char> key((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    ASSERT_EQ(key.size(), 1449u);

    auto write = [&](const char* name, const std::vector<char>& bytes) {
        const boost::filesystem::path p = dir / name;
        std::ofstream out(p.string(), std::ios::binary);
        out.write(bytes.data(), bytes.size());
        return p.string();
    };
    std::vector<std::string> bad = {
        (dir / "missing.key").string(),
        write("empty.key", std::vector<char>()),
        write("truncated.key", std::vector<char>(key.begin(), key.begin() + 1000)),
        write("zeros.key", std::vector<char>(key.size(), 0)),
    };
    for (const std::string& p : bad) {
        EXPECT_THROW(ZCJoinSplit::Prepared(p), std::runtime_error) << p;
    }
    // The installed key is still the real one.
    for (const Fixture& f : All()) {
        EXPECT_TRUE(Strict(f)) << "height " << f.height;
    }
    // Loading the real key again is accepted and changes nothing.
    std::unique_ptr<ZCJoinSplit> again(ZCJoinSplit::Prepared(write("again.key", key)));
    EXPECT_TRUE(again != nullptr);
    for (const Fixture& f : All()) {
        EXPECT_TRUE(Strict(f)) << "height " << f.height;
    }
    boost::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Non-canonical and malformed proof encodings, through both doors: the
// consensus path (PHGRProof deserialization, then JSDescription::Verify with
// the strict and the disabled verifier) and the C23 verifier directly
// (zcl_c23_phgr13_proof_decodes, zcl_c23_phgr13_verify). libsnark, as zclassicd
// used it, rejected every vector below. PHGR13_TABLE=1 prints one line per vector.
// ---------------------------------------------------------------------------
namespace {

struct Verdict {
    bool deserializes;
    bool strict;
    bool disabled;
    bool decodes;
    bool direct;
};

Verdict Judge(const Fixture& base, const std::vector<unsigned char>& wire)
{
    Verdict v{true, false, false, false, false};
    try {
        Fixture m = WithWire(base, wire);
        v.strict = Strict(m);
        v.disabled = Disabled(m);
    } catch (const std::ios_base::failure&) {
        v.deserializes = false;
    }
    unsigned char w[ZCL_C23_PHGR13_PROOF_SIZE];
    EXPECT_EQ(wire.size(), (size_t)ZCL_C23_PHGR13_PROOF_SIZE);
    memcpy(w, wire.data(), sizeof(w));
    v.decodes = zcl_c23_phgr13_proof_decodes(w);
    uint256 hsig = ZCJoinSplit::h_sig(base.js.randomSeed, base.js.nullifiers, base.pubKey);
    v.direct = zcl_c23_phgr13_verify(w, base.js.anchor.begin(), hsig.begin(),
                                     base.js.macs[0].begin(), base.js.macs[1].begin(),
                                     base.js.nullifiers[0].begin(), base.js.nullifiers[1].begin(),
                                     base.js.commitments[0].begin(), base.js.commitments[1].begin(),
                                     base.js.vpub_old, base.js.vpub_new);
    return v;
}

// mustNotDecode: the encoding itself is invalid (not just a wrong proof), so
// the decode-only path (what ProofVerifier::Disabled runs) must refuse it too.
void ExpectRejected(const Fixture& base, const std::vector<unsigned char>& wire, const std::string& what,
                    bool mustNotDecode)
{
    const Verdict v = Judge(base, wire);
    if (getenv("PHGR13_TABLE")) {
        fprintf(stderr, "PHGR13_TABLE %-52s deser=%d strict=%d disabled=%d decodes=%d direct_verify=%d\n",
                what.c_str(), v.deserializes, v.strict, v.disabled, v.decodes, v.direct);
    }
    EXPECT_FALSE(v.strict) << what << " (consensus path, strict)";
    EXPECT_FALSE(v.direct) << what << " (zcl_c23_phgr13_verify)";
    if (mustNotDecode) {
        EXPECT_FALSE(v.disabled) << what << " (consensus path, decode only)";
        EXPECT_FALSE(v.decodes) << what << " (zcl_c23_phgr13_proof_decodes)";
    }
}

std::vector<unsigned char> Put(std::vector<unsigned char> w, size_t off, const std::vector<unsigned char>& b)
{
    std::copy(b.begin(), b.end(), w.begin() + off);
    return w;
}

// a += k*b over 256 bits, big-endian; false on carry out of 256 bits.
bool AddMul256(std::vector<unsigned char>& a, const std::vector<unsigned char>& b, unsigned k)
{
    unsigned carry = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned v = a[i] + (unsigned)b[i] * k + carry;
        a[i] = v & 0xff;
        carry = v >> 8;
    }
    return carry == 0;
}

} // namespace

TEST(phgr13_malformed, valid_proof_accepted_by_every_path)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    ASSERT_EQ(f.height, 241);
    const Verdict v = Judge(f, f.wire);
    EXPECT_TRUE(v.deserializes);
    EXPECT_TRUE(v.strict);
    EXPECT_TRUE(v.disabled);
    EXPECT_TRUE(v.decodes);
    EXPECT_TRUE(v.direct);
}

TEST(phgr13_malformed, g2_x_not_reduced)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    const std::vector<unsigned char> q = ParseHex(Q_HEX);
    const size_t c1 = SPANS[2].off + 1; // wire bytes 67..98, the high half of x
    // c1 + k*q for k = 1..5. FE2IP needs c1 < q, so every one that does not wrap
    // past 2^256 is an invalid encoding; a wrapped one is some other value that
    // must still not verify.
    for (unsigned k = 1; k <= 5; k++) {
        std::vector<unsigned char> hi(f.wire.begin() + c1, f.wire.begin() + c1 + 32);
        const bool nowrap = AddMul256(hi, q, k);
        ExpectRejected(f, Put(f.wire, c1, hi), "G2 x high + " + std::to_string(k) + "q", nowrap);
    }
    // c1 = q exactly (c0 unchanged).
    ExpectRejected(f, Put(f.wire, c1, q), "G2 x c1 = q", true);
    // (q, q): the integer is >= q^2.
    std::vector<unsigned char> qq(q);
    qq.insert(qq.end(), q.begin(), q.end());
    ExpectRejected(f, Put(f.wire, c1, qq), "G2 x = (q, q)", true);
    ExpectRejected(f, Put(f.wire, c1, std::vector<unsigned char>(64, 0xff)), "G2 x = 2^512-1", true);
}

TEST(phgr13_malformed, g1_x_not_reduced_and_x_zero)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    const std::vector<unsigned char> q = ParseHex(Q_HEX);
    std::vector<unsigned char> qp1 = q;
    qp1[31] += 1;
    const std::vector<unsigned char> ones(32, 0xff);
    for (const PointSpan& s : SPANS) {
        if (s.g2) continue;
        const std::string at = " at " + std::to_string(s.off);
        ExpectRejected(f, Put(f.wire, s.off + 1, q), "G1 x = q" + at, true);
        ExpectRejected(f, Put(f.wire, s.off + 1, qp1), "G1 x = q+1" + at, true);
        ExpectRejected(f, Put(f.wire, s.off + 1, ones), "G1 x = 2^256-1" + at, true);
        // x = 0 with lead 0x02: (0, sqrt 3) if 3 is a square, else not a point.
        // Never the point at infinity, and never a valid proof.
        std::vector<unsigned char> w = Put(f.wire, s.off + 1, std::vector<unsigned char>(32, 0));
        w[s.off] = 0x02;
        ExpectRejected(f, w, "G1 x = 0 lead 02" + at, false);
    }
}

TEST(phgr13_malformed, lead_bytes_and_infinity)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    const unsigned char g1leads[] = {0x00, 0x01, 0x04, 0x06, 0x07, 0x12, 0x13, 0x82, 0xff};
    const unsigned char g2leads[] = {0x08, 0x0e, 0x0f, 0x1a, 0x8a};
    for (const PointSpan& s : SPANS) {
        const std::string at = " at " + std::to_string(s.off);
        if (!s.g2) {
            for (unsigned char b : g1leads) {
                std::vector<unsigned char> w = f.wire;
                w[s.off] = b;
                char name[64];
                snprintf(name, sizeof(name), "G1 lead %02x", b);
                // The consensus path throws at deserialization; the C23 entry
                // points must refuse it as well.
                ExpectRejected(f, w, name + at, true);
            }
            std::vector<unsigned char> inf(33, 0);
            inf[0] = 0x06;
            ExpectRejected(f, Put(f.wire, s.off, inf), "G1 infinity (06 + 32 zero)" + at, true);
        } else {
            for (unsigned char b : g2leads) {
                std::vector<unsigned char> w = f.wire;
                w[s.off] = b;
                char name[64];
                snprintf(name, sizeof(name), "G2 lead %02x", b);
                ExpectRejected(f, w, name + at, true);
            }
            std::vector<unsigned char> inf(65, 0);
            inf[0] = 0x0e;
            ExpectRejected(f, Put(f.wire, s.off, inf), "G2 infinity (0e + 64 zero)" + at, true);
        }
    }
}

TEST(phgr13_malformed, flipped_parity_and_non_square_x)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    for (const PointSpan& s : SPANS) {
        const std::string at = " at " + std::to_string(s.off);
        std::vector<unsigned char> w = f.wire;
        w[s.off] ^= 1; // y parity (G1) / y_gt (G2): the negated point
        ExpectRejected(f, w, std::string(s.g2 ? "G2 y_gt flipped" : "G1 y parity flipped") + at, false);
    }
    // G1: x values where x^3 + 3 is a non-square. The decoder is the oracle that
    // finds them; each must be refused by the verifier and the decode-only path.
    for (const PointSpan& s : SPANS) {
        if (s.g2) continue;
        int found = 0;
        for (unsigned x = 1; x < 200 && found < 3; x++) {
            std::vector<unsigned char> xb(32, 0);
            xb[31] = (unsigned char)x;
            xb[30] = (unsigned char)(x >> 8);
            std::vector<unsigned char> w = Put(f.wire, s.off + 1, xb);
            unsigned char raw[ZCL_C23_PHGR13_PROOF_SIZE];
            memcpy(raw, w.data(), sizeof(raw));
            if (zcl_c23_phgr13_proof_decodes(raw)) continue; // x is on the curve
            found++;
            ExpectRejected(f, w, "G1 non-square x=" + std::to_string(x) + " at " + std::to_string(s.off), true);
        }
        EXPECT_EQ(found, 3) << "no non-square x found for the point at " << s.off;
    }
}

TEST(phgr13_malformed, off_subgroup_twist_points)
{
    // Twist-curve points outside the order-r subgroup placed in g_B
    // (x = q+2 as FE2IP, both signs).
    const Fixture f = Make(PHGR_VECTORS[0]);
    const char* OFF[] = {
        "0a000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd49",
        "0b000000000000000000000000000000000000000000000000000000000000000030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd49",
    };
    for (const char* hex : OFF) {
        ExpectRejected(f, Put(f.wire, SPANS[2].off, ParseHex(hex)), std::string("g_B off-subgroup lead ") + hex[1], true);
    }
}

TEST(phgr13_malformed, swapped_points_and_public_input)
{
    for (const Fixture& f : All()) {
        const size_t pairs[][2] = {{0, 33}, {164, 197}};
        for (const auto& pr : pairs) {
            std::vector<unsigned char> w = f.wire;
            for (size_t i = 0; i < 33; i++) std::swap(w[pr[0] + i], w[pr[1] + i]);
            ExpectRejected(f, w, "swap " + std::to_string(pr[0]) + "," + std::to_string(pr[1]) +
                                     " h" + std::to_string(f.height), false);
        }
        Fixture g = f;
        g.js.vpub_old += 1;
        ExpectRejected(g, f.wire, "vpub_old+1 h" + std::to_string(f.height), false);
    }
}

TEST(phgr13_malformed, sixteen_threads_all_accept)
{
    const Fixture f = Make(PHGR_VECTORS[0]);
    std::atomic<bool> go(false);
    std::atomic<int> bad(0);
    std::vector<std::thread> threads;
    for (int t = 0; t < 16; t++) {
        threads.emplace_back([&]() {
            while (!go.load()) {}
            for (int i = 0; i < 20; i++) {
                if (!Judge(f, f.wire).strict) bad++;
            }
        });
    }
    go = true;
    for (auto& th : threads) th.join();
    EXPECT_EQ(bad.load(), 0);
}
