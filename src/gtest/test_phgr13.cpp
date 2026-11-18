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
        boost::filesystem::temp_directory_path() / boost::filesystem::unique_path("phgr13-vk-%%%%%%%%");
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
