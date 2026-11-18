// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Differential test: the accept/reject verdict of the daemon's Sprout PHGR13
// verification against libsnark. The reference is the real pre-removal
// src/zcash/Proof.cpp, PHGRProof deserialization, gadget.tcc witness_map and
// r1cs_ppzksnark_online_verifier_strong_IC, built from the commit before libsnark was
// deleted (build.sh). The candidate is what the daemon builds now: the vendored
// bn254.c, the shim zcl_c23_phgr13.c and the current Proof.cpp, reached through the
// hooks of phgr13_c23.h (phgr13_adapter*.c*). The "Z23RAW" column is the shim without
// the C++ lead-byte check in front of it.
//
//   phgr13_gate all <sprout-verifying.key> <g1_compressed.json> <g2_compressed.json> <blocks-dir|-> [mutated-proofs]
//   phgr13_gate bench <sprout-verifying.key> <blocks-dir|->
//
// Every disagreement between libsnark and the candidate is printed with its bytes
// and makes the exit status non-zero.
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"
#include "streams.h"
#include "version.h"
#include "uint256.h"

#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libsnark/common/profiling.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp>
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp>

#include <sodium.h>
#include <boost/foreach.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <map>
#include <set>
#include <random>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "sapling/bn254.h"
}
#include "phgr13_c23.h"

using namespace libsnark;

namespace libzcash {
#include "zcash/circuit/gadget.tcc"
}

typedef alt_bn128_pp curve_pp;
typedef alt_bn128_pp::G1_type curve_G1;
typedef alt_bn128_pp::G2_type curve_G2;
typedef alt_bn128_pp::Fq_type curve_Fq;
typedef alt_bn128_pp::Fqe_type curve_Fq2;
typedef Fr<curve_pp> FieldT;

// ── Reference: zclassicd's verify, line for line (JoinSplit.cpp:114-150) ──

struct RefVk {
    r1cs_ppzksnark_verification_key<curve_pp> vk;
    r1cs_ppzksnark_processed_verification_key<curve_pp> pvk;
};

static std::string slurp(const std::string &path)
{
    std::ifstream f(path, std::ios::binary);
    std::stringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

// JoinSplit.cpp:48-67 loadFromFile + JoinSplit.cpp:81 process_vk.
static void ref_vk_load(RefVk &out, const std::string &bytes)
{
    std::stringstream ss;
    ss << bytes;
    ss.rdbuf()->pubseekpos(0, std::ios_base::in);
    r1cs_ppzksnark_verification_key<curve_pp> obj;
    ss >> obj;
    out.vk = std::move(obj);
    out.pvk = r1cs_ppzksnark_verifier_process_vk(out.vk);
}

struct JS {
    uint8_t proof[296];
    uint8_t rt[32], hsig[32], nf[2][32], mac[2][32], cm[2][32];
    uint64_t vpub_old, vpub_new;
};

static uint256 u256(const uint8_t b[32])
{
    uint256 r;
    memcpy(r.begin(), b, 32);
    return r;
}

// Deserialization (Proof.hpp:206-216, which throws on a bad lead byte and so
// rejects the whole transaction) followed by JoinSplitCircuit::verify.
static bool ref_verify(RefVk &rv, const JS &j)
{
    libzcash::PHGRProof proof;
    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write((const char *)j.proof, 296);
        ss >> proof;
        if (!ss.empty())
            return false;
    } catch (...) {
        return false;
    }
    static libzcash::ProofVerifier verifier = libzcash::ProofVerifier::Strict();
    try {
        auto r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<curve_pp>>();
        std::array<uint256, 2> macs = {u256(j.mac[0]), u256(j.mac[1])};
        std::array<uint256, 2> nfs = {u256(j.nf[0]), u256(j.nf[1])};
        std::array<uint256, 2> cms = {u256(j.cm[0]), u256(j.cm[1])};
        auto witness = libzcash::joinsplit_gadget<FieldT, 2, 2>::witness_map(
            u256(j.rt), u256(j.hsig), macs, nfs, cms, j.vpub_old, j.vpub_new);
        return verifier.check(rv.vk, rv.pvk, witness, r1cs_proof);
    } catch (...) {
        return false;
    }
}

static bool cand_verify(const zc23_phgr13_vk *vk, const JS &j)
{
    return zc23_phgr13_verify(vk, j.proof, j.rt, j.hsig, j.nf[0], j.nf[1], j.mac[0], j.mac[1],
                              j.cm[0], j.cm[1], j.vpub_old, j.vpub_new);
}

static bool raw_verify(const zc23_phgr13_vk *vk, const JS &j)
{
    return zc23_phgr13_verify_z23_raw(vk, j.proof, j.rt, j.hsig, j.nf[0], j.nf[1], j.mac[0], j.mac[1],
                                      j.cm[0], j.cm[1], j.vpub_old, j.vpub_new);
}

// ── helpers ────────────────────────────────────────────────────────

static std::string hex(const uint8_t *p, size_t n)
{
    static const char *d = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; i++) {
        s += d[p[i] >> 4];
        s += d[p[i] & 15];
    }
    return s;
}

static bool unhex(const std::string &h, std::vector<uint8_t> &out)
{
    if (h.size() % 2) return false;
    out.clear();
    for (size_t i = 0; i < h.size(); i += 2) {
        unsigned v;
        if (sscanf(h.c_str() + i, "%2x", &v) != 1) return false;
        out.push_back((uint8_t)v);
    }
    return true;
}

static void fq_be(uint8_t out[32], const curve_Fq &x)
{
    auto b = x.as_bigint();
    for (int i = 0; i < 4; i++)
        for (int k = 0; k < 8; k++)
            out[i * 8 + k] = (uint8_t)(b.data[3 - i] >> (56 - 8 * k));
}

static void g1_affine_be(uint8_t out[64], curve_G1 p)
{
    if (p.is_zero()) { memset(out, 0, 64); return; }
    p.to_affine_coordinates();
    fq_be(out, p.X);
    fq_be(out + 32, p.Y);
}

static void g2_affine_be(uint8_t out[128], curve_G2 p)
{
    if (p.is_zero()) { memset(out, 0, 128); return; }
    p.to_affine_coordinates();
    fq_be(out, p.X.c0);
    fq_be(out + 32, p.X.c1);
    fq_be(out + 64, p.Y.c0);
    fq_be(out + 96, p.Y.c1);
}

static curve_Fq fq_from_be(const uint8_t b[32])
{
    bigint<4> v;
    for (int i = 0; i < 4; i++) {
        uint64_t w = 0;
        for (int k = 0; k < 8; k++) w = (w << 8) | b[i * 8 + k];
        v.data[3 - i] = w;
    }
    return curve_Fq(v);
}

// Reference decode of one compressed point: deserialize + to_libsnark_*.
static bool ref_g1_decode(const uint8_t in[33], uint8_t out[64])
{
    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write((const char *)in, 33);
        libzcash::CompressedG1 c;
        ss >> c;
        g1_affine_be(out, c.to_libsnark_g1<curve_G1>());
        return true;
    } catch (...) {
        return false;
    }
}

static bool ref_g2_decode(const uint8_t in[65], uint8_t out[128])
{
    try {
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write((const char *)in, 65);
        libzcash::CompressedG2 c;
        ss >> c;
        g2_affine_be(out, c.to_libsnark_g2<curve_G2>());
        return true;
    } catch (...) {
        return false;
    }
}

// Raw Z23 decoders, unwrapped (parity report only).
static bool raw_g1_decode(const uint8_t in[33], uint8_t out[64])
{
    struct bn_g1 p;
    if (!bn_g1_decompress(&p, in)) return false;
    if (bn_g1_is_identity(&p)) { memset(out, 0, 64); return true; }
    struct bn_fq x, y;
    bn_g1_to_affine(&x, &y, &p);
    bn_fq_to_bytes_be(out, &x);
    bn_fq_to_bytes_be(out + 32, &y);
    return true;
}

static bool raw_g2_decode(const uint8_t in[65], uint8_t out[128])
{
    struct bn_g2 p;
    if (!bn_g2_decompress(&p, in)) return false;
    if (bn_g2_is_identity(&p)) { memset(out, 0, 128); return true; }
    struct bn_fq2 x, y;
    bn_g2_to_affine(&x, &y, &p);
    bn_fq_to_bytes_be(out, &x.c0);
    bn_fq_to_bytes_be(out + 32, &x.c1);
    bn_fq_to_bytes_be(out + 64, &y.c0);
    bn_fq_to_bytes_be(out + 96, &y.c1);
    return true;
}

static void compress_g1(uint8_t out[33], const curve_G1 &p)
{
    libzcash::CompressedG1 c(p);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << c;
    memcpy(out, &ss[0], 33);
}

static void compress_g2(uint8_t out[65], const curve_G2 &p)
{
    libzcash::CompressedG2 c(p);
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << c;
    memcpy(out, &ss[0], 65);
}

// ── counters ───────────────────────────────────────────────────────

struct Tally {
    std::map<std::string, long> cases, ref_accept, cand_dis, raw_dis;
    long total_cand_dis = 0, total_raw_dis = 0;
};
static Tally T;
static int g_raw_print_budget = 40;

static void record(const std::string &cls, bool ref, bool cand, bool raw,
                   const std::string &bytes_hex)
{
    T.cases[cls]++;
    if (ref) T.ref_accept[cls]++;
    if (ref != cand) {
        T.cand_dis[cls]++;
        T.total_cand_dis++;
        printf("CANDIDATE-DISAGREE class=%s ref=%d cand=%d bytes=%s\n", cls.c_str(), ref, cand,
               bytes_hex.c_str());
    }
    if (ref != raw) {
        T.raw_dis[cls]++;
        T.total_raw_dis++;
        if (g_raw_print_budget-- > 0)
            printf("Z23RAW-DISAGREE class=%s ref=%d raw=%d bytes=%s\n", cls.c_str(), ref, raw,
                   bytes_hex.c_str());
    }
}

// ── point-level differential ───────────────────────────────────────

static void diff_g1(const std::string &cls, const uint8_t in[33])
{
    uint8_t a[64], b[64], c[64];
    bool r = ref_g1_decode(in, a), k = zc23_phgr13_g1_decode(in, b), z = raw_g1_decode(in, c);
    bool kk = k && (!r || memcmp(a, b, 64) == 0);
    bool zz = z && (!r || memcmp(a, c, 64) == 0);
    // A coordinate mismatch on a both-accept counts as a disagreement.
    record(cls, r, r ? kk : k, r ? zz : z, hex(in, 33));
}

static void diff_g2(const std::string &cls, const uint8_t in[65])
{
    uint8_t a[128], b[128], c[128];
    bool r = ref_g2_decode(in, a), k = zc23_phgr13_g2_decode(in, b), z = raw_g2_decode(in, c);
    bool kk = k && (!r || memcmp(a, b, 128) == 0);
    bool zz = z && (!r || memcmp(a, c, 128) == 0);
    record(cls, r, r ? kk : k, r ? zz : z, hex(in, 65));
}

static std::vector<std::string> json_strings(const std::string &path)
{
    std::vector<std::string> out;
    std::string s = slurp(path);
    size_t p = 0;
    while ((p = s.find('"', p)) != std::string::npos) {
        size_t e = s.find('"', p + 1);
        if (e == std::string::npos) break;
        out.push_back(s.substr(p + 1, e - p - 1));
        p = e + 1;
    }
    return out;
}

static const uint8_t Q_BE[32] = {
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47};

// big-endian add: a += b (n bytes), returns carry
static int be_add(uint8_t *a, const uint8_t *b, size_t n)
{
    int c = 0;
    for (size_t i = n; i-- > 0;) {
        int s = a[i] + b[i] + c;
        a[i] = (uint8_t)s;
        c = s >> 8;
    }
    return c;
}

// x (n bytes BE) += q * 2^(8*shift_bytes)
static int be_add_q_shifted(uint8_t *x, size_t n, size_t shift_bytes)
{
    std::vector<uint8_t> t(n, 0);
    if (32 + shift_bytes > n) return 1;
    memcpy(&t[n - 32 - shift_bytes], Q_BE, 32);
    return be_add(x, t.data(), n);
}

static void q_squared_be(uint8_t out[64])
{
    bigint<4> q = curve_Fq::field_char();
    bigint<8> qq;
    mpn_mul_n(qq.data, q.data, q.data, 4);
    for (int i = 0; i < 8; i++)
        for (int k = 0; k < 8; k++)
            out[i * 8 + k] = (uint8_t)(qq.data[7 - i] >> (56 - 8 * k));
}

static void g1_mutations(const uint8_t base[33], std::mt19937_64 &rng, bool exhaustive_lead)
{
    uint8_t m[33];
    if (exhaustive_lead) {
        for (int lb = 0; lb < 256; lb++) {
            memcpy(m, base, 33); m[0] = (uint8_t)lb; diff_g1("g1.lead_byte", m);
        }
    }
    for (int bit = 0; bit < 256; bit += 37) {
        memcpy(m, base, 33); m[1 + (31 - bit / 8)] ^= (uint8_t)(1 << (bit % 8)); diff_g1("g1.x_bitflip", m);
    }
    memcpy(m, base, 33);
    if (!be_add(m + 1, Q_BE, 32)) diff_g1("g1.x_plus_q", m);
    memcpy(m, base, 33); memcpy(m + 1, Q_BE, 32); diff_g1("g1.x_eq_q", m);
    memcpy(m, base, 33); memset(m + 1, 0xff, 32); diff_g1("g1.x_all_ff", m);
    memcpy(m, base, 33); memset(m + 1, 0, 32); diff_g1("g1.x_zero", m);
    for (uint8_t lb : {0x04, 0x05, 0x06, 0x07, 0x0c, 0x0e, 0x0f, 0x44, 0xff}) {
        memset(m, 0, 33); m[0] = lb; diff_g1("g1.infinity_encoding", m);
    }
    for (int i = 0; i < 4; i++) {
        memcpy(m, base, 33);
        for (int k = 1; k < 33; k++) m[k] = (uint8_t)rng();
        m[1] &= 0x3f;
        diff_g1("g1.random_x", m);
    }
}

static void g2_mutations(const uint8_t base[65], std::mt19937_64 &rng, bool exhaustive_lead)
{
    uint8_t m[65], qq[64];
    q_squared_be(qq);
    if (exhaustive_lead) {
        for (int lb = 0; lb < 256; lb++) {
            memcpy(m, base, 65); m[0] = (uint8_t)lb; diff_g2("g2.lead_byte", m);
        }
    }
    for (int bit = 0; bit < 512; bit += 61) {
        memcpy(m, base, 65); m[1 + (63 - bit / 8)] ^= (uint8_t)(1 << (bit % 8)); diff_g2("g2.x_bitflip", m);
    }
    // FE2IP non-canonical: + q^2 (c1 >= q), + q*2^256 (quotient above 2^256),
    // c1 := q exactly, combined = q^2, q^2 - 1, all ff.
    memcpy(m, base, 65); if (!be_add(m + 1, qq, 64)) diff_g2("g2.fe2ip_plus_q2", m);
    memcpy(m, base, 65); if (!be_add_q_shifted(m + 1, 64, 32)) diff_g2("g2.fe2ip_plus_q_2pow256", m);
    {
        // c1 = q: combined = q*q + c0 with c0 = base's c0 (base mod q)
        // computed as (base - c1*q) + q*q via libsnark bigints.
        bigint<8> comb;
        for (int i = 0; i < 8; i++) {
            uint64_t w = 0;
            for (int k = 0; k < 8; k++) w = (w << 8) | base[1 + i * 8 + k];
            comb.data[7 - i] = w;
        }
        bigint<4> q = curve_Fq::field_char();
        bigint<5> quo;
        bigint<4> rem;
        mpn_tdiv_qr(quo.data, rem.data, 0, comb.data, 8, q.data, 4);
        bigint<8> res;
        mpn_mul_n(res.data, q.data, q.data, 4);
        mpn_add(res.data, res.data, 8, rem.data, 4);
        memcpy(m, base, 65);
        for (int i = 0; i < 8; i++)
            for (int k = 0; k < 8; k++) m[1 + i * 8 + k] = (uint8_t)(res.data[7 - i] >> (56 - 8 * k));
        diff_g2("g2.fe2ip_c1_eq_q", m);
    }
    memcpy(m, base, 65); memcpy(m + 1, qq, 64); diff_g2("g2.fe2ip_eq_q2", m);
    memcpy(m, base, 65); memcpy(m + 1, qq, 64);
    for (int i = 63; i >= 0; i--) { if (m[1 + i]--) break; }
    diff_g2("g2.fe2ip_q2_minus_1", m);
    memcpy(m, base, 65); memset(m + 1, 0xff, 64); diff_g2("g2.fe2ip_all_ff", m);
    memcpy(m, base, 65); memset(m + 1, 0, 64); diff_g2("g2.x_zero", m);
    for (uint8_t lb : {0x04, 0x05, 0x0e, 0x0f, 0x06, 0x4e, 0xff}) {
        memset(m, 0, 65); m[0] = lb; diff_g2("g2.infinity_encoding", m);
    }
    for (int i = 0; i < 3; i++) {
        memcpy(m, base, 65);
        for (int k = 1; k < 65; k++) m[k] = (uint8_t)rng();
        m[1] &= 0x07;
        diff_g2("g2.random_x", m);
    }
}

// On-curve twist points outside the order-r subgroup (gtest test_proofs.cpp:69-128).
static curve_G2 off_subgroup_point(std::mt19937_64 &rng)
{
    (void)rng;
    curve_G2 p = curve_G2::one();
    for (;;) {
        p.X = curve_Fq2::random_element();
        try {
            p.Y = ((p.X.squared() * p.X) + alt_bn128_twist_coeff_b).sqrt();
            p.Z = curve_Fq2::one();
            if (alt_bn128_modulus_r * p != curve_G2::zero()) return p;
        } catch (...) {
        }
    }
}

static void point_level(const std::string &g1json, const std::string &g2json, std::mt19937_64 &rng)
{
    auto g1 = json_strings(g1json);
    auto g2 = json_strings(g2json);
    std::vector<uint8_t> b;
    size_t n1 = 0, n2 = 0;
    for (size_t i = 0; i < g1.size(); i++) {
        if (!unhex(g1[i], b) || b.size() != 33) continue;
        n1++;
        diff_g1("g1.vector", b.data());
        if (i % 50 == 0) g1_mutations(b.data(), rng, i < 200);
    }
    for (size_t i = 0; i < g2.size(); i++) {
        if (!unhex(g2[i], b) || b.size() != 65) continue;
        n2++;
        diff_g2("g2.vector", b.data());
        if (i % 50 == 0) g2_mutations(b.data(), rng, i < 200);
    }
    printf("point vectors: g1=%zu g2=%zu\n", n1, n2);
    // random G1/G2 group elements, both y signs
    for (int i = 0; i < 2000; i++) {
        uint8_t m[65];
        compress_g1(m, curve_G1::random_element());
        diff_g1("g1.random_point", m);
        m[0] ^= 1; diff_g1("g1.random_point_negy", m);
    }
    for (int i = 0; i < 500; i++) {
        uint8_t m[65];
        compress_g2(m, curve_G2::random_element());
        diff_g2("g2.random_point", m);
        m[0] ^= 1; diff_g2("g2.random_point_negy", m);
    }
    for (int i = 0; i < 200; i++) {
        uint8_t m[65];
        curve_G2 p = off_subgroup_point(rng);
        compress_g2(m, p);
        diff_g2("g2.off_subgroup", m);
        m[0] ^= 1; diff_g2("g2.off_subgroup", m);
    }
    // Fq2 square roots, including elements of Fq (c1 = 0), where the vendored
    // G2 decoder's root finder fails (finding F5).
    for (int i = 0; i < 4000; i++) {
        curve_Fq2 a = curve_Fq2::random_element();
        if (i % 2 == 0) a.c1 = curve_Fq::zero();
        uint8_t in[64], out[64];
        fq_be(in, a.c0); fq_be(in + 32, a.c1);
        bool r = true;
        curve_Fq2 s;
        try { s = a.sqrt(); } catch (...) { r = false; }
        bool k = zc23_phgr13_fq2_sqrt(in, out);
        bool kk = k;
        if (r && k) {
            curve_Fq2 got(fq_from_be(out), fq_from_be(out + 32));
            kk = (got == s || got == -s);
        }
        record(i % 2 ? "fq2.sqrt_random" : "fq2.sqrt_in_fq", r, r ? kk : k, r ? kk : k, hex(in, 64));
    }
}

// ── pairing at infinity: libsnark (0,1) precompute vs Z23 identity ──

static void z23_g1(struct bn_g1 *o, curve_G1 p)
{
    p.to_affine_coordinates();
    uint8_t b[32];
    fq_be(b, p.X); bn_fq_from_bytes_be(&o->x, b);
    fq_be(b, p.Y); bn_fq_from_bytes_be(&o->y, b);
    bn_fq_one(&o->z);
}

static void z23_g2(struct bn_g2 *o, curve_G2 p)
{
    p.to_affine_coordinates();
    uint8_t b[32];
    fq_be(b, p.X.c0); bn_fq_from_bytes_be(&o->x.c0, b);
    fq_be(b, p.X.c1); bn_fq_from_bytes_be(&o->x.c1, b);
    fq_be(b, p.Y.c0); bn_fq_from_bytes_be(&o->y.c0, b);
    fq_be(b, p.Y.c1); bn_fq_from_bytes_be(&o->y.c1, b);
    bn_fq2_one(&o->z);
}

static void infinity_pairing()
{
    for (int i = 0; i < 50; i++) {
        curve_G1 r1 = curve_G1::random_element();
        curve_G2 r2 = curve_G2::random_element();
        // libsnark: e(0, r2) * e(r1, r2) * e(r1, r2)^-1 == 1, through the
        // same precompute(zero) path the verifier takes when A+acc == 0.
        auto ml = curve_pp::double_miller_loop(curve_pp::precompute_G1(curve_G1::zero()),
                                               curve_pp::precompute_G2(r2),
                                               curve_pp::precompute_G1(r1),
                                               curve_pp::precompute_G2(r2));
        auto ml2 = curve_pp::miller_loop(curve_pp::precompute_G1(r1), curve_pp::precompute_G2(r2));
        bool ref = curve_pp::final_exponentiation(ml * ml2.unitary_inverse()) == alt_bn128_GT::one();
        struct bn_g1 a[3];
        struct bn_g2 b[3];
        bn_g1_identity(&a[0]);
        z23_g1(&a[1], r1);
        z23_g1(&a[2], -r1);
        z23_g2(&b[0], r2); z23_g2(&b[1], r2); z23_g2(&b[2], r2);
        bool z = bn254_multi_pairing_check(a, b, 3);
        record("pairing.g1_infinity", ref, z, z, "-");
        // and a non-trivial product must not collapse to one in either
        bool ref2 = curve_pp::final_exponentiation(ml) == alt_bn128_GT::one();
        bool z2 = bn254_multi_pairing_check(a, b, 2);
        record("pairing.g1_infinity_nontrivial", ref2, z2, z2, "-");
    }
}

// ── block scan ─────────────────────────────────────────────────────

struct Reader {
    const uint8_t *p, *e;
    bool ok = true;
    bool need(size_t n) { if ((size_t)(e - p) < n) { ok = false; return false; } return true; }
    uint64_t u(int n) { if (!need(n)) return 0; uint64_t v = 0; for (int i = 0; i < n; i++) v |= (uint64_t)p[i] << (8 * i); p += n; return v; }
    uint64_t cs() {
        if (!need(1)) return 0;
        uint8_t c = *p++;
        if (c < 253) return c;
        if (c == 253) return u(2);
        if (c == 254) return u(4);
        return u(8);
    }
    void skip(uint64_t n) { if (!need(n)) return; p += n; }
    void get(uint8_t *o, size_t n) { if (!need(n)) return; memcpy(o, p, n); p += n; }
};

static const uint8_t HSIG_PERS[16] = {'Z','c','a','s','h','C','o','m','p','u','t','e','h','S','i','g'};

static void parse_tx(Reader &r, std::vector<JS> &out, long &groth)
{
    uint32_t header = (uint32_t)r.u(4);
    bool over = header >> 31;
    uint32_t ver = header & 0x7fffffff;
    uint32_t vgid = 0;
    if (over) vgid = (uint32_t)r.u(4);
    uint64_t nin = r.cs();
    for (uint64_t i = 0; i < nin && r.ok; i++) { r.skip(36); r.skip(r.cs()); r.skip(4); }
    uint64_t nout = r.cs();
    for (uint64_t i = 0; i < nout && r.ok; i++) { r.skip(8); r.skip(r.cs()); }
    r.skip(4);
    bool sapling = over && vgid == 0x892f2085 && ver >= 4;
    if (over) r.skip(4);
    uint64_t nsp = 0, nso = 0;
    if (sapling) {
        r.skip(8);
        nsp = r.cs(); r.skip(nsp * 384);
        nso = r.cs(); r.skip(nso * 948);
    }
    if (ver >= 2) {
        uint64_t njs = r.cs();
        bool use_groth = over && ver >= 4;
        std::vector<JS> tmp;
        std::vector<uint8_t> seeds;
        for (uint64_t i = 0; i < njs && r.ok; i++) {
            JS j;
            uint8_t eph[32], seed[32];
            j.vpub_old = r.u(8);
            j.vpub_new = r.u(8);
            r.get(j.rt, 32);
            r.get(j.nf[0], 32); r.get(j.nf[1], 32);
            r.get(j.cm[0], 32); r.get(j.cm[1], 32);
            r.get(eph, 32);
            r.get(seed, 32);
            r.get(j.mac[0], 32); r.get(j.mac[1], 32);
            if (use_groth) { r.skip(192); groth++; }
            else r.get(j.proof, 296);
            r.skip(2 * 601);
            if (!use_groth) { tmp.push_back(j); seeds.insert(seeds.end(), seed, seed + 32); }
        }
        if (njs > 0) {
            uint8_t pk[32];
            r.get(pk, 32);
            r.skip(64);
            for (size_t i = 0; i < tmp.size() && r.ok; i++) {
                uint8_t blk[128];
                memcpy(blk, &seeds[i * 32], 32);
                memcpy(blk + 32, tmp[i].nf[0], 32);
                memcpy(blk + 64, tmp[i].nf[1], 32);
                memcpy(blk + 96, pk, 32);
                crypto_generichash_blake2b_salt_personal(tmp[i].hsig, 32, blk, 128, NULL, 0, NULL, HSIG_PERS);
                out.push_back(tmp[i]);
            }
        }
    }
    if (sapling && (nsp + nso) > 0) r.skip(64);
}

static std::vector<JS> scan_blocks(const std::string &dir, long &blocks, long &txs, long &bad, long &groth)
{
    std::vector<JS> out;
    std::vector<std::string> files;
    if (DIR *d = opendir(dir.c_str())) {
        while (struct dirent *e = readdir(d)) {
            std::string n = e->d_name;
            if (n.size() == 12 && n.compare(0, 3, "blk") == 0 && n.compare(8, 4, ".dat") == 0)
                files.push_back(dir + "/" + n);
        }
        closedir(d);
    }
    std::sort(files.begin(), files.end());
    for (auto &f : files) {
        std::string data = slurp(f);
        const uint8_t *p = (const uint8_t *)data.data(), *e = p + data.size();
        while (e - p >= 8) {
            if (!(p[0] == 0x24 && p[1] == 0xe9 && p[2] == 0x27 && p[3] == 0x64)) { p++; continue; }
            uint32_t sz = p[4] | p[5] << 8 | p[6] << 16 | (uint32_t)p[7] << 24;
            if ((size_t)(e - p - 8) < sz) break;
            Reader r{p + 8, p + 8 + sz};
            r.skip(4 + 32 + 32 + 32 + 4 + 4 + 32);
            r.skip(r.cs());
            uint64_t ntx = r.cs();
            std::vector<JS> got;
            long g = 0;
            for (uint64_t i = 0; i < ntx && r.ok; i++) parse_tx(r, got, g);
            blocks++;
            if (r.ok && r.p == r.e) {
                txs += (long)ntx;
                out.insert(out.end(), got.begin(), got.end());
                groth += g;
            } else {
                bad++;
            }
            p += 8 + sz;
        }
    }
    return out;
}

// ── proof-level mutations ──────────────────────────────────────────

static const size_t OFF[8] = {0, 33, 66, 131, 164, 197, 230, 263};
static const char *NAME[8] = {"A", "A'", "B", "B'", "C", "C'", "K", "H"};
static size_t elen(int i) { return i == 2 ? 65 : 33; }

static void diff_js(RefVk &rv, const zc23_phgr13_vk *vk, const std::string &cls, const JS &j)
{
    bool r = ref_verify(rv, j), k = cand_verify(vk, j), z = raw_verify(vk, j);
    std::string b = hex(j.proof, 296) + ":" + hex(j.rt, 32) + ":" + hex(j.hsig, 32) + ":" +
                    hex(j.nf[0], 32) + hex(j.nf[1], 32) + ":" + hex(j.mac[0], 32) + hex(j.mac[1], 32) +
                    ":" + hex(j.cm[0], 32) + hex(j.cm[1], 32) + ":" + std::to_string(j.vpub_old) + ":" +
                    std::to_string(j.vpub_new);
    record(cls, r, k, z, b);
}

static void proof_mutations(RefVk &rv, const zc23_phgr13_vk *vk, const JS &base, std::mt19937_64 &rng)
{
    JS m;
    uint8_t qq[64];
    q_squared_be(qq);
    for (int e = 0; e < 8; e++) {
        uint8_t *el;
        std::string pre = std::string("proof.") + NAME[e] + ".";
        // y-sign flip, x bit flips
        m = base; m.proof[OFF[e]] ^= 1; diff_js(rv, vk, pre + "sign_flip", m);
        for (int t = 0; t < 3; t++) {
            m = base; el = m.proof + OFF[e];
            size_t bytes = elen(e) - 1;
            size_t bit = rng() % (bytes * 8);
            el[1 + bit / 8] ^= (uint8_t)(1 << (bit % 8));
            diff_js(rv, vk, pre + "x_bitflip", m);
        }
        m = base; m.proof[OFF[e] + 1] ^= 0x80; diff_js(rv, vk, pre + "x_topbit", m);
        // wrong lead bytes
        for (uint8_t lb : {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x0a, 0x0b, 0x0e, 0x0f, 0x12, 0x82, 0xff}) {
            m = base; m.proof[OFF[e]] = lb; diff_js(rv, vk, pre + "lead_byte", m);
            m = base; m.proof[OFF[e]] = (uint8_t)(lb ^ 1); diff_js(rv, vk, pre + "lead_byte", m);
        }
        // non-canonical encodings
        if (e != 2) {
            m = base; el = m.proof + OFF[e];
            if (!be_add(el + 1, Q_BE, 32)) diff_js(rv, vk, pre + "x_plus_q", m);
            m = base; memcpy(m.proof + OFF[e] + 1, Q_BE, 32); diff_js(rv, vk, pre + "x_eq_q", m);
        } else {
            m = base; el = m.proof + OFF[e];
            if (!be_add(el + 1, qq, 64)) diff_js(rv, vk, pre + "fe2ip_plus_q2", m);
            m = base; el = m.proof + OFF[e];
            if (!be_add_q_shifted(el + 1, 64, 32)) diff_js(rv, vk, pre + "fe2ip_plus_q_2pow256", m);
        }
        // infinity encodings
        m = base; el = m.proof + OFF[e];
        memset(el, 0, elen(e)); el[0] = e == 2 ? 0x0e : 0x06; diff_js(rv, vk, pre + "infinity", m);
        m = base; el = m.proof + OFF[e];
        memset(el, 0, elen(e)); el[0] = 0x04; diff_js(rv, vk, pre + "infinity", m);
        // not on curve / off subgroup
        if (e != 2) {
            for (;;) {
                curve_Fq x = curve_Fq::random_element();
                bool sq = true;
                try { ((x.squared() * x) + alt_bn128_coeff_b).sqrt(); } catch (...) { sq = false; }
                if (sq) continue;
                m = base; el = m.proof + OFF[e];
                fq_be(el + 1, x);
                diff_js(rv, vk, pre + "not_on_curve", m);
                break;
            }
        } else {
            for (int t = 0; t < 2; t++) {
                m = base;
                compress_g2(m.proof + OFF[e], off_subgroup_point(rng));
                diff_js(rv, vk, pre + "off_subgroup", m);
            }
            for (;;) {
                curve_Fq2 x = curve_Fq2::random_element();
                bool sq = true;
                try { ((x.squared() * x) + alt_bn128_twist_coeff_b).sqrt(); } catch (...) { sq = false; }
                if (sq) continue;
                m = base; el = m.proof + OFF[e];
                el[0] = 0x0a;
                bigint<8> comb;
                auto c0 = x.c0.as_bigint(), c1 = x.c1.as_bigint();
                bigint<4> q = curve_Fq::field_char();
                mpn_mul_n(comb.data, c1.data, q.data, 4);
                mpn_add(comb.data, comb.data, 8, c0.data, 4);
                for (int i = 0; i < 8; i++)
                    for (int k = 0; k < 8; k++) el[1 + i * 8 + k] = (uint8_t)(comb.data[7 - i] >> (56 - 8 * k));
                diff_js(rv, vk, pre + "not_on_curve", m);
                break;
            }
        }
        // replace with a random valid group element
        m = base;
        if (e == 2) compress_g2(m.proof + OFF[e], curve_G2::random_element());
        else compress_g1(m.proof + OFF[e], curve_G1::random_element());
        diff_js(rv, vk, pre + "random_point", m);
    }
    // swapped G1 elements
    int g1s[7] = {0, 1, 3, 4, 5, 6, 7};
    for (int a = 0; a < 7; a++)
        for (int b = a + 1; b < 7; b++) {
            m = base;
            uint8_t t[33];
            memcpy(t, m.proof + OFF[g1s[a]], 33);
            memcpy(m.proof + OFF[g1s[a]], m.proof + OFF[g1s[b]], 33);
            memcpy(m.proof + OFF[g1s[b]], t, 33);
            diff_js(rv, vk, "proof.swap_g1", m);
        }
    // knowledge pairs both at infinity (raw Z23 passes the knowledge check)
    for (int pr = 0; pr < 3; pr++) {
        m = base;
        int x = pr == 0 ? 0 : pr == 1 ? 2 : 4, y = pr == 0 ? 1 : pr == 1 ? 3 : 5;
        memset(m.proof + OFF[x], 0, elen(x)); m.proof[OFF[x]] = x == 2 ? 0x0e : 0x06;
        memset(m.proof + OFF[y], 0, 33); m.proof[OFF[y]] = 0x06;
        diff_js(rv, vk, "proof.pair_infinity", m);
    }
    // all signs flipped
    m = base; for (int e = 0; e < 8; e++) m.proof[OFF[e]] ^= 1; diff_js(rv, vk, "proof.all_signs", m);
    // public inputs
    uint8_t *fields[8] = {m.rt, m.hsig, m.nf[0], m.nf[1], m.mac[0], m.mac[1], m.cm[0], m.cm[1]};
    const char *fname[8] = {"rt", "h_sig", "nf1", "nf2", "mac1", "mac2", "cm1", "cm2"};
    for (int f = 0; f < 8; f++) {
        for (int bit : {0, 7, 255, (int)(rng() % 256)}) {
            m = base;
            uint8_t *fl[8] = {m.rt, m.hsig, m.nf[0], m.nf[1], m.mac[0], m.mac[1], m.cm[0], m.cm[1]};
            fl[f][bit / 8] ^= (uint8_t)(1 << (bit % 8));
            diff_js(rv, vk, std::string("input.") + fname[f], m);
        }
    }
    (void)fields;
    for (uint64_t v : {base.vpub_old ^ 1, base.vpub_old + 1, (uint64_t)1 << 63, UINT64_MAX}) {
        m = base; m.vpub_old = v; diff_js(rv, vk, "input.vpub_old", m);
    }
    for (uint64_t v : {base.vpub_new ^ 1, base.vpub_new + 1, (uint64_t)1 << 63, UINT64_MAX}) {
        m = base; m.vpub_new = v; diff_js(rv, vk, "input.vpub_new", m);
    }
    m = base; std::swap(m.nf[0], m.nf[1]); diff_js(rv, vk, "input.swap_nf", m);
    m = base; std::swap(m.cm[0], m.cm[1]); diff_js(rv, vk, "input.swap_cm", m);
    m = base; std::swap(m.mac[0], m.mac[1]); diff_js(rv, vk, "input.swap_mac", m);
    m = base; std::swap(m.vpub_old, m.vpub_new); diff_js(rv, vk, "input.swap_vpub", m);
}

// Z23's KAT (tests/harness/src/test_sprout_phgr13_kat.c @ origin/main).
static JS kat_241()
{
    JS j;
    std::vector<uint8_t> b;
    unhex("03285153c3029f3e5955395ca617498d8ae3db7d2c5904103f71b4d67ccc1e408a021e63826bac468e89a96f47d4878a"
          "775af18971b5b94167e3772402b735cac47b0a0521402661d91c8d7bd00ac04da33e6604c5d578f9d6317ecb0618d4f7"
          "a6755e94fca74453a74a328b09dc11831210442ed7ef2ebabcde71187f92f6be87455503201c1713b784fa09e5657a67"
          "a917515a9e833ab65c9a773e8f96993b4777de850309af0cb0a057a18c17e956d5db9066c2d38c4b885e3931f1f9cf8a"
          "1b380a7688032ec70722fff9ecd43afc06ee53a580cf6d139844f1bc7c6b0a1e762e64509417020ed0097f4ea82d6b1f"
          "ba4eb831743f1dfe220e48d26a356d2ba19345850cbb0a0312f3b2990da9df24195260c531b4b17c726cb9a2f03503ea"
          "16044cf9306e201f", b);
    memcpy(j.proof, b.data(), 296);
    unhex("d7c612c817793191a1e68652121876d6b3bde40f4fa52bc314145ce6e5cdd259", b); memcpy(j.rt, b.data(), 32);
    unhex("ce79461df91ca43c3da7e715e43845fc7054b4cf8fc1291f72015bebc56e31cd", b); memcpy(j.hsig, b.data(), 32);
    unhex("b65e0e165f5daef5311098467772c00486739c420f1c47d7ecf490cb5b1df051", b); memcpy(j.mac[0], b.data(), 32);
    unhex("957b152d1ce122fdbe75debbde06b3fb26264e2414939c62fb715a6bec723d4a", b); memcpy(j.mac[1], b.data(), 32);
    unhex("c2f4f6342207af5ffa181fb1d1b6bac3496f2ae476b55a4a1da0d7ff2584d34b", b); memcpy(j.nf[0], b.data(), 32);
    unhex("99fe254e53c66639a81140a64e277dfe3eaf251e302122794e3dc30d6e563b3b", b); memcpy(j.nf[1], b.data(), 32);
    unhex("869e92d09df2362aed6cb367554d94fa9ec2dd40211aef204e4a963fbb56bc04", b); memcpy(j.cm[0], b.data(), 32);
    unhex("dfee184b5cb8a50461ca21f0f409fd4a1b17d3139a367af95367556a9acf77e0", b); memcpy(j.cm[1], b.data(), 32);
    j.vpub_old = 1249990000ULL;
    j.vpub_new = 0;
    return j;
}

static void check_packing(const JS &j)
{
    std::array<uint256, 2> macs = {u256(j.mac[0]), u256(j.mac[1])};
    std::array<uint256, 2> nfs = {u256(j.nf[0]), u256(j.nf[1])};
    std::array<uint256, 2> cms = {u256(j.cm[0]), u256(j.cm[1])};
    auto w = libzcash::joinsplit_gadget<FieldT, 2, 2>::witness_map(u256(j.rt), u256(j.hsig), macs, nfs, cms,
                                                                   j.vpub_old, j.vpub_new);
    uint64_t mine[9][4];
    zc23_phgr13_pack_inputs(mine, j.rt, j.hsig, j.nf[0], j.nf[1], j.mac[0], j.mac[1], j.cm[0], j.cm[1],
                            j.vpub_old, j.vpub_new);
    bool same = w.size() == 9;
    for (size_t i = 0; same && i < 9; i++) {
        auto b = w[i].as_bigint();
        for (int k = 0; k < 4; k++) same = same && b.data[k] == mine[i][k];
    }
    record("input.packing", true, same, same, hex(j.rt, 32));
}

static double now_ms()
{
    return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

static double median(std::vector<double> v)
{
    std::sort(v.begin(), v.end());
    return v[v.size() / 2];
}

static std::string loadavg()
{
    std::string s = slurp("/proc/loadavg");
    while (!s.empty() && (s.back() == '\n')) s.pop_back();
    return s;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s all <vk> <g1.json> <g2.json> <blocks|-> [mutated]\n"
                        "       %s bench <vk> <blocks|->\n", argv[0], argv[0]);
        return 2;
    }
    if (sodium_init() < 0) return 2;
    inhibit_profiling_info = true;
    inhibit_profiling_counters = true;
    libzcash::initialize_curve_params();
    std::string mode = argv[1];
    std::string vkbytes = slurp(argv[2]);

    RefVk rv;
    ref_vk_load(rv, vkbytes);
    zc23_phgr13_vk *vk = zc23_phgr13_vk_load((const uint8_t *)vkbytes.data(), vkbytes.size());
    if (!vk) { printf("FAIL: candidate could not load the verifying key\n"); return 1; }

    if (mode == "bench") {
        std::vector<JS> proofs;
        proofs.push_back(kat_241());
        if (std::string(argv[3]) != "-") {
            long b = 0, t = 0, bad = 0, g = 0;
            auto s = scan_blocks(argv[3], b, t, bad, g);
            if (!s.empty()) proofs.push_back(s[s.size() / 2]);
        }
        printf("load before: %s\n", loadavg().c_str());
        for (size_t pi = 0; pi < proofs.size(); pi++) {
            const JS &j = proofs[pi];
            std::vector<double> a, b;
            if (!ref_verify(rv, j) || !cand_verify(vk, j)) { printf("bench proof %zu not valid\n", pi); return 1; }
            for (int i = 0; i < 21; i++) {
                double t0 = now_ms(); bool r = ref_verify(rv, j); double t1 = now_ms();
                bool k = cand_verify(vk, j); double t2 = now_ms();
                if (!r || !k) return 1;
                a.push_back(t1 - t0); b.push_back(t2 - t1);
            }
            printf("verify proof%zu (ms, median of 21): libsnark=%.3f candidate=%.3f ratio=%.2f\n", pi,
                   median(a), median(b), median(b) / median(a));
        }
        std::vector<double> a, b;
        for (int i = 0; i < 21; i++) {
            double t0 = now_ms();
            { RefVk x; ref_vk_load(x, slurp(argv[2])); }
            double t1 = now_ms();
            { std::string s = slurp(argv[2]); zc23_phgr13_vk_free(zc23_phgr13_vk_load((const uint8_t *)s.data(), s.size())); }
            double t2 = now_ms();
            a.push_back(t1 - t0); b.push_back(t2 - t1);
        }
        printf("vk load incl. file read + process/warm (ms, median of 21): libsnark=%.3f candidate=%.3f\n",
               median(a), median(b));
        printf("load after: %s\n", loadavg().c_str());
        zc23_phgr13_vk_free(vk);
        return 0;
    }

    if (argc < 6) return 2;
    std::mt19937_64 rng(0x7068677231335ULL);
    // PHGR13_SHARD=k/n: verify only real proofs with index % n == k; shard 0
    // alone also runs the point-level, mutation and random classes.
    size_t shard_k = 0, shard_n = 1;
    if (const char *sh = getenv("PHGR13_SHARD")) {
        if (sscanf(sh, "%zu/%zu", &shard_k, &shard_n) != 2 || shard_n == 0 || shard_k >= shard_n) return 2;
    }
    const bool lead = shard_k == 0;

    // 1. verifying key: both parsers produce the same points.
    if (lead) {
        std::vector<uint8_t> mine(8192);
        size_t n = zc23_phgr13_vk_export(vk, mine.data(), mine.size());
        std::vector<uint8_t> ref;
        uint8_t t[128];
        g2_affine_be(t, rv.vk.alphaA_g2); ref.insert(ref.end(), t, t + 128);
        g1_affine_be(t, rv.vk.alphaB_g1); ref.insert(ref.end(), t, t + 64);
        g2_affine_be(t, rv.vk.alphaC_g2); ref.insert(ref.end(), t, t + 128);
        g2_affine_be(t, rv.vk.gamma_g2); ref.insert(ref.end(), t, t + 128);
        g1_affine_be(t, rv.vk.gamma_beta_g1); ref.insert(ref.end(), t, t + 64);
        g2_affine_be(t, rv.vk.gamma_beta_g2); ref.insert(ref.end(), t, t + 128);
        g2_affine_be(t, rv.vk.rC_Z_g2); ref.insert(ref.end(), t, t + 128);
        g1_affine_be(t, rv.vk.encoded_IC_query.first); ref.insert(ref.end(), t, t + 64);
        size_t dom = rv.vk.encoded_IC_query.domain_size();
        for (size_t i = 0; i < dom; i++) {
            curve_G1 p = curve_G1::zero();
            for (size_t k = 0; k < rv.vk.encoded_IC_query.rest.indices.size(); k++)
                if (rv.vk.encoded_IC_query.rest.indices[k] == i) p = rv.vk.encoded_IC_query.rest.values[k];
            g1_affine_be(t, p); ref.insert(ref.end(), t, t + 64);
        }
        bool same = n == ref.size() && memcmp(mine.data(), ref.data(), n) == 0;
        printf("vk: libsnark domain=%zu points-bytes=%zu candidate-bytes=%zu identical=%d\n", dom, ref.size(), n, same);
        record("vk.points", true, same, same, "-");
    }

    // 2. point-level decode differential + Fq2 sqrt + pairing at infinity.
    if (lead) {
        point_level(argv[3], argv[4], rng);
        infinity_pairing();
    }

    // 3. real proofs: Z23 KAT + every PHGR13 JoinSplit in the block files.
    std::vector<JS> real;
    real.push_back(kat_241());
    long blocks = 0, txs = 0, bad = 0, groth = 0;
    if (std::string(argv[5]) != "-") {
        auto s = scan_blocks(argv[5], blocks, txs, bad, groth);
        // Block files can hold the same block twice (re-downloads, stale
        // forks); verify each distinct JoinSplit statement once.
        std::set<std::string> seen;
        for (auto &j : s) {
            std::string key((const char *)&j, sizeof(JS));
            if (seen.insert(key).second) real.push_back(j);
        }
        printf("scan: blocks=%ld parsed-txs=%ld unparsed-blocks=%ld phgr13-joinsplits=%zu distinct=%zu groth16-joinsplits=%ld\n",
               blocks, txs, bad, s.size(), real.size() - 1, groth);
    }
    double t0 = now_ms();
    size_t mine = 0;
    for (size_t i = shard_k; i < real.size(); i += shard_n) {
        diff_js(rv, vk, i == 0 ? "real.z23_kat_241" : "real.mainnet", real[i]);
        if (i < 64) check_packing(real[i]);
        if (++mine % 2000 == 0) { printf("  shard %zu real %zu  %.1fs\n", shard_k, mine, (now_ms() - t0) / 1000); fflush(stdout); }
    }

    // 4. mutations of a sample of real proofs.
    size_t nmut = !lead ? 0 : argc > 6 ? (size_t)atol(argv[6]) : 12;
    for (size_t s = 0; s < nmut && s < real.size(); s++) {
        size_t idx = s == 0 ? 0 : (size_t)(rng() % real.size());
        proof_mutations(rv, vk, real[idx], rng);
    }
    // 5. random invalid proofs (PHGRProof::random_invalid, Proof.cpp:203-217).
    for (int i = 0; lead && i < 200; i++) {
        JS m = real[rng() % real.size()];
        auto p = libzcash::PHGRProof::random_invalid();
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << p;
        memcpy(m.proof, &ss[0], 296);
        diff_js(rv, vk, "proof.random_invalid", m);
    }

    printf("\n%-34s %9s %9s %9s %9s\n", "class", "cases", "ref-acc", "cand-dis", "z23raw-dis");
    long tc = 0;
    for (auto &kv : T.cases) {
        tc += kv.second;
        printf("%-34s %9ld %9ld %9ld %9ld\n", kv.first.c_str(), kv.second, T.ref_accept[kv.first],
               T.cand_dis[kv.first], T.raw_dis[kv.first]);
    }
    printf("TOTAL cases=%ld candidate-disagreements=%ld z23raw-disagreements=%ld\n", tc, T.total_cand_dis,
           T.total_raw_dis);
    zc23_phgr13_vk_free(vk);
    return T.total_cand_dis == 0 ? 0 : 1;
}
