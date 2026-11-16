// zclassicd baseline hash micro-bench: links the SAME objects the daemon links
// (libbitcoin_crypto.a CSHA256/CRIPEMD160, depends libsodium BLAKE2b).
#include "bench_common.h"
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"
#include "hash.h"
#include <sodium.h>
#include <string.h>
#include <vector>

static unsigned char sink[64];
static void use(const unsigned char* p, size_t n) { for (size_t i = 0; i < n; i++) sink[i & 63] ^= p[i]; }

int main()
{
    if (sodium_init() < 0) return 1;
    printf("libsodium %s  avx2=%d sse41=%d ssse3=%d avx512f=%d\n", sodium_version_string(),
           sodium_runtime_has_avx2(), sodium_runtime_has_sse41(), sodium_runtime_has_ssse3(),
           sodium_runtime_has_avx512f());
    const size_t BIG = 1 << 20;
    std::vector<unsigned char> raw(BIG + 64);
    for (size_t i = 0; i < raw.size(); i++) raw[i] = (unsigned char)(i * 131 + 7);
    unsigned char out[64];

    for (size_t off : {0u, 1u}) {
        char l[64]; snprintf(l, sizeof l, "sha256 bulk 1MiB off=%zu", (size_t)off);
        HB_RUN(l, BIG, { CSHA256 s; s.Write(raw.data() + off, BIG); s.Finalize(out); use(out, 32); });
    }
    for (size_t n : {32u, 55u, 64u, 80u, 250u, 1487u}) {
        char l[64]; snprintf(l, sizeof l, "sha256 oneshot %zuB", n);
        HB_RUN(l, n, { CSHA256 s; s.Write(raw.data(), n); s.Finalize(out); use(out, 32); });
    }
    for (size_t n : {64u, 250u, 1487u}) {
        char l[64]; snprintf(l, sizeof l, "dsha256 (CHash256) %zuB", n);
        HB_RUN(l, n, { CHash256 h; h.Write(raw.data(), n); h.Finalize(out); use(out, 32); });
    }
    HB_RUN("merkle node Hash(64B) via Hash()", 64, {
        uint256 r = Hash(raw.begin(), raw.begin() + 64); use((const unsigned char*)&r, 32); });
    HB_RUN("SHA256Compress combine (64B no pad)", 64, {
        CSHA256 s; s.Write(raw.data(), 32); s.Write(raw.data() + 32, 32); s.FinalizeNoPadding(out); use(out, 32); });
    for (size_t n : {32u, 64u}) {
        char l[64]; snprintf(l, sizeof l, "ripemd160 oneshot %zuB", n);
        HB_RUN(l, n, { CRIPEMD160 r; r.Write(raw.data(), n); r.Finalize(out); use(out, 20); });
    }
    HB_RUN("ripemd160 bulk 1MiB", BIG, { CRIPEMD160 r; r.Write(raw.data(), BIG); r.Finalize(out); use(out, 20); });
    for (size_t n : {33u, 65u}) {
        char l[64]; snprintf(l, sizeof l, "Hash160 %zuB (pubkey)", n);
        HB_RUN(l, n, { CHash160 h; h.Write(raw.data(), n); h.Finalize(out); use(out, 20); });
    }
    HB_RUN("blake2b bulk 1MiB (sodium)", BIG, {
        crypto_generichash_blake2b_state st; crypto_generichash_blake2b_init(&st, NULL, 0, 32);
        crypto_generichash_blake2b_update(&st, raw.data(), BIG); crypto_generichash_blake2b_final(&st, out, 32); use(out, 32); });
    unsigned char pers[16] = {'Z','c','a','s','h','P','o','W', 200, 0, 0, 0, 9, 0, 0, 0};
    for (int cfg = 0; cfg < 2; cfg++) {
        size_t hlen = cfg == 0 ? 50 : 48;
        crypto_generichash_blake2b_state base;
        crypto_generichash_blake2b_init_salt_personal(&base, NULL, 0, hlen, NULL, pers);
        crypto_generichash_blake2b_update(&base, raw.data(), 140);
        char l[64]; snprintf(l, sizeof l, "equihash GenerateHash hLen=%zu (4B idx)", hlen);
        uint32_t g = 0;
        HB_RUN(l, 144, { crypto_generichash_blake2b_state st = base; uint32_t le = g++;
            crypto_generichash_blake2b_update(&st, (const unsigned char*)&le, 4);
            crypto_generichash_blake2b_final(&st, out, hlen); use(out, 8); });
    }
    for (size_t n : {36u, 100u, 400u, 1500u}) {
        char l[64]; snprintf(l, sizeof l, "blake2b personalised %zuB -> 32", n);
        HB_RUN(l, n, { crypto_generichash_blake2b_state st;
            crypto_generichash_blake2b_init_salt_personal(&st, NULL, 0, 32, NULL, pers);
            crypto_generichash_blake2b_update(&st, raw.data(), n);
            crypto_generichash_blake2b_final(&st, out, 32); use(out, 32); });
    }
    return sink[0] == 0xff;
}
