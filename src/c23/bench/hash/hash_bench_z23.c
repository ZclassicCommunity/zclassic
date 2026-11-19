// Z23 C23 hash micro-bench: same inputs as hash_bench_base.cpp, built -O3
// from a Z23 checkout (core/modules/crypto), standalone.
#include "bench_common.h"
#include "crypto/sha256.h"
#include "crypto/ripemd160.h"
#include "crypto/blake2b.h"
#include <string.h>
#include <stdlib.h>

static unsigned char sink[64];
static void use(const unsigned char* p, size_t n) { for (size_t i = 0; i < n; i++) sink[i & 63] ^= p[i]; }

static void sha_suite(const char *tag, const unsigned char *raw, size_t BIG)
{
    unsigned char out[64]; char l[96];
    for (size_t off = 0; off < 2; off++) {
        snprintf(l, sizeof l, "%s sha256 bulk 1MiB off=%zu", tag, off);
        HB_RUN(l, BIG, { struct sha256_ctx s; sha256_init(&s); sha256_write(&s, raw + off, BIG); sha256_finalize(&s, out); use(out, 32); });
    }
    size_t ns1[] = {32, 55, 64, 80, 250, 1487};
    for (int i = 0; i < 6; i++) { size_t n = ns1[i];
        snprintf(l, sizeof l, "%s sha256 oneshot %zuB", tag, n);
        HB_RUN(l, n, { struct sha256_ctx s; sha256_init(&s); sha256_write(&s, raw, n); sha256_finalize(&s, out); use(out, 32); });
    }
    size_t ns2[] = {64, 250, 1487};
    for (int i = 0; i < 3; i++) { size_t n = ns2[i];
        snprintf(l, sizeof l, "%s dsha256 %zuB", tag, n);
        HB_RUN(l, n, { struct sha256_ctx s; unsigned char t[32]; sha256_init(&s); sha256_write(&s, raw, n); sha256_finalize(&s, t);
                       sha256_init(&s); sha256_write(&s, t, 32); sha256_finalize(&s, out); use(out, 32); });
    }
    snprintf(l, sizeof l, "%s SHA256Compress combine (64B no pad)", tag);
    HB_RUN(l, 64, { struct sha256_ctx s; sha256_init(&s); sha256_write(&s, raw, 32); sha256_write(&s, raw + 32, 32);
                    sha256_finalize_no_padding(&s, out, 1); use(out, 32); });
}

int main(void)
{
    const size_t BIG = 1 << 20;
    unsigned char *raw = malloc(BIG + 64), out[64];
    for (size_t i = 0; i < BIG + 64; i++) raw[i] = (unsigned char)(i * 131 + 7);
    printf("Z23 sha256 impl: %s\n", sha256_implementation());
    sha_suite("[auto]", raw, BIG);
    sha256_select_impl(SHA256_IMPL_PORTABLE);
    printf("Z23 sha256 impl: %s\n", sha256_implementation());
    sha_suite("[portable]", raw, BIG);
    sha256_select_impl(SHA256_IMPL_AUTO);

    char l[96];
    size_t r1[] = {32, 64};
    for (int i = 0; i < 2; i++) { size_t n = r1[i];
        snprintf(l, sizeof l, "ripemd160 oneshot %zuB", n);
        HB_RUN(l, n, { struct ripemd160_ctx r; ripemd160_init(&r); ripemd160_write(&r, raw, n); ripemd160_finalize(&r, out); use(out, 20); });
    }
    HB_RUN("ripemd160 bulk 1MiB", BIG, { struct ripemd160_ctx r; ripemd160_init(&r); ripemd160_write(&r, raw, BIG); ripemd160_finalize(&r, out); use(out, 20); });
    size_t h1[] = {33, 65};
    for (int i = 0; i < 2; i++) { size_t n = h1[i];
        snprintf(l, sizeof l, "Hash160 %zuB (pubkey)", n);
        HB_RUN(l, n, { struct sha256_ctx s; struct ripemd160_ctx r; unsigned char t[32];
            sha256_init(&s); sha256_write(&s, raw, n); sha256_finalize(&s, t);
            ripemd160_init(&r); ripemd160_write(&r, t, 32); ripemd160_finalize(&r, out); use(out, 20); });
    }
    HB_RUN("blake2b bulk 1MiB (z23 scalar)", BIG, { blake2b(out, 32, raw, BIG, NULL, 0); use(out, 32); });
    unsigned char pers[16] = {'Z','c','a','s','h','P','o','W', 200, 0, 0, 0, 9, 0, 0, 0};
    for (int cfg = 0; cfg < 2; cfg++) {
        size_t hlen = cfg == 0 ? 50 : 48;
        struct blake2b_ctx base; blake2b_init_salt_personal(&base, hlen, NULL, 0, NULL, pers);
        blake2b_update(&base, raw, 140);
        snprintf(l, sizeof l, "equihash GenerateHash hLen=%zu (4B idx)", hlen);
        uint32_t g = 0;
        HB_RUN(l, 144, { struct blake2b_ctx st = base; uint32_t le = g++;
            blake2b_update(&st, &le, 4); blake2b_final(&st, out, hlen); use(out, 8); });
        enum blake2b_batch_impl tiers[] = {BLAKE2B_BATCH_IMPL_SCALAR, BLAKE2B_BATCH_IMPL_AVX2, BLAKE2B_BATCH_IMPL_AVX512};
        for (int t = 0; t < 3; t++) {
            equihash_blake2b_batch_select_impl(tiers[t]);
            snprintf(l, sizeof l, "equihash batch8 hLen=%zu [%s] per 8", hlen, equihash_blake2b_batch_implementation());
            unsigned char hb[8][64]; unsigned char *hp[8]; for (int k = 0; k < 8; k++) hp[k] = hb[k];
            uint32_t idx[8];
            HB_RUN(l, 8 * 144, { for (int k = 0; k < 8; k++) idx[k] = g++; equihash_generate_hash_batch8(&base, idx, hp, hlen); use(hb[0], 8); });
        }
        equihash_blake2b_batch_select_impl(BLAKE2B_BATCH_IMPL_AUTO);
    }
    size_t p1[] = {36, 100, 400, 1500};
    for (int i = 0; i < 4; i++) { size_t n = p1[i];
        snprintf(l, sizeof l, "blake2b personalised %zuB -> 32", n);
        HB_RUN(l, n, { struct blake2b_ctx st; blake2b_init_salt_personal(&st, 32, NULL, 0, NULL, pers);
            blake2b_update(&st, raw, n); blake2b_final(&st, out, 32); use(out, 32); });
    }
    return sink[0] == 0xff;
}

/* Stubs for the Z23 logger: only reached on error paths, never timed. */
#include "base/log_level.h"
enum zcl_log_level zcl_log_level_get(void) { return (enum zcl_log_level)99; }
void zcl_log_emit_at(enum zcl_log_level level, const char *fmt, ...) { (void)level; (void)fmt; }
