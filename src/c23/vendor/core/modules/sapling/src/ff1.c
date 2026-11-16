/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * FF1 format-preserving encryption (NIST SP 800-38G) with AES-256.
 * Implements FF1.Encrypt for radix=2 binary numeral strings. */

#include "sapling/ff1.h"
#include "crypto/aes256.h"
#include "support/cleanse.h"
#include <string.h>

/* Incremental AES CBC-MAC over a stream whose total length is a multiple
 * of 16: bytes are staged one block at a time, never the whole message. */
struct cbcmac_stream {
    const struct aes256_ctx *aes;
    uint8_t mac[16];
    uint8_t blk[16];
    size_t fill;
};

static void cbcmac_init(struct cbcmac_stream *s, const struct aes256_ctx *aes)
{
    s->aes = aes;
    memset(s->mac, 0, sizeof(s->mac));
    memset(s->blk, 0, sizeof(s->blk));
    s->fill = 0;
}

static void cbcmac_absorb_byte(struct cbcmac_stream *s, uint8_t b)
{
    s->blk[s->fill++] = b;
    if (s->fill < 16)
        return;
    for (int i = 0; i < 16; i++)
        s->blk[i] ^= s->mac[i];
    aes256_encrypt(s->aes, s->blk, s->mac);
    s->fill = 0;
}

static void cbcmac_absorb(struct cbcmac_stream *s, const uint8_t *p, size_t len)
{
    for (size_t i = 0; i < len; i++)
        cbcmac_absorb_byte(s, p[i]);
}

static void cbcmac_zeros(struct cbcmac_stream *s, size_t len)
{
    for (size_t i = 0; i < len; i++)
        cbcmac_absorb_byte(s, 0);
}

/* Copy the MAC out and wipe the stream state. */
static void cbcmac_finish(struct cbcmac_stream *s, uint8_t out[16])
{
    memcpy(out, s->mac, 16);
    memory_cleanse(s, sizeof(*s));
}

/* Convert bits [start_bit..start_bit+n_bits) from LE-byte array to BE number */
static void bits_to_be(uint8_t *out, size_t out_len,
                       const uint8_t *le_bytes, size_t start_bit, size_t n_bits)
{
    memset(out, 0, out_len);
    for (size_t i = 0; i < n_bits; i++) {
        size_t src = start_bit + i;
        int val = (le_bytes[src / 8] >> (src % 8)) & 1;
        size_t be_bit = n_bits - 1 - i;
        size_t byte_idx = out_len - 1 - be_bit / 8;
        out[byte_idx] |= (uint8_t)(val << (be_bit % 8));
    }
}

/* Write BE number back to bits [start_bit..start_bit+n_bits) in LE-byte array */
static void be_to_bits(uint8_t *le_bytes, size_t start_bit, size_t n_bits,
                       const uint8_t *be, size_t be_len)
{
    for (size_t i = 0; i < n_bits; i++) {
        size_t dst = start_bit + i;
        size_t be_bit = n_bits - 1 - i;
        size_t byte_idx = be_len - 1 - be_bit / 8;
        int val = (byte_idx < be_len) ? ((be[byte_idx] >> (be_bit % 8)) & 1) : 0;
        if (val)
            le_bytes[dst / 8] |= (uint8_t)(1u << (dst % 8));
        else
            le_bytes[dst / 8] &= (uint8_t)~(1u << (dst % 8));
    }
}

/* a + b mod 2^m, all big-endian, result in out (m_bytes long) */
static void add_mod(uint8_t *out, size_t m_bytes,
                    const uint8_t *a, size_t a_len,
                    const uint8_t *b, size_t b_len, size_t m)
{
    uint8_t wa[32], wb[32];
    memset(wa, 0, 32);
    memset(wb, 0, 32);
    if (a_len <= 32) memcpy(wa + 32 - a_len, a, a_len);
    if (b_len <= 32) memcpy(wb + 32 - b_len, b, b_len);

    uint16_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint16_t s = (uint16_t)wa[i] + wb[i] + carry;
        wa[i] = (uint8_t)s;
        carry = s >> 8;
    }

    memcpy(out, wa + 32 - m_bytes, m_bytes);
    size_t extra = m % 8;
    if (extra > 0)
        out[0] &= (uint8_t)((1u << extra) - 1);
}

void ff1_aes256_encrypt(const uint8_t key[32],
                        const uint8_t *tweak, size_t tweak_len,
                        uint8_t *data, size_t n)
{
    struct aes256_ctx aes;
    aes256_init(&aes, key);

    size_t u = n / 2;
    size_t v = n - u;
    size_t data_bytes = (n + 7) / 8;

    /* P block (16 bytes) */
    uint8_t P[16];
    memset(P, 0, 16);
    P[0] = 1; P[1] = 2; P[2] = 1;
    P[3] = 0; P[4] = 0; P[5] = 2; /* radix=2 in 3 BE bytes */
    P[6] = 10;
    P[7] = (uint8_t)(u & 0xff);
    P[8]  = (uint8_t)((n >> 24) & 0xff);
    P[9]  = (uint8_t)((n >> 16) & 0xff);
    P[10] = (uint8_t)((n >> 8) & 0xff);
    P[11] = (uint8_t)(n & 0xff);
    P[12] = (uint8_t)((tweak_len >> 24) & 0xff);
    P[13] = (uint8_t)((tweak_len >> 16) & 0xff);
    P[14] = (uint8_t)((tweak_len >> 8) & 0xff);
    P[15] = (uint8_t)(tweak_len & 0xff);

    /* Working buffers: left (A) and right (B) as BE numbers */
    uint8_t left[16], right[16];
    memset(left, 0, 16);
    memset(right, 0, 16);
    bits_to_be(left, 16, data, 0, u);
    bits_to_be(right, 16, data, u, v);

    size_t left_bits = u, right_bits = v;

    for (int i = 0; i < 10; i++) {
        size_t m = (i % 2 == 0) ? u : v;
        size_t b = (right_bits + 7) / 8;
        size_t d = 4 * ((b + 3) / 4) + 4;

        /* Q = tweak || zero pad || i_byte || B_bytes, streamed after P */
        size_t q_raw = tweak_len + 1 + b;
        size_t pad = (16 - q_raw % 16) % 16;

        struct cbcmac_stream cm;
        cbcmac_init(&cm, &aes);
        cbcmac_absorb(&cm, P, 16);
        if (tweak_len > 0 && tweak)
            cbcmac_absorb(&cm, tweak, tweak_len);
        else
            cbcmac_zeros(&cm, tweak_len);
        cbcmac_zeros(&cm, pad);
        cbcmac_absorb_byte(&cm, (uint8_t)i);
        cbcmac_absorb(&cm, right + 16 - b, b);

        uint8_t R[16];
        cbcmac_finish(&cm, R);

        uint8_t S[48];
        memcpy(S, R, 16);
        for (size_t j = 1; j * 16 < d + 16; j++) {
            uint8_t block[16];
            memset(block, 0, 16);
            block[15] = (uint8_t)j;
            for (int k = 0; k < 16; k++)
                block[k] ^= R[k];
            aes256_encrypt(&aes, block, S + j * 16);
            memory_cleanse(block, sizeof(block));
        }

        /* c = (num(left) + y) mod 2^m where y = first d bytes of S */
        size_t c_bytes = (m + 7) / 8;
        uint8_t c[16];
        memset(c, 0, 16);
        add_mod(c + 16 - c_bytes, c_bytes,
                left + 16 - ((left_bits + 7) / 8), (left_bits + 7) / 8,
                S, d, m);

        /* Swap: left = old right, right = C */
        memcpy(left, right, 16);
        memset(right, 0, 16);
        memcpy(right + 16 - c_bytes, c + 16 - c_bytes, c_bytes);

        memory_cleanse(c, sizeof(c));
        memory_cleanse(S, sizeof(S));
        memory_cleanse(R, sizeof(R));

        size_t t = left_bits;
        left_bits = right_bits;
        right_bits = t;
    }

    /* Write back */
    memset(data, 0, data_bytes);
    be_to_bits(data, 0, left_bits, left, 16);
    be_to_bits(data, left_bits, right_bits, right, 16);

    memory_cleanse(&aes, sizeof(aes));
}
