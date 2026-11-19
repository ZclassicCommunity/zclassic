/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Pedersen hash for Sapling Merkle tree — pure C23 implementation.
 * Precomputed chunk-multiple tables on the Jubjub Pedersen generators
 * (BLS12-381 Fr base field): each 3-bit window decodes to v = ±m with
 * m in {1,2,3,4} at radix 16^chunk, so the per-segment scalar multiply
 * becomes table lookups and point additions, one mixed addition per two
 * chunks. The summed point is exactly [scalar]·G — byte-identical output to
 * the naive scalar-mul form. */

#include "sapling/pedersen_hash.h"
#include "sapling/sapling.h"
#include "sapling/fr.h"
#include <assert.h>
#include <pthread.h>
#include <string.h>
#include "util/log_macros.h"

#ifdef ZCL_TESTING
#include <stdatomic.h>
#endif

#define PEDERSEN_CHUNKS_PER_GENERATOR 63
#define PEDERSEN_NUM_GENERATORS PEDERSEN_SEGMENT_GENERATORS
/* Per-chunk window magnitude values: the (a,b,c) encoding yields
 * v = ±(1 + a + 2b), so m spans 1..4 (4 table slots per chunk). */
#define PEDERSEN_TABLE_SLOTS 4

static struct jub_point cached_generators[PEDERSEN_NUM_GENERATORS];
static pthread_once_t generators_once = PTHREAD_ONCE_INIT;

/* s_chunk_tables[seg][chunk][m-1] = m · 16^chunk · G_seg in extended
 * twisted-Edwards coordinates. The per-chunk radix is 16, matching the
 * scalar accumulation this replaces: each chunk doubles cur once for
 * the b-term setup and three more times at the end (cur: C -> 16C).
 * ~193 KB of read-only-after-init data. */
static struct jub_point
    s_chunk_tables[PEDERSEN_NUM_GENERATORS][PEDERSEN_CHUNKS_PER_GENERATOR]
                  [PEDERSEN_TABLE_SLOTS];
static pthread_once_t s_tables_once = PTHREAD_ONCE_INIT;

/* s_pair_tables[seg][p][i] covers chunks 2p and 2p+1 of a segment in one
 * addition: with i = slot0 | slot1 << 2 | flip << 4 the entry is
 *     m0 · 16^(2p) · G_seg  +  s · m1 · 16^(2p+1) · G_seg,
 * m = slot + 1 and s = -1 when flip is set. flip is the XOR of the two
 * chunks' sign bits; when chunk 2p itself is negative the whole entry is
 * subtracted. Entries are prepared affine points (jub_add_niels), so a pair of
 * chunks costs 7 field multiplications where two extended additions cost 20.
 * The 63rd chunk of a segment, and a chunk the input ends on, have no partner
 * and still go through s_chunk_tables. ~571 KB, read-only after init. */
#define PEDERSEN_PAIRS_PER_GENERATOR (PEDERSEN_CHUNKS_PER_GENERATOR / 2)
#define PEDERSEN_PAIR_SLOTS 32
static struct jub_niels
    s_pair_tables[PEDERSEN_NUM_GENERATORS][PEDERSEN_PAIRS_PER_GENERATOR]
                 [PEDERSEN_PAIR_SLOTS];
static_assert(PEDERSEN_PAIR_SLOTS <= JUB_NIELS_BATCH_MAX,
              "a pair row is converted to affine in one batch");

#ifdef ZCL_TESTING
/* Observability for concurrent-first-caller race. Post-fix the
 * pthread_once guarantees exactly one execution of the init body. */
_Atomic int zcl_pedersen_generators_body_runs_for_test = 0;

void zcl_pedersen_generators_reset_for_test(void)
{
    /* Reassigning a pthread_once_t is not specified by POSIX but is
     * the canonical test-only trick on glibc (the type is a plain int
     * with PTHREAD_ONCE_INIT == 0). Only safe to call when no other
     * thread is racing — the race tests join all workers first.
     * The chunk tables derive deterministically from the generators,
     * so they must be re-armed together: a reset that re-derived the
     * generators while leaving the tables armed would leave no caller
     * that ever re-runs the generator body (body_runs assertion). */
    generators_once = (pthread_once_t)PTHREAD_ONCE_INIT;
    memset(cached_generators, 0, sizeof(cached_generators));
    s_tables_once = (pthread_once_t)PTHREAD_ONCE_INIT;
    memset(s_chunk_tables, 0, sizeof(s_chunk_tables));
    memset(s_pair_tables, 0, sizeof(s_pair_tables));
    atomic_store(&zcl_pedersen_generators_body_runs_for_test, 0);
}
#endif

/* Derive Pedersen hash generators via find_group_hash("Zcash_PH", index).
 * The tag is the 4-byte LE segment index followed by a counter byte. */
static void load_generators(void)
{
#ifdef ZCL_TESTING
    atomic_fetch_add(&zcl_pedersen_generators_body_runs_for_test, 1);
#endif

    const uint8_t pers[8] = {'Z','c','a','s','h','_','P','H'};

    for (int i = 0; i < PEDERSEN_NUM_GENERATORS; i++) {
        /* Tag: 4-byte LE segment index + counter byte */
        uint8_t tag[5];
        tag[0] = (uint8_t)(i & 0xff);
        tag[1] = (uint8_t)((i >> 8) & 0xff);
        tag[2] = (uint8_t)((i >> 16) & 0xff);
        tag[3] = (uint8_t)((i >> 24) & 0xff);

        /* Try counter values until group_hash succeeds */
        for (int c = 0; c < 256; c++) {
            tag[4] = (uint8_t)c;
            if (group_hash(&cached_generators[i], tag, 5, pers))
                break;
        }
    }
}

static void ensure_generators(void)
{
    pthread_once(&generators_once, load_generators);
}

/* Build the chunk-multiple tables from the generators. Chunk 0 holds
 * {1,2,3,4}·G_seg; each later chunk quadruple-doubles the previous row
 * (16^chunk · m · G_seg — the per-chunk radix is 16: the replaced scalar
 * loop doubled cur once for the b-term setup and three more times at the
 * end of every chunk). Cost is ~6k point operations, one-time —
 * about two naive Pedersen combines. */
static void load_chunk_tables(void)
{
    ensure_generators();
    for (int seg = 0; seg < PEDERSEN_NUM_GENERATORS; seg++) {
        struct jub_point *row0 = s_chunk_tables[seg][0];
        row0[0] = cached_generators[seg];          /* 1·G */
        jub_double(&row0[1], &row0[0]);            /* 2·G */
        jub_add(&row0[2], &row0[1], &row0[0]);     /* 3·G */
        jub_double(&row0[3], &row0[1]);            /* 4·G */
        for (int c = 1; c < PEDERSEN_CHUNKS_PER_GENERATOR; c++) {
            for (int m = 0; m < PEDERSEN_TABLE_SLOTS; m++) {
                struct jub_point p;
                jub_double(&p, &s_chunk_tables[seg][c - 1][m]);
                jub_double(&p, &p);
                jub_double(&p, &p);
                jub_double(&s_chunk_tables[seg][c][m], &p);
            }
        }
    }
}

/* Build the pair tables from the chunk tables: every sum of one multiple of
 * chunk 2p with one signed multiple of chunk 2p+1, normalised a row at a
 * time. ~6k additions and 186 inversions, one-time. */
static void load_pair_tables(void)
{
    for (int seg = 0; seg < PEDERSEN_NUM_GENERATORS; seg++) {
        for (int p = 0; p < PEDERSEN_PAIRS_PER_GENERATOR; p++) {
            struct jub_point row[PEDERSEN_PAIR_SLOTS];
            for (int i = 0; i < PEDERSEN_PAIR_SLOTS; i++) {
                struct jub_point hi = s_chunk_tables[seg][2 * p + 1][(i >> 2) & 3];
                if (i >> 4)
                    jub_neg(&hi, &hi);
                jub_add(&row[i], &s_chunk_tables[seg][2 * p][i & 3], &hi);
            }
            jub_to_niels_batch(s_pair_tables[seg][p], row, PEDERSEN_PAIR_SLOTS);
        }
    }
}

static void load_tables(void)
{
    load_chunk_tables();
    load_pair_tables();
}

static void ensure_chunk_tables(void)
{
    pthread_once(&s_tables_once, load_tables);
}

bool pedersen_segment_generator(size_t index, struct jub_point *out)
{
    if (!out || index >= PEDERSEN_NUM_GENERATORS)
        LOG_FAIL("pedersen",
                 "segment_generator: index %zu out of range (max %d) or NULL out",
                 index, PEDERSEN_NUM_GENERATORS - 1);
    ensure_generators();
    *out = cached_generators[index];
    return true;
}

/* One 3-bit window: bits (a,b,c) select v = ±(1 + a + 2b), with a missing
 * trailing bit read as 0. slot = m - 1. */
struct pedersen_chunk {
    unsigned slot;
    bool negative;
};

static struct pedersen_chunk pedersen_read_chunk(const uint8_t *bits, int nbits,
                                                 int *bit_pos)
{
    uint8_t v[3] = {0, 0, 0};
    for (int k = 0; k < 3 && *bit_pos < nbits; k++)
        v[k] = bits[(*bit_pos)++];
    return (struct pedersen_chunk){ (unsigned)(v[0] + 2 * v[1]), v[2] != 0 };
}

/* result += the segment's contribution: v · 16^chunk · G_seg summed over its
 * chunks — the exact summands of the scalar the naive form accumulated in Fs,
 * so the segment total is the same group element. Chunks are taken two at a
 * time while a partner exists. */
static void pedersen_add_segment(struct jub_point *result, int seg,
                                 const uint8_t *bits, int nbits, int *bit_pos)
{
    for (int chunk = 0; chunk < PEDERSEN_CHUNKS_PER_GENERATOR; chunk += 2) {
        if (*bit_pos >= nbits)
            return;
        struct pedersen_chunk lo = pedersen_read_chunk(bits, nbits, bit_pos);
        if (chunk + 1 >= PEDERSEN_CHUNKS_PER_GENERATOR || *bit_pos >= nbits) {
            struct jub_point term = s_chunk_tables[seg][chunk][lo.slot];
            if (lo.negative)
                jub_neg(&term, &term);
            jub_add(result, result, &term);
            return;
        }
        struct pedersen_chunk hi = pedersen_read_chunk(bits, nbits, bit_pos);
        unsigned flip = (unsigned)(lo.negative != hi.negative);
        jub_add_niels(result, result,
                      &s_pair_tables[seg][chunk / 2]
                                    [lo.slot | hi.slot << 2 | flip << 4],
                      lo.negative);
    }
}

/* Core Pedersen hash over pre-assembled bits (personalization already included) */
void pedersen_hash_bits(const uint8_t *bits, int nbits,
                         struct jub_point *result_pt)
{
    ensure_chunk_tables();

    jub_identity(result_pt);

    int bit_pos = 0;
    for (int seg = 0; seg < PEDERSEN_NUM_GENERATORS && bit_pos < nbits; seg++)
        pedersen_add_segment(result_pt, seg, bits, nbits, &bit_pos);
}

void pedersen_merkle_hash(size_t depth,
                           const uint8_t a[32],
                           const uint8_t b[32],
                           uint8_t result[32])
{
    /* Extract bits: 6 personalization + 255 from a + 255 from b = 516 bits */
    uint8_t bits[516];
    int nbits = 0;

    /* Personalization: depth as 6 LE bits */
    for (int i = 0; i < 6; i++)
        bits[nbits++] = (depth >> i) & 1;

    /* a: 255 bits, LE (bit 0 of byte 0 first) */
    for (int i = 0; i < 255; i++)
        bits[nbits++] = (a[i / 8] >> (i % 8)) & 1;

    /* b: 255 bits, LE */
    for (int i = 0; i < 255; i++)
        bits[nbits++] = (b[i / 8] >> (i % 8)) & 1;

    struct jub_point result_pt;
    pedersen_hash_bits(bits, nbits, &result_pt);

    struct fr x_coord;
    jub_get_x(&x_coord, &result_pt);
    fr_to_bytes(result, &x_coord);
}

void sapling_uncommitted(uint8_t out[32])
{
    memset(out, 0, 32);
    out[0] = 1;
}
