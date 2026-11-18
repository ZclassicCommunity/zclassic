/* slpverify: replay raw ZClassic blocks and judge every SLP Token Type 1 transaction with the
 * validity rules vendored from Z23 (src/c23/services/glue/zcl_slp_index.c: zcl_slp_evaluate, the
 * decision rules of Z23's contexts/market/models/src/zslp_validity.c, and zcl_slp_parse_message,
 * which forwards to Z23's slp_parse unmodified).
 *
 * A test tool (qa/rpc-tests/zslp_send.sh compiles it). Not installed, not linked into any zclassic
 * binary. It is a SECOND, independent implementation of everything around the rules: it parses the
 * raw block and transaction bytes itself, hashes with its own SHA-256, and keeps its own ledger of
 * unspent token outputs and per-transaction results. It shares nothing with the C++ index (src/zslp)
 * except the rule function, so the two can be compared on the same chain.
 *
 *   slpverify <blocks.hex> [min_slp_transactions]
 *
 * blocks.hex: one serialized block per line in hex, heights 1, 2, 3, ... (the genesis block is
 * left out). Transparent transactions only: a transaction with shielded data is skipped over
 * (it cannot carry ZSLP tokens) but still parsed for its length.
 *
 * Output, all on stdout, one record per line:
 *   tx <txid> <GENESIS|MINT|SEND> <valid|invalid|unknown> <reason>
 *   token <tokenid> minted <units> burnedsends <units> burnedspent <units>
 *   unspent <txid> <vout> <tokenid> <token|mintbaton> <units>
 *   summary slp <n> valid <n> invalid <n> unknown <n>
 * Ids are in the order the RPC prints them. Exit status 1 when any SLP transaction is not valid or
 * fewer than min_slp_transactions were seen, 2 on a malformed input. */

#include "zcl_slp_index.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- SHA-256 (public domain algorithm, FIPS 180-4) ------------------------------------------ */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    size_t total = ((len + 9 + 63) / 64) * 64;
    uint8_t *m = calloc(1, total);
    if (!m) { fprintf(stderr, "out of memory\n"); exit(2); }
    memcpy(m, data, len);
    m[len] = 0x80;
    const uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        m[total - 1 - i] = (uint8_t)(bits >> (8 * i));
    for (size_t off = 0; off < total; off += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++)
            w[i] = (uint32_t)m[off + 4 * i] << 24 | (uint32_t)m[off + 4 * i + 1] << 16 |
                   (uint32_t)m[off + 4 * i + 2] << 8 | m[off + 4 * i + 3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t t1 = hh + S1 + ch + K[i] + w[i];
            uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
            uint32_t mj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t t2 = S0 + mj;
            hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }
    free(m);
    for (int i = 0; i < 8; i++) {
        out[4 * i] = (uint8_t)(h[i] >> 24); out[4 * i + 1] = (uint8_t)(h[i] >> 16);
        out[4 * i + 2] = (uint8_t)(h[i] >> 8); out[4 * i + 3] = (uint8_t)h[i];
    }
}

static void sha256d(const uint8_t *d, size_t n, uint8_t out[32])
{
    uint8_t t[32];
    sha256(d, n, t);
    sha256(t, 32, out);
}

/* ---- byte reader ---------------------------------------------------------------------------- */

struct rd {
    const uint8_t *p, *end;
    int bad;
};

static const uint8_t *take(struct rd *r, size_t n)
{
    if (r->bad || (size_t)(r->end - r->p) < n) { r->bad = 1; return NULL; }
    const uint8_t *q = r->p;
    r->p += n;
    return q;
}
static uint32_t rd32(struct rd *r)
{
    const uint8_t *q = take(r, 4);
    return q ? (uint32_t)q[0] | (uint32_t)q[1] << 8 | (uint32_t)q[2] << 16 | (uint32_t)q[3] << 24 : 0;
}
static uint64_t rd64(struct rd *r)
{
    const uint8_t *q = take(r, 8);
    uint64_t v = 0;
    if (q) for (int i = 7; i >= 0; i--) v = v << 8 | q[i];
    return v;
}
static uint64_t rdcs(struct rd *r)
{
    const uint8_t *q = take(r, 1);
    if (!q) return 0;
    if (*q < 253) return *q;
    if (*q == 253) { const uint8_t *z = take(r, 2); return z ? (uint64_t)z[0] | (uint64_t)z[1] << 8 : 0; }
    if (*q == 254) return rd32(r);
    return rd64(r);
}

/* ---- transactions ---------------------------------------------------------------------------- */

struct vin { uint8_t hash[32]; uint32_t n; };
struct vout { uint64_t value; const uint8_t *script; size_t len; };
struct tx {
    uint8_t txid[32];
    int coinbase;
    size_t nvin, nvout;
    struct vin *vin;
    struct vout *vout;
};

static int parse_tx(struct rd *r, struct tx *t)
{
    const uint8_t *start = r->p;
    const uint32_t header = rd32(r);
    const int overwintered = (header >> 31) & 1;
    const uint32_t version = header & 0x7fffffffu;
    if (overwintered) rd32(r); /* version group id */
    t->nvin = (size_t)rdcs(r);
    if (r->bad || t->nvin > 100000) return 0;
    t->vin = calloc(t->nvin ? t->nvin : 1, sizeof(struct vin));
    for (size_t i = 0; i < t->nvin && !r->bad; i++) {
        const uint8_t *h = take(r, 32);
        if (h) memcpy(t->vin[i].hash, h, 32);
        t->vin[i].n = rd32(r);
        const uint64_t sl = rdcs(r);
        take(r, (size_t)sl);
        rd32(r);
    }
    t->nvout = (size_t)rdcs(r);
    if (r->bad || t->nvout > 100000) return 0;
    t->vout = calloc(t->nvout ? t->nvout : 1, sizeof(struct vout));
    for (size_t i = 0; i < t->nvout && !r->bad; i++) {
        t->vout[i].value = rd64(r);
        const uint64_t sl = rdcs(r);
        t->vout[i].script = take(r, (size_t)sl);
        t->vout[i].len = (size_t)sl;
    }
    rd32(r); /* locktime */
    if (overwintered) rd32(r); /* expiry height */
    uint64_t nshielded = 0;
    if (overwintered && version >= 4) {
        rd64(r); /* value balance */
        const uint64_t ns = rdcs(r);
        take(r, (size_t)ns * 384);
        const uint64_t no = rdcs(r);
        take(r, (size_t)no * 948);
        nshielded = ns + no;
    }
    if (version >= 2) {
        const uint64_t njs = rdcs(r);
        take(r, (size_t)njs * (version >= 4 ? 1698 : 1802));
        if (njs) take(r, 32 + 64); /* joinSplitPubKey, joinSplitSig */
    }
    if (nshielded) take(r, 64); /* the Sapling binding signature */
    if (r->bad) return 0;
    static const uint8_t zero[32];
    t->coinbase = t->nvin == 1 && memcmp(t->vin[0].hash, zero, 32) == 0 && t->vin[0].n == 0xffffffffu;
    sha256d(start, (size_t)(r->p - start), t->txid);
    return 1;
}

/* ---- the ledger ------------------------------------------------------------------------------- */

struct entry { uint8_t txid[32]; uint32_t vout; uint8_t token[32]; int role; uint64_t amount; };
struct txrec { uint8_t txid[32]; uint8_t token[32]; int type; int status; };
struct tokrec { uint8_t id[32]; uint64_t minted, burnedSends, burnedSpent; };

static struct entry *ledger; static size_t nledger, caplegder;
static struct txrec *recs; static size_t nrecs, caprecs;
static struct tokrec *toks; static size_t ntoks, captoks;

static void *grow(void *p, size_t *cap, size_t need, size_t sz)
{
    if (need <= *cap) return p;
    size_t nc = *cap ? *cap * 2 : 64;
    while (nc < need) nc *= 2;
    p = realloc(p, nc * sz);
    if (!p) { fprintf(stderr, "out of memory\n"); exit(2); }
    *cap = nc;
    return p;
}

static struct tokrec *tok(const uint8_t id[32])
{
    for (size_t i = 0; i < ntoks; i++)
        if (memcmp(toks[i].id, id, 32) == 0) return &toks[i];
    toks = grow(toks, &captoks, ntoks + 1, sizeof(*toks));
    memset(&toks[ntoks], 0, sizeof(toks[ntoks]));
    memcpy(toks[ntoks].id, id, 32);
    return &toks[ntoks++];
}

static struct entry *find_entry(const uint8_t txid[32], uint32_t vout)
{
    for (size_t i = 0; i < nledger; i++)
        if (ledger[i].vout == vout && memcmp(ledger[i].txid, txid, 32) == 0) return &ledger[i];
    return NULL;
}

static struct txrec *find_rec(const uint8_t txid[32])
{
    for (size_t i = 0; i < nrecs; i++)
        if (memcmp(recs[i].txid, txid, 32) == 0) return &recs[i];
    return NULL;
}

static void add_entry(const uint8_t txid[32], uint32_t vout, const uint8_t token[32], int role, uint64_t amount)
{
    ledger = grow(ledger, &caplegder, nledger + 1, sizeof(*ledger));
    memcpy(ledger[nledger].txid, txid, 32);
    ledger[nledger].vout = vout;
    memcpy(ledger[nledger].token, token, 32);
    ledger[nledger].role = role;
    ledger[nledger].amount = amount;
    nledger++;
}

static void hexrev(const uint8_t b[32], char out[65])
{
    for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", b[31 - i]);
}

static const char *reason_text(const char *r) { return r ? r : ""; }

static unsigned nslp, nvalid, ninvalid, nunknown;

static void process(const struct tx *t)
{
    /* the message: the first output whose script starts with OP_RETURN */
    int nmsg = -1;
    for (size_t i = 0; i < t->nvout; i++)
        if (t->vout[i].len > 0 && t->vout[i].script[0] == 0x6a) { nmsg = (int)i; break; }
    struct zcl_slp_parsed msg;
    int isslp = 0;
    if (nmsg >= 0) isslp = zcl_slp_parse_message(t->vout[nmsg].script, t->vout[nmsg].len, &msg);

    uint8_t target[32];
    memset(target, 0, 32);
    struct zcl_slp_eval ev;
    memset(&ev, 0, sizeof(ev));
    if (isslp) {
        if (msg.type == ZCL_SLP_TX_GENESIS)
            memcpy(target, t->txid, 32);
        else
            for (int i = 0; i < 32; i++) target[i] = msg.token_id_wire[31 - i];
        struct zcl_slp_input *in = calloc(t->nvin ? t->nvin : 1, sizeof(*in));
        for (size_t i = 0; i < t->nvin && !t->coinbase; i++) {
            const struct entry *e = find_entry(t->vin[i].hash, t->vin[i].n);
            if (e) {
                in[i].has_ledger = 1;
                in[i].role = e->role;
                memcpy(in[i].token_id, e->token, 32);
                in[i].amount = e->amount;
            }
            const struct txrec *pr = find_rec(t->vin[i].hash);
            if (pr && pr->type != 0 && memcmp(pr->token, target, 32) == 0) {
                in[i].parent_same_token = 1;
                in[i].parent_status = pr->status;
            }
        }
        zcl_slp_evaluate(&msg, target, t->nvout, in, t->nvin, &ev);
        free(in);
        recs = grow(recs, &caprecs, nrecs + 1, sizeof(*recs));
        memcpy(recs[nrecs].txid, t->txid, 32);
        memcpy(recs[nrecs].token, target, 32);
        recs[nrecs].type = msg.type;
        recs[nrecs].status = ev.status;
        nrecs++;
        nslp++;
        if (ev.status == ZCL_SLP_STATUS_VALID) nvalid++;
        else if (ev.status == ZCL_SLP_STATUS_INVALID) ninvalid++;
        else nunknown++;
        char id[65];
        hexrev(t->txid, id);
        printf("tx %s %s %s %s\n", id, msg.type == ZCL_SLP_TX_GENESIS ? "GENESIS" : msg.type == ZCL_SLP_TX_MINT ? "MINT" : "SEND",
               ev.status == ZCL_SLP_STATUS_VALID ? "valid" : ev.status == ZCL_SLP_STATUS_INVALID ? "invalid" : "unknown",
               reason_text(ev.reason));
    }
    const int valid = isslp && ev.status == ZCL_SLP_STATUS_VALID;
    const int carries = valid && msg.type == ZCL_SLP_TX_SEND;

    /* every spent token or baton output leaves the ledger; units a valid SEND does not carry are burned */
    if (!t->coinbase) {
        for (size_t i = 0; i < t->nvin; i++) {
            struct entry *e = find_entry(t->vin[i].hash, t->vin[i].n);
            if (!e) continue;
            if (e->role == ZCL_SLP_ROLE_TOKEN && !carries) tok(e->token)->burnedSpent += e->amount;
            *e = ledger[--nledger];
        }
    }
    if (!valid) return;

    struct tokrec *tr = tok(target);
    if (msg.type == ZCL_SLP_TX_SEND) {
        tr->burnedSends += ev.burned_units;
        for (int i = 0; i < msg.num_outputs; i++)
            if (msg.output_quantities[i] > 0)
                add_entry(t->txid, (uint32_t)i + 1, target, ZCL_SLP_ROLE_TOKEN, msg.output_quantities[i]);
    } else {
        tr->minted += ev.minted_units;
        if (msg.quantity > 0) add_entry(t->txid, 1, target, ZCL_SLP_ROLE_TOKEN, msg.quantity);
        if (msg.mint_baton_vout) add_entry(t->txid, msg.mint_baton_vout, target, ZCL_SLP_ROLE_MINT_BATON, 0);
    }
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int cmp_entry(const void *a, const void *b)
{
    char x[65], y[65];
    const struct entry *p = a, *q = b;
    hexrev(p->txid, x);
    hexrev(q->txid, y);
    int c = strcmp(x, y);
    if (c) return c;
    return p->vout < q->vout ? -1 : p->vout > q->vout;
}

static int cmp_tok(const void *a, const void *b)
{
    char x[65], y[65];
    hexrev(((const struct tokrec *)a)->id, x);
    hexrev(((const struct tokrec *)b)->id, y);
    return strcmp(x, y);
}

int main(int argc, char **argv)
{
    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: slpverify <blocks.hex> [min_slp_transactions]\n");
        return 2;
    }
    const unsigned minslp = argc == 3 ? (unsigned)strtoul(argv[2], NULL, 10) : 0;
    FILE *f = fopen(argv[1], "r");
    if (!f) { perror(argv[1]); return 2; }
    size_t cap = 1 << 20, len;
    char *line = malloc(cap);
    uint8_t *raw = NULL;
    size_t rawcap = 0;
    unsigned blocks = 0;
    for (;;) {
        len = 0;
        int c;
        while ((c = fgetc(f)) != EOF && c != '\n') {
            if (len + 1 >= cap) { cap *= 2; line = realloc(line, cap); if (!line) return 2; }
            line[len++] = (char)c;
        }
        if (len == 0 && c == EOF) break;
        if (len == 0) continue;
        if (len % 2) { fprintf(stderr, "odd hex length in block %u\n", blocks + 1); return 2; }
        if (len / 2 > rawcap) { rawcap = len / 2; raw = realloc(raw, rawcap); if (!raw) return 2; }
        for (size_t i = 0; i < len / 2; i++) {
            int hi = hexval(line[2 * i]), lo = hexval(line[2 * i + 1]);
            if (hi < 0 || lo < 0) { fprintf(stderr, "bad hex in block %u\n", blocks + 1); return 2; }
            raw[i] = (uint8_t)(hi << 4 | lo);
        }
        struct rd r = {raw, raw + len / 2, 0};
        take(&r, 140);                 /* the header, without the solution */
        take(&r, (size_t)rdcs(&r));    /* the Equihash solution */
        const uint64_t ntx = rdcs(&r);
        for (uint64_t i = 0; i < ntx && !r.bad; i++) {
            struct tx t;
            memset(&t, 0, sizeof(t));
            if (!parse_tx(&r, &t)) { fprintf(stderr, "cannot parse transaction %llu of block %u\n", (unsigned long long)i, blocks + 1); return 2; }
            process(&t);
            free(t.vin);
            free(t.vout);
        }
        if (r.bad) { fprintf(stderr, "malformed block %u\n", blocks + 1); return 2; }
        blocks++;
    }
    fclose(f);

    qsort(toks, ntoks, sizeof(*toks), cmp_tok);
    for (size_t i = 0; i < ntoks; i++) {
        char id[65];
        hexrev(toks[i].id, id);
        printf("token %s minted %llu burnedsends %llu burnedspent %llu\n", id, (unsigned long long)toks[i].minted,
               (unsigned long long)toks[i].burnedSends, (unsigned long long)toks[i].burnedSpent);
    }
    qsort(ledger, nledger, sizeof(*ledger), cmp_entry);
    for (size_t i = 0; i < nledger; i++) {
        char id[65], tk[65];
        hexrev(ledger[i].txid, id);
        hexrev(ledger[i].token, tk);
        printf("unspent %s %u %s %s %llu\n", id, ledger[i].vout, tk, ledger[i].role == ZCL_SLP_ROLE_TOKEN ? "token" : "mintbaton",
               (unsigned long long)ledger[i].amount);
    }
    printf("summary slp %u valid %u invalid %u unknown %u blocks %u\n", nslp, nvalid, ninvalid, nunknown, blocks);
    if (nvalid != nslp) { fprintf(stderr, "slpverify: %u SLP transactions are not valid\n", nslp - nvalid); return 1; }
    if (nslp < minslp) { fprintf(stderr, "slpverify: only %u SLP transactions, %u required\n", nslp, minslp); return 1; }
    return 0;
}
