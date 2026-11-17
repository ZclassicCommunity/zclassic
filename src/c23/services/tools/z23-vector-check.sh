#!/bin/sh
# Run Z23's OWN SLP tests against the vendored copy, compiled the way the
# wallet compiles it (C, -std=gnu11 by default, glue headers through -iquote).
#
# usage: z23-vector-check.sh <cc> <z23-repo> [std-flag]
#
# Nothing from Z23 is stored here. At run time the script reads two test files
# from the Z23 repository AT THE COMMIT PINNED IN Z23_SOURCE.tsv:
#
#   tests/harness/src/test_slp.c
#       the pure parser / builder / classifier test functions, verbatim
#       (the wallet- and service-level tests in that file need all of Z23 and
#       are not run);
#   tests/harness/src/test_overlay_parse_parity.c
#       Z23's frozen reference implementation of the SLP parser and builders
#       (the `ref_slp_*` functions) and its comparator, verbatim. The vendored
#       parser is compared with that reference, verdict and whole decoded
#       struct, over the corpus that file describes: every truncation, every
#       single-byte opcode overwrite, inserted empty pushes, trailing bytes,
#       over-long push prefixes, and pseudo-random scripts. The corpus driver
#       below is zclassicd's; the reference and the comparator are Z23's.
#
# Exit status 0 only if every extracted test passes, the differential finds no
# split and the builders are byte-identical to the reference.
set -eu
[ $# -ge 2 ] || { echo "usage: $0 <cc> <z23-repo> [std-flag]" >&2; exit 2; }
cc=$1
repo=$2
std=${3:--std=gnu11}
here=$(cd "$(dirname "$0")" && pwd)
svc=$(dirname "$here")
pin=$(sed -n 's/^# z23_commit=//p' "$svc/Z23_SOURCE.tsv")
[ -n "$pin" ] || { echo "FAIL: no pin in Z23_SOURCE.tsv" >&2; exit 1; }

work=$(mktemp -d) || exit 1
trap 'rm -rf "$work"' EXIT

git -C "$repo" show "$pin:tests/harness/src/test_slp.c" >"$work/test_slp.c"
git -C "$repo" show "$pin:tests/harness/src/test_overlay_parse_parity.c" >"$work/parity.c"

# Print the named file-scope static functions of a C file, verbatim, in the
# order asked for. A function runs from its `static ... name(` line to the
# first line that is exactly `}`.
extract() {
    file=$1
    shift
    for fn in "$@"; do
        awk -v n="$fn" '
            BEGIN { pat = "^static .*[ *]" n "\\(" }
            !on && $0 ~ pat { on = 1 }
            on { print }
            on && /^}$/ { found = 1; print ""; exit }
            END { if (!found) exit 3 }
        ' "$file" || { echo "FAIL: function $fn not found in $(basename "$file") at $pin" >&2; exit 1; }
    done
}

slp_tests="test_slp_parse_valid_genesis test_slp_parse_genesis_document_hash
test_slp_parse_mint_cases test_slp_parse_send_cases test_slp_parse_rejects_malformed
test_slp_genesis_round_trip test_slp_mint_round_trip
test_slp_send_round_trip_and_empty_ticker test_slp_null_ticker_and_decimals
test_slp_send_output_counts test_slp_quantity_bounds test_slp_send_zero_quantities
test_slp_classifier_normalizes_token_id"

# shellcheck disable=SC2086
extract "$work/test_slp.c" test_slp_fill_index_bytes test_slp_genesis_output_roles $slp_tests >"$work/z23_test_slp.inc"

extract "$work/parity.c" \
    ref_be_to_u64 ref_u64_to_be ref_slp_copy_str_field ref_slp_read_command \
    ref_slp_parse_genesis_text ref_slp_parse_genesis ref_slp_parse_mint \
    ref_slp_parse_send ref_slp_parse ref_slp_push_str_field ref_slp_push_baton \
    ref_slp_build_genesis ref_slp_build_mint ref_slp_build_send \
    prng_next reencode_noncanonical slp_compare_one \
    builders_genesis_fields_identical builders_genesis_capacity_identical \
    builders_genesis_identical builders_mint_identical builders_send_identical \
    builders_mint_send_identical >"$work/z23_parity.inc"

{
    printf '#include "z23_vector_shim.h"\n'
    printf '#include "z23_test_slp.inc"\n'
    printf '#include "z23_parity.inc"\n'
    cat <<'EOF'

/* ---- zclassicd corpus driver (the comparator and reference are Z23's) ---- */

static int compare_mutations(const struct script_case *seed, long *checked)
{
    static const uint8_t opcodes[] = {
        0x00, 0x01, 0x02, 0x08, 0x20, 0x4b, 0x4c, 0x4d, 0x4e, 0x50, 0x7f, 0xff
    };
    uint8_t buf[CORPUS_MAX + 16];
    int splits = 0;

    /* the seed and every truncation of it */
    for (size_t n = 0; n <= seed->len; n++)
        splits += slp_compare_one(seed->bytes, n, checked);

    /* every single-byte overwrite with each interesting opcode */
    for (size_t i = 0; i < seed->len; i++) {
        for (size_t k = 0; k < sizeof(opcodes); k++) {
            memcpy(buf, seed->bytes, seed->len);
            buf[i] = opcodes[k];
            splits += slp_compare_one(buf, seed->len, checked);
        }
    }

    /* an empty push, in both spellings, inserted at every offset */
    for (size_t i = 0; i <= seed->len; i++) {
        memcpy(buf, seed->bytes, i);
        buf[i] = 0x00;
        memcpy(buf + i + 1, seed->bytes + i, seed->len - i);
        splits += slp_compare_one(buf, seed->len + 1, checked);

        memcpy(buf, seed->bytes, i);
        buf[i] = 0x4c;
        buf[i + 1] = 0x00;
        memcpy(buf + i + 2, seed->bytes + i, seed->len - i);
        splits += slp_compare_one(buf, seed->len + 2, checked);
    }

    /* trailing bytes */
    for (size_t extra = 1; extra <= 12; extra++) {
        memcpy(buf, seed->bytes, seed->len);
        for (size_t j = 0; j < extra; j++)
            buf[seed->len + j] = (uint8_t)prng_next();
        splits += slp_compare_one(buf, seed->len + extra, checked);
    }

    /* over-long push prefixes, and every truncation of that */
    size_t n = reencode_noncanonical(seed->bytes, seed->len, buf, CORPUS_MAX);
    for (size_t m = 0; m <= n; m++)
        splits += slp_compare_one(buf, m, checked);

    return splits;
}

static void add_seed(struct script_case *seeds, size_t *count, const uint8_t *b, size_t len)
{
    if (len == 0 || len > CORPUS_MAX) {
        printf("corpus: a seed did not build\n");
        exit(1);
    }
    memcpy(seeds[*count].bytes, b, len);
    seeds[*count].len = len;
    (*count)++;
}

static int differential(long *checked)
{
    static struct script_case seeds[32];
    size_t count = 0;
    uint8_t b[CORPUS_MAX];
    uint8_t dh[32];
    struct uint256 tid;
    uint64_t q[19];
    int splits = 0;

    memset(dh, 0xab, sizeof(dh));
    for (int i = 0; i < 32; i++) tid.data[i] = (uint8_t)(0xf0 ^ i);
    for (int i = 0; i < 19; i++) q[i] = (uint64_t)(i + 1) * 1000003u;

    add_seed(seeds, &count, b, slp_build_genesis(b, sizeof(b), "ZCL", "ZClassic Token", "https://zclassic.org", NULL, 8, 0, 1000000));
    add_seed(seeds, &count, b, slp_build_genesis(b, sizeof(b), "TEST", "Test Token", "https://example.com", dh, 4, 2, 5000));
    add_seed(seeds, &count, b, slp_build_genesis(b, sizeof(b), NULL, NULL, NULL, NULL, 0, 0, 0));
    add_seed(seeds, &count, b, slp_build_genesis(b, sizeof(b), "", "n", "", dh, 9, 255, UINT64_MAX));
    add_seed(seeds, &count, b, slp_build_mint(b, sizeof(b), &tid, 0, 1));
    add_seed(seeds, &count, b, slp_build_mint(b, sizeof(b), &tid, 2, UINT64_MAX));
    add_seed(seeds, &count, b, slp_build_send(b, sizeof(b), &tid, q, 1));
    add_seed(seeds, &count, b, slp_build_send(b, sizeof(b), &tid, q, 3));
    add_seed(seeds, &count, b, slp_build_send(b, sizeof(b), &tid, q, 19));
    {
        /* Z23 tests/harness/fuzz_seeds/overlay/slp_genesis_min.bin and
         * slp_send_min.bin, without their leading harness-selector byte. */
        static const uint8_t genesis_min[] = {
            0x6a,0x04,0x53,0x4c,0x50,0x00,0x01,0x01,0x07,0x47,0x45,0x4e,0x45,0x53,0x49,0x53,
            0x03,0x54,0x53,0x54,0x04,0x54,0x65,0x73,0x74,0x00,0x00,0x01,0x08,0x00,0x08,0x00,
            0x00,0x00,0x00,0x00,0x00,0x03,0xe8 };
        uint8_t send_min[64];
        size_t n = 0;
        static const uint8_t head[] = { 0x6a,0x04,0x53,0x4c,0x50,0x00,0x01,0x01,0x04,0x53,0x45,0x4e,0x44,0x20 };
        memcpy(send_min, head, sizeof(head)); n = sizeof(head);
        memset(send_min + n, 0x41, 32); n += 32;
        static const uint8_t tail[] = { 0x08,0,0,0,0,0,0,0,1, 0x08,0,0,0,0,0,0,0,2 };
        memcpy(send_min + n, tail, sizeof(tail)); n += sizeof(tail);
        add_seed(seeds, &count, genesis_min, sizeof(genesis_min));
        add_seed(seeds, &count, send_min, n);
    }

    for (size_t i = 0; i < count; i++)
        splits += compare_mutations(&seeds[i], checked);

    /* pseudo-random scripts: raw, and behind a valid SLP header + command */
    static const char *cmds[] = { "GENESIS", "MINT", "SEND", "BURN", "" };
    for (int round = 0; round < 200000; round++) {
        size_t off = 0;
        uint64_t r = prng_next();
        if (r & 1) {
            static const uint8_t hdr[] = { 0x6a,0x04,0x53,0x4c,0x50,0x00,0x01,0x01 };
            memcpy(b, hdr, sizeof(hdr)); off = sizeof(hdr);
            const char *cmd = cmds[(r >> 1) % 5];
            size_t cl = strlen(cmd);
            b[off++] = (uint8_t)cl;
            memcpy(b + off, cmd, cl); off += cl;
        }
        size_t tail = (size_t)((r >> 8) % 160);
        for (size_t j = 0; j < tail; j++) {
            uint64_t x = prng_next();
            /* bias towards bytes that are meaningful to a push parser */
            b[off++] = (x & 3) == 0 ? (uint8_t)(x >> 8) : (uint8_t)((x >> 8) % 0x50);
        }
        splits += slp_compare_one(b, off, checked);
    }
    return splits;
}

int main(void)
{
    int failures = 0;
    int ran = 0;
#define RUN(fn) do { failures += fn(); ran++; } while (0)
EOF
    for t in $slp_tests; do printf '    RUN(%s);\n' "$t"; done
    cat <<'EOF'
#undef RUN
    printf("z23 test_slp.c: %d test functions run, %d failures\n", ran, failures);

    long checked = 0;
    int splits = differential(&checked);
    printf("z23 parser differential: %ld scripts compared, %d splits\n", checked, splits);

    bool builders = builders_genesis_identical() && builders_mint_send_identical();
    printf("z23 builder byte identity: %s\n", builders ? "OK" : "FAIL");

    if (failures || splits || !builders) {
        printf("z23-vector-check: FAILED\n");
        return 1;
    }
    printf("z23-vector-check: OK\n");
    return 0;
}
EOF
} >"$work/driver.c"

# The driver holds Z23 test code written against Z23's warning set; only the
# vendored sources and the glue are held to -Wall -Wextra -Werror here.
inc="-iquote $svc/glue -iquote $svc/vendor/contexts/market/modules/zslp/include -iquote $svc/vendor/engine/modules/overlay/include -iquote $svc/vendor/core/modules/script/include"
# shellcheck disable=SC2086
$cc $std -O2 -Wall -Wextra -Werror $inc -c "$svc/vendor/contexts/market/modules/zslp/src/slp.c" -o "$work/slp.o"
# shellcheck disable=SC2086
$cc $std -O2 -Wall -Wextra -Werror $inc -c "$svc/vendor/engine/modules/overlay/src/overlay_codec.c" -o "$work/overlay_codec.o"
# shellcheck disable=SC2086
$cc $std -O2 -Wall -Wextra -Werror $inc -c "$svc/glue/zcl_token_guard.c" -o "$work/zcl_token_guard.o"
# shellcheck disable=SC2086
$cc $std -O2 -w $inc -iquote "$here" -iquote "$work" -c "$work/driver.c" -o "$work/driver.o"
$cc "$work/driver.o" "$work/slp.o" "$work/overlay_codec.o" "$work/zcl_token_guard.o" -o "$work/z23-vector-check"

echo "z23-vector-check: cc='$cc' std=$std pin=$pin"
rc=0
"$work/z23-vector-check" >"$work/out.txt" || rc=$?
# Z23's tests print one "<case>... OK" or "<case>... FAIL" line per case.
grep -v '\.\.\. OK$' "$work/out.txt" || true
echo "z23 test_slp.c cases: $(grep -c '\.\.\. OK$' "$work/out.txt" || true) OK, $(grep -c 'FAIL$' "$work/out.txt" || true) FAIL"
exit "$rc"
