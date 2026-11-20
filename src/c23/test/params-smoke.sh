#!/bin/sh
# TEST-ONLY. Startup behaviour of zclassicd on missing / damaged Zcash parameters.
#
# usage: sh src/c23/test/params-smoke.sh --bin <dir> --work <empty scratch dir>
#            [--params <dir>] [--port-base <n>] [--label <s>]
#
# Runs the daemon (regtest, no network, fresh datadirs) with HOME pointed at a
# scratch directory whose .zcash-params is built from the real parameter files
# (symlinks; damaged files are private copies; the real files are only read).
# Prints one line per case:  CASE <name> rc=<exit> started=<yes|no> msg=<first error line>
# Run it once per binary and diff the output.
#
# Cases
#   intact               all four files present and correct (sprout-proving.key is never needed)
#   legacy-proving-key   an old sprout-proving.key next to them is ignored
#   missing-vk           sprout-verifying.key absent
#   corrupt-vk           sprout-verifying.key, right size, one byte flipped (the
#                        SHA-256 pin is never cached for it)
#   missing-spend        sapling-spend.params absent
#   missing-groth16      sprout-groth16.params absent
#   truncated-output     sapling-output.params cut to half its size
#   corrupt-output       sapling-output.params, right size, one byte flipped, no verified-params cache
#   corrupt-spend        sapling-spend.params, same
#   cached-new-datadir   a fresh datadir reuses zclassic-params-verify.cache beside the params
#   cached-corrupt-output  as corrupt-output, but the params directory holds a valid cache from
#                        an intact start and the damaged file keeps the original size and mtime,
#                        so init.cpp's SHA-256 gate is skipped and only the crypto library's
#                        own check of the file stands between it and startup
set -u
bin=""; work=""; params="${HOME:-}/.zcash-params"; base=""; label=""
while [ $# -gt 0 ]; do
    case "$1" in
        --bin) bin=$2; shift 2 ;;
        --work) work=$2; shift 2 ;;
        --params) params=$2; shift 2 ;;
        --port-base) base=$2; shift 2 ;;
        --label) label=$2; shift 2 ;;
        *) echo "params-smoke: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -x "$bin/zclassicd" ] && [ -n "$work" ] && [ -f "$params/sapling-spend.params" ] || {
    echo "usage: params-smoke.sh --bin <dir> --work <dir> [--params <dir>]" >&2; exit 2; }
mkdir -p "$work" || exit 2
work=$(cd "$work" && pwd)
. "$(dirname "$0")/../../../qa/lib/isolation.sh"
iso_base base "$base" 16
[ -z "$(ls -A "$work")" ] || { echo "params-smoke: $work is not empty" >&2; exit 2; }
FILES="sapling-spend.params sapling-output.params sprout-groth16.params sprout-verifying.key"

mkhome() { # <home>: all four files as symlinks to the real ones
    mkdir -p "$1/.zcash-params" || exit 2
    for f in $FILES; do ln -s "$params/$f" "$1/.zcash-params/$f"; done
}
flip() { # <home> <file>: private copy, same size and mtime, one byte changed
    p=$1/.zcash-params/$2
    rm -f "$p" && cp "$params/$2" "$p" && chmod u+w "$p" || exit 2
    sz=$(wc -c <"$p" | tr -d ' ')
    off=$((sz / 2))
    old=$(dd if="$p" bs=1 skip=$off count=1 2>/dev/null | od -An -tu1 | tr -d ' ')
    new=$(( (old + 1) % 256 ))
    printf "$(printf '\\%03o' "$new")" | dd of="$p" bs=1 seek=$off conv=notrunc 2>/dev/null
    touch -r "$params/$2" "$p"
}
run_case() { # <name> <home> <datadir>
    name=$1; home=$2; dd=$3
    mkdir -p "$dd"
    printf 'rpcuser=p\nrpcpassword=p%s\nrpcport=%s\n' "$$" "$((base + 1))" >"$dd/zclassic.conf"
    log=$work/$name.log
    HOME=$home "$bin/zclassicd" -regtest -datadir="$dd" -port="$base" -listen=0 -connect=0 -dnsseed=0 \
        -bootstrap=0 -upnp=0 -listenonion=0 -showmetrics=0 -printtoconsole >"$log" 2>&1 &
    pid=$!
    started=no; i=0
    while [ $i -lt 300 ]; do
        kill -0 $pid 2>/dev/null || break
        if "$bin/zclassic-cli" -regtest -datadir="$dd" getblockcount >/dev/null 2>&1; then
            started=yes
            "$bin/zclassic-cli" -regtest -datadir="$dd" stop >/dev/null 2>&1
            break
        fi
        sleep 1; i=$((i + 1))
    done
    [ $i -lt 300 ] || kill $pid 2>/dev/null
    wait $pid; rc=$?
    msg=$(grep -a -m1 -E 'Error:|panicked|abort|Cannot find|Deleting|mismatch|is corrupt|corrupt|wrong|zc23|FATAL|not the expected' "$log" | cut -c1-220)
    echo "CASE $name rc=$rc started=$started msg=${msg:-<none>}"
}

echo "# params-smoke ${label:-$bin}"
h=$work/h-intact; mkhome "$h"; run_case intact "$h" "$work/d-intact"

h=$work/h-legacy; mkhome "$h"; : >"$h/.zcash-params/sprout-proving.key"
run_case legacy-proving-key "$h" "$work/d-legacy"

h=$work/h-missing-vk; mkhome "$h"; rm "$h/.zcash-params/sprout-verifying.key"
run_case missing-vk "$h" "$work/d-missing-vk"

h=$work/h-corrupt-vk; mkhome "$h"; flip "$h" sprout-verifying.key
run_case corrupt-vk "$h" "$work/d-corrupt-vk"

h=$work/h-missing-spend; mkhome "$h"; rm "$h/.zcash-params/sapling-spend.params"
run_case missing-spend "$h" "$work/d-missing-spend"

h=$work/h-missing-groth16; mkhome "$h"; rm "$h/.zcash-params/sprout-groth16.params"
run_case missing-groth16 "$h" "$work/d-missing-groth16"

h=$work/h-truncated-output; mkhome "$h"
p=$h/.zcash-params/sapling-output.params; rm "$p"
sz=$(wc -c <"$params/sapling-output.params" | tr -d ' ')
dd if="$params/sapling-output.params" of="$p" bs=$((sz / 2)) count=1 2>/dev/null
run_case truncated-output "$h" "$work/d-truncated-output"

h=$work/h-corrupt-output; mkhome "$h"; flip "$h" sapling-output.params
run_case corrupt-output "$h" "$work/d-corrupt-output"

h=$work/h-corrupt-spend; mkhome "$h"; flip "$h" sapling-spend.params
run_case corrupt-spend "$h" "$work/d-corrupt-spend"

# Valid cache first (private copy of the small file so its mtime can be kept).
h=$work/h-cached; mkhome "$h"
p=$h/.zcash-params/sapling-output.params; rm "$p"; cp -p "$params/sapling-output.params" "$p"
run_case cached-intact-first-start "$h" "$work/d-cached"
ls "$h/.zcash-params/zclassic-params-verify.cache" >/dev/null 2>&1 || echo "# note: no zclassic-params-verify.cache was written"
run_case cached-new-datadir "$h" "$work/d-cached-b"
echo "# $(grep -a -m1 'param-cache: .* skipped' "$work/cached-new-datadir.log" | sed 's/^.*param-cache: /param-cache: /')"
flip "$h" sapling-output.params; touch -r "$params/sapling-output.params" "$p"
run_case cached-corrupt-output "$h" "$work/d-cached"
exit 0
