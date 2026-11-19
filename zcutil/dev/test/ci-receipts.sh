#!/bin/sh
# Receipts and --only through local-ci.sh's `dry` stage (three fake steps, no root filesystem).
# usage: sh test/ci-receipts.sh <zcl-dev>
set -eu
# local-ci.sh --only exports ZCL_CI_ONLY; the nested dry runs below must not inherit it.
unset ZCL_CI_ONLY ZCL_CI_JOBS ZCL_CI_FLAVOR ZCL_CI_TESTDIR
bin=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
ci=$(cd "$(dirname "$0")/../.." && pwd)/local-ci.sh
out=$(mktemp -d "${TMPDIR:-/tmp}/zcl-ci-receipts.XXXXXX")
trap 'rm -rf "$out"' EXIT
fail() { echo "FAIL ci-receipts: $*" >&2; exit 1; }
sum() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

ZCL_CI_JOBS=3 sh "$ci" dry "$out/all" >/dev/null 2>&1 || fail "dry stage failed"
r=$out/all/receipts.jsonl
[ "$(wc -l <"$r")" -eq 3 ] || fail "expected 3 receipts"
for want in dry-pass:PASS dry-fail:FAIL dry-skip:SKIP; do
    s=${want%%:*}; v=${want##*:}
    line=$("$bin" receipt "$s" "$out/all") || fail "no receipt for $s"
    case $line in *'"verdict":"'$v'"'*) ;; *) fail "$s: verdict is not $v: $line" ;; esac
    for k in commit tree stage step seconds started os arch gcc mingw glibc env_names env_sha256 log_sha256; do
        case $line in *'"'$k'":'*) ;; *) fail "$s: key $k missing" ;; esac
    done
    got=$(printf '%s' "$line" | sed -n 's/.*"log_sha256":"\([0-9a-f]*\)".*/\1/p')
    [ "$got" = "$(sum "$out/all/dry/logs/$s.log")" ] || fail "$s: log_sha256 does not match the log"
done
# the environment is recorded by name and digest, never by value
ZCL_CI_JOBS=SECRETVALUE sh "$ci" dry "$out/env" >/dev/null 2>&1
if grep -q SECRETVALUE "$out/env/receipts.jsonl"; then fail "an environment value leaked into a receipt"; fi
grep -q '"env_names":\[[^]]*"ZCL_CI_JOBS"' "$out/env/receipts.jsonl" || fail "env name missing"
if grep -q "$(uname -n)" "$out/env/receipts.jsonl"; then fail "host name in receipt"; fi
# --only runs and records just the named steps
sh "$ci" --only dry-pass,dry-skip dry "$out/only" >/dev/null 2>&1
[ "$(wc -l <"$out/only/receipts.jsonl")" -eq 2 ] || fail "--only did not filter"
if grep -q dry-fail "$out/only/receipts.jsonl"; then fail "--only ran an unlisted step"; fi
echo "ci-receipts: ok"
