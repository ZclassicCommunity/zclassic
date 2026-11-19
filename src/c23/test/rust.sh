#!/bin/sh
# TEST-ONLY (unit U4). Builds the Rust-linked twins of the suite drivers on a
# host that still has a Rust-backed depends prefix (librustzcash.a), and runs
# them to obtain Rust's results. Never part of the zclassicd build.
#
# usage: sh src/c23/test/rust.sh --depends <prefix> --out <dir> [options]
#   --params <dir>     Zcash parameter directory (default: $HOME/.zcash-params)
#   --golden <dir>     golden corpus (default: src/test/data/c23_golden)
#   --steps <list>     comma list of: build,mutations,c23made,bench (default build,mutations)
#   --cases <file>     C23-made cases for the c23made step (from run.sh --prove)
#   --expect <file>    expected results for --cases
#   --runs <n>         bench runs (default 21)
set -u
dep=""; out=""; params="${HOME:-}/.zcash-params"; golden=""; steps="build,mutations"; cases=""; expect=""; runs=21
while [ $# -gt 0 ]; do
    case "$1" in
        --depends) dep=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --params) params=$2; shift 2 ;;
        --golden) golden=$2; shift 2 ;;
        --steps) steps=$2; shift 2 ;;
        --cases) cases=$2; shift 2 ;;
        --expect) expect=$2; shift 2 ;;
        --runs) runs=$2; shift 2 ;;
        *) echo "rust.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$dep" ] && [ -n "$out" ] || { echo "usage: rust.sh --depends <prefix> --out <dir> [options]" >&2; exit 2; }
[ -f "$dep/lib/librustzcash.a" ] || { echo "rust.sh: $dep/lib/librustzcash.a not found" >&2; exit 2; }
here=$(cd "$(dirname "$0")" && pwd)
src=$(dirname "$(dirname "$here")")
[ -n "$golden" ] || golden=$src/test/data/c23_golden
mkdir -p "$out" || exit 2
has_step() { case ",$steps," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }
cc=${CC:-gcc}
rc=0
if has_step build; then
    for p in kat_cases kat_bench; do
        if ! $cc -std=gnu17 -O2 -Wall -Wextra -Werror -DKAT_RUST "$here/$p.c" "$here/kat_common.c" \
                "$dep/lib/librustzcash.a" -lpthread -ldl -lm -o "$out/${p}_rust" 2>"$out/${p}_rust.err"; then
            echo "BUILD FAIL ${p}_rust"; head -30 "$out/${p}_rust.err"; exit 2
        fi
    done
    echo "built $out/kat_cases_rust $out/kat_bench_rust against $dep/lib/librustzcash.a"
fi
if has_step mutations; then
    sh "$here/make-pdir.sh" "$params" "$out/pdir" || exit 2
    "$out/kat_cases_rust" --cases "$here/vectors/mutations.cases" --params "$params" --pdir "$out/pdir" \
        >"$out/mutations.rust.out" 2>"$out/mutations.rust.err" || rc=1
    tail -1 "$out/mutations.rust.err"
    echo "wrote $out/mutations.rust.out ($(grep -c '^[0-9]' "$out/mutations.rust.out") results)"
fi
if has_step c23made; then
    [ -n "$cases" ] && [ -n "$expect" ] || { echo "rust.sh: c23made needs --cases and --expect" >&2; exit 2; }
    "$out/kat_cases_rust" --cases "$cases" --params "$params" >"$out/c23made.rust.out" 2>"$out/c23made.rust.err" || rc=1
    "$out/kat_cases_rust" --compare "$cases" "$expect" "$out/c23made.rust.out" || rc=1
fi
if has_step bench; then
    "$out/kat_bench_rust" --dir "$golden" --params "$params" --runs "$runs" || rc=1
fi
exit $rc
