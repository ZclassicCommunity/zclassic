#!/bin/sh
# TEST-ONLY (unit U4). Builds and runs the standalone librustzcash ABI
# known-answer / mutation / concurrency suite against the C23 shim
# (src/c23/compat + vendored Z23 + src/c23/sprout_prover + TEST glue).
# No daemon, no Rust, no libsodium. POSIX sh; works in MSYS2 (Windows) and Linux.
#
# usage: sh src/c23/test/run.sh --out <dir> [options]
#   --cc <cc>            C compiler (default: gcc)
#   --std <flag>         language flag (default: -std=gnu17)
#   --opt <flags>        optimisation flags (default: -O3)
#   --san <flags>        sanitizer flags added to compile and link
#                        (e.g. "-fsanitize=address,undefined -fno-sanitize-recover=undefined")
#   --params <dir>       Zcash parameter directory (default: $HOME/.zcash-params)
#   --golden <dir>       golden corpus (default: src/test/data/c23_golden)
#   --steps <list>       comma list of: build,replay,mutations,threads,bench (default build,replay,mutations,threads)
#   --prove              replay re-runs every prover (Sapling and Sprout) and emits C23-made
#                        proofs to <out>/c23made.cases (+ .expect) for the Rust verifier
#   --threads-only       build only kat_threads (used for -fsanitize=thread)
# Exit status: 0 all steps passed, 1 a step failed, 2 usage/build error.
set -u

cc=gcc; std=-std=gnu17; opt=-O3; san=""; out=""; params="${HOME:-}/.zcash-params"; golden=""
steps="build,replay,mutations,threads"; prove=0; threads_only=0
while [ $# -gt 0 ]; do
    case "$1" in
        --cc) cc=$2; shift 2 ;;
        --std) std=$2; shift 2 ;;
        --opt) opt=$2; shift 2 ;;
        --san) san=$2; shift 2 ;;
        --out) out=$2; shift 2 ;;
        --params) params=$2; shift 2 ;;
        --golden) golden=$2; shift 2 ;;
        --steps) steps=$2; shift 2 ;;
        --prove) prove=1; shift ;;
        --threads-only) threads_only=1; shift ;;
        *) echo "run.sh: unknown argument $1" >&2; exit 2 ;;
    esac
done
[ -n "$out" ] || { echo "usage: run.sh --out <dir> [options]" >&2; exit 2; }

here=$(cd "$(dirname "$0")" && pwd)
c23=$(dirname "$here")
src=$(dirname "$c23")
root=$(dirname "$src")
v=$c23/vendor
g=$c23/glue
compat=$c23/compat
sp=$c23/sprout_prover
[ -n "$golden" ] || golden=$src/test/data/c23_golden
mkdir -p "$out/obj" || exit 2
out=$(cd "$out" && pwd)

has_step() { case ",$steps," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

inc="-I$compat -I$g -I$g/chain -I$sp"
for d in "$v"/core/math/include "$v"/core/modules/*/include "$v"/platform/modules/*/include \
         "$v"/core/modules/sapling/src; do
    inc="$inc -I$d"
done
posix=""; spflags=""
case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) libs="-lbcrypt -lshell32 -lpsapi"; exe=".exe" ;;
    *) libs="-lm"; exe=""; posix="-D_POSIX_C_SOURCE=200809L"; spflags="-U_POSIX_C_SOURCE -D_GNU_SOURCE" ;;
esac
base="$std $opt $san -pthread -include $g/zcl_c23_compat.h -fno-strict-aliasing $posix $inc"
log=$out/build.log
: >"$log"
fail=0

compile() { # <src> <obj> <extra flags...>
    s=$1; o=$2; shift 2
    if [ "$o" -nt "$s" ] && [ -f "$out/.flags" ] && [ "$(cat "$out/.flags")" = "$cc|$base" ]; then
        return 0
    fi
    # shellcheck disable=SC2086
    if ! $cc $base "$@" -c "$s" -o "$o" 2>"$o.err"; then
        echo "COMPILE FAIL $s" | tee -a "$log"; sed 's/^/  /' "$o.err" | head -40; fail=1
    elif [ -s "$o.err" ]; then
        echo "DIAGNOSTICS $s" >>"$log"; sed 's/^/  /' "$o.err" >>"$log"
    fi
}

lib=$out/libkat_c23.a
if has_step build || [ ! -f "$lib" ]; then
    t0=$(date +%s)
    objs=""
    for rel in $(awk -F"	" 'index($1,"src/c23/vendor/")==1 && substr($1,length($1)-1)==".c" {print $1}' "$c23/Z23_SOURCE.tsv"); do
        b=$(echo "$rel" | sed 's#.*/##; s#\.c$##')
        compile "$root/$rel" "$out/obj/v_$b.o"
        objs="$objs $out/obj/v_$b.o"
    done
    for gf in zcl_c23_stubs zcl_c23_tree_selftest zcl_c23_test_glue; do
        compile "$g/$gf.c" "$out/obj/g_$gf.o"
        objs="$objs $out/obj/g_$gf.o"
    done
    # The shim exactly as the daemon builds it (production flags, -Werror, no test hook).
    for cf in librustzcash_compat witness_codec zip32_codec; do
        compile "$compat/$cf.c" "$out/obj/c_$cf.o" -Wall -Wextra -Werror
        objs="$objs $out/obj/c_$cf.o"
    done
    # The real C23 Sprout prover (not the U3 test stub).
    for sf in sprout_circuit sprout_par sprout_prove; do
        # shellcheck disable=SC2086
        compile "$sp/$sf.c" "$out/obj/s_$sf.o" $spflags
        objs="$objs $out/obj/s_$sf.o"
    done
    [ "$fail" -eq 0 ] || { echo "run.sh: build FAILED ($cc $std)"; exit 2; }
    printf '%s' "$cc|$base" >"$out/.flags"
    rm -f "$lib"
    # shellcheck disable=SC2086
    ar rcs "$lib" $objs || exit 2
    echo "built $lib in $(( $(date +%s) - t0 ))s ($cc $std $opt $san)"
fi

tflags="-Wall -Wextra -Werror -DKAT_C23_HEADER"
tcommon="$here/kat_common.c $here/kat_jub.c"
link_test() { # <name> <sources...>
    n=$1; shift
    # shellcheck disable=SC2086
    if ! $cc $base $tflags "$@" $tcommon "$lib" $libs -o "$out/$n$exe" 2>"$out/$n.err"; then
        echo "BUILD FAIL $n"; head -40 "$out/$n.err"; exit 2
    fi
}
if [ "$threads_only" -eq 1 ]; then
    link_test kat_threads "$here/kat_threads.c"
else
    link_test kat_replay "$here/kat_replay.c"
    link_test kat_cases "$here/kat_cases.c"
    link_test kat_mutgen "$here/kat_mutgen.c"
    link_test kat_threads "$here/kat_threads.c"
    link_test kat_bench "$here/kat_bench.c"
fi
echo "built tests in $out"

rc=0
if has_step replay; then
    pf=""
    [ "$prove" -eq 1 ] && pf="--prove --emit $out/c23made.cases --emit-expect $out/c23made.expect"
    echo "== replay (golden corpus) =="
    # shellcheck disable=SC2086
    "$out/kat_replay$exe" --dir "$golden" --params "$params" $pf --mismatch-log "$out/replay.mismatch.tsv" \
        >"$out/replay.log" 2>"$out/replay.err"
    r=$?
    grep -E '^(MISMATCH|RESULT|canonical)' "$out/replay.log" | head -60
    echo "replay exit $r (log $out/replay.log)"
    [ "$r" -eq 0 ] || rc=1
fi
if has_step mutations; then
    echo "== mutations (expected = Rust librustzcash output) =="
    vec=$here/vectors
    "$out/kat_mutgen$exe" --golden "$golden" --out "$out/mutations.cases" >"$out/mutgen.log" 2>&1 || { cat "$out/mutgen.log"; exit 2; }
    if ! cmp -s "$out/mutations.cases" "$vec/mutations.cases"; then
        echo "mutations.cases regenerated differently from vectors/mutations.cases (generator not deterministic?)"
        rc=1
    fi
    pdir=$out/pdir
    sh "$here/make-pdir.sh" "$params" "$pdir" || exit 2
    "$out/kat_cases$exe" --cases "$vec/mutations.cases" --params "$params" --pdir "$pdir" \
        >"$out/mutations.c23.out" 2>"$out/mutations.c23.err"
    "$out/kat_cases$exe" --compare "$vec/mutations.cases" "$vec/mutations.rust.out" "$out/mutations.c23.out" \
        >"$out/mutations.compare" 2>&1
    r=$?
    cat "$out/mutations.compare" | tail -80
    [ "$r" -eq 0 ] || rc=1
fi
if has_step threads; then
    echo "== threads (16 threads after init) =="
    "$out/kat_threads$exe" --dir "$golden" --params "$params" --threads 16 >"$out/threads.log" 2>&1
    r=$?
    tail -5 "$out/threads.log"
    [ "$r" -eq 0 ] || rc=1
fi
if has_step bench; then
    echo "== bench (C23) =="
    "$out/kat_bench$exe" --dir "$golden" --params "$params" --runs 21 >"$out/bench.c23.txt" 2>&1
    r=$?
    cat "$out/bench.c23.txt"
    [ "$r" -eq 0 ] || rc=1
fi
echo "run.sh: exit $rc"
exit $rc
