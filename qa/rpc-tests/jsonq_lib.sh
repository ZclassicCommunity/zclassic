#!/bin/sh
# jsonq_lib.sh (sourced): small JSON helpers for the shell tests. POSIX sh, no Python, no external JSON tool.
# They wrap the vendored jsonq (zcutil/tools, built to zcutil/bin/jsonq) and mimic the lookups
# the tests used to make, so a converted script behaves as before:
#   jget PATH          stdin -> value, prints the raw value  (a missing path prints "null", status 0)
#   jgetd PATH DEFAULT stdin -> value, or DEFAULT when the path is missing or null
#   jraw PATH          stdin -> compact JSON of the value, prints compact JSON
#   jlen [PATH]        stdin -> number of elements/keys, length  (containers only; a scalar or missing path prints nothing and fails)
#   jhas PATH          stdin -> true or false, for a top-level key
# PATH is jsonq's: dotted keys and [index], optional leading '.', e.g. result.items[1].id.
# Malformed input makes every helper fail with a non-zero status.
# The caller is sourced as `. "$(dirname "$0")/jsonq_lib.sh"` (or ../rpc-tests/ from qa/zslp).
if [ -z "${JSONQ:-}" ]; then
    _js_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    for _js_c in "$_js_dir/../../zcutil/bin/jsonq" "$_js_dir/../../zcutil/bin/jsonq.exe"; do
        if [ -x "$_js_c" ]; then JSONQ=$_js_c; break; fi
    done
    if [ -z "${JSONQ:-}" ] && command -v jsonq >/dev/null 2>&1; then JSONQ=jsonq; fi
    if [ -z "${JSONQ:-}" ] && [ -f "$_js_dir/../../zcutil/tools/Makefile" ]; then
        # first use in a fresh checkout: build the vendored tool (host cc, libc only)
        make -s -C "$_js_dir/../../zcutil/tools" >&2 || true
        [ -x "$_js_dir/../../zcutil/bin/jsonq" ] && JSONQ=$_js_dir/../../zcutil/bin/jsonq
    fi
    unset _js_dir _js_c
fi
if [ -z "${JSONQ:-}" ]; then
    echo "jsonq is required (make -C zcutil/tools, or set JSONQ=<path>)" >&2; exit 2
fi
export JSONQ

jget() {
    _js_o=$("$JSONQ" get "$1"); _js_r=$?
    case $_js_r in 0) printf '%s\n' "$_js_o" ;; 1) echo null ;; *) return "$_js_r" ;; esac
}
jgetd() {
    _js_o=$("$JSONQ" get "$1"); _js_r=$?
    case $_js_r in
        0) if [ "$_js_o" = null ]; then printf '%s\n' "$2"; else printf '%s\n' "$_js_o"; fi ;;
        1) printf '%s\n' "$2" ;;
        *) return "$_js_r" ;;
    esac
}
jraw() {
    _js_o=$("$JSONQ" raw "$1"); _js_r=$?
    case $_js_r in 0) printf '%s\n' "$_js_o" ;; 1) echo null ;; *) return "$_js_r" ;; esac
}
jlen() {
    _js_o=$("$JSONQ" count "${1:-.}"); _js_r=$?
    # a scalar or a missing path is not a container: print nothing and fail, so that a check
    # expecting 0 cannot pass on the wrong shape
    case $_js_r in 0) printf '%s\n' "$_js_o" ;; *) return "$_js_r" ;; esac
}

jhas() {
    "$JSONQ" has "$1"; _js_r=$?
    case $_js_r in 0) echo true ;; 1) echo false ;; *) return "$_js_r" ;; esac
}

# Composite helpers for the tests that compared several values at once. Each reads one JSON document on
# stdin, takes the same paths as jget, and prints what the old one-line expression printed.
#   jarr PATH...   [raw,raw,...] compact JSON of the values (a missing path is null) (what a one-line array expression of two fields printed)
#   jcat PATH...   the values (jget) joined by single spaces
#   jpick [FIELD]  one value per array element (its FIELD, or the element itself), one per line
#                  (fails, printing nothing, when the document is not an array)
#   jjoin FIELD    jpick, comma-joined
#   jpluck FIELD   [raw,raw,...] compact JSON of the FIELD of every element
#   jsatlist       the .amount of every element of an array in satoshi (integer), one per line; NaN for a non-number
#   jkeys [PATH]   the sorted keys of an object as a compact JSON array
jarr() {
    _ja_d=$(cat); _ja_o=; _ja_s=
    for _ja_p in "$@"; do _ja_o="$_ja_o$_ja_s$(printf '%s' "$_ja_d" | jraw "$_ja_p")"; _ja_s=,; done
    printf '[%s]\n' "$_ja_o"
}
jcat() {
    _jc_d=$(cat); _jc_o=; _jc_s=
    for _jc_p in "$@"; do _jc_o="$_jc_o$_jc_s$(printf '%s' "$_jc_d" | jget "$_jc_p")"; _jc_s=' '; done
    printf '%s\n' "$_jc_o"
}
jpick() {
    _jp_d=$(cat); _jp_n=$(printf '%s' "$_jp_d" | jlen) || return 1; _jp_i=0
    while [ "$_jp_i" -lt "$_jp_n" ]; do
        printf '%s' "$_jp_d" | jget "[$_jp_i]${1:+.$1}"; _jp_i=$((_jp_i + 1))
    done
}
jjoin() { jpick "$1" | tr '\n' ',' | sed 's/,$//'; echo; }
jsatlist() { jpick amount | awk '{ if ($1 ~ /^-?[0-9]+([.][0-9]+)?([eE][-+]?[0-9]+)?$/) printf "%d\n", $1 * 100000000 + 0.5; else print "NaN" }'; }
jkeys() {
    _jk_o=$("$JSONQ" keys "${1:-.}") || return $?
    [ -n "$_jk_o" ] || { echo '[]'; return 0; }
    printf '%s\n' "$_jk_o" | LC_ALL=C sort | awk 'BEGIN { printf "[" } { printf "%s\"%s\"", (NR > 1 ? "," : ""), $0 } END { print "]" }'
}
jpluck() {
    _jl_d=$(cat); _jl_n=$(printf '%s' "$_jl_d" | jlen) || return 1; _jl_i=0; _jl_o=; _jl_s=
    while [ "$_jl_i" -lt "$_jl_n" ]; do
        _jl_o="$_jl_o$_jl_s$(printf '%s' "$_jl_d" | jraw "[$_jl_i].$1")"; _jl_s=,; _jl_i=$((_jl_i + 1))
    done
    printf '[%s]\n' "$_jl_o"
}
