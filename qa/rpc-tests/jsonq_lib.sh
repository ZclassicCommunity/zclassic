#!/bin/sh
# jsonq_lib.sh (sourced): small jq-free JSON helpers for the shell tests. POSIX sh, no Python, no jq.
# They wrap the vendored jsonq (zcutil/tools, built to zcutil/bin/jsonq) and mimic the jq calls
# the tests used to make, so a converted script behaves as before:
#   jget PATH          stdin -> value, like `jq -r .PATH`  (a missing path prints "null", status 0)
#   jgetd PATH DEFAULT stdin -> value, like `jq -r '.PATH // DEFAULT'` (missing or null -> DEFAULT)
#   jraw PATH          stdin -> compact JSON of the value, like `jq -c .PATH`
#   jlen [PATH]        stdin -> number of elements/keys, like `jq length`  (containers only)
#   jhas PATH          stdin -> true or false, like `jq has("PATH")` for a top-level key
# PATH is jsonq's: dotted keys and [index], optional leading '.', e.g. result.items[1].id.
# Malformed input makes every helper fail with a non-zero status, as jq does.
# The caller is sourced as `. "$(dirname "$0")/jsonq_lib.sh"` (or ../rpc-tests/ from qa/zslp).
if [ -z "${JSONQ:-}" ]; then
    _jq_dir=$(cd "$(dirname "$0")" 2>/dev/null && pwd)
    for _jq_c in "$_jq_dir/../../zcutil/bin/jsonq" "$_jq_dir/../../zcutil/bin/jsonq.exe"; do
        if [ -x "$_jq_c" ]; then JSONQ=$_jq_c; break; fi
    done
    if [ -z "${JSONQ:-}" ] && command -v jsonq >/dev/null 2>&1; then JSONQ=jsonq; fi
    if [ -z "${JSONQ:-}" ] && [ -f "$_jq_dir/../../zcutil/tools/Makefile" ]; then
        # first use in a fresh checkout: build the vendored tool (host cc, libc only)
        make -s -C "$_jq_dir/../../zcutil/tools" >&2 || true
        [ -x "$_jq_dir/../../zcutil/bin/jsonq" ] && JSONQ=$_jq_dir/../../zcutil/bin/jsonq
    fi
    unset _jq_dir _jq_c
fi
if [ -z "${JSONQ:-}" ]; then
    echo "jsonq is required (make -C zcutil/tools, or set JSONQ=<path>)" >&2; exit 2
fi
export JSONQ

jget() {
    _jq_o=$("$JSONQ" get "$1"); _jq_r=$?
    case $_jq_r in 0) printf '%s\n' "$_jq_o" ;; 1) echo null ;; *) return "$_jq_r" ;; esac
}
jgetd() {
    _jq_o=$("$JSONQ" get "$1"); _jq_r=$?
    case $_jq_r in
        0) if [ "$_jq_o" = null ]; then printf '%s\n' "$2"; else printf '%s\n' "$_jq_o"; fi ;;
        1) printf '%s\n' "$2" ;;
        *) return "$_jq_r" ;;
    esac
}
jraw() {
    _jq_o=$("$JSONQ" raw "$1"); _jq_r=$?
    case $_jq_r in 0) printf '%s\n' "$_jq_o" ;; 1) echo null ;; *) return "$_jq_r" ;; esac
}
jlen() {
    _jq_o=$("$JSONQ" count "${1:-.}"); _jq_r=$?
    case $_jq_r in 0) printf '%s\n' "$_jq_o" ;; 1) echo 0 ;; *) return "$_jq_r" ;; esac
}

jhas() {
    "$JSONQ" has "$1"; _jq_r=$?
    case $_jq_r in 0) echo true ;; 1) echo false ;; *) return "$_jq_r" ;; esac
}
