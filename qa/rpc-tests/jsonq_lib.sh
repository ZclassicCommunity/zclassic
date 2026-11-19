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
