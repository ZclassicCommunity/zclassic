#!/bin/sh
# Check the exploit-mitigation properties of release binaries.
#
#   zcutil/check-hardening.sh <binary>...
#
# Format is detected from the file magic.  One line per check:
#   PASS <file>: <check> ...   FAIL <file>: <check> ...   INFO / SKIP <file>: ...
# Exit status is non-zero when any hard check fails.  Pure POSIX sh plus
# binutils; READELF and OBJDUMP override the tool names (a cross toolchain's
# x86_64-w64-mingw32-objdump is preferred for PE when it is on PATH).
#
# ELF   : PIE, full RELRO (GNU_RELRO + BIND_NOW), non-executable stack,
#         stack canary (__stack_chk_fail); FORTIFY (_chk symbols) is info.
# PE    : DYNAMIC_BASE, NX_COMPAT, HIGH_ENTROPY_VA and a non-empty .reloc
#         section (without relocations ASLR cannot apply).
# Mach-O: PIE flag via otool (skipped with a message when otool is absent).

set -u
READELF=${READELF:-readelf}
fails=0

pass() { echo "PASS $f: $*"; }
fail() { echo "FAIL $f: $*"; fails=$((fails + 1)); }
info() { echo "INFO $f: $*"; }
skip() { echo "SKIP $f: $*"; }

have() { command -v "$1" >/dev/null 2>&1; }

magic() { od -An -tx1 -N4 "$1" | tr -d ' \n'; }

check_elf() {
    have "$READELF" || { fail "readelf not found (set READELF)"; return; }
    hdr=$("$READELF" -hW "$f" 2>/dev/null) || { fail "readelf cannot read file"; return; }
    seg=$("$READELF" -lW "$f" 2>/dev/null)
    dyn=$("$READELF" -dW "$f" 2>/dev/null)
    case $(printf '%s\n' "$hdr" | awk '/^ *Type:/ { print $2 }') in
        DYN)
            if printf '%s\n' "$seg" | grep -q ' INTERP ' || printf '%s\n' "$dyn" | grep -q 'Flags: .*PIE'; then
                pass "PIE (ET_DYN with interpreter or DF_1_PIE)"
            else
                fail "ET_DYN without interpreter or DF_1_PIE (shared object, not PIE)"
            fi ;;
        EXEC) fail "PIE missing (ET_EXEC)" ;;
        *) fail "unexpected ELF type" ;;
    esac
    if printf '%s\n' "$seg" | grep -q ' GNU_RELRO '; then
        if printf '%s\n' "$dyn" | grep -Eq 'BIND_NOW|Flags: .*NOW'; then
            pass "full RELRO (GNU_RELRO + BIND_NOW)"
        else
            fail "partial RELRO only (no BIND_NOW)"
        fi
    else
        fail "RELRO missing (no GNU_RELRO)"
    fi
    stk=$(printf '%s\n' "$seg" | awk '/ GNU_STACK / { print $(NF-1) }')
    case $stk in
        '') fail "no GNU_STACK header (stack may be executable)" ;;
        *E*) fail "executable stack (GNU_STACK flags $stk)" ;;
        *) pass "NX stack (GNU_STACK flags $stk)" ;;
    esac
    syms=$("$READELF" -sW "$f" 2>/dev/null)
    nsyms=$(printf '%s\n' "$syms" | grep -c ':')
    if printf '%s\n' "$syms" | grep -q '__stack_chk_fail'; then
        pass "stack canary (__stack_chk_fail referenced)"
    elif [ "$nsyms" -eq 0 ]; then
        skip "stack canary not checkable (binary has no symbol table)"
    else
        fail "stack canary missing (no __stack_chk_fail)"
    fi
    nchk=$(printf '%s\n' "$syms" | grep -Ec '[A-Za-z0-9]_chk(@|$| )')
    info "FORTIFY: $nchk _chk symbol(s)"
    note=$("$READELF" -nW "$f" 2>/dev/null | grep -E 'IBT|SHSTK' | tr -s ' ' | tr '\n' ' ')
    [ -n "$note" ] && info "CET property note:$note"
    return 0
}

check_pe() {
    obj=${OBJDUMP:-}
    if [ -z "$obj" ]; then
        for c in x86_64-w64-mingw32-objdump x86_64-w64-mingw32ucrt-objdump objdump; do
            have "$c" && { obj=$c; break; }
        done
    fi
    [ -n "$obj" ] || { fail "no objdump found (set OBJDUMP)"; return; }
    hex=$("$obj" -p "$f" 2>/dev/null | awk '/^DllCharacteristics/ { print $2; exit }')
    if [ -z "$hex" ]; then fail "cannot read DllCharacteristics with $obj"; return; fi
    v=$((0x$hex))
    [ $((v & 0x40)) -ne 0 ] && pass "DYNAMIC_BASE (DllCharacteristics 0x$hex)" || fail "DYNAMIC_BASE missing (0x$hex)"
    [ $((v & 0x100)) -ne 0 ] && pass "NX_COMPAT" || fail "NX_COMPAT missing (0x$hex)"
    [ $((v & 0x20)) -ne 0 ] && pass "HIGH_ENTROPY_VA" || fail "HIGH_ENTROPY_VA missing (0x$hex)"
    size=$("$obj" -h "$f" 2>/dev/null | awk '$2 == ".reloc" { print $3; exit }')
    if [ -z "$size" ]; then
        fail ".reloc section absent (ASLR does not apply)"
    elif [ $((0x$size)) -gt 0 ]; then
        pass ".reloc present (0x$size bytes)"
    else
        fail ".reloc empty (ASLR does not apply)"
    fi
}

check_macho() {
    if ! have otool; then skip "Mach-O PIE not checked (otool not available on this host)"; return; fi
    if otool -hv "$f" 2>/dev/null | grep -qw PIE; then pass "PIE flag"; else fail "PIE flag missing"; fi
}

[ $# -gt 0 ] || { echo "usage: $0 <binary>..." >&2; exit 2; }
for f in "$@"; do
    [ -f "$f" ] || { echo "FAIL $f: no such file"; fails=$((fails + 1)); continue; }
    m=$(magic "$f")
    case $m in
        7f454c46) check_elf ;;
        4d5a*) check_pe ;;
        cffaedfe|feedfacf|cafebabe|bebafeca) check_macho ;;
        *) fail "unrecognised binary format (magic $m)" ;;
    esac
done
[ "$fails" -eq 0 ] || { echo "check-hardening: $fails hard failure(s)" >&2; exit 1; }
echo "check-hardening: all hard checks passed"
