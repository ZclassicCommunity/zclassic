#!/bin/sh
# Proves a linked zclassicd-family binary carries the C23 crypto core and no Rust.
# usage: check-no-rust.sh <nm> <binary>...
# For every binary that defines librustzcash_* symbols it requires
#   - exactly 31 of them (the 32 Rust names minus the never-called eh_isvalid),
#   - the C23 shim marker zcl_c23_params_initialized,
#   - no Rust runtime symbol (rust_begin_unwind, rust_eh_personality, __rust_alloc,
#     mangled core::/alloc::/std:: paths, the bellman/pairing/sapling_crypto crates).
# A binary with no librustzcash_* symbol at all (zclassic-cli) only gets the
# no-Rust check. Exit 0 when every binary passes, 1 otherwise.
set -u
[ $# -ge 2 ] || { echo "usage: $0 <nm> <binary>..." >&2; exit 2; }
nm=$1; shift
rc=0
for bin in "$@"; do
    [ -f "$bin" ] || [ ! -f "$bin.exe" ] || bin=$bin.exe
    if ! syms=$($nm "$bin" 2>/dev/null) || [ -z "$syms" ]; then
        echo "check-no-rust: FAIL $bin: no symbol table (run before stripping)"; rc=1; continue
    fi
    # Whole names only: GCC also emits local librustzcash_<fn>.cold fragments.
    n=$(printf '%s\n' "$syms" | grep -c ' [Tt] _\{0,1\}librustzcash_[A-Za-z0-9_]*$')
    rust=$(printf '%s\n' "$syms" | grep -c -E 'rust_begin_unwind|rust_eh_personality|__rust_alloc|__rust_dealloc|rust_panic|_ZN4core|_ZN5alloc|_ZN3std[0-9]|_ZN7bellman|_ZN7pairing|_ZN14sapling_crypto|_ZN12librustzcash')
    marker=$(printf '%s\n' "$syms" | grep -c ' [Tt] _\{0,1\}zcl_c23_params_initialized$')
    if [ "$rust" -ne 0 ]; then
        echo "check-no-rust: FAIL $bin: $rust Rust runtime/crate symbols"; rc=1; continue
    fi
    if [ "$n" -eq 0 ]; then
        echo "check-no-rust: OK   $bin: no librustzcash_* and no Rust symbols"; continue
    fi
    if [ "$n" -ne 31 ] || [ "$marker" -ne 1 ]; then
        echo "check-no-rust: FAIL $bin: $n librustzcash_* symbols (want 31), C23 marker $marker (want 1)"; rc=1; continue
    fi
    echo "check-no-rust: OK   $bin: 31 librustzcash_* from the C23 shim, 0 Rust symbols"
done
exit $rc
