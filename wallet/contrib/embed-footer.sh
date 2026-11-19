#!/bin/sh
# ZQWDMON1 single-file bundle footer (POSIX sh, openssl, od): the one place that writes and
# checks it for the dev and release scripts (replaces their former Python heredocs).
#
#   [ image ][ daemon ][ sha256(daemon) :32 ][ daemon length :8, little endian ][ "ZQWDMON1" :8 ]
#
#   embed-footer.sh append <image> <daemon>   append daemon and footer to <image> (in place)
#   embed-footer.sh verify <bundle>            footer present, length sane, sha256 matches
#   embed-footer.sh selftest                   round trip and corruption checks on scratch files
#
# Exit 0 on success. The daemon size must be 1..512 MiB, the loader limit.
set -eu
MAX=536870912

die() { echo "embed-footer: $*" >&2; exit 1; }

size_of() { wc -c < "$1" | tr -d '[:space:]'; }

sha_bin() { openssl dgst -sha256 -binary; }

# little-endian unsigned 64-bit encoding of $1 on stdout
le64() {
    n=$1; i=0
    while [ "$i" -lt 8 ]; do
        printf "\\$(printf '%03o' "$((n % 256))")"
        n=$((n / 256)); i=$((i + 1))
    done
}

do_append() {
    image=$1 daemon=$2
    [ -f "$image" ] && [ -f "$daemon" ] || die "usage: append <image> <daemon> (both must exist)"
    [ "$(tail -c 8 "$image" | od -An -c | tr -d ' \n')" != ZQWDMON1 ] || die "$image already has an embedded daemon"
    size=$(size_of "$daemon")
    [ "$size" -gt 0 ] && [ "$size" -le "$MAX" ] || die "daemon size $size outside the loader limit (1..512 MiB)"
    before=$(size_of "$image")
    cat "$daemon" >> "$image"
    sha_bin < "$daemon" >> "$image"
    le64 "$size" >> "$image"
    printf ZQWDMON1 >> "$image"
    [ "$(size_of "$image")" -eq $((before + size + 48)) ] || die "appended length mismatch"
}

do_verify() {
    f=$1
    [ -f "$f" ] || die "usage: verify <bundle>"
    total=$(size_of "$f")
    [ "$total" -ge 48 ] || die "file too small for a daemon footer"
    [ "$(tail -c 8 "$f" | od -An -c | tr -d ' \n')" = ZQWDMON1 ] || die "missing ZQWDMON1 footer"
    len=0; mult=1
    for b in $(tail -c 16 "$f" | head -c 8 | od -An -tu1 -v); do
        len=$((len + b * mult)); mult=$((mult * 256))
    done
    [ "$len" -gt 0 ] && [ "$len" -le "$MAX" ] && [ "$len" -le $((total - 48)) ] || die "invalid embedded daemon length $len"
    want=$(tail -c 48 "$f" | head -c 32 | od -An -tx1 -v | tr -d ' \n')
    got=$(tail -c +$((total - 48 - len + 1)) "$f" | head -c "$len" | sha_bin | od -An -tx1 -v | tr -d ' \n')
    [ "$want" = "$got" ] || die "embedded daemon checksum mismatch"
    echo "embed-footer: ok, daemon $len bytes, sha256 $got"
}

do_selftest() {
    d=$(mktemp -d)
    trap 'rm -rf "$d"' EXIT HUP INT TERM
    printf '\177ELFgui-image' > "$d/gui"
    # 300 bytes: the length needs two little-endian bytes (0x012c)
    head -c 300 /dev/zero | tr '\0' 'x' > "$d/daemon"
    cp "$d/gui" "$d/bundle"
    do_append "$d/bundle" "$d/daemon"
    do_verify "$d/bundle" > /dev/null
    [ "$(tail -c 16 "$d/bundle" | head -c 8 | od -An -tx1 | tr -d ' \n')" = 2c01000000000000 ] || die "selftest: length is not little endian"
    want=$(openssl dgst -sha256 -r "$d/daemon" | cut -d' ' -f1)
    [ "$(tail -c 48 "$d/bundle" | head -c 32 | od -An -tx1 -v | tr -d ' \n')" = "$want" ] || die "selftest: wrong sha256 in the footer"
    [ "$(head -c "$(size_of "$d/gui")" "$d/bundle")" = "$(cat "$d/gui")" ] || die "selftest: image bytes changed"
    # a second append, a flipped daemon byte, a cut footer and a wrong length must all fail
    ( do_append "$d/bundle" "$d/daemon" ) 2>/dev/null && die "selftest: double append accepted"
    cp "$d/bundle" "$d/bad"; printf 'y' | dd of="$d/bad" bs=1 seek=$(( $(size_of "$d/gui") + 10 )) conv=notrunc 2>/dev/null
    ( do_verify "$d/bad" ) 2>/dev/null && die "selftest: corrupted daemon accepted"
    head -c $(( $(size_of "$d/bundle") - 3 )) "$d/bundle" > "$d/cut"
    ( do_verify "$d/cut" ) 2>/dev/null && die "selftest: truncated footer accepted"
    : > "$d/empty"
    ( do_append "$d/gui" "$d/empty" ) 2>/dev/null && die "selftest: empty daemon accepted"
    echo "embed-footer: selftest passed"
}

case ${1:-} in
    append) [ $# -eq 3 ] || die "usage: append <image> <daemon>"; do_append "$2" "$3" ;;
    verify) [ $# -eq 2 ] || die "usage: verify <bundle>"; do_verify "$2" ;;
    selftest) do_selftest ;;
    *) die "usage: embed-footer.sh append <image> <daemon> | verify <bundle> | selftest" ;;
esac
