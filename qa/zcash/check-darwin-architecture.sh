#!/bin/sh
# Exercise native macOS detection without requiring either kind of Mac.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
cat > "$scratch/uname" <<'EOF'
#!/bin/sh
case "$1" in
  -m) echo "$TEST_MACHINE" ;;
  -p) echo "$TEST_PROCESSOR" ;;
  -s) echo Darwin ;;
  -r) echo 25.0.0 ;;
  -v) echo test ;;
  *) exit 1 ;;
esac
EOF
chmod +x "$scratch/uname"
check() {
    actual=$(PATH="$scratch:$PATH" TEST_MACHINE="$1" TEST_PROCESSOR="$2" \
        sh "$root/depends/config.guess")
    test "$actual" = "$3-apple-darwin25.0.0" || {
        echo "FAIL: $1/$2 detected as $actual" >&2; exit 1;
    }
    test "$(sh "$root/depends/config.sub" "$actual")" = "$actual"
    echo "PASS: $1/$2 -> $actual"
}
check arm64 arm aarch64
check aarch64 arm aarch64
# Rosetta reports the process architecture as Intel; retain the Intel target.
check x86_64 i386 x86_64
