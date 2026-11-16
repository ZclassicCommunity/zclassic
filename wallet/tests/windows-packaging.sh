#!/bin/sh
# Real MinGW PE fixtures: reject dynamic runtimes, verify the embedded bytes.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CC=${CC:-x86_64-w64-mingw32-gcc}
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
trap 'exit 1' HUP INT TERM
cd "$temp"
cat > fixture.c <<'EOF'
#include <pthread.h>
static void *run(void *arg) { return arg; }
int main(void) {
    pthread_t thread;
    if (pthread_create(&thread, 0, run, 0)) return 1;
    return pthread_join(thread, 0);
}
EOF
"$CC" -std=c23 fixture.c -o dynamic.exe -lpthread
"$CC" -std=c23 fixture.c -o static.exe -static -static-libgcc -lpthread
gate="$root/contrib/cross/check-win-deps.sh"
pack="$root/contrib/cross/package-win.sh"
sh "$gate" static.exe
if sh "$gate" dynamic.exe; then echo 'FAIL: dynamic runtime accepted'; exit 1; fi
if sh "$gate" fixture.c; then echo 'FAIL: non-PE accepted'; exit 1; fi
if sh "$gate" missing.exe; then echo 'FAIL: absent binary accepted'; exit 1; fi
if sh "$pack" static.exe dynamic.exe rejected.exe; then exit 1; fi
[ ! -e rejected.exe ]
if sh "$pack" dynamic.exe static.exe rejected.exe; then exit 1; fi
[ ! -e rejected.exe ]
sh "$pack" static.exe static.exe 'bundle with spaces.exe'
bundle='bundle with spaces.exe'
[ "$(tail -c 8 "$bundle")" = ZQWDMON1 ]
size=$(wc -c < static.exe)
actual=$(tail -c 16 "$bundle" | head -c 8 | od -An -tu1 | awk '{for(i=NF;i>0;i--) n=n*256+$i} END {printf "%.0f",n}')
[ "$actual" = "$size" ]
tail -c "$((size + 48))" "$bundle" | head -c "$size" > extracted.exe
cmp static.exe extracted.exe
tail -c 48 "$bundle" | head -c 32 > actual.hash
openssl dgst -sha256 -binary extracted.exe > expected.hash
cmp actual.hash expected.hash
head -c "$size" "$bundle" > gui.exe
cmp static.exe gui.exe
if sh "$pack" static.exe static.exe "$bundle"; then exit 1; fi
if sh "$pack" "$bundle" static.exe double.exe; then exit 1; fi
[ ! -e double.exe ]
# Reject a valid PE with an oversized overlay before copying half a gigabyte.
cp static.exe oversized.exe
truncate -s 536870913 oversized.exe
if sh "$pack" static.exe oversized.exe oversized-bundle.exe; then exit 1; fi
[ ! -e oversized-bundle.exe ]

# Rebuild the original daemon precisely between copy and hash. The packager
# must hash its staged snapshot, so the final embedded bytes still verify.
REAL_OPENSSL=$(command -v openssl)
export REAL_OPENSSL
mkdir wrappers
cat > wrappers/openssl <<'EOF'
#!/bin/sh
cp dynamic.exe mutable.exe
exec "$REAL_OPENSSL" "$@"
EOF
chmod +x wrappers/openssl
cp static.exe mutable.exe
PATH="$temp/wrappers:$PATH" sh "$pack" static.exe mutable.exe rebuilt.exe
tail -c "$((size + 48))" rebuilt.exe | head -c "$size" > extracted.exe
cmp static.exe extracted.exe
tail -c 48 rebuilt.exe | head -c 32 > actual.hash
openssl dgst -sha256 -binary extracted.exe > expected.hash
cmp actual.hash expected.hash
echo 'PASS: Windows packaging regression tests'
