#!/bin/bash
set -euo pipefail

# First thing to do is see if libsodium.a exists in the res folder. If it does, then there's nothing to do
if [ -f res/libsodium.a ]; then
    exit 0
fi

echo "Building libsodium"

# Go into the lib sodium directory
cd res/libsodium
expected_sha256="eeadc7e1e1bcef09680fb4837d448fbdf57224978f865ac1c16745868fbd0533"

verify_archive() {
    actual_sha256="$(sha256sum libsodium-1.0.16.tar.gz | awk '{print $1}')"
    [ "$actual_sha256" = "$expected_sha256" ]
}

if [ -f libsodium-1.0.16.tar.gz ] && ! verify_archive; then
    echo "Existing libsodium-1.0.16.tar.gz failed checksum; redownloading" >&2
    rm -f libsodium-1.0.16.tar.gz
fi

if [ ! -f libsodium-1.0.16.tar.gz ]; then
    urls=(
        "https://download.libsodium.org/libsodium/releases/libsodium-1.0.16.tar.gz"
        "https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz"
    )
    fetched=0
    for url in "${urls[@]}"; do
        echo "Downloading libsodium from $url"
        rm -f libsodium-1.0.16.tar.gz
        if command -v wget >/dev/null 2>&1; then
            wget -O libsodium-1.0.16.tar.gz "$url" && fetched=1 && break
        elif command -v curl >/dev/null 2>&1; then
            curl -fL -o libsodium-1.0.16.tar.gz "$url" && fetched=1 && break
        else
            echo "ERROR: need wget or curl to download libsodium" >&2
            exit 1
        fi
    done
    if [ "$fetched" -ne 1 ]; then
        echo "ERROR: failed to download libsodium-1.0.16.tar.gz" >&2
        exit 1
    fi
fi

if ! verify_archive; then
    echo "ERROR: libsodium-1.0.16.tar.gz checksum mismatch" >&2
    exit 1
fi

# Re-extract if the source dir is absent OR a prior run left it INCOMPLETE (e.g. an
# interrupted extraction with no ./configure). A bare `[ ! -d ... ]` check would skip
# extraction over such a stale dir and then fail at `./configure: No such file`.
if [ ! -x libsodium-1.0.16/configure ]; then
    rm -rf libsodium-1.0.16
    tar xf libsodium-1.0.16.tar.gz
fi

# Now build it
cd libsodium-1.0.16
LIBS="" ./configure
make clean
if [[ "$OSTYPE" == "darwin"* ]]; then
    make CFLAGS="-mmacosx-version-min=10.11" CPPFLAGS="-mmacosx-version-min=10.11" -j4
else
    make -j4
fi
cd ..

# copy the library to the parents's res/ folder
cp libsodium-1.0.16/src/libsodium/.libs/libsodium.a ../
