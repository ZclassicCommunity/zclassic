#!/bin/sh
# Exercise the actual depends fetch macro using local, deterministic downloads.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
export TEST_ROOT="$scratch"
printf 'verified archive\n' > "$scratch/expected"
expected_hash=$(sha256sum "$scratch/expected" | cut -d ' ' -f 1)
cat > "$scratch/download.sh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$2" >> "$TEST_ROOT/requests"
case "$SCENARIO:$2" in
  good-mirror:*) cp "$TEST_ROOT/expected" "$1" ;;
  failed-mirror:*mirror*) exit 22 ;;
  bad-both:*|*:*/mirror/*) printf 'invalid mirror response\n' > "$1" ;;
  *) cp "$TEST_ROOT/expected" "$1" ;;
esac
EOF
cat > "$scratch/Makefile" <<'EOF'
include $(ROOT)/depends/funcs.mk
mock_source_dir=$(TEST_ROOT)/sources
mock_download_dir=$(TEST_ROOT)/download
build_DOWNLOAD=sh $(TEST_ROOT)/download.sh
build_SHA256SUM=sha256sum
PRIORITY_DOWNLOAD_PATH=https://fixture.invalid/mirror
$(eval mock_fetch_cmds = $(call fetch_file,mock,https://fixture.invalid/origin,archive,archive,$(EXPECTED_HASH)))
.PHONY: fetch
fetch:
	@$(mock_fetch_cmds)
EOF
for scenario in good-mirror bad-mirror failed-mirror bad-both; do
    mkdir -p "$scratch/sources"
    : > "$scratch/requests"
    if SCENARIO="$scenario" make -f "$scratch/Makefile" ROOT="$root" \
            EXPECTED_HASH="$expected_hash" fetch > "$scratch/result" 2>&1; then
        test "$scenario" != bad-both
        cmp "$scratch/expected" "$scratch/sources/archive"
    else
        test "$scenario" = bad-both || { cat "$scratch/result"; exit 1; }
        test ! -e "$scratch/sources/archive"
    fi
    expected_requests=2
    test "$scenario" != good-mirror || expected_requests=1
    test "$(wc -l < "$scratch/requests" | tr -d ' ')" = "$expected_requests"
    rm -f "$scratch/sources/archive"
    echo "PASS: $scenario"
done
