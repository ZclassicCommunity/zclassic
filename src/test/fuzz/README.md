# Opt-in fuzz and sanitizer-replay harnesses

Three targets exercise the consensus-adjacent decoders of this node:

| Target | Input | What runs |
| --- | --- | --- |
| `fuzz_block` | serialized block | `CBlockHeader` then `CBlock` deserialization, `CheckBlockHeader(fCheckPOW=false)`, `CheckBlock(ProofVerifier::Disabled(), fCheckPOW=false, fCheckMerkleRoot=true)` |
| `fuzz_tx` | serialized transaction | `CTransaction` deserialization, `CheckTransactionWithoutProofVerification`, `GetLegacySigOpCount`, `SignatureHash` per input (`SIGHASH_ALL`, Sapling branch id). No proof or signature verification |
| `fuzz_p2p_payload` | one selector byte plus a message payload | byte 0 mod 10 picks 0 inv, 1 getdata, 2 addr, 3 headers, 4 getblocks, 5 filterload, 6 filteradd, 7 merkleblock, 8 tx, 9 block; the rest is read through `CDataStream(SER_NETWORK, PROTOCOL_VERSION)` with the types `ProcessMessage` uses. No `CNode` |

Everything here is outside the default build: no autotools or Makefile
change, nothing is compiled or linked into `zclassicd`, and no CI runs it.
It is meant to be run on your own machine (for example from a nightly cron
job) after a normal build.

Only `std::ios_base::failure` may escape decoding, and each target catches it.
Any other exception, assertion, ASan or UBSan report aborts the process, which
is how the fuzzer records a crash. Inputs over 2 MB are ignored. Each target
selects mainnet parameters and starts ECC once, in a static initializer.

## Build

```sh
# in a configured, built tree (the one holding src/Makefile and the .a files)
sh src/test/fuzz/build-fuzz.sh <builddir> <outdir> [cxx]
```

* `cxx` containing `clang`: links libFuzzer (`-fsanitize=fuzzer`) with ASan and
  UBSan. Run `<outdir>/fuzz_block -max_total_time=60 src/test/fuzz/corpus/block`.
* anything else (default `g++`): links `replay_main.cpp` with ASan and UBSan;
  the binary takes files or directories and replays every file:
  `<outdir>/fuzz_block src/test/fuzz/corpus/block`.

Only the harness translation unit is instrumented; the project static
libraries are linked as built. The include and library flags are read from the
configured `src/Makefile` (`BITCOIN_INCLUDES`, `BOOST_LIBS`, `BDB_LIBS`, ...),
and the archive list copies the `test_bitcoin` `LDADD` in
`src/Makefile.test.include`. If a toolchain change breaks the link, compare
that list first; the replay mode needs only a C++ compiler and Boost.

## Local nightly use

```sh
OUT=$HOME/fuzz-out
sh src/test/fuzz/build-fuzz.sh /path/to/build $OUT clang++
for t in fuzz_block fuzz_tx fuzz_p2p_payload; do
    c=${t#fuzz_}; c=${c%_payload}; mkdir -p $OUT/work-$c
    $OUT/$t -max_total_time=3600 -max_len=65536 $OUT/work-$c src/test/fuzz/corpus/$c
done
# gcc-only hosts: replay the checked-in corpus under ASan+UBSan
sh src/test/fuzz/build-fuzz.sh /path/to/build $OUT g++
$OUT/fuzz_block src/test/fuzz/corpus/block
$OUT/fuzz_tx src/test/fuzz/corpus/tx
$OUT/fuzz_p2p_payload src/test/fuzz/corpus/p2p
```

libFuzzer writes new interesting inputs to the first corpus directory given
(`work-*` above), so the checked-in corpus stays untouched.

## Crash rule

A crash, hang or sanitizer report is never fixed first. Minimize it
(`-minimize_crash=1`), turn it into a Boost regression case in
`wire_robustness_tests` (`src/test/wire_robustness_tests.cpp`, add it to
`src/Makefile.test.include` with the first case) that fails on the current
tree, and only then change the decoder. Do not commit the raw `crash-*` file as
a corpus seed until the regression case exists. Never touch behaviour that
affects consensus results: a decoder fix must keep every valid encoding
accepted and every invalid one rejected exactly as before.

## Corpus

* `corpus/block`, `corpus/p2p`: seeds copied byte for byte from Z23
  `origin/main` (`git show origin/main:<path>`), named seeds and `crash-*`
  seeds only; every `timeout-*` seed was skipped.
  The Z23 `compactblock` seeds live in `corpus/p2p` with a `z23-compactblock-`
  prefix. Z23's p2p seeds use Z23's own selector table, so for this
  harness they are just structured inputs; `sel*` files in `corpus/p2p` are
  locally made seeds with this harness's selector byte in front.
* `corpus/tx`: `empty.bin` plus eight transactions taken from
  `src/test/data/tx_valid.json`, one per distinct hex length (smallest eight),
  generated with:

  ```sh
  grep -o '^"[0-9a-f]\{40,\}",' src/test/data/tx_valid.json | tr -d '",' \
    | awk '{print length($0), $0}' | sort -n -s -k1,1 | awk '!s[$1]++ {print $2}' | head -8 \
    | while read h; do i=$((i+1)); printf %s "$h" | xxd -r -p > corpus/tx/tx_valid_$i.bin; done
  ```

Provenance of the Z23 seeds (Z23 path, git blob sha):

| Local file | Z23 path (`origin/main`) | Blob sha |
| --- | --- | --- |
| `block/empty_version.bin` | `tests/harness/fuzz_seeds/block/empty_version.bin` | `86906d2f2176b77221aa6575cf6b92b619fd637d` |
| `block/header_size.bin` | `tests/harness/fuzz_seeds/block/header_size.bin` | `037b42be38fff7ce167a4f668c65fe798ac00173` |
| `block/tx_empty.bin` | `tests/harness/fuzz_seeds/block/tx_empty.bin` | `32354e902f066d3296273d77500be8ea6e7d086f` |
| `block/tx_null_input.bin` | `tests/harness/fuzz_seeds/block/tx_null_input.bin` | `76cf9422d9762a8a4f219cd10a6a83c8b1ec98e5` |
| `p2p/z23-compactblock-cmpct_maxcap.bin` | `tests/harness/fuzz_seeds/compactblock/cmpct_maxcap.bin` | `fd3bb3a7b46e8bafa5747e1ae2bc2ab1c62ba82c` |
| `p2p/z23-compactblock-cmpct_min.bin` | `tests/harness/fuzz_seeds/compactblock/cmpct_min.bin` | `24c6bb8b992afbffe14275f50d1cc58b57b9d6d6` |
| `p2p/z23-compactblock-empty.bin` | `tests/harness/fuzz_seeds/compactblock/empty.bin` | `e69de29bb2d1d6434b8b29ae775ad8c2e48c5391` |
| `p2p/crash-478b30c0482cf3e2842fa459987a7a2e5374e708.bin` | `tests/harness/fuzz_seeds/p2p/crash-478b30c0482cf3e2842fa459987a7a2e5374e708.bin` | `8433b6f12e2564476db1ff950d38e6f25900bb8f` |
| `p2p/crash-e3fef02ed5b5b9239b2d68e94fc48f7fc76879ea.bin` | `tests/harness/fuzz_seeds/p2p/crash-e3fef02ed5b5b9239b2d68e94fc48f7fc76879ea.bin` | `8b102e6ee3410a10f92854303723b376074c6365` |
| `p2p/short.bin` | `tests/harness/fuzz_seeds/p2p/short.bin` | `593f4708db84ac8fd0f5cc47c634f38c013fe9e4` |
| `p2p/tx_v1_stub.bin` | `tests/harness/fuzz_seeds/p2p/tx_v1_stub.bin` | `32354e902f066d3296273d77500be8ea6e7d086f` |

The Z23 `crash-*` files crashed Z23, not this node; here they are ordinary inputs.
