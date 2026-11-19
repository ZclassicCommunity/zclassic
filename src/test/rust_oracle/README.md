# Rust oracle golden capture

`gen_golden.cpp` links the Rust `librustzcash.a` from a built `depends` prefix
and records its behaviour for the 31 `librustzcash_*` functions zclassicd calls.
The output is `src/test/data/c23_golden/*.golden`, described in
`src/test/data/c23_golden/FORMAT.md`. It exists so the C23 replacement can be
checked against the real Rust after Rust is deleted from `depends`.

## Regenerate

Requirements: x86_64 Linux, g++ with C++17, a `depends` prefix that still
contains `lib/librustzcash.a`, `lib/libsodium.a`, `lib/libgmp.a`,
`lib/libgmpxx.a` and `include/librustzcash.h` (any tree before the Rust removal,
built with `make -C depends`), and the Zcash parameter files
(`zcutil/fetch-params.sh`). No configure step is needed.

```sh
DEPENDS=$PWD/depends/x86_64-unknown-linux-gnu PARAMS=$HOME/.zcash-params \
    src/test/rust_oracle/build.sh            # full corpus, writes src/test/data/c23_golden
src/test/rust_oracle/build.sh build-only     # compile only
src/test/rust_oracle/build.sh --quick        # 40 random cases per function, few proofs
```

`OUT=<dir>` writes elsewhere. On a shared host run it under the host's job
broker; the full corpus forks about 60,000 short-lived children and creates
about 20 Groth16 proofs.

Fixed inputs come from a ChaCha20 stream with a fixed seed, so a rerun records
the same inputs. Rust's `OsRng` makes proofs, signatures and `generate_r`
outputs differ between runs (see FORMAT.md). A rerun therefore changes those
records and nothing else; compare with `MANIFEST.tsv` record counts and verdict
counts.

## What the generator checks before it writes

The generator stops (exit status 2) unless Rust reproduces every published
vector it uses: all 10 rows of `sapling_key_components.json` (to_scalar,
ask_to_ak, nsk_to_nk, crh_ivk, ivk_to_pkd, compute_cm, compute_nf), the empty
Sapling roots, the 16 depth-4 tree roots, the Pedersen hash vector, the ZIP-32
vectors, the testnet spend and output, every description and binding signature
of the 13 mainnet Sapling transactions, the 75 mainnet Sprout JoinSplit proofs,
and Rust's own verification of each valid bundle it proved. These checks
validate the generator's byte orders, witness encoding and sighash code, not
Rust.

## Inputs

- `inputs/mainnet_sapling_txs.txt`: public mainnet transactions fetched on
  2026-11-16 from a public Insight explorer (`/api/rawtx/<txid>`). The
  transport is untrusted; the generator recomputes each txid from the bytes and
  requires Rust to accept every proof and signature in them.
- `inputs/mainnet_sprout_txs.txt`: copied from Z23 `origin/main`
  `aa9eed8322b686cf9ee5443adfe9bb6063d985e7`,
  `tests/harness/src/test_sprout_groth16_kat.c` and
  `tests/harness/src/fixture_tx_oversize_478544.c`.

## Not covered

- `librustzcash_eh_isvalid` (declared, never called by zclassicd).
- Windows UTF-16 parameter paths: the capture ran on Linux, where `codeunit` is
  a byte.
- Full-history replay of the Sapling tree and of every JoinSplit (plan unit U11).
