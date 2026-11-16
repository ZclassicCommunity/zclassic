# Build wiring for src/test/rust_oracle and src/test/data/c23_golden

Nothing in the autotools build has to change for this unit.

- `gen_golden.cpp` is a standalone maintenance tool. It is built only by
  `src/test/rust_oracle/build.sh` against a `depends` prefix that still has
  `librustzcash.a`. It must not be added to any `Makefile.am`: after the Rust
  removal there is no `librustzcash.a` to link.
- The goldens are read at test run time by the consumers (plan units U4 and
  U6). If a consumer is built by automake and `make dist` must carry the data,
  that consumer's wiring unit adds to `src/Makefile.test.include` or
  `src/Makefile.gtest.include`:

  ```make
  EXTRA_DIST += test/data/c23_golden/FORMAT.md test/data/c23_golden/MANIFEST.tsv \
      $(wildcard $(srcdir)/test/data/c23_golden/*.golden)
  ```

  and passes the directory to the test, for example through an environment
  variable such as `C23_GOLDEN_DIR=$(srcdir)/test/data/c23_golden`.
- Optional, for regeneration only: `EXTRA_DIST += test/rust_oracle/README.md
  test/rust_oracle/WIRING.md test/rust_oracle/build.sh test/rust_oracle/gen_golden.cpp
  test/rust_oracle/inputs/mainnet_sapling_txs.txt test/rust_oracle/inputs/mainnet_sprout_txs.txt`.
