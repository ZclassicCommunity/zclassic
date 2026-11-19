# TRAPS.md: guardrails for coding agents

**Verify fresh before trusting any line here; this file rots.** Line numbers shift; read 30-50 lines around any reference before acting. Each item is: what not to do, why, where. The live code is the only authority. `zcl-dev guide <path>` prints the section titles that match your paths (a `Paths:` line under each heading drives the match).

## (1) Consensus and chain state

Paths: src/main.cpp src/consensus/ src/chain.cpp src/pow.cpp src/script/ src/zcash/ src/coins.cpp

- **Do not change a rule, checkpoint, activation height or acceptance predicate to fix a bug or a speedup.** zclassicd is the reference and Z23 matches it bug-for-bug; a "cleaner" check forks the chain. Prove any rewrite accept/reject-identical on the same inputs, and fix divergences in both implementations. Where: `src/main.cpp`, `src/consensus/`. Verify fresh: run the differential and golden tests (`src/c23/test/run.sh`) before and after.
- **Do not "fix" the oversize-transaction grandfather table or the pinned Groth16 point-decode quirk.** They reproduce historical chain behaviour. Where: `src/consensus/oversize_grandfather.cpp`, [doc/oversize-grandfather.md](../oversize-grandfather.md), [src/c23/README.md](../../src/c23/README.md) ("Known pinned quirk"). Verify fresh: read both before touching.
- **Do not trust a block-file scan that deserializes cleanly.** A stale or misaligned header can parse into garbage; the record must consume exactly its declared length, else the scan resumes one byte past the magic. Where: `LoadExternalBlockFile` in `src/main.cpp`. Verify fresh: read the comment above the length check.
- **Do not count the 8-byte magic+length header twice for a known block position.** `FindBlockPos(..., fKnown=true)` ends the record at `pos.nPos + nAddSize - 8`; counting twice leaves an 8-byte hole in the file. Where: `FindBlockPos` in `src/main.cpp`.

## (2) Wallet database and locks

Paths: src/wallet/ src/init.cpp doc/wallet-crash-consistency.md

- **Do not assume a committed wallet write is on disk.** The environment opens with `DB_TXN_WRITE_NOSYNC`, so a commit reaches the log buffer, not the platter; durability needs an explicit checkpoint/flush (`CDB::Flush`, `ThreadFlushWalletDB`, shutdown flush). Where: `src/wallet/db.cpp`, `src/wallet/walletdb.cpp`. Verify fresh: [wallet-crash-consistency.md](../wallet-crash-consistency.md) and the `wallet_crash_*` scripts.
- **Do not call `SetBestChain` (or write the checkpoint) holding only `cs_main`.** The whole checkpoint runs under `cs_main` then `cs_wallet`: Berkeley DB has no deadlock detector here, so a notifier-thread write racing the checkpoint waits forever (an `invalidateblock` never returned). Where: `CWallet::SetBestChain` in `src/wallet/wallet.cpp`.
- **Do not take wallet locks out of order.** The order is `cs_main` -> `cs_wallet` -> `mempool.cs`; take `LOCK2(cs_main, cs_wallet)` first. Where: `src/wallet/wallet.cpp` (the re-accept loop locks `mempool.cs` last). Verify fresh: the debug build runs lock-order checks (`DEBUG=1`).
- **Do not copy a live wallet file to back it up.** Backup copies to a temp name with exclusive create and a sync, compares SHA-256 with the source, then renames. Where: `src/wallet/walletdb.cpp` (backup path), `qa/rpc-tests/backupwallet_atomic.sh`.
- **Do not write the witness checkpoint after a disconnect lost witnesses, and never block shutdown on the rebuild.** The flag is memory-only; write nothing and let the next start repair. Where: `CWallet::SetBestChain`.

## (3) C23 core and vendored code

Paths: src/c23/ zcutil/tools/ src/Makefile.am THIRD-PARTY-LICENSES

- **Do not edit anything under a `vendor/` directory.** It is verbatim Z23; the checker fails on a changed blob or an unlisted file. Re-vendor, then check. Where: [src/c23/AGENTS.md](../../src/c23/AGENTS.md), `src/c23/tools/check-vendor.sh`.
- **Do not compile vendored C as C23-only.** Release builds use GCC 9, i.e. gnu17; `nullptr`, `constexpr`, attributes, `typeof` break the release. Where: `src/c23/test/run.sh` defaults `--std gnu17`; `src/c23/tools/build-check.sh`.
- **Do not add an unprefixed global to `libzcl_c23.a`.** It collides with libsodium or OpenSSL at link time. Where: `src/c23/tools/symbol-prefix.sh`, `src/c23/glue/zcl_c23_symbol_prefix.h`.
- **Do not use `%zu` in C built for MinGW without `__USE_MINGW_ANSI_STDIO=1`.** msvcrt printf misreads the arguments that follow. Where: `src/Makefile.am` (`libzcl_c23_a_CPPFLAGS`).

## (4) Build, toolchain, release

Paths: zcutil/ depends/ configure.ac Makefile.am src/Makefile.am

- **Do not pass `HOST=` as an argument to `build.sh`.** It is an environment variable: as an argument it reaches only the `make` calls (depends may be built for it) while `configure` still uses `depends/<build triple>`, so you get a host or mixed build, not a cross build. Where: `zcutil/build.sh` (`HOST` defaults to `BUILD`; `DEPS_DIR` uses the shell variable).
- **Do not build a shipped Linux binary on a new host.** Newer glibc raises the symbol floor; the candidate must stay at `GLIBC_2.31`. Use `zcutil/local-ci.sh daemon-linux`. Where: `zcutil/local-ci.sh` (`inner_daemon_linux`).
- **Do not trust a build's exit status behind a pipe.** Check the artifact (footer, floor, `NEEDED`, hash sidecar). Where: [doc/building-quickstart.md](../building-quickstart.md).

## (5) qa scripts and local CI

Paths: qa/ zcutil/local-ci.sh zcutil/local-ci-smoke.sh zcutil/dev/ src/c23/test/

- **Do not derive test ports from the PID.** `$((20000 + ($$ % 20000)))` collides between parallel runs; the failure looks like a random "address in use" or a node that talks to the wrong peer. Take an explicit base. Where: `qa/rpc-tests/wallet_matrix.sh` and others (`git grep -n '\$\$ %' qa`).
- **Do not read wallet state right after a hard kill.** A node killed before its first chainstate flush restarts from height 0; wait for the re-sync from the peer. Where: `qa/rpc-tests/wallet_platform_checks.sh`, `qa/rpc-tests/wallet_reaccept_bound.sh`.
- **Do not use `-testcrashpoint` outside regtest.** It is rejected there; it is the deterministic crash hook. Where: `src/init.cpp`, `src/util.cpp`.
- **Do not weaken a timeout, tolerance or assertion to turn a step green.** Steps have wall-clock limits and a log cap on purpose. Where: `step()` in `zcutil/local-ci.sh`.
- **Do not let host environment leak into the CI rootfs.** `--clearenv` is deliberate (a broker's `TMPDIR` is host-only); pass what a step needs explicitly. Where: `enter()` in `zcutil/local-ci.sh`.
- **Do not run sanitizer steps with full ASLR.** High `mmap` entropy makes the runtime loop on DEADLYSIGNAL; the step runs under `setarch -R`. Where: `noaslr()` in `zcutil/local-ci.sh`.

## (6) Wallet GUI, Windows, packaging

Paths: wallet/ zcutil/local-ci-macos.sh

- **Do not run the widget tests on stock Qt for Windows and expect `QMessageBox` to work.** It crashes under the offscreen platform; patched QtWidgets is needed (`KNOWN-CRASH` otherwise). Where: `wallet/tests/run-windows.sh`, `wallet/tests/qt-5.15.2-windows-offscreen.patch`.
- **Do not call `windeployqt` without `--debug` on kits whose release DLLs carry a debug link.** It reads the `.gnu_debuglink` as "debug", skips every plugin and stops with "Unable to find the platform plugin"; `--release` cannot work around it. Where: `wallet/contrib/release/build-windows.sh`, `wallet/docs/BUILDING.md`.
- **Do not change the daemon footer layout in one place.** Three writers and one reader must agree. Where: `wallet/src/embeddeddaemon.cpp` and the scripts under `wallet/contrib/`.
- **Do not rely on the wallet's cleanup to stop the embedded daemon.** A `taskkill /F` or a crash skips it; the Windows job object is the backstop. Where: `wallet/src/daemonjob.h`.

## (7) Bootstrap snapshots

Paths: src/bootstrap.cpp src/bootstrap.h doc/bootstrap-snapshots.md qa/bootstrap-resume/

- **Do not reason about snapshot serving with per-peer quotas alone.** The aggregate serve caps are process-wide and opt-in (default 0 = unlimited); an attacker across many address groups sums past a per-IP quota. Where: `src/bootstrap.cpp` ("S1: process-wide aggregate serve caps"), `src/bootstrap.h`. Verify fresh: read the comment and defaults.
