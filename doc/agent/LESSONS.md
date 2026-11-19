# Shared agent lessons

Tracked input for `zcl-dev guide`: lessons are matched to the paths you are about to edit. Each lesson is one line:

```text
OPEN|DONE <tracked-path> — <measured failure and the invariant>
```

`OPEN` means the invariant is not yet proven by repeatable evidence; change it to `DONE` only with a test or gate that holds it. Keep closed lines: they are the evidence trail. `zcl-dev check-docs` fails when a path is not tracked or a line has another shape. Verify each line against the code before relying on it; the code is the authority.

OPEN qa/rpc-tests/wallet_matrix.sh — tests that derive ports from the PID (`20000 + $$ % 20000`) collided under parallel runs several times in one release cycle; every script takes an explicit leased port base and fails fast on a bound port.
DONE src/wallet/db.cpp — the wallet DB environment opens with DB_TXN_WRITE_NOSYNC, so a commit is not durable on its own; durability needs an explicit checkpoint or flush (CDB::Flush, the flush thread, shutdown).
DONE src/wallet/wallet.cpp — CWallet::SetBestChain runs under cs_main then cs_wallet for the whole checkpoint; with cs_main alone a notifier-thread write deadlocked it (invalidateblock never returned) because Berkeley DB runs no deadlock detector here.
DONE src/wallet/wallet.cpp — wallet lock order is cs_main, then cs_wallet, then mempool.cs; never take cs_wallet or cs_main while holding mempool.cs.
DONE src/wallet/walletdb.cpp — a wallet backup is written to an exclusive temp file, synced, compared by SHA-256 with the source and only then renamed over the destination.
DONE qa/rpc-tests/wallet_platform_checks.sh — a node killed before its first chainstate flush restarts from height 0; tests wait for the re-sync from the peer before reading wallet state after a hard kill.
DONE src/main.cpp — LoadExternalBlockFile rejects a record whose deserialized length differs from its declared length, so a misaligned header cannot swallow a real block.
DONE src/main.cpp — FindBlockPos with a known position ends the record at pos + size - 8 (the header is already counted in the size); counting it twice leaves an 8-byte hole in the block file.
DONE src/init.cpp — -testcrashpoint (and the other -test* hooks) are accepted on regtest only, so no production node can be told to _exit.
DONE src/Makefile.am — MinGW C code needs -D__USE_MINGW_ANSI_STDIO=1 for %zu (msvcrt printf misreads the following arguments), set for libzcl_c23.a.
DONE src/c23/test/run.sh — release builds use GCC 9, so vendored C must compile as gnu17 with zero warnings; the harness defaults to -std=gnu17 and C23-only syntax is not allowed in anything linkable.
DONE wallet/contrib/release/build-windows.sh — windeployqt must run with --debug on kits whose release DLLs carry a debug link, or it skips every plugin and stops at "Unable to find the platform plugin".
DONE wallet/tests/run-windows.sh — QMessageBox crashes under the offscreen platform on stock Qt for Windows; the widget tests report KNOWN-CRASH unless a patched Qt5Widgets.dll is supplied.
DONE wallet/src/daemonjob.h — a wallet killed without cleanup (taskkill /F, crash) leaves the embedded daemon orphaned on its datadir and ports unless the Windows job object terminates it.
DONE src/bootstrap.cpp — snapshot serving needs process-wide aggregate caps in addition to per-IP quotas, since an attacker spread over many address groups sums past a per-IP quota; the caps are opt-in and default to unlimited.
DONE zcutil/local-ci.sh — the CI rootfs runs with --clearenv so a build broker's host-only TMPDIR and other host variables cannot leak into a step; each step also has a wall-clock timeout and a log-size cap so a hang or a runaway sanitizer fails fast.
DONE zcutil/local-ci.sh — sanitizer steps run under setarch -R because high mmap entropy makes the sanitizer runtime loop on DEADLYSIGNAL.
