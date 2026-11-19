# Building ZClassic: quickstart

The daemon (`zclassicd`, `zclassic-cli`, `zclassic-tx`) and the all-in-one Qt wallet (`zclwallet`) for Linux, Windows and macOS. This is the map; the detailed procedures are in [building-daemon-from-source.md](building-daemon-from-source.md) and [../wallet/docs/BUILDING.md](../wallet/docs/BUILDING.md). Scripts move: before you quote a line, read it. Build rules: [../AGENTS.md](../AGENTS.md).

## Big picture

The wallet and the daemon live in this one repository (`wallet/` is the Qt wallet). There is no Rust and no Python in any build step.

The shipped wallet on Linux and Windows is one self-contained executable. The daemon is appended to the wallet binary as a footer; the wallet verifies and extracts it on first launch:

```
[ wallet binary ][ daemon bytes ][ sha256(daemon):32 ][ len(daemon):8 LE u64 ][ magic "ZQWDMON1":8 ]
```

Written in `wallet/contrib/release/linux.sh` and `wallet/contrib/release/build-windows.sh`, and also by `wallet/contrib/make-allinone.sh` (development); read in `wallet/src/embeddeddaemon.cpp`. Keep all of them in sync when you touch the layout.

macOS is the exception: notarization forbids executing a runtime-written binary, so the daemon ships as a sibling inside `zclwallet.app/Contents/MacOS/` and there is no footer.

The version is `CLIENT_VERSION_*` in `src/clientversion.h` (build N reports as beta N+1); the wallet release scripts carry their own `release_version`.

## Entry points

| Target | Command |
|---|---|
| Daemon, Linux dev build (into `src/`) | `./zcutil/build.sh -j"$(getconf _NPROCESSORS_ONLN)"` |
| Daemon, Linux release (stripped) | `./zcutil/build-release.sh linux -j"$(getconf _NPROCESSORS_ONLN)"` |
| Daemon, Windows cross build | `sudo bash zcutil/setup-mingw-toolchain.sh`, then `./zcutil/build-release.sh win64 -j...` |
| Daemon, macOS | built natively on a Mac, `zcutil/local-ci-macos.sh` |
| Wallet, Linux portable bundle | `wallet/contrib/release/linux.sh` (run on Ubuntu 20.04; it gates the glibc floor) |
| Wallet, Windows | `wallet/contrib/release/build-windows.sh` (Qt kit and MinGW, see its header) |
| Wallet, macOS | `wallet/contrib/release/macos.sh` (codesigns the app after bundling) |
| Release candidates on our own machines | `zcutil/local-ci.sh all <outdir>`, see [local-ci.md](local-ci.md) |

`./zcutil/fetch-params.sh` downloads the zk parameters into `~/.zcash-params` before first run (a runtime prerequisite, not a build one).

## Gotchas

- `HOST` is an environment variable, never an argument: `HOST=x86_64-w64-mingw32 ./zcutil/build.sh` cross-builds; `./zcutil/build.sh HOST=...` does not cross-build (the token reaches only the `make` calls; `configure` uses the host depends). Prefer `build-release.sh win64`.
- The mingw compiler must use the POSIX thread model (`x86_64-w64-mingw32-g++ -v` prints `Thread model: posix`), or `std::thread` and `std::mutex` fail to compile.
- Clean when you switch `HOST`: stale trees mix ELF and COFF objects. For the wallet, `make distclean && rm -f Makefile .qmake.stash` before a different kit.
- Release binaries are built with GCC 9 on glibc 2.31 so they run on old distributions. A newer host raises the floor; `local-ci.sh daemon-linux` and `wallet/contrib/release/linux.sh` enforce `GLIBC_2.31` and report it. Use `local-ci.sh` (a focal root filesystem built without root) rather than a host build for anything you ship.
- The daemon has no OpenMP dependency; check `objdump -p <bin> | grep NEEDED` on both daemon and wallet for stray libraries.
- A build log that ends in success is not a build: check the artifact. Footer: `tail -c 8 <bundle>` prints `ZQWDMON1`. Glibc floor: `objdump -T <bin> | grep -oE 'GLIBC_[0-9.]+' | sort -V | tail -1`. Hashes: compare `sha256sum` with the sidecar the gate wrote; local files and published assets drift.
- Windows: `wallet/contrib/release/build-windows.sh` embeds the daemon footer itself; run `windeployqt` with `--debug` on kits whose release DLLs carry a debug link.
- macOS: sign after `macdeployqt` (the scripts do); signing earlier gets the app killed on Apple Silicon.
- Cross-building macOS on Linux is not set up: use a Mac.

## Verify a candidate

```sh
zcutil/local-ci.sh --commit <sha> all <outdir>      # builds, hardening and glibc gates, full tests
cat <outdir>/receipts.jsonl                         # one JSON receipt per step
zcutil/dev/zcl-dev receipt test_bitcoin-full <outdir>
```

Publishing release assets is a separate, reviewed act; compare `sha256sum` of what you upload with the candidate's `SHA256SUMS.txt`.
