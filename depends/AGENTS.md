# depends agent rules

Imports the root contract: [../AGENTS.md](../AGENTS.md). How to use the system: [README.md](README.md) and [packages.md](packages.md). Packages are `packages/*.mk`, host settings `hosts/*.mk`, patches `patches/`.

- This is the pinned third-party build system. A package version, hash or URL changes only with the reason in the commit and a rebuild that proves it; never change a hash to make a download pass.
- Release binaries come from here, so a change affects every shipped build: `depends/*` maps to `ALL daemon-linux daemon-win64` in `zcutil/dev/impact.rules`.
- Rust is gone: add no Rust, cargo or Python package. The cryptographic core is `src/c23/`.
- Build products (`sources/`, `work/`, `built/`, `SDKs/`, the per-triplet prefix directories such as `x86_64-w64-mingw32/`) are ignored output; never commit or search them.
- `HOST` is an environment variable of `zcutil/build.sh`, not an argument ([doc/agent/TRAPS.md](../doc/agent/TRAPS.md) section 4).

Tests: `make -C depends HOST=<triplet> -j"$(getconf _NPROCESSORS_ONLN)"` on a build host, then `zcutil/local-ci.sh --commit <sha> --only check-c23-no-rust test <outdir>` and the stages `daemon-linux` and `daemon-win64`.
