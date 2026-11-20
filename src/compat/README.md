# src/compat: portability shims and start-up sanity checks

Small compatibility code that keeps the daemon linkable against an older glibc and checks at start-up that the C and C++ runtimes behave as the code expects.

## What lives here

- `glibc_compat.cpp`: aliases `memcpy` to `memmove` and defines `__fdelt_chk` as a weak alias of a bounds-checked `__fdelt_warn`, so the binary needs no newer glibc symbol version.
- `glibc_sanity.cpp`, `glibcxx_sanity.cpp`, `sanity.h`: `glibc_sanity_test` and `glibcxx_sanity_test`, called from `src/init.cpp` before the node starts.
- `strnlen.cpp`: `strnlen`, compiled only when the platform declares none (`HAVE_DECL_STRNLEN`).
- `byteswap.h`, `endian.h`: byte-order macros for platforms without them.

## Traps

- The shipped Linux binary must stay at `GLIBC_2.31`; build it only in the focal root filesystem (`zcutil/local-ci.sh` stage `daemon-linux`), never on a newer host. The CI stage fails when a higher `GLIBC_` symbol appears.
- A failed sanity test makes `InitSanityCheck` in `src/init.cpp` return false, so the node does not start on a runtime it was not built for.
- Do not edit these files for a feature; they exist so that the build floor does not move. A change here needs a `daemon-linux` and `daemon-win64` candidate build.
- All of this code is compiled into the consensus-relevant binary, so keep it free of behaviour that depends on the host.

## Tests

Boost suite `sanity_tests`; the `daemon-linux` stage checks the symbol floor. See [doc/local-ci.md](../../doc/local-ci.md). List suites with `zcutil/bin/zcl-dev t-list`.

## Related

Rules: [../AGENTS.md](../AGENTS.md). Facts: `zcutil/bin/zcl-dev know glibc-symbol-floor`, `zcutil/bin/zcl-dev know glibc-floor`.
