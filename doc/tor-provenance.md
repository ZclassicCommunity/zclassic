# Embedded Tor: source provenance, build policy and licences

Unit T1 of the embedded-Tor work. This file records exactly what the
`tor` and `zlib` depends packages build and from what. It adds no daemon
behaviour: the packages are built by default for linux, mingw32 and darwin hosts (`NO_EMBEDDED_TOR=1` leaves them out; other hosts need `WITH_EMBEDDED_TOR=1`) when this is passed to
`make -C depends`, so default builds are unchanged.

    make -C depends HOST=<triple> WITH_EMBEDDED_TOR=1 tor

## Source identity (shared with Z23)

Z23 pins its Tor as the git submodule `vendor/tor` (Z23 `origin/main`,
`vendor/provenance/tor.manifest`, `source_status=submodule-pinned`). This
package builds the same commit.

| Item | Value |
|---|---|
| Upstream of the pin | `https://github.com/RhettCreighton/tor.git` (a fork of the Tor Project source with an added `src/feature/dynhost`) | <!-- doc-path-ok -->
| Commit | `f4e28103c0eb9016e0b500d02486b7a59d20ee5d` ("dynhost client: explicit-method fetch_ex with a bounded request body") |
| Tor version string | `0.4.9.2-alpha-dev` (`AC_INIT` in `configure.ac`; `tor --version` prints it) |
| Source archive | `https://github.com/RhettCreighton/tor/archive/f4e28103c0eb9016e0b500d02486b7a59d20ee5d.tar.gz` |
| Archive sha256 | `72c187cd6228cfde5a8befd299899db24ae857c0c565dbebf92261933cae06a7` (10,044,682 bytes) |
| zlib source | `https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz`, sha256 `9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23` |

The archive hash was taken from a download on 2026-11-16. GitHub generates
`archive/<sha>.tar.gz` on demand, so if GitHub ever changes its tar/gzip output
the hash check in `depends` fails closed; the file must then be re-fetched from
a mirror of the same commit (a `git archive` of it) and the hash re-recorded.

## Carried patches (`depends/patches/tor/`)

The pin is unchanged. `tor.mk` applies these four patches, in order with
`patch -p1`, in its preprocess step (before `./autogen.sh`); the step is plain
`patch` and `sh`, so it is the same on linux, mingw and darwin hosts.

Why: the fork turns its dynhost subsystem on unconditionally. Observed on the
pre-patch build (child and in-process mode, regtest): once Tor has a circuit,
`hs_service_callback` calls `dynhost_check_and_activate()` every second; the
log shows `Activating dynhost ephemeral service` and `Dynamic onion host
ephemeral service created with address: <random>`, and that second onion
service answers on port 80 with the demo pages `/`, `/time` and `/calculator`
(fetched through the node's own SocksPort). The daemon uses stock Tor onion
service forwarding (`ADD_ONION` from `src/torcontrol.cpp`) and has no use for
it, so every node would otherwise publish an unrelated second service.

| Patch | What it does |
|---|---|
| `0001-dynhost-stream-shutdown.patch` | Z23 `vendor/patches/tor-dynhost-stream-shutdown.patch`, verbatim (sha256 `c4c135447e85c5934b2c8af8ea4e52566c50ab15cc4219d2dbefa3daa75599d8`, Z23 `origin/main`). Applies cleanly to the pin. Dynhost stream shutdown: refuses opens after the subsystem stops, no read of freed connections at cleanup, terminal callback/close ordering. Keeps the two projects on the same fork behaviour. | <!-- doc-path-ok -->
| `0002-dynhost-set-enabled.patch` | Adds `void dynhost_set_enabled(int)` and `int dynhost_is_enabled(void)` (default 1: unchanged for other embedders). Off: subsystem init registers no port-80 virtual port, the subsystem option hook is a no-op, `dynhost_activate_service()` refuses and `dynhost_check_and_activate()` returns at once, so no service is created. zclassicd calls `dynhost_set_enabled(0)` before `tor_run_main()` in both child and in-process mode; `tor_api.h` does not declare it, so `src/c23/tor/zcl_tor_dispatch.c` and `zcl_tor_inproc.c` carry a local prototype. |
| `0003-dynhost-free-reassembly-buf.patch` | `connection_free_minimal()` frees `edge_conn->dynhost_reassembly_buf`, which `dynhost_handlers.c` allocates per dynhost connection and nothing freed. |
| `0004-dynhost-clamp-external-handler-length.patch` | Clamps the length an external dynhost handler returns to the 65536-byte buffer it was given. |

The dynhost code is still compiled into `libtor.a` (it is part of the pin) but
with the off switch nothing in it runs in the daemon.

The archive carries no generated `configure`; `./autogen.sh` runs in the
package preprocess step, so autoconf, automake and libtool are build-host
requirements (same as Z23 `tools/scripts/build_tor_full.sh`). <!-- doc-path-ok -->

## Configure policy

From Z23 `tools/scripts/build_tor_full.sh`: `ac_cv_func_backtrace=no`, <!-- doc-path-ok -->
`--disable-asciidoc --disable-systemd --disable-seccomp --disable-lzma
--disable-zstd --disable-libscrypt`, `ac_cv_lib_cap_cap_init=no
ac_cv_func_cap_set_proc=no`, `--with-openssl-dir`, `--with-libevent-dir` and
`--with-zlib-dir` all pointing at the depends prefix (never the system), and
for mingw `--host` (supplied by depends), `--disable-tool-name-check` and
`LIBS="-liphlpapi -lbcrypt -lws2_32"`.

Additions here (differences from Z23, all subtractive or build hygiene):

- `--disable-module-relay --disable-module-dirauth`: no relay or directory
  authority code; a client plus onion service needs neither. Z23 does not set
  these.
- `--disable-unittests --disable-system-torrc --disable-manpage
  --disable-html-manual`.
- `--enable-pic`.
- `--enable-static-openssl --enable-static-libevent --enable-static-zlib`
  (only affects the `tor` executable, which is not built).
- No `--enable-gpl`: the Equi-X proof-of-work code (LGPL-3.0) is therefore not
  compiled. `nm` on `libtor.a` shows no `equix` or `hashx` symbols.

Only these targets are built: `libtor.a`,
`src/ext/ed25519/donna/libed25519_donna.a`,
`src/ext/ed25519/ref10/libed25519_ref10.a`,
`src/ext/keccak-tiny/libkeccak-tiny.a`. They are staged to `<prefix>/lib/`
with `tor_api.h` in `<prefix>/include/`. These are the same four archives Z23
links.

Link line (Linux): the four Tor archives, then `libevent.a libssl.a libcrypto.a
libz.a -lm -lpthread -ldl`. Windows adds `-liphlpapi -lbcrypt -lws2_32
-lshlwapi -lcrypt32 -lgdi32 -ladvapi32 -luser32`; a program including
`tor_api.h` must include `<winsock2.h>` first.

Note: `make -C depends ... tor` only builds and caches the package. The
files appear under `<prefix>` when the normal `install` flow extracts the
cache, or by extracting `built/<host>/tor/tor-*.tar.gz` into `<prefix>`.

## Verified on the build host (2026-11-16, Ubuntu 24.04, gcc 14.2.0)

depends OpenSSL 1.1.1w, libevent 2.1.12, zlib 1.3.1 (all from this tree).
depends has since moved to OpenSSL 3.5.9 (static, with assembly); the hashes and
the version line below are the 2026-11-16 record of the 1.1.1w build and were
not regenerated.

| Archive | Linux x86_64 bytes | sha256 | mingw-w64 x86_64 bytes | sha256 |
|---|---|---|---|---|
| libtor.a | 6,588,030 | `44ea9acce09868557e6fb1152160729be27d651469289c28b8cfd86a3ec44c84` | 5,068,958 | `4147f89541fd39b1b06d0ef98cb1b8ecf26669ce9c2667bddde4e384e0bc6022` |
| libed25519_donna.a | 121,120 | `4fc45e9c74960d1b22e435b89ae0f0869a8c9661399fef72da9a3524ea3b33d2` | 116,732 | `49f6645d8c7cb96e892c7e956084a428d55a98a861b681a580131fa4b61a87ed` |
| libed25519_ref10.a | 137,576 | `9c3b4a2e4acb0448c02d36ad63a4d3c7d106f0105e9086d256cc419a71bae8f8` | 116,862 | `8fdee7b13059738dc774c2e7b8de0b443e2065c4f546a9f5fba376f64395afef` |
| libkeccak-tiny.a | 34,956 | `44b6a9178bd431e6f2c733fced83e1340e3dadd395b6ec3f6e6a79cd040607d1` | 34,764 | `4d554bff640952bbf7744eb7a1928a879813ec1d4047f46e274a774d245221b9` |
| libz.a | 132,028 | `0eff8b7438a3ac51369aa13158dab4c29bb8f1dfd890d8b788ef61524cae04e5` | 105,816 | `74d9b23391bef8f7e90e8fc74843c047aba5f568f64fb2af0543062a8c0022ad` |

These hashes are build records, not a reproducibility claim: archive bytes
depend on toolchain and build path.

`nm` shows `T tor_run_main` and `T tor_main_configuration_new` in both
`libtor.a` files. A 10-line C program that calls
`tor_main_configuration_new`, `tor_main_configuration_set_command_line`
(`tor --version`) and `tor_run_main`, linked against the archives, prints on
Linux:

    Tor version 0.4.9.2-alpha-dev.
    Tor is running on Linux with Libevent 2.1.12-stable, OpenSSL 1.1.1w, Zlib 1.3.1, Liblzma N/A, Libzstd N/A and Glibc 2.39 as libc.

The mingw program links (5,804,204 bytes unstripped, 4,479,488 stripped) but
was not executed: the build host has no wine and no Windows machine was used.

Size cost, stripped, against a program that already links the same
`libevent.a`, `libssl.a`, `libcrypto.a` and `libz.a` (a stand-in for a daemon
that already carries OpenSSL and libevent):

| Target | Tor test program | baseline (libevent, libssl, zlib) | delta |
|---|---|---|---|
| Linux x86_64 | 4,839,568 | 1,921,616 | about 2.92 MB |
| mingw-w64 x86_64 | 4,479,488 | 1,685,504 | about 2.79 MB |

The real delta for zclassicd will differ: the daemon may already pull more of
libcrypto, and final link flags (`--gc-sections`, LTO) were not applied here.

## Licences

The pinned tree contains `LICENSE` (Apache-2.0, new work such as dynhost,
sha256 `2b99312f95ab015802f37d1bf177d7ce6c0d72a160ed9991a1f796bc1d0417bc`),
`LICENSE-BSD` (Tor, BSD-3-Clause, sha256
`bb5152a8c8468b1cfee9c7b265a540dc9fe79925335b7e01ad779909bafe236c`) and
`THIRD-PARTY-LICENSES` (sha256
`739cf32094ec3c0ec3961000ba3135e51da288cb4800a3c6140f16074cdbf890`). A binary
that includes this code must ship them with the release.

Paths in the "Where" column are inside the Tor source archive (the pinned fork), not this repository.

| Component | Licence | Where |
|---|---|---|
| Tor | BSD-3-Clause | `LICENSE-BSD`, text below |
| dynhost, other new fork code | Apache-2.0 | `src/feature/dynhost`, `LICENSE` | <!-- doc-path-ok -->
| curve25519-donna, ed25519-donna | public domain | `src/ext/curve25519_donna`, `src/ext/ed25519/donna` | <!-- doc-path-ok -->
| ed25519 ref10 | public domain (SUPERCOP; not listed in THIRD-PARTY-LICENSES, unverified) | `src/ext/ed25519/ref10` | <!-- doc-path-ok -->
| keccak-tiny | CC0 | `src/ext/keccak-tiny` | <!-- doc-path-ok -->
| trunnel generated code | BSD-style | `src/ext/trunnel` | <!-- doc-path-ok -->
| SipHash (csiphash) | MIT | `src/ext/csiphash.c` | <!-- doc-path-ok -->
| strlcat, strlcpy, readpassphrase | ISC | `src/ext` | <!-- doc-path-ok -->
| mulodi | MIT / UIUC | `src/ext/mulodi` | <!-- doc-path-ok -->
| ht.h, tor_queue.h | BSD-3-Clause | `src/ext` | <!-- doc-path-ok -->
| Equi-X, HashX (tevador) | LGPL-3.0 | NOT built (needs `--enable-gpl`) |
| OpenSSL 3.5.9 | Apache-2.0 | depends `openssl`, linked, not in libtor.a |
| libevent 2.1.12 | BSD-3-Clause | depends `libevent` |
| zlib 1.3.1 | zlib licence | depends `zlib` |

The component rows come from the pinned `THIRD-PARTY-LICENSES` and were not
audited file by file; the owner should confirm them before a release.

Tor BSD-3-Clause text (from `LICENSE-BSD`):

    BSD 3-Clause License

    Copyright (c) 2001-2004, Roger Dingledine
    Copyright (c) 2004-2006, Roger Dingledine, Nick Mathewson
    Copyright (c) 2007-2019, The Tor Project, Inc.
    All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this
       list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice,
       this list of conditions and the following disclaimer in the documentation
       and/or other materials provided with the distribution.

    3. Neither the name of the copyright holder nor the names of its
       contributors may be used to endorse or promote products derived from
       this software without specific prior written permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
    FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
    SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
    CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
    OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
    OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
