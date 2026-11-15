# Qt / LGPLv3 notice and written offer (single-file Linux & Windows builds)

The single-file ZclWallet binaries (the self-contained Linux executable and the
Windows `.exe`) **statically link the Qt framework**, which is licensed under the
**GNU Lesser General Public License, version 3 (LGPLv3)**. ZclWallet's own source
code is MIT-licensed. This file documents how we comply with the LGPLv3 when Qt is
linked statically.

> The `.deb` package and the macOS `.app` do **not** static-link in a way that
> removes the user's ability to replace Qt; this notice primarily concerns the
> statically-linked single-file builds.

## Qt version used

- **Qt 5.15 (LGPLv3)** — the exact point release and configure flags used to build
  the static Qt kit are recorded in the release notes for each version, and the
  build is reproducible from the public Qt sources.
- Qt is © The Qt Company and contributors. Upstream sources:
  <https://download.qt.io/archive/qt/5.15/> and <https://code.qt.io/>.

## How we satisfy LGPLv3 §4 (statically-linked "Combined Work")

LGPLv3 permits distributing a work that statically links an LGPL library provided
the recipient can **relink** the application against a modified version of that
library. We satisfy this in two ways:

1. **The complete application source is public.** ZclWallet is built entirely from
   <https://github.com/ZclassicCommunity/zcl-qt-wallet> (MIT). Anyone can rebuild
   it against their own (modified) Qt by following `README.md` / `src/scripts/mkrelease.sh`.

2. **Relinkable object files are published with each single-file release.** Each
   release that ships a statically-linked binary also publishes
   `linux-relink-objects-v<version>.tar.gz`, containing ZclWallet's compiled
   object files (`*.o`) plus `RELINK.txt` with the exact link command. With these
   object files and your own build of Qt 5.15, you can produce a new ZclWallet
   binary linked against your modified Qt, without recompiling the application.

## Written offer

For any single-file binary we distribute, and for **three (3) years** from the date
we distributed that binary, we will, on request, provide:

- the application object files needed to relink ZclWallet against a different
  build of Qt (the same `linux-relink-objects-v<version>.tar.gz` described above), and
- the corresponding source code of the exact Qt version used, or a precise pointer
  to obtain it from the Qt Project.

Send requests via a GitHub issue on
<https://github.com/ZclassicCommunity/zcl-qt-wallet/issues> (preferred), referencing
the binary's version string (shown in **Help → About**).

## Notes

- Qt's own license texts (LGPLv3 and the GPLv3 it incorporates by reference) are
  included with the Qt sources linked above.
- This notice covers Qt only. Other bundled components (e.g. libsodium, the
  embedded `zclassicd` node) carry their own licenses; the node and CLI are
  distributed under the terms in this repository and the ZClassic daemon repository.
