# Licence texts shipped in the Windows bundle

`build-windows.sh` copies every `*.txt` file here into the `licenses/` folder of the
bundle (listed in `THIRD-PARTY-NOTICES.txt`, covered by `SHA256SUMS.txt`). The
files are verbatim copies of the texts that came with the exact third-party
components used to build the release; nothing was retyped. `.gitattributes` marks
them `-text -diff` so Git never rewrites their line endings (GPL-3.0 and LGPL-3.0 are
CRLF as published) and carries them in patches as binary blobs.
Update a file only by copying again from a newer upstream/toolchain, and update this
table with the new source.

| File | Applies to | Copied from |
|---|---|---|
| `LGPL-3.0.txt` | Qt 5.15.2 (Qt5*.dll, plugins) | `C:\Qt\5.15.2\Src\LICENSE.LGPLv3` (Qt 5.15.2 source tree, Qt Company) |
| `GPL-3.0.txt` | the GPLv3 that LGPL-3.0 refers to; also GCC/libstdc++ runtime | `C:\Qt\5.15.2\Src\LICENSE.GPLv3` (Qt 5.15.2 source tree) |
| `OpenSSL-LICENSE.txt` | OpenSSL 1.1.1 DLLs (OpenSSL License + original SSLeay License) | `C:\Qt\Tools\OpenSSL\src\LICENSE` (Qt installer OpenSSL 1.1.1 source tree that matches the DLLs in `Tools\OpenSSL\Win_x64\bin`) |
| `GCC-Runtime-Library-Exception-3.1.txt` | libgcc_s_seh-1.dll, libstdc++-6.dll | `C:\Qt\Tools\mingw810_64\licenses\gcc\COPYING.RUNTIME` (MinGW-w64 8.1.0 toolchain shipped with Qt) |
| `MinGW-w64-COPYING.txt` | MinGW-w64 runtime/headers linked into the binaries | `C:\Qt\Tools\mingw810_64\licenses\mingw-w64\COPYING` |
| `winpthreads-COPYING.txt` | libwinpthread-1.dll | `C:\Qt\Tools\mingw810_64\licenses\winpthreads\COPYING` |
| `libsodium-LICENSE.txt` | libsodium 1.0.20 (ISC), linked into zclwallet.exe | `libsodium-1.0.20/LICENSE` of the source tree the static library is built from |

The wallet's own licence (`LICENSE`), the node's `COPYING` and `THIRD-PARTY-LICENSES`
and `QT-LGPL-NOTICE.md` are copied into the bundle separately.
