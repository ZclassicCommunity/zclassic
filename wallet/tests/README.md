# tst_logic — L0 unit suite

Pure-logic unit tests for the ZClassic Qt5 GUI wallet (the **L0** layer from
[`docs/TESTING.md`](../docs/TESTING.md)). Guiless QtTest binary that links ONLY
the wallet's pure-logic translation units plus test shims — **no daemon, no
libsodium, and zero modifications to any file under `src/`**.

## Build + run (inside the proot build chroot)

```sh
/home/rhett/zclbuild/prun bash -c '\
  cd /src/wallet/tests && \
  /opt/qt-static/bin/qmake tests.pro && \
  make -j$(nproc) && \
  QT_QPA_PLATFORM=offscreen ./tst_logic'
```

Expected tail:

```
Totals: 74 passed, 0 failed, 0 skipped, 0 blacklisted
```

`QT_QPA_PLATFORM=offscreen` is required: `addresscombo.cpp` derives from
`QComboBox`, so the target links `QtWidgets` and instantiates a widget — the
offscreen platform plugin lets that happen with no X server.

## What it links

| Product TU (UNMODIFIED) | Why |
|-------------------------|-----|
| `../src/settings.cpp`   | address classifiers + formatters + token name |
| `../src/senttxstore.cpp`| at-rest 0600 store, save-gating |
| `../src/addresscombo.cpp` | label/paren address parsing (D6) |

Plus shims under `shim/` that shadow the heavy product headers **purely via
`INCLUDEPATH` ordering** (`shim/` is searched before `../src`):

- `precompiled.h` — minimal QtCore/QtNetwork-lite PCH; **no `SODIUM_STATIC`, no
  sodium header** (so no libsodium at link time).
- `mainwindow.h` — only the plain-data `ToFields` / `Tx` structs (copied from
  `src/mainwindow.h:18-31`); no `QMainWindow`/`Ui::`.
- `rpc.h` — only the full 8-field `TransactionItem` (copied from `src/rpc.h:16-25`);
  no `RPC` class.
- `addressbook.h` + `addressbook_stub.cpp` — tiny in-memory `AddressBook` with the
  three entry points `addresscombo.cpp` uses, semantics matching
  `src/addressbook.cpp`.

## Checklist coverage (from docs/TESTING.md)

`C3, C5, C6, D6, E7` (field/format pieces needing no RPC), `G1, G4, H1, H2`,
plus exhaustive `Settings` address classifiers
(`isTAddress`/`isZAddress`/`isSaplingAddress`/`isSproutAddress`) and formatters
(`getDecimalString`/`getZCLDisplayFormat`/`getUSDFormat`/token name).

### H1/H2 mirror note

The four H1/H2 classifiers (`looksLikeDbCorruption`, `startupDiagHasMarker`,
`isLongWarmupPhase`, `blocksDirSizeBytes`) are non-extractable members of the
widget-entangled `ConnectionLoader` (`connection.cpp` pulls `ui_*.h` + `RPC` +
the daemon launcher and cannot link at L0), and the no-`src`-modification
constraint forbids extracting them. The bodies under `namespace cxmirror` in
`tst_logic.cpp` are copied **verbatim** from `connection.cpp` at the cited line
numbers and must stay in sync; the tests exercise that exact classification
logic, and `blocksDirSizeBytes` runs real recursive filesystem traversal over a
`QTemporaryDir`. If `connection.cpp`'s marker tables change, update the mirror.

## Safety

`initTestCase()` calls `QStandardPaths::setTestModeEnabled(true)` and sets a
throwaway org/app name, so `QSettings` and `SentTxStore` writes land in a
sandbox (`~/.config/ZClassicTest`, `~/.local/share/ZClassicTest`) — never the
real wallet profile or `~/.zclassic`. The suite cleans up after itself.
