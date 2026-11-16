# ZClassic Wallet 2.1.2-beta10

Beta10 fixes startup feedback and text clipping observed in beta9. Windows, Linux and macOS builds have passed release verification.

- Show the node's actual startup progress in the main window, including block
  index loading. Routine RPC polling no longer replaces that progress with
  "No connection". Keep actionable errors visible until a new attempt starts.
- Display the validated block count during ordinary sync. Remove the misleading
  percentage and ETA calculated from a still-growing set of downloaded headers.
  Snapshot byte progress remains separate.
- Preserve every balance digit. Adapt the balance font, stack Home cards in narrow
  windows, and allow pages to scroll instead of compressing text vertically.
- Keep Windows packaging static: no separate Qt, GCC or pthread runtime DLLs.

## Validation

Windows: 59 widget tests and 106 logic tests pass, with one existing documented
skip in each suite. Layout checks pass at 100%, 125%, 150%, 175%, 200%, 250% and
300% scaling, including narrow windows, main pages and send confirmation dialogs.
These tests use synthetic balances and isolated test state.

## Sync and consensus

The embedded daemon and consensus rules are unchanged. Z23 peers can already
serve ordinary blocks to this node, which validates them using the existing
ZClassic rules. This release does not claim a measured full-chain speedup.

FlyClient/MMB snapshot activation is not enabled. A header-chain proof alone
does not authenticate all wallet-relevant chain state. Importing that state
without a complete validation and installation path would violate the unchanged
validation requirement. Pure C23 transport code can be integrated in future work
with compatibility and adversarial tests; changing language alone is not a sync
optimization.

Windows signing and macOS notarization remain separate release requirements;
this update does not bypass operating-system security prompts.

Platform requirements: Windows x86_64 (unsigned); Linux x86_64 with glibc 2.31+ and system X11/XCB libraries; macOS 15+ Apple Silicon (ad-hoc signed, not notarized). Linux/macOS native CI and release gates passed. See SHA256SUMS.txt for download checksums.
