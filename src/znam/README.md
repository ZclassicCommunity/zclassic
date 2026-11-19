# src/znam: ZNAM name index and resolver

The read-only ZNAM name index (register, update, transfer, renew and record commands in `OP_RETURN` data), the service that builds it from connected blocks and the resolver that turns a name into an address.

## What lives here

- `znamindex.cpp`, `znamindex.h`: the index with its command ids (`CMD_REGISTER` to `CMD_SET_TEXT`), record types (`TYPE_ONION`, `TYPE_ZADDR`, `TYPE_TADDR`), owner rendering (`OwnerFromScript`) and per-block atomic batches with undo records.
- `znamservice.cpp`, `znamservice.h`: `ZnamService` (a `CValidationInterface`), `StartService`, `StopService`.
- `znamresolve.cpp`, `znamresolve.h`: `ValidName`, `Candidate`, `Resolution`, `DEFAULT_RECENT_BLOCKS`.

The index reuses the key-value layer of `src/zslp/zslpindex.h` and reads block undo data to learn the owner of each spent input.

## Traps

- Nothing here is consensus. Off unless `-znamindex=1`, which refuses `-prune`; the index lives in `<datadir>/znamindex`.
- The rules are Z23's, bug for bug, from `src/c23/services/vendor`; fix a rule in Z23 first and re-vendor. The one deliberate difference, ZNAM-OWNER-2, is written in the design document.
- An unreadable undo record stops the build with a named error rather than guessing an owner.
- Delete an index directory only with the node stopped and only in a datadir created for a test.

## Tests

Boost suite `znam_tests`; qa script `qa/rpc-tests/znam_index.sh` (real transactions, reorgs, a rebuild interrupted by `kill -9`); the shared vectors are checked by `qa/rpc-tests/token_name_rules.sh`.

## Related

Rules: [../zslp/AGENTS.md](../zslp/AGENTS.md). Design: [doc/znam.md](../../doc/znam.md). RPC: `src/rpc/znam.cpp`. Facts: `zcutil/bin/zcl-dev know znam-undo-data`.
