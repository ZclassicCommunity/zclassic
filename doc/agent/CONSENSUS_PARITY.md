# Consensus parity in zclassicd

What counts as consensus in this tree, why zclassicd is the reference, what evidence a change on a validation path needs, and which odd-looking behaviours must never be tidied. A change that makes this node accept a block or transaction the network rejects, or reject one it accepts, splits the chain; there is no opt-in or signalled version of that which is acceptable.

Adapted from Z23's consensus parity doctrine (Z23 `docs/CONSENSUS_PARITY_DOCTRINE.md`), turned around: there Z23 follows zclassicd, here zclassicd is the thing followed. The seal ritual itself is in [UNSEAL.md](UNSEAL.md); the area rules are in [src/consensus/AGENTS.md](../../src/consensus/AGENTS.md). <!-- doc-path-ok -->

## The rule

zclassicd is the reference implementation of ZClassic consensus. Z23 matches it bug for bug, and a divergence between the two is fixed in Z23 to match zclassicd, never the reverse (FACTS row `consensus decided-by zclassicd`). Within this tree that means: no rule, checkpoint, activation height, limit or acceptance predicate changes, including one that looks like a bug fix. A speedup or refactor on a validation path must be proven accept/reject-identical on the same inputs, not argued.

If a consensus change is ever warranted, it is proposed to the network, agreed with an activation height, implemented here first and mirrored in Z23 afterwards. An agent never starts that process on its own; it escalates to the owner.

## What counts as consensus

### Sealed files

`zcl-lint consensus-seal` (rule source `zcutil/lint/rules/consensus_seal.c`, function `consensus_sealed`) pins the git blob of every file in this set in `zcutil/consensus.seal`; a changed blob fails the lint until the ritual reseals it. <!-- claim: symbol-present consensus_sealed zcutil/lint/rules/consensus_seal.c --> <!-- claim: file-present zcutil/consensus.seal -->

- everything under `src/consensus/` (limits in `consensus.h`, `Consensus::Params` and `NetworkUpgradeActive` in `params.cpp`, upgrade metadata in `upgrades.cpp`, the oversize table), including its `AGENTS.md`; <!-- claim: symbol-present NetworkUpgradeActive src/consensus/params.cpp -->
- `src/primitives/` (block and transaction serialization, hence txid and block hash);
- `src/pow.cpp`, `src/pow.h` and `src/pow/` except the vendored miner `src/pow/tromp/`;
- `src/chainparams.cpp` (genesis, activation heights in `consensus.vUpgrades`, checkpoints in `checkpointData`, the per-epoch Equihash table read by `CChainParams::EquihashN`); <!-- claim: symbol-present checkpointData src/chainparams.cpp --> <!-- claim: symbol-present EquihashN src/chainparams.h -->
- `src/script/interpreter.{cpp,h}` and `src/script/script.{cpp,h}`;
- `src/zcash/` `JoinSplit`, `Note`, `NoteEncryption`, `Proof`, `Address` and `IncrementalMerkleTree`.

### Unsealed but consensus-critical

The seal freezes text, not behaviour. These are not sealed because they are too broad or change often, yet each one decides which blocks are valid. A change to any of them carries the same burden of proof as a sealed edit; only the reseal step is absent.

- `src/main.cpp`: `CheckBlockHeader`, `CheckBlock`, `ContextualCheckBlockHeader`, `ContextualCheckBlock`, `AcceptBlockHeader`, `AcceptBlock`, `ConnectBlock`, `CheckTransaction`, `CheckTransactionWithoutProofVerification`, `ContextualCheckTransaction`, `CheckTxInputs`, `ContextualCheckInputs`, `GetBlockSubsidy` and `LoadExternalBlockFile`. `zcutil/dev/impact.rules` maps `src/main.cpp` to every local-ci step (FACTS row `src/main.cpp selects ALL`). <!-- claim: symbol-present CheckBlock src/main.cpp --> <!-- claim: symbol-present ContextualCheckBlock src/main.cpp --> <!-- claim: symbol-present ConnectBlock src/main.cpp --> <!-- claim: symbol-present ContextualCheckTransaction src/main.cpp --> <!-- claim: symbol-present CheckTransactionWithoutProofVerification src/main.cpp --> <!-- claim: symbol-present AcceptBlockHeader src/main.cpp --> <!-- claim: symbol-present ContextualCheckInputs src/main.cpp -->
- `src/checkpoints.cpp`, `src/chain.cpp`, `src/coins.cpp` and `src/crypto/` (hashes behind txids, merkle roots and `OP_SHA256`). <!-- claim: file-present src/checkpoints.cpp -->
- The C23 verifiers that replaced librustzcash and libsnark: `src/c23/compat/` (`librustzcash_compat.c`, `zcl_c23_phgr13.c`), the vendored core under `src/c23/vendor/`, and `src/zcash/tree_root.c`. Sprout, Sapling and Groth16 verdicts must equal what zclassicd gave before the swap ([src/c23/AGENTS.md](../../src/c23/AGENTS.md), [doc/c23-phgr13.md](../c23-phgr13.md)). <!-- claim: file-present src/c23/compat/librustzcash_compat.c --> <!-- claim: file-present src/zcash/tree_root.c -->

### Not consensus

Mempool policy, relay, fee estimation, peer scoring, service bits, address gossip, the RPC surface, wallet behaviour, storage layout, start-up checks such as the clean shutdown marker (`src/shutdownmarker.h`: "It has no effect on block or transaction validity") and logging. These may improve freely, under the ordinary review and tests. Be careful at the edges: `AcceptToMemoryPool` calls `CheckTransaction`, so a mempool change can still reach a consensus function. <!-- claim: symbol-present AcceptToMemoryPool src/main.cpp -->

## The evidence ladder

A change on a validation path climbs as far up this ladder as its risk needs; anything that can change a verdict needs every rung. Record what was run and where its log is, in the commit message or the review.

1. **Pure refactor with characterization tests passing before and after.** The suites that cover the path (`zcutil/bin/zcl-dev tests <path>` names them; for `src/main.cpp` it answers `broad:` and the full set) pass on the old commit and on the new one, with no assertion changed. Write the missing test on the old code first and watch it pass there.
2. **A differential against a reference implementation on the same inputs.** Examples in the tree:
   - `randomized_differential_against_reference` in `src/test/findmostwork_tests.cpp` drives a memoised chain-selection walk and a plain reference walk over random block forests and compares every answer; <!-- claim: symbol-present randomized_differential_against_reference src/test/findmostwork_tests.cpp -->
   - the C23 known-answer replay (`src/c23/test/kat_replay.c`, run by `sh src/c23/test/run.sh` and the local-ci step `c23-run-linked`) replays every recorded librustzcash input against the linked archive; <!-- claim: file-present src/c23/test/kat_replay.c --> <!-- claim: step-exists c23-run-linked -->
   - the PHGR13 gate (`src/c23/test/phgr13-gate/`, `phgr13_diff.cpp`) links the libsnark verifier zclassicd used beside today's verifier and prints every disagreement. <!-- claim: file-present src/c23/test/phgr13-gate/phgr13_diff.cpp -->
3. **Mainnet block replay.** `MainnetBlocks.ShieldedConsensusChecksAcceptRealBlocks` in `src/gtest/test_mainnet_blocks.cpp` runs real blocks from `blk*.dat` copies through the shielded checks. It does nothing unless `ZCL_MAINNET_BLK_FILES` names the files, so a pass without that variable proves nothing. Work on copies; never point it at a live datadir. <!-- claim: symbol-present ShieldedConsensusChecksAcceptRealBlocks src/gtest/test_mainnet_blocks.cpp --> <!-- claim: symbol-present ZCL_MAINNET_BLK_FILES src/gtest/test_mainnet_blocks.cpp -->
4. **The full suites and the local-ci receipts.** `test_bitcoin-full`, `zcash-gtest-full`, `c23-run-linked` and `regtest-smoke` through `zcutil/local-ci.sh --commit <sha> --only ... test <outdir>`, then `local-ci.sh all` on the candidate. A step that reports SKIP (exit 77, for example `c23-run-linked` without a golden corpus) did not run and is not a pass. <!-- claim: step-exists zcash-gtest-full --> <!-- claim: step-exists regtest-smoke -->

A tightening predicate (one that rejects something that used to pass) needs rung 3 over the whole chain before it ships: the oversize history below is what happens without it.

## Quirks that must not be tidied

Each of these looks like a bug or dead code. Each one reproduces what the network accepted, so "fixing" it is a consensus change.

- **The oversize grandfather table.** `MAX_TX_SIZE_AFTER_SAPLING` (102,000 bytes) was lowered without a height gate, and 413 historical transactions exceed it. `CheckTransactionWithoutProofVerification` excuses exactly those `(txid, size)` pairs, and only inside a block (`fInBlock`), through `IsOversizeGrandfathered` (`src/consensus/oversize_grandfather.h`). Never edit `src/consensus/z23/oversize_grandfather_table.inc` or widen the rule; proof script `contrib/devtools/check-oversize-grandfather.sh`; history in [doc/oversize-grandfather.md](../oversize-grandfather.md). <!-- claim: symbol-present IsOversizeGrandfathered src/consensus/oversize_grandfather.h --> <!-- claim: symbol-present MAX_TX_SIZE_AFTER_SAPLING src/consensus/consensus.h --> <!-- claim: file-present contrib/devtools/check-oversize-grandfather.sh -->
- **`ContextualCheckTransaction` returns true during initial block download.** Its first statement is `if (isInitBlockDownload()) return true;` (the function pointer defaults to `IsInitialBlockDownload`, `src/main.h`), so the per-transaction contextual rules (Overwinter and Sapling version gating, expiry, the pre-Sapling 100,000 byte limit) do not run while the node believes it is in IBD. The `isInitBlockDownload() ? 0 : dosLevel` expressions further down are therefore unreachable in that state; leave both the early return and the dead ternaries alone. Z23 reproduces the same gating. <!-- claim: symbol-present IsInitialBlockDownload src/main.h -->
- **Checkpoints change what is checked.** With `-checkpoints` on (the default, `fCheckpointsEnabled`), `ConnectBlock` re-runs `CheckBlock` with `ProofVerifier::Disabled()` and no script checks for any ancestor of the last checkpoint, and `ContextualCheckBlockHeader` rejects a fork below the last checkpoint. A syncing node therefore never re-verifies old proofs: a verifier change is proven by the differential and KAT rungs, not by a mainnet sync. <!-- claim: symbol-present fCheckpointsEnabled src/main.cpp --> <!-- claim: symbol-present GetLastCheckpoint src/checkpoints.h -->
- **Two block size constants.** `CheckBlock` and `LoadExternalBlockFile` bound a block by `GENEROUS_BLOCK_SIZE_LIMIT` (2,000,000), while `MAX_BLOCK_SIZE` in `src/consensus/consensus.h` is 200,000 and is a policy and sanity value: the miner and `getblocktemplate` default (`DEFAULT_BLOCK_MAX_SIZE` in `src/main.h`, `sizelimit`), and the transaction-count bound in `CPartialMerkleTree::ExtractMatches` (`src/merkleblock.cpp`). Do not "unify" them in either direction. <!-- claim: symbol-present GENEROUS_BLOCK_SIZE_LIMIT src/consensus/consensus.h --> <!-- claim: symbol-present DEFAULT_BLOCK_MAX_SIZE src/main.h -->
- **The Groth16 infinity flag.** The vendored Z23 point decode accepts the point at infinity; librustzcash refused a proof with the flag set in A, B or C. The shim rejects it in `proof_has_infinity_flag` (`src/c23/compat/librustzcash_compat.c`). Removing the check, or "fixing" the vendored decoder by hand, changes Sapling verdicts. <!-- claim: symbol-present proof_has_infinity_flag src/c23/compat/librustzcash_compat.c -->
- **Non-canonical compact sizes are refused.** `ReadCompactSize` (`src/serialize.h`) throws on a size that could have been encoded shorter. It is part of the transaction and block encoding, so relaxing it changes which bytes parse. <!-- claim: symbol-present ReadCompactSize src/serialize.h -->

## The seal ritual and review

A change to a sealed file follows [UNSEAL.md](UNSEAL.md): a differential and golden pass on the same inputs, review by someone other than the author, a parity check against Z23 where the same rule exists, then `zcl-lint consensus-seal --reseal --reason "<one line>"`, which rewrites `zcutil/consensus.seal` and appends a line to [SEAL_LOG.md](SEAL_LOG.md); the edit, the seal and the log line are one commit. An agent never runs `--reseal` on its own and never edits the seal by hand; it escalates with the evidence attached. <!-- claim: file-present doc/agent/SEAL_LOG.md -->

An unsealed consensus-critical change (the list above) needs the same evidence and the same non-author review, and its commit message names the rungs that were run. A reviewer who cannot reproduce the evidence from the message rejects the change.

## Outside contributions

Treat a pull request that touches a validation path as possibly adversarial, and be courteous. A consensus change framed as opt-in, miner-signalled or "only for new blocks" is not merged here first. Credit a good idea and build it through the process above; judge non-consensus work (portability, relay policy, tooling) on its merits.
