# Consensus seal: the unseal ritual

The consensus seal is a tripwire. `zcl-lint consensus-seal` (rule source
`zcutil/lint/rules/consensus_seal.c`, pins in `zcutil/consensus.seal`) fails when the git
blob of a consensus-sealed file differs from its pin. It does not prove that a change is
correct. It makes every change to the consensus surface visible and forces the ritual below.

## What is sealed

- `src/consensus/**`, `src/primitives/**`, `src/pow/**` (except `src/pow/tromp/**`, the vendored miner)
- `src/pow.cpp`, `src/pow.h`, `src/chainparams.cpp`
- `src/script/interpreter.{cpp,h}`, `src/script/script.{cpp,h}`
- `src/zcash/{JoinSplit,Note,NoteEncryption,Proof,Address,IncrementalMerkleTree}.*`

`src/main.cpp` is not in the seal because it is too broad. The sealed set is fixed in
`consensus_sealed()`; changing that list is itself a change that needs the ritual.

## Why

zclassicd consensus is the reference. Z23 matches it bug for bug, and a divergence is fixed in
both trees. No change to a sealed file is a routine edit, including a fix that looks harmless.

## The ritual

1. Show the change is consensus-neutral or intended. A differential and golden pass on the same
   inputs (`src/c23/test/run.sh`, and `test_bitcoin-full` from the node build) must agree.
2. Get a review from someone other than the author.
3. Check parity with Z23 where the same rule exists there.
4. Reseal and record the reason:

   ```
   zcutil/bin/zcl-lint --root . consensus-seal --reseal --reason "<why this consensus change is needed>"
   ```

   This rewrites `zcutil/consensus.seal` from the index and appends a dated line to
   `doc/agent/SEAL_LOG.md`. `--reason` must be one non-empty line.
5. Commit the sealed edit, the new `zcutil/consensus.seal` and the `SEAL_LOG.md` line together.
6. Run the full lint at the candidate tip before landing.

## Limits and rules for agents

- The check compares the index with the seal, and also reports a sealed path that is edited but not
  staged, deleted on disk, or untracked (a new file under a sealed prefix), so the usual edit-then-lint
  loop sees it. `--reseal` refuses (exit 2, nothing written) while a sealed path is unmerged, unstaged
  or untracked.
- Each `SEAL_LOG.md` line records `seal=<git blob of zcutil/consensus.seal>`. The check requires the
  current seal to equal the blob on the last line, so a hand-edited seal fails unless a log line is also
  forged.
- An agent never runs `--reseal` on its own, and never edits `zcutil/consensus.seal` by hand.
  A change to a sealed file is escalated to the owner, with the differential result attached.
- The seal log is append-only. Do not edit past lines.
