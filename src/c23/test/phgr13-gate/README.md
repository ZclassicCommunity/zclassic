# PHGR13 differential gate

Not part of the daemon build. It exists so the claim "the accept/reject verdict for every
Sprout PHGR13 proof is the one libsnark gave" can be re-checked from this tree, now that
libsnark is no longer in it.

`phgr13_diff.cpp` runs the same inputs through two verifiers and prints every
disagreement:

* **reference**: libsnark as zclassicd used it. `build.sh` extracts `src/` of the commit
  before libsnark was removed, builds `libsnark.a` there with the old flags and links the
  old `src/zcash/Proof.cpp` and `circuit/gadget.tcc` (its `witness_map`), unchanged.
* **candidate**: what the daemon builds now. The vendored `bn254.c` (included verbatim by
  `phgr13_adapter.c`), `bn254_accel.c`, the shim `src/c23/compat/zcl_c23_phgr13.c` and
  today's `src/zcash/Proof.cpp` (compiled under another namespace so both can be in one
  binary). The verify entry is `JoinSplitCircuit::verify` with `ProofVerifier::Strict()`
  and a caller-supplied `h_sig`.

Inputs: every distinct PHGR13 JoinSplit of the mainnet block files (433,209 JoinSplits,
432,407 distinct) with the real `sprout-verifying.key`, the mutation classes (lead bytes, `x = q`,
`x + q`, top bits, sign flips, points at infinity, off-subgroup G2 points, non-curve x,
swapped points) applied to 24 base proofs per shard, the 10,000 + 10,000 compressed
point vectors of `src/test/data/g1_compressed.json` and `g2_compressed.json`, the public
input packing, the verifying-key points, and the pairing with a point at infinity.

```sh
D=$PWD/depends/x86_64-unknown-linux-gnu           # boost headers, libsodium
CPPFLAGS=-I$D/include LDFLAGS=-L$D/lib \
  sh src/c23/test/phgr13-gate/build.sh $PWD /scratch/gate        # builds /scratch/gate/phgr13_gate
# 20 shards, blocks dir = height-ordered blk*.dat, last argument = mutated proofs per class
sh src/c23/test/phgr13-gate/run_shards.sh /scratch/gate/phgr13_gate 20 /scratch/gate/out \
  ~/.zcash-params/sprout-verifying.key src/test/data/g1_compressed.json src/test/data/g2_compressed.json \
  /path/to/blocks 24
```

The last line of `out/summary.txt` (written under the run's output directory) must read `candidate-disagreements=0`. Needs about <!-- doc-path-ok -->
1.2 GiB per shard and about 25 minutes on 20 cores for the full mainnet scan; pass `-` for
the blocks directory to run only the synthetic classes (a minute).
