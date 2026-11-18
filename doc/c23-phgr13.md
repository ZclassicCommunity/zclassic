# Sprout PHGR13 on the C23 core (libsnark is gone)

zclassicd linked libsnark (about 19,000 lines of C++, plus libgmp and OpenMP) for exactly one
purpose that matters to consensus: to check the pre-Sapling Sprout JoinSplit proofs
(PHGR13, also called BCTV14, on the BN254 curve). Those proofs end at height 476,969, are
in the chain forever, and every node has to keep accepting exactly the ones libsnark
accepted. This file records how that check now runs on the vendored Z23 C23 code, what was
removed, and the evidence that the accept/reject verdict did not change.

Nothing in this change is a consensus change. The rule is the same; only the code that
evaluates it differs.

## Where the code is

| step | before | now |
|---|---|---|
| deserialize the proof from a transaction (lead byte of every point) | `zcash/Proof.hpp` `CompressedG1/G2::SerializationOp` | unchanged (`zcash/Proof.hpp:90`, `:134`) |
| decode the points, check the subgroup | `Proof.cpp` `to_libsnark_*` (libsnark field code) | vendored `bn_g1_decompress`, `bn_g2_decompress`, `ppzksnark_proof_read` (`c23/vendor/.../bn254.c:1396`, `:1416`, `:1447`; engine `bn254_engine.inc:1146`, `:1216`) |
| pack the 9 public inputs | `circuit/gadget.tcc` `witness_map` | vendored `sprout_verify_phgr13` (`bn254.c:1970`) |
| five pairing checks | `r1cs_ppzksnark_online_verifier_strong_IC` | vendored `ppzksnark_verify` (`bn254.c:1882`) |
| load `sprout-verifying.key` | `JoinSplit.cpp` `loadFromFile` | `JoinSplit.cpp:30` `loadVerifyingKey` -> `zcl_c23_phgr13_load_vk` -> vendored `ppzksnark_vk_read` |
| the door | | `c23/compat/zcl_c23_phgr13.{h,c}` |
| `ProofVerifier::Strict()/Disabled()` | `Proof.cpp` | same two factories (`Proof.cpp`), plus `performs_verification()` |
| `JoinSplitCircuit::verify` | `JoinSplit.cpp:114` | `JoinSplit.cpp:58` |

`JoinSplitCircuit::verify` now: serialize the `PHGRProof` back to its 296 wire bytes
(`PHGRProof::ToBytes`, exact: the lead byte is rebuilt from the stored parity bit), compute
`h_sig` as before, call `zcl_c23_phgr13_verify` with the same inputs libsnark's `witness_map`
received. The whole body stays inside `try { ... } catch (...) { return false; }`.

### Every check libsnark's path made, and where it lives now

The old C++ wrapper had checks of its own on top of libsnark's. Each is kept; the left
column is the line in the base commit (4973a1d2c).

| # | check (reject unless) | base | now |
|---|---|---|---|
| 1 | G1 lead byte is 0x02 or 0x03 | `Proof.hpp:105` | `Proof.hpp:90` (unchanged, at deserialization) and `bn_g1_decompress` |
| 2 | G2 lead byte is 0x0a or 0x0b | `Proof.hpp:155` | `Proof.hpp:134` and `bn_g2_decompress` |
| 3 | G1 x < q | `Proof.cpp:68-77` | `bn_g1_decompress` (canonical `bn_fq_from_bytes_be`) |
| 4 | G2 x is the FE2IP integer c1*q + c0 with c1 < q | `Proof.cpp:86-96` | `fq2_decode_fe2ip` (`bn254.c:1109`) |
| 5 | x^3 + 3 is a square in Fq, else `sqrt` threw | `Proof.cpp:117` | engine `g1_decompress` |
| 6 | the y with the lead bit's parity | `Proof.cpp:119-121` | engine `g1_decompress` |
| 7 | x^3 + b' is a square in Fq2, else `sqrt` threw | `Proof.cpp:152` | `bn_fq2_sqrt` / engine `g2_decompress` |
| 8 | G2 y sign: FE2IP(y) > FE2IP(-y) matches the lead bit | `Proof.cpp:155-157` | engine `g2_decompress` |
| 9 | G2 point in the order-r subgroup | `Proof.cpp:166-168` | engine `g2_in_subgroup` (`bn254_engine.inc:928`, endomorphism test with a proof in the comment) |
| 10 | element order A, A', B, B', C, C', K, H | `Proof.hpp:208-215`, `Proof.cpp:191-198` | `ppzksnark_proof_read` |
| 11 | public inputs packed 253 bits per Fr | `circuit/gadget.tcc` | `bn254_multipack_be` (`bn254.c`) |
| 12 | input count equals the IC size (strong IC) | libsnark `r1cs_ppzksnark.tcc:769` | `sprout_verify_phgr13` |
| 13 | the five pairing equations | libsnark `r1cs_ppzksnark.tcc:694-745` | `ppzksnark_verify` |
| 14 | with `ProofVerifier::Disabled()` the proof is still decoded and a bad one makes `verify` false | `JoinSplit.cpp:131`, `Proof.cpp:244-248` | `JoinSplit.cpp:79` -> `zcl_c23_phgr13_proof_decodes` |
| 15 | any exception is a rejection | `JoinSplit.cpp:147` | `JoinSplit.cpp:95` |
| 16 | the verifying key is pinned by SHA-256 before it is loaded | `init.cpp` (`GetZcashParamSpecs` loop, never cache-skipped for `sprout-verifying.key`) | unchanged |
| 17 | `ProofVerifier::Disabled()` use sites (IBD, checkpoints, reindex) | `main.cpp` | unchanged |

Item 14 is the one a straight port would lose: libsnark decompressed the proof before it
looked at the verifier, so even a "disabled" verifier rejected a proof whose points do not
decode.

### Thread safety

Verification runs from the script-check threads and from the RPC and wallet threads. The
vendored engine initialises its shared state with `pthread_once` (Frobenius table, CPU
detection in `bn254_accel.c`), a relaxed-atomic engine pointer whose racers all store the
same value, and a mutex plus release/acquire publication for the per-key line tables.
`zcl_c23_phgr13_load_vk` runs once on the parameter-loading thread before anything verifies
(`ZC_LoadParams`, joined by `AppInit2` before blocks are processed) and selects the CPU path
there. A second load of the same key is a no-op; a different key replaces the installed one
(tests only, the old one is deliberately leaked because a verifier may still hold it).
The standalone TSan run in the evidence below drives it from 32 threads from a cold start.

### Platforms

x86-64 gets two instances of one engine, chosen once by CPUID: a portable multiply and a
BMI2+ADX one (`mont_adx.h`, inline asm, `__attribute__((target("bmi2,adx")))`). Everything
x86-only is under `#if defined(__x86_64__) || defined(_M_X64)` (`bn254.c:26`, `:1217`,
`mont_adx.h:53`, `bn254_accel.c`), and the engine's assembly add/sub is under
`BNE_ASM_ADDSUB`, defined only for the ADX instance. On arm64 (macOS) only the portable
instance is compiled and `bn254_accel_cpu_has_adx()` is false. The two instances produce
the same field elements (`test_bn254_engine_parity` in Z23).

## What was removed

* `src/snark/` (libsnark), its Makefile rules, `LIBSNARK`, `-DUSE_ASM`, `-DMONTGOMERY_OUTPUT`,
  `-DBINARY_OUTPUT`, `-DCURVE_ALT_BN128`, `-DSTATIC`, `-DMULTICORE`.
* `src/zcash/circuit/*.tcc`: the R1CS gadgets that existed only to prove and to test the
  PHGR13 circuit.
* libgmp and OpenMP: `configure.ac` checks, `depends/packages/libgmp.mk`, `-lgmp -lgmpxx`,
  `ax_openmp.m4`, and the static-libgomp handling (`ZQW_STATIC_GOMP`) in
  `zcutil/build-release.sh` and the daemon release workflow. The variable is still accepted
  and ignored, because the GUI's build scripts export it. Nothing else in zclassicd used
  either (`src/test/rust_oracle/gen_golden.cpp` is a stand-alone developer tool that has
  its own build script and still uses GMP).
* PHGR13 proving: `JoinSplitCircuit::prove` with `makeGrothProof == false`, parameter
  generation (`JoinSplit::Generate`), `-savesproutr1cs`.
* `sprout-proving.key` (910 MB): no longer required, fetched, hashed at startup, or
  checked by the GUI. A copy left in `~/.zcash-params` is not used, except that a
  `-bootstrapserve` node still offers it to older releases (see "Peers" below).

## What changes for users

Mainnet: nothing. Sapling activated at height 476,969 and Sprout JoinSplits created since
are Groth16. No transaction a node could create today has a PHGR13 proof.

The parameter download shrinks from about 1.7 GB to about 780 MB. The first start of a
fresh node, the GUI's first-run text and `fetch-params.sh` say so.

On regtest or a private chain that has not activated Sapling, creating a Sprout JoinSplit
(for example `z_sendmany` from a Sprout address, or `z_shieldcoinbase` to one) is no longer
possible. The operation fails with

    Sprout PHGR13 proofs can no longer be created: they existed only before Sapling activated,
    and this node only verifies them. Use a Sapling-era (Groth16) transaction version.

Receiving, validating, relaying and mining blocks and transactions that carry PHGR13
JoinSplits works as before, including ones created by older binaries. Building a
transaction without computing its proof (fee estimation) is unchanged.

Peers: the compiled parameter table (`bootstrap.cpp` `ZCASH_PARAM_FILES_RAW`) now lists four
files, so a new node neither requires nor fetches `sprout-proving.key`. Releases up to
beta12 still refuse to start without it and fetch it from the compiled bootstrap peers
(z.cash no longer serves it), so a `-bootstrapserve` node keeps offering it when it holds a
copy of the compiled size (`ZCASH_PARAM_FILES_LEGACY_SERVED`); the fetching node checks the
content against its own compiled SHA-256, as for every file. Bootstrap operators must keep
the file on disk until those releases are retired: a bootstrap node without it makes a
fresh older node fail with "zcash param peer does not serve sprout-proving.key". The
older release needs the file only to start, not to validate. The P2P messages are
unchanged: files are located by name in the served manifest.

## Tests

* `gtest/test_phgr13.cpp` (15 tests, with `gtest/phgr13_vectors.h`): 14 real mainnet
  JoinSplits (block 241 and every 11,000th after it) through `JSDescription::Verify`;
  every public input changed, swapped points, every point's x and y bits flipped, lead
  bytes (refused at deserialization), non-canonical x (x = q, q+1, all ones, FE2IP = q^2),
  x not on the curve, a g_B on the twist but outside G2 (libsnark: "point is not in G2"),
  all rejected also under `ProofVerifier::Disabled()` where libsnark decoded first;
  default and random proofs; 8 threads at once; the "cannot create" error; and a
  verifying-key file that is missing, empty, truncated or zero-filled makes `Prepared`
  throw without replacing the installed key.
* `gtest/test_param_presence.cpp` `ManifestOffersTheLegacyProvingKeyOnlyWhenHeld`: the
  served parameter manifest lists `sprout-proving.key` exactly when the node holds it, and
  its first chunk is served byte for byte.
* `MainnetBlocks.ShieldedConsensusChecksAcceptRealBlocks` runs every JoinSplit of real
  mainnet block files through `CheckTransaction` (set `ZCL_MAINNET_BLK_FILES`).
* The 22 tests of `test_proofs.cpp` and `test_circuit.cpp` tested libsnark's own field and
  curve code through zclassicd's conversion layer; they went with it. The same classes are
  covered at point level by the differential gate below, which keeps libsnark as the
  reference outside the tree.
* `test_basic_joinsplit_verification` (boost) builds and verifies a Groth16 JoinSplit.
* `src/c23/test/regtest-smoke.sh --peer-bin <previous release>`: the previous release
  creates and mines a PHGR13 JoinSplit, the new node must accept the block;
  `qa/rpc-tests/wallet_matrix.sh` scenarios 3 and 9 and the `interop` platform check need
  such a peer too and report `SKIP` without one.

## Evidence

Run on 2026-11-17/18 on two 32-core hosts that also run other work (load average 30-60),
so every wall-clock number below is indicative; where two builds are compared they ran at
the same time on the same host. "Base" is `2f2f298ce` (libsnark, the parent of this
change); "new" is this branch.

**Vendoring.** Z23 `b1617102fa` (the landed verifier, with the reviewer's tests).
`check-vendor.sh` OK, 87 rows; five vendored files differ from the old pin `03a8b1d4c9`
(`bn254.h`, `bn254_accel.h`, `bn254.c`, `bn254_accel.c`, new `bn254_engine.inc`), every
other row has the same git blob. `c23-symbols.stamp` and `check-c23-no-rust` pass. The
golden suite (`src/c23/test/run.sh --linked src/libzcl_c23.a`) is unchanged: 45,991
records, 0 mismatches (32 skipped as before), 336 of 336 mutation cases, threads PASS.

**Differential gate, every distinct mainnet proof (`src/c23/test/phgr13-gate`).** The
candidate is the exact vendored bytes (49 sapling-module files checked against
`Z23_SOURCE.tsv`), the shim and the daemon's `Proof.cpp`; the reference is libsnark from
the base tree. 20 shards, 24 mutated base proofs per shard:

    TOTAL cases=483797 candidate-disagreements=0 z23raw-disagreements=0
    real.mainnet 432407 cases, 432407 accepted by both
    scan: 3,343,579 blocks, 433,209 PHGR13 JoinSplits, 432,407 distinct
    vk: libsnark points == candidate points (1408 bytes, identical)
    point vectors: 10,000 G1 + 10,000 G2; shard-exit-status=0; disagreements.txt empty

The same 483,797 cases and the same totals as the gate that approved the Z23 change, now
through the daemon's code path.

**Real blocks.** `MainnetBlocks.ShieldedConsensusChecksAcceptRealBlocks`, strict verifier,
16 threads: blocks 0..169,449 (the first five files): 152,412 PHGR13 JoinSplits (heights
241..169,449), 0 failures, 43 s. (The brief expected 152,382; an independent block scanner
and the test both count 152,412.) All 52 files (3,321,764 blocks, 432,407 PHGR13 and
95,592 Groth16 JoinSplits, 454,954 Sapling spends, 1,066,109 outputs): no proof failure,
928 s. The test reports 4 failures, `bad-txns-oversize` from `CheckTransaction` at heights
478,544, 478,596, 596,034 and 609,439. The base gtest binary reports the same four in 1,474 s,
so they are a limit the test applies to oversized mainnet transactions and not a proof
result.

**Chain import (`gettxoutsetinfo`).** Mainnet blocks 0..60,000 fed from genesis by
`submitblock` (`-connect=0 -dnsseed=0 -bootstrap=0 -listen=0 -disablewallet`), new and base
at the same time:

| | blocks 1..40,000 | 40,001..60,000 | total |
|---|---|---|---|
| base (libsnark, GCC 14 build) | 745 s | 348 s | 1,094 s |
| new | 286 s | 123 s | 411 s |

Every block accepted. At 40,000 both give bestblock
`00000005dab3e5ce1aa0a7cafe5b218e0fbef06916f4b4042e60ba8707e620c0`, txouts 307261,
hash_serialized `da82375527b52e23c767ff96ef79e5a1d079a50516d9f7d44e5d964e11f607f7`
(the reference). At 60,000 both give bestblock
`0000000aaebf0cef05226077a4b037080e11893fa4f3d84d12d2b87197722b58`, txouts 397453,
hash_serialized `0961e3fc898b4420772fab7f5e829e21279d28c692654df4dba230f2436f1755`.
(The earlier single-run figures were 495 s with a GCC 9.3 build and 583 s with GCC 14
assembly; this change measured 286 s.)

**Speed of one proof.** Gate bench, one thread, median of 21: libsnark (portable build)
22.7 ms, candidate 2.76 ms; `sprout-verifying.key` load plus warm-up 1.65 ms against
0.006 ms (the key is parsed once at startup). Z23's own measurement against libsnark with
assembly is 2.97 ms against 12.9-13.4 ms.

**Tests.** `zcash-gtest`: 290 tests, all pass (base 303: 22 libsnark tests removed, 13
added). `test_bitcoin`: 477 test cases, no errors, after
`test_basic_joinsplit_verification` was moved to Groth16. `check-c23-vendor`,
`make check-c23-no-rust` OK. `-savesproutr1cs` no longer exists.

**Sanitizers** (vendored bn254 files and the shim built with the production flags plus the
sanitizer, driven by the gtest vectors, `libsodium` for `h_sig`):
ThreadSanitizer, 32 threads x 400 iterations released together right after the key load,
each iteration a valid proof, a one-bit mutation and a decode: no report, PASS.
AddressSanitizer + UBSan (`-fno-sanitize-recover`): 14 mainnet vectors accepted, every
byte of every vector flipped (4,144 mutations) rejected, 5,376 neighbouring x values (2,352
decode, 3,024 refused, none accepted as a proof), 20,000 random proofs refused, 0 reports.

**Regtest.** `regtest-smoke.sh --peer-bin` the previous release (beta12 + libsnark): the
peer creates and mines a PHGR13 JoinSplit at height 106, node A accepts the block (tips
equal), imports the Sprout key, and later spends the note with a Groth16 JoinSplit; the
peer follows every block to the same tip, `verifychain 4 0` true after restart: PASS, 82 s.
Without a peer (Sprout note made after Sapling): PASS, 47 s. `wallet_matrix.sh --peer-bin
<previous release> --only 3,9`: scenario 3 (Sprout legacy notes) 14 pass, scenario 9
(two-node interop) 12 pass, including the refusal text. `wallet_platform_checks.sh
--only interop` with the previous release as the peer: 7 pass, at least 20 shielded
transactions recorded.
`params-smoke.sh`: intact (four files) and an extra `sprout-proving.key` start; a missing
or corrupt `sprout-verifying.key` is refused ("hash ... is not correct"); the other cases
are the same as the base binary.

**Binaries.** Linux x86-64, stripped, GCC 14.2: zclassicd 17,194,032 -> 16,468,704 bytes
(-725,328, -4.2%), zclassic-cli 2,896,568 -> 2,896,504, zclassic-tx 4,801,032 ->
5,100,056 (+6.2%); the base `NEEDED` list had `libgomp.so.1`, the new one is
libstdc++, libm, libgcc_s, libc. Windows (mingw, `build-release.sh win64`, same
toolchain and depends): zclassicd.exe 17,934,336 -> 18,142,720 (+208,384, +1.2%),
zclassic-cli.exe 3,662,336 -> 3,662,336, zclassic-tx.exe 5,727,744 -> 5,934,592; imported
DLLs identical (ADVAPI32, bcrypt, IPHLPAPI, KERNEL32, msvcrt, SHELL32, SHLWAPI, USER32,
WS2_32). The engine is compiled twice (portable and BMI2+ADX) and the BN254 code is about 1 MB,
which pays for libsnark on Linux and about breaks even on Windows.
Clean builds, ccache off, 8 CPUs each, run concurrently: base 214 s, new 225 s (libsnark
was cheap to build; the C++ of the daemon dominates). The aarch64 compile
(`clang -target aarch64-linux-gnu`, no sysroot, stubbed `pthread.h`) of `bn254.c`,
`bn254_accel.c` and the shim gives no diagnostics, no x86 instruction and no `bne_adx_*`
function: only the portable engine exists there.

**Not covered here.** The sanitizer runs used the vendored
files plus shim, not a full sanitizer build of zclassicd. Windows binaries were
cross-built, not run. macOS/arm64 was compiled for, not run. The Qt GUI edits
(`wallet/src/connection.*`, parameter list and download size text) were not compiled.
`wallet/docs/BUILDING.md` still names `ZQW_STATIC_GOMP`, which is accepted and ignored.
