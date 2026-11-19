# Codebase map

Where things live in zclassicd: every top-level directory, every `src/` subdirectory and the major single files, each with a one-line purpose, its test suites and the nearest `AGENTS.md` that owns it.

Suite names are the ones `zcutil/bin/zcl-dev t-list` prints (Boost suites run through `test_bitcoin --run_test=<suite>`, gtest suites through `zcash-gtest --gtest_filter='<Suite>.*'`, qa scripts and CI steps by name). Owner rules are the nearest `AGENTS.md`; a path without one inherits the root contract [AGENTS.md](../../AGENTS.md). Navigate first with `zcutil/bin/zcl-dev code map`, `zcutil/bin/zcl-dev code owner <path>` and `zcutil/bin/zcl-dev guide <paths>`. Every path below is checked by `zcl-lint doc-paths`, and the claim markers are checked by `zcl-lint doc-claims`.

<!-- claim: file-present AGENTS.md # root contract -->
<!-- claim: file-present src/AGENTS.md # rules for src -->
<!-- claim: file-present src/main.cpp # validation and message handling -->
<!-- claim: file-present src/init.cpp # start-up, options and shutdown -->
<!-- claim: file-present src/net.cpp # connections and address selection -->
<!-- claim: file-present src/txdb.cpp # chainstate and block-tree databases -->
<!-- claim: file-present src/dbwrapper.cpp # LevelDB wrapper and fd budget -->
<!-- claim: file-present src/httpserver.cpp # HTTP server and work queue -->
<!-- claim: file-present src/torcontrol.cpp # Tor control client -->
<!-- claim: file-present src/embeddedtor.cpp # embedded Tor wrapper -->
<!-- claim: file-present src/headerprecheck.cpp # header Equihash pre-pass -->
<!-- claim: file-present src/shutdownmarker.cpp # clean-shutdown marker -->
<!-- claim: file-present src/shieldedcache.cpp # Sapling verdict cache -->
<!-- claim: file-present src/equihashmemo.cpp # Equihash memo -->
<!-- claim: file-present src/rpc/server.cpp # RPC table -->
<!-- claim: file-present src/rpc/rpcstats.cpp # in-flight RPC tracking -->
<!-- claim: file-present src/rpc/AGENTS.md # rpc rules -->
<!-- claim: file-present src/consensus/AGENTS.md # consensus rules -->
<!-- claim: file-present src/wallet/AGENTS.md # daemon wallet rules -->
<!-- claim: file-present src/zslp/AGENTS.md # token and name index rules -->
<!-- claim: file-present src/c23/AGENTS.md # vendored C23 rules -->
<!-- claim: file-present src/test/AGENTS.md # Boost test rules -->
<!-- claim: file-present src/gtest/AGENTS.md # gtest rules -->
<!-- claim: file-present qa/AGENTS.md # qa rules -->
<!-- claim: file-present zcutil/AGENTS.md # tooling rules -->
<!-- claim: file-present doc/AGENTS.md # doc rules -->
<!-- claim: file-present wallet/AGENTS.md # Qt wallet rules -->
<!-- claim: file-present contrib/AGENTS.md # contrib rules -->
<!-- claim: file-present zcutil/local-ci.sh # own-machine CI -->
<!-- claim: file-present zcutil/dev/impact.rules # path to CI step rules -->
<!-- claim: file-present zcutil/consensus.seal # consensus tripwire -->
<!-- claim: file-present doc/agent/FACTS.tsv # closed facts table -->
<!-- claim: file-present doc/agent/LESSONS.md # measured lessons -->
<!-- claim: file-present doc/agent/TRAPS.md # guardrails -->
<!-- claim: file-present qa/lib/isolation.sh # test isolation -->

## Top level

- `src/`: the daemon `zclassicd`, `zclassic-cli`, `zclassic-tx` and their unit tests. Tests: every Boost suite and gtest suite. Owner: [src/AGENTS.md](../../src/AGENTS.md).
- `wallet/`: the Qt GUI wallet `zclwallet`; it talks to the daemon over RPC only. Tests: `wallet-qt-logic-widget`, `wallet-mockrpc`, `wallet-embed-footer`. Owner: [wallet/AGENTS.md](../../wallet/AGENTS.md).
- `qa/`: regtest scenarios and test isolation libraries. Tests: the qa scripts in `zcl-dev t-list`. Owner: [qa/AGENTS.md](../../qa/AGENTS.md).
- `zcutil/`: build and release scripts, `local-ci.sh`, the `zcl-dev` tools, the `zcl-lint` gates. Tests: `check-dev-tools`, `zcl-lint`. Owner: [zcutil/AGENTS.md](../../zcutil/AGENTS.md).
- `doc/`: manuals, release notes, design notes and the agent documents in `doc/agent/`. Tests: `check-dev-tools` (`check-docs`, `md-links`). Owner: [doc/AGENTS.md](../../doc/AGENTS.md).
- `contrib/`: maintainer scripts, the fixed-seed generator, the ZMQ subscriber example, service files. Tests: `seed-generator`, `zmq-sub-example`. Owner: [contrib/AGENTS.md](../../contrib/AGENTS.md).
- `depends/`: pinned third-party packages and the patches built by the cross-build system (`depends/patches/tor` carries the Tor patches). Tests: `daemon-linux`, `daemon-win64` stages. Owner: [depends/AGENTS.md](../../depends/AGENTS.md).
- `build-aux/`: autoconf macros under `build-aux/m4`. Tests: `daemon-linux`.
- `share/`: `share/genbuild.sh`, which writes the build identity header.
- `.claude/`, `.github/`: agent skills and the contribution rules. No tests.

## src subdirectories

- `src/c23/`: the vendored C23 core (Sprout, Sapling, Groth16 verifiers, Tor, services) at the Z23 pin; vendor trees are byte-identical. Tests: `c23-run-linked`, `check-c23-vendor`, `check-c23-no-rust`, `check-c23-tor-symbols`, gtest `EquihashC23`. Owner: [src/c23/AGENTS.md](../../src/c23/AGENTS.md).
- `src/c23/tor/`: embedded Tor library, keyfile, process layer. Tests: `tor-twonode`, `tor-threenode`, `tor-addrv2gossip`. Owner: `src/c23/AGENTS.md`. See [src/c23/tor/README.md](../../src/c23/tor/README.md).
- `src/compat/`: glibc compatibility and start-up sanity checks. Tests: `sanity_tests`. Owner: `src/AGENTS.md`. See [src/compat/README.md](../../src/compat/README.md).
- `src/config/`: output directory for the generated configuration header; holds only a placeholder. No tests.
- `src/consensus/`: consensus parameters, upgrade heights, the oversize-transaction grandfather table (sealed). Tests: `main_tests`, gtest `UpgradesTest`, `oversize_grandfather_tests`. Owner: [src/consensus/AGENTS.md](../../src/consensus/AGENTS.md).
- `src/crypto/`: hash functions and the C++ Equihash solver. Tests: `crypto_tests`, `hash_tests`, `sha256compress_tests`, `equihash_tests`. Owner: `src/consensus/AGENTS.md`. See [src/crypto/README.md](../../src/crypto/README.md).
- `src/gtest/`: the `zcash-gtest` cases. Tests: all gtest suites. Owner: [src/gtest/AGENTS.md](../../src/gtest/AGENTS.md). See [src/gtest/README.md](../../src/gtest/README.md).
- `src/leveldb/`: vendored LevelDB; do not edit. Tests: `dbwrapper_tests`. Owner: `src/AGENTS.md`.
- `src/obj/`: build output directory, ignored by git.
- `src/policy/`: fee and priority estimation. Tests: `policyestimator_tests`. Owner: `src/AGENTS.md`. See [src/policy/README.md](../../src/policy/README.md).
- `src/pow/`: `src/pow/tromp` is third-party Equihash solver code; do not reformat. Tests: `pow_tests`, `equihash_tests`. Owner: `src/consensus/AGENTS.md`.
- `src/primitives/`: block and transaction types and serialization (sealed). Tests: `transaction_tests`, `CheckBlock_tests`, `serialize_tests`. Owner: `src/consensus/AGENTS.md`.
- `src/rpc/`: JSON-RPC command tables and call statistics. Tests: `rpc_tests`, `rpcstats_tests`, `getrpcinfo.sh`, `rpc_busy.sh`. Owner: [src/rpc/AGENTS.md](../../src/rpc/AGENTS.md). See [src/rpc/README.md](../../src/rpc/README.md).
- `src/script/`: script interpreter, signatures, standard scripts, the signature cache. Tests: `script_tests`, `script_P2SH_tests`, `sigencoding_tests`, `sighash_tests`. Owner: `src/consensus/AGENTS.md`. See [src/script/README.md](../../src/script/README.md).
- `src/secp256k1/`: vendored curve library; do not edit. Tests: `key_tests`. Owner: `src/AGENTS.md`.
- `src/support/`: memory cleansing, locked pages, secure allocators. Tests: `allocator_tests`. Owner: `src/AGENTS.md`. See [src/support/README.md](../../src/support/README.md).
- `src/test/`: the Boost suites compiled into `test_bitcoin`, with fixtures under `src/test/data`. Tests: all Boost suites. Owner: [src/test/AGENTS.md](../../src/test/AGENTS.md). See [src/test/README.md](../../src/test/README.md).
- `src/univalue/`: vendored JSON library; do not edit. Tests: `univalue_tests`. Owner: `src/AGENTS.md`.
- `src/wallet/`: the daemon wallet (`wallet.dat`, note state, sends, tokens). Custody code. Tests: `wallet_tests`, `rpc_wallet_tests`, gtest `WalletTests`, `TokenGuardTest`, `wallet_matrix-1-9`. Owner: [src/wallet/AGENTS.md](../../src/wallet/AGENTS.md).
- `src/zcash/`: the Zcash protocol types (addresses, notes, Merkle tree, JoinSplit, ZIP 32) (sealed in part). Tests: gtest `merkletree`, `noteencryption`, `joinsplit`, `ZIP32`, `tree-root-asan`. Owner: `src/consensus/AGENTS.md`.
- `src/zmq/`: optional ZeroMQ notifications. Tests: `zmq-sub-example`. Owner: `src/AGENTS.md`. See [src/zmq/README.md](../../src/zmq/README.md).
- `src/znam/`: the read-only name index and resolver. Tests: `znam_tests`, `znam_index.sh`. Owner: [src/zslp/AGENTS.md](../../src/zslp/AGENTS.md). See [src/znam/README.md](../../src/znam/README.md).
- `src/zslp/`: the read-only token index and builders. Tests: `zslp_tests`, `zslpbuild_tests`, `zslp_index.sh`. Owner: `src/zslp/AGENTS.md`. See [src/zslp/README.md](../../src/zslp/README.md).

## Major files in src

- `src/main.cpp`: block and transaction validation, `ProcessMessage`, chain activation, flush policy. There is no `net_processing.cpp`; message handling is here. Tests: `main_tests`, `DoS_tests`, `p2p_message_limits_tests`. Owner: `src/consensus/AGENTS.md`.
- `src/init.cpp`: option help, `AppInit2`, the params cache, the start-up check, `Shutdown`. Tests: `startup_bad_home.sh`, `chain_clean_shutdown_marker.sh`, `startup_conf_staging.sh`. Owner: `src/AGENTS.md`.
- `src/net.cpp`: sockets, peers, outbound selection (`SelectOutboundCandidate`). Tests: `addrman_tests`, `addrv2_tests`, `netbase_tests`, `p2p_sync_tests`. Owner: `src/AGENTS.md`.
- `src/txdb.cpp`: the coin database and block-tree database. Tests: `coins_tests`, `dbwrapper_tests`. Owner: `src/AGENTS.md`.
- `src/dbwrapper.cpp`: the LevelDB wrapper and its open-file budget. Tests: `dbwrapper_tests`. Owner: `src/AGENTS.md`.
- `src/httpserver.cpp`: libevent HTTP server, work queue, HTTP 503 on overload. Tests: `httpserver_tests`, `rpc_busy.sh`. Owner: `src/rpc/AGENTS.md`.
- `src/httprpc.cpp`: JSON-RPC over HTTP, authentication. Tests: gtest `HTTPRPC`. Owner: `src/rpc/AGENTS.md`.
- `src/torcontrol.cpp`: Tor control client and onion service creation. Tests: `torcontrol_tests`, `onion_v3_tests`. Owner: `src/AGENTS.md`.
- `src/embeddedtor.cpp`: wrapper for the Tor built into the binary. Tests: `embeddedtor_tests`, `tor-twonode`. Owner: `src/c23/AGENTS.md`.
- `src/headerprecheck.cpp`: parallel Equihash pre-pass for `headers` messages. Tests: `headerprecheck_tests`. Owner: `src/AGENTS.md`.
- `src/shutdownmarker.cpp`: the content-bound clean-shutdown marker. Tests: `shutdownmarker_tests`, `chain_clean_shutdown_marker.sh`. Owner: `src/AGENTS.md`.
- `src/shieldedcache.cpp`: positive-only cache of Sapling verdicts. Tests: `shieldedcache_tests`. Owner: `src/AGENTS.md`.
- `src/equihashmemo.cpp`: positive-only Equihash memo. Tests: `equihashmemo_tests`. Owner: `src/AGENTS.md`.
- `src/bootstrap.cpp`, `src/bootstrap_resume.cpp`, `src/bootstrapvalidation.cpp`: snapshot serving, resumable download, background validation (owned by other work). Tests: `bootstrap_resume_tests`, `bootstrap_snapshot_protocol_tests`, `bootstrap_import_invalidation.sh`. Owner: `src/AGENTS.md`.
- `src/chainparams.cpp`, `src/checkpoints.cpp`, `src/chain.cpp`, `src/coins.cpp`, `src/pow.cpp`: chain parameters, checkpoints, the block index, the coin view, difficulty (sealed or consensus path). Tests: `Checkpoints_tests`, `coins_tests`, `pow_tests`. Owner: `src/consensus/AGENTS.md`.
- `src/txmempool.cpp`, `src/miner.cpp`: the mempool and block assembly. Tests: `mempool_tests`, `mempool_cap_tests`, `miner_tests`. Owner: `src/AGENTS.md`.
- `src/addrman.cpp`, `src/netbase.cpp`, `src/protocol.cpp`: address manager, name resolution and proxies, wire message types. Tests: `addrman_tests`, `netbase_tests`. Owner: `src/AGENTS.md`.
- `src/util.cpp`, `src/sync.cpp`, `src/scheduler.cpp`, `src/validationinterface.cpp`: logging, durable file helpers, lock-order checks, scheduler, validation signals. Tests: `util_tests`, `scheduler_tests`, `reverselock_tests`. Owner: `src/AGENTS.md`.
- `src/key.cpp`, `src/keystore.cpp`, `src/pubkey.cpp`: keys and key storage. Tests: `key_tests`, gtest `keystore_tests`. Owner: `src/AGENTS.md`.
- `src/bitcoind.cpp`, `src/bitcoin-cli.cpp`, `src/bitcoin-tx.cpp`: the `zclassicd`, `zclassic-cli` and `zclassic-tx` entry points. Tests: `regtest-smoke`, `zclassic-tx-util`. Owner: `src/AGENTS.md`.
- `src/transaction_builder.cpp`, `src/asyncrpcoperation.cpp`, `src/metrics.cpp`: shielded transaction builder, asynchronous RPC operations, the metrics screen. Tests: gtest `TransactionBuilder`, `AsyncRPCOperationId`, `Metrics`. Owner: `src/wallet/AGENTS.md`.
- `src/Makefile.am`, `src/Makefile.test.include`, `src/Makefile.gtest.include`: build targets and test lists; a new file needs a rule in `zcutil/dev/impact.rules`. Tests: `check-rules`. Owner: `src/AGENTS.md`.

## Tooling and documents

- `zcutil/dev/`: `zcl-dev` and `zcl-port`; see [zcutil/dev/README.md](../../zcutil/dev/README.md).
- `zcutil/lint/`: the `zcl-lint` gates and their shrink-only baselines; see [zcutil/lint/README.md](../../zcutil/lint/README.md).
- `zcutil/tools/`: tools built from vendored Z23 sources; see [zcutil/tools/README.md](../../zcutil/tools/README.md).
- `zcutil/agent/`: the agent guard and the MCP server; see [zcutil/agent/guard/README.md](../../zcutil/agent/guard/README.md).
- `qa/rpc-tests/`: the regtest scenarios; see [qa/rpc-tests/README.md](../../qa/rpc-tests/README.md) and [qa/README.md](../../qa/README.md).
- `doc/agent/`: [README.md](README.md), [TRAPS.md](TRAPS.md), [LESSONS.md](LESSONS.md), [FACTS.tsv](FACTS.tsv), [WIKI.md](WIKI.md).
