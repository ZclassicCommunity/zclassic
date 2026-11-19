# Consensus seal log

Append-only. Each line is written by `zcl-lint consensus-seal --reseal --reason`; see
[UNSEAL.md](UNSEAL.md) for the ritual. Never edit a past line.

Format: `- <UTC time> <HEAD commit> seal=<seal blob> <sealed files> sealed files; changed: <paths>; reason: <text>`

- 2026-11-19T05:16:46Z c4b686a98f51 32 sealed files; changed: src/chainparams.cpp src/consensus/consensus.h src/consensus/oversize_grandfather.cpp src/consensus/oversize_grandfather.h src/consensus/params.cpp src/consensus/params.h src/consensus/upgrades.cpp src/consensus/upgrades.h src/consensus/validation.h src/consensus/z23/oversize_grandfather_table.inc src/pow.cpp src/pow.h src/primitives/block.cpp src/primitives/block.h src/primitives/transaction.cpp src/primitives/transaction.h src/script/interpreter.cpp src/script/interpreter.h src/script/script.cpp src/script/script.h src/zcash/Address.cpp src/zcash/Address.hpp src/zcash/IncrementalMerkleTree.cpp src/zcash/IncrementalMerkleTree.hpp src/zcash/JoinSplit.cpp src/zcash/JoinSplit.hpp src/zcash/Note.cpp src/zcash/Note.hpp src/zcash/NoteEncryption.cpp src/zcash/NoteEncryption.hpp src/zcash/Proof.cpp src/zcash/Proof.hpp; reason: initial seal at base c4b686a98 (U15)
- 2026-11-19T05:21:20Z 218816cdf83a seal=0719e8bb2cdf7a66b7a1bc5afe40b8a88c176b4f 32 sealed files; changed: (none); reason: bind the seal to the log (seal= blob); no sealed file changed
- 2026-11-19T06:23:57Z c731cc2b2274 seal=39d9e0f86c82ee4dc2b174d773c825c8e5a689cf 34 sealed files; changed: src/consensus/AGENTS.md src/consensus/CLAUDE.md; reason: add area guides src/consensus AGENTS.md and CLAUDE.md to the seal; documents only, no consensus bytes changed
- 2026-11-19T10:32:30Z 6900feb95301 seal=bad9b1ad27e2c7d7b30c53020efbba1342a9cb38 34 sealed files; changed: src/chainparams.cpp; reason: src/chainparams.cpp: dead DNS seed dnsseed.zslp.org removed and two comments reworded (commit 5fe062d36, speed/connect); no consensus parameter, checkpoint or activation height touched; reviewed by a non-author Opus reviewer at bb78c8957; test_bitcoin and zcash-gtest pass on Linux, Windows and macOS at 39ca3f5e3
