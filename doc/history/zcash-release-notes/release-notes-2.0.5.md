Notable changes
===============

Deep reorg protection in Zclassic
---------------------------------
This release adds deep reorg protection by implementing a rolling 10 block checkpoint.

ASIC Resistance
---------------
Changed PoW algorithm from Equihash<200,9> to Equihash<192,7> to prevent centralization of mining power.

Bubbles Activation on Mainnet
-----------------------------
This release includes Bubbles activation on mainnet. It features deep reorg protection and ASIC resistance. The mainnet activation height is 585318.

Changelog
=========
- Auto-finalize block once they reach a depth of 10 and time of 30mins have elapsed since the block header received time.
- Introduce a penalty to alternative chains based on the depth of the fork. This makes it harder for an attacker to do reorg before the next block finalization. The node implicitly parks the block if it causes deep reorg. A parked chain will be automatically unparked if it has twice as much PoW accumulated as the main chain since the fork block.
- Added -maxreorgdepth flag to configure the block finalization depth. Default is 10. Use -1 to disable.
- Added -finalizationdelay flag to configure the minimum amount of time to wait between block header reception and the block finalization. Unit is seconds, default is 1800 (30mins).
- Added RPC to park a chain and finalize a block.
- Added RPC getfinalizedblockhash to get the finalized blockhash.
- Added RPC tests for reorg protection and also fixed the existing RPC tests.
- Changed Equihash parameters to 192, 7.
- Refactored the code.

