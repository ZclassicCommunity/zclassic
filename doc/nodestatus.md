# getnodestatus: an honest "is this node synced" answer

`getnodestatus` takes no arguments and returns the node state, the reasons for it, sync lag, peers, mempool, indexes
and free disk space in one cheap answer. It is read-only and takes each lock briefly (`cs_main`, then `cs_vNodes`,
then the mempool lock, never nested), so scripts can poll it.

## Why it exists

`getblockchaininfo.syncphase` uses `ClassifySyncPhase`, which answers `synced` as soon as `IsInitialBlockDownload()`
is false. After a snapshot install that latch clears once the tip is within `-maxtipage` (24 hours) and the headers
equal the blocks, while the node can still be hundreds of blocks behind its peers. `getnodestatus` classifies with
`ClassifySyncPhaseV2` (`src/syncphase.cpp`), which also looks at tip age and the height the outbound peers reported.
Nothing about IBD, validation or relay changes; `getblockchaininfo` is untouched.

## Fields

| field | meaning |
| --- | --- |
| `state` | `ok`, `initial_block_download`, `syncing`, `tip_stale`, `no_peers`, `reindexing` or `importing` |
| `syncphase` | `reindexing`, `importing`, `waiting_for_peers`, `downloading_headers`, `downloading_blocks` or `synced` |
| `synced` | `syncphase` is `synced` |
| `reasons` | fixed English strings explaining a state other than `ok` |
| `blocks`, `headers` | active chain height and best header height |
| `best_peer_height` | highest height a handshaken outbound peer reported at connect, `-1` unknown |
| `blocks_behind` | blocks to the best peer or header, `0` when level |
| `tip_age_seconds` | seconds since the tip block time |
| `peers` | `in` and `out` connection counts |
| `mempool` | `size` and `bytes` |
| `uptime_seconds` | same source as the `uptime` call |
| `indexes` | `txindex` flag; `zslpindex` and `znamindex` with `enabled` and, when enabled, `synced` and `indexed_height` |
| `datadir_free_bytes` | free space where the data directory lives, `-1` unknown |

## Classification rules

After the IBD latch has cleared, with `SLACK` = 2 blocks, fresh = 30 minutes:

1. no connections: `waiting_for_peers`;
2. headers above `blocks + SLACK`, or best peer height above `blocks + SLACK`: `downloading_blocks`;
3. best peer height unknown: `downloading_headers`;
4. tip age within the fresh window: `synced`;
5. old tip, but every peer at our height and the longest peer connected for 60 s: `synced` (a quiet chain);
6. otherwise `downloading_blocks`.

Per poll the index service-info calls each take cs_main briefly and do one LevelDB read, so the RPC is cheap but not free.

The peer height is the second-highest starting height among handshaken outbound peers (one outlier cannot hold the node behind); a lone peer is bounded by headers plus SLACK. The starting height is each peer announced when it connected, so it is a lower bound for a peer
that has been connected a long time; the tip-age rule covers that case.

Tests: `src/test/test_bitcoin --run_test=syncphase_tests`, `qa/rpc-tests/nodestatus.sh --bin <dir> --work <dir>`
(`NODESTATUS_BENCH=1` also times 1000 sequential calls against `getblockchaininfo` while `gettxoutsetinfo` runs).
