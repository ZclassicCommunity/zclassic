# src/policy: fee and priority estimation

The block policy estimator: it watches transactions enter the mempool and get mined, and answers how much fee or priority a transaction needs to confirm within a number of blocks.

## What lives here

- `fees.cpp`, `fees.h`: `CBlockPolicyEstimator` (`processTransaction`, `processBlock`, `estimateFee`, `estimatePriority`), `isFeeDataPoint`, `isPriDataPoint`, `Read` and `Write` for the saved estimates.

Transactions are grouped into buckets of similar fee or priority and the estimator tracks how long each bucket takes to be mined; the answer is the lowest bucket whose confirmation share passes the threshold.

## Traps

- This is relay and wallet policy, not consensus. Nothing here may reject a block or a transaction that the consensus code accepts.
- The mempool size cap (`-mempoolmaxbytes`) lives in `src/main.cpp`; `qa/rpc-tests/mempool_cap.sh` shows a full pool refusing a send and a mined block making room again.
- `CTxMemPool::addUnchecked` and `CTxMemPool::removeForBlock` pass a `fCurrentEstimate` flag into `processTransaction` and `processBlock`; keep it when changing those callers.
- The estimates are saved to `fee_estimates.dat` by `src/init.cpp`; the estimator's `Read` and `Write` own the file layout.

## Tests

Boost suites `policyestimator_tests`, `mempool_tests`, `mempool_cap_tests`; qa script `qa/rpc-tests/mempool_cap.sh`. List them with `zcutil/bin/zcl-dev t-list`.

## Related

Rules: [../AGENTS.md](../AGENTS.md). Facts: `zcutil/bin/zcl-dev know fee-estimation`. The wallet fee paths are custody code: [../wallet/AGENTS.md](../wallet/AGENTS.md).
