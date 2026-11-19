Regression tests of the RPC interface
=====================================

Each test is a POSIX `sh` script that starts isolated regtest nodes in temporary
datadirs and checks their behaviour through `zclassic-cli`. Run one with its source
`src` directory (the directory holding `zclassicd` and `zclassic-cli`):

    sh qa/rpc-tests/wallet_matrix.sh src

The header of each script lists its environment variables and what it checks. The old
Python test framework has been removed; `zcutil/local-ci.sh` runs the scripts that
belong to the release gate.

`zclassic_tx_util.sh <dir>` runs every case of `data/zclassic_tx_util/cases.json` through `zclassic-tx` (needs jq).
