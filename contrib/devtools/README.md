# contrib/devtools

Scripts for developers working on this repository. All are POSIX sh; none needs Python.

## github-merge.sh

Merges a pull request securely: fetches the target branch and the pull request, builds the merge
commit locally, shows the diff, asks you to verify the tree (run your test command), then asks
whether to GPG-sign and push. Nothing can change between review and merge.

    ./github-merge.sh <owner>/<repo> <pull request number>

Setup (once per repository):

    git config githubmerge.repository <owner>/<repo>
    git config githubmerge.testcmd "make -j4 check"      # whatever you test with
    git config --global user.signingkey <key id>          # to sign

## gen-manpages.sh

Creates the manpages in `doc/man` by running the release binaries with `-help`. Needs
[help2man](https://www.gnu.org/software/help2man/).

## git-subtree-check.sh

Verifies that a subtree matches the commit it claims to have been updated to. Fetch the upstream
branch first (`src/secp256k1` from its upstream master, `src/leveldb` from the bitcoin-fork branch).

    git-subtree-check.sh DIR [COMMIT]      # COMMIT defaults to HEAD

## split-debug.sh

Splits a binary into a stripped binary and a separate debug file linked by a debuglink.

    split-debug.sh <input> <stripped-binary> <debug-binary>

## check-oversize-grandfather.sh

Verifies the historical oversize-transaction table described in
[doc/oversize-grandfather.md](../../doc/oversize-grandfather.md) against the Z23 list, optionally
against a chain scan file.

    check-oversize-grandfather.sh [chain-scan-file]

The vendored-source and Python/CI guards live in `zcutil/` (`zcutil/check-no-python.sh`,
`zcutil/lint`), and `zcutil/dev/zcl-dev` selects tests for a change.
