# Security Policy

ZClassic is experimental, security-sensitive software. Thank you for helping keep it and its users safe.

## Reporting a vulnerability

Do not open a public issue, pull request or forum post for a vulnerability. Report it privately through GitHub:

<https://github.com/ZclassicCommunity/zclassic/security/advisories/new>

(Repository page, "Security" tab, "Report a vulnerability".) Only the maintainers and you can see the report.

Please include:

- what is affected: component, version or commit, and platform (the output of `zclassicd --version` helps);
- what an attacker can do and under which conditions (loss of funds, loss of privacy, consensus split, crash, remote or local);
- steps or a test that reproduce it, as small as you can make them;
- any fix you suggest, and whether and how you would like to be credited.

If you cannot send everything at once, send a short description first and add detail later.

## What to expect

- Reports are acknowledged by the maintainers through the private advisory thread.
- We will work with you to confirm the problem, prepare a fix and agree a time for a coordinated public release. Credit is given if you want it.
- Please keep the details private until a fixed release is available.

There is no bounty program.

## Scope

Vulnerabilities in the node (`zclassicd`, `zclassic-cli`, `zclassic-tx`), in the wallet and in the build and release tooling of this repository are in scope. Problems in the Zcash protocol itself that also affect ZClassic should be reported here as well; the original Zcash disclosure policy is kept for reference in [doc/history/upstream-responsible-disclosure.md](doc/history/upstream-responsible-disclosure.md) and does not apply to ZClassic reports.

Ordinary bugs and questions that are not security problems belong in the [issue tracker](https://github.com/ZclassicCommunity/zclassic/issues).
