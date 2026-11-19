# src/script: script interpreter, signing and standard scripts

The transparent script engine: the interpreter that decides whether an input may spend an output, the signature checkers and encoding rules, the standard script templates and the signing helpers the wallet uses.

## What lives here

- `interpreter.cpp`, `interpreter.h`: `EvalScript`, `VerifyScript`, `SignatureHash`, `TransactionSignatureChecker`, `PrecomputedTransactionData`. Sealed consensus code.
- `script.cpp`, `script.h`: `CScript` and the opcodes. Sealed consensus code.
- `sigencoding.cpp`, `sigencoding.h`: `CheckTransactionSignatureEncoding`, `CheckDataSignatureEncoding`, `CheckPubKeyEncoding`; `sighashtype.h` the sighash type flags; `script_flags.h` the verification flags; `script_error.cpp` the error codes.
- `standard.cpp`, `standard.h`: `Solver`, `IsStandard`, `ExtractDestination`, `ExtractDestinations` (policy-side classification).
- `sign.cpp`, `sign.h`: `ProduceSignature`, `SignSignature`, `UpdateTransaction`.
- `sigcache.cpp`, `sigcache.h`: the ECDSA signature cache, 40 MiB by default.
- `zcashconsensus.cpp`, `zcashconsensus.h`: the C API of `libzcashconsensus`.

## Traps

- zclassicd is the reference: no rule, flag or acceptance predicate changes here, even to fix an apparent bug. The files listed in `zcutil/consensus.seal` change only through the ritual in [doc/agent/UNSEAL.md](../../doc/agent/UNSEAL.md).
- Every file here maps to `ALL` in `zcutil/dev/impact.rules`, so a change runs the full test set.
- A speedup or refactor is proven accept/reject-identical on the same inputs, not argued.
- The signature cache holds only successes; keep it that way.

## Tests

Boost suites `script_tests`, `script_P2SH_tests`, `scriptnum_tests`, `sigencoding_tests`, `sighash_tests`, `sighashtype_tests`, `sigopcount_tests`, `checkdatasig_tests`, `multisig_tests`, `transaction_tests`. List them with `zcutil/bin/zcl-dev t-list`.

## Related

Rules: [../consensus/AGENTS.md](../consensus/AGENTS.md). Facts: `zcutil/bin/zcl-dev know signature-cache-size`, `zcutil/bin/zcl-dev know consensus-seal`.
