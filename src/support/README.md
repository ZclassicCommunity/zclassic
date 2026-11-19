# src/support: secret-memory helpers

Memory helpers for key material: a wiping primitive, locked (non-swappable) pages and allocators that wipe and lock what they hold.

## What lives here

- `cleanse.cpp`, `cleanse.h`: `memory_cleanse`, a wipe the optimizer cannot remove.
- `pagelocker.cpp`, `pagelocker.h`: `LockedPageManagerBase`, which counts locks per page because `mlock` calls do not stack.
- `allocators/secure.h`: `secure_allocator`, which locks its pages on allocation and cleanses and unlocks them on free.
- `allocators/zeroafterfree.h`: `zero_after_free_allocator` for buffers that need only wiping.
- `events.h`: RAII wrappers around libevent objects used by the HTTP server.

## Traps

- Anything that holds a key, seed or passphrase belongs in a secure or zero-after-free container; a plain `std::string` or `std::vector` leaves copies in freed memory and swap.
- Never log or print the contents of these containers; `zcl-lint secretlog` flags log calls whose arguments name a secret.
- This directory is custody-adjacent: a change needs a reviewer who is not its author ([../wallet/AGENTS.md](../wallet/AGENTS.md)).

## Tests

Boost suite `allocator_tests` covers the locked-page bookkeeping. List suites with `zcutil/bin/zcl-dev t-list`.

## Related

Rules: [../AGENTS.md](../AGENTS.md). Facts: `zcutil/bin/zcl-dev know memory-cleanse`, `zcutil/bin/zcl-dev know secret-log-calls`.
