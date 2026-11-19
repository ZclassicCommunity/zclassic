# The wiki and the facts table

`zcl-dev wiki`, `zcl-dev read`, `zcl-dev lessons` and `zcl-dev know` are one C program (`zcutil/dev/wiki/`, binaries in `zcutil/bin/`) that acts by the name it is run under. Build them with `make -C zcutil`; test them with `make -C zcutil/dev/wiki check`. They need no network, no database and no running node, and they read only the checkout in the current directory. The design follows the docs navigator and the fact table of the sibling project Z23.

## Navigating

`zcl-dev wiki [topic] [--after=N] [--json]` shows one topic: its title, a one-paragraph summary, the commands it names, and its children. With no topic it shows the root, `doc/`, plus a `code/` child for the source tree.

- A directory under `doc/` is a topic and its `README.md` is the topic index. A single `.md` file is a child page.
- The title is the first heading and the summary is the first paragraph, with links rendered as plain text (`[text](url)` becomes `text`).
- A topic README may carry one line that starts with `Commands:` followed by backticked commands. Only commands that resolve in this checkout are listed: a `zcl-dev <cmd>` that exists, a `make -C <dir>` with a Makefile, a script path that exists.
- Replies stay under 16 KiB. A topic with more than 64 children (or more than fit) pages: the last line is `next: zcl-dev wiki <topic> --after=N`.
- `--json` replies are `{"ok":true,"topic":...,"children":[{"path","kind","title","summary"}],"next":...}`; a refusal is `{"ok":false,"code":...}` with exit 2.

## Source tree

`zcl-dev wiki code/<dir>` walks the repository. A directory's summary is the first paragraph of its `AGENTS.md`, else its `README.md`, else "N files". A file's summary is the `purpose:` line of its leading comment, else the first substantive comment line (licence lines are skipped); shell scripts and Makefiles use their first comment line. Not served: dot directories, `depends/`, `vendor/` trees, `src/leveldb`, `src/secp256k1`, `src/univalue`, build outputs (`build/`, `obj/`, `zcutil/bin`, `zcutil/gen`, object files) and symlinks that leave the repository. Refusals: `EXCLUDED_PATH`, `OUTSIDE_CODE`, `UNKNOWN_TOPIC` (with the nearest existing topic as evidence).

`zcl-dev read <path> [--offset=N] [--bytes=N] [--json]` reads one file in chunks of at most 15872 bytes and ends with the `--offset` for the next chunk. It refuses the `.git` directory, key and wallet files, binary chunks (`BINARY_FILE`) and paths that leave the repository.

## Lessons

`zcl-dev lessons find <query...>` searches `LESSONS.md`, `TRAPS.md` and `FACTS.tsv`, case-insensitively; every word must match. It prints up to 8 hits as `file:line: text`. `zcl-dev lessons add OPEN <tracked-path> "<text>"` appends one line in the shape `zcl-dev check-docs` enforces: a lesson starts `OPEN`, the path must be tracked, the text is one line, and a duplicate is refused.

## Facts

[FACTS.tsv](FACTS.tsv) is one fact per line, six tab-separated fields: `subject relation object context confidence why`. Header lines declare the closed vocabularies: `#!relations`, `#!contexts` and `#!terms`. A term that contains `/` must be a tracked path; every other term is a plain token. `confidence` is `DOCTRINE` (asserted) or `OBSERVED` (derived from a test, gate or measurement); `UNKNOWN` is never written, it is what a query answers when no row exists. `why` is prose for the reader and is never a term.

- `zcl-dev know <term>` prints the rows where the term is subject or object, or `UNKNOWN`, never silence.
- `zcl-dev know --check` is the validator: declared relations, contexts and terms only, tracked paths, no duplicate rows, no unused terms, and a table with no rows fails (exit 2) rather than passing. It runs in `make -C zcutil/dev/wiki check`.
- Add a fact by declaring any new term and adding the row; a fact with no backing is a false statement about the tree.
