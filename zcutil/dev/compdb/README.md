# zcl-dev compdb

`compile_commands.json` for clangd and other code-navigation agents, taken from a configured build. With it clangd resolves zclassicd's include paths, defines and C++ dialect exactly, including the C23 glue under `src/c23/` and the depends include tree, instead of guessing.

```sh
make -C zcutil
zcutil/bin/zcl-dev compdb --build-dir ~/work/zc23-factory/w2-compdb-build   # out-of-tree build
zcutil/bin/zcl-dev compdb --check --build-dir <dir>                         # 0 fresh, 1 stale
clangd --compile-commands-dir=<repo root> --check=src/main.cpp
```

Options: `--build-dir DIR` (default: the repo root, an in-tree build), `--out PATH` (default `<repo root>/compile_commands.json`, git-ignored), `--subdir src` (the directory under the build dir that make is run in).

## How it works

It runs `make -n -B -w -C <DIR>/<subdir>` with argv (no shell) and `LC_ALL=C`; `MAKEFLAGS`, `MFLAGS` and `MAKELEVEL` are cleared. `ZCL_COMPDB_MAKE` names another make. From the output it:

- follows `Entering directory` and `Leaving directory` lines, so a recursive `$(MAKE) -C sub` gives the right `directory`;
- joins backslash-continued lines and splits a recipe line on `&&`, `||` and `;` outside quotes;
- takes the command after `--mode=compile` (or `libtool: compile:`) for libtool lines, drops a leading `ccache` and `VAR=value` words;
- accepts a command whose first word is `g++`, `gcc`, `c++`, `cc`, `clang`, `clang++` or `*-g++`/`*-gcc`, with `-c` and exactly one `.c`, `.cc`, `.cpp` or `.cxx` source;
- strips `-MT/-MQ/-MF <arg>`, `-MD`, `-MMD`, `-MP` and `-MG`;
- handles `'...'`, `"..."` and backslash escapes in the recipe and expands nothing else; a compile that still has `$(` or a backtick is skipped and counted.

The database is a JSON array of `{directory, file (absolute), arguments}` sorted by file, written atomically (temp file, then rename). The summary on stderr is `entries E, skipped S, duplicates D`; a duplicate is the same file twice, the first is kept. Zero entries exits 2 (hollow). Where make is not on `PATH` (some Windows hosts) it prints `UNAVAILABLE` and exits 2.

Exit: 0 written or fresh, 1 `--check` found the file stale or missing, 2 broken invocation, no make, or hollow.

## Warning

`make -n` is a dry run, not a no-op. Make still evaluates `$(shell ...)`, runs recipes marked `+`, and runs `$(MAKE)` recursive recipes (with `-n` passed down). Those are make's own rules; this tool does not suppress them. Run it on a tree you would let `make` read, and never one whose Makefiles you do not trust. The build tree must already be configured (`configure` done); an unconfigured tree has no Makefile and is reported hollow.

## Tests

`make -C zcutil/dev/compdb check` runs `--selftest` (word splitting, command splitting, paths, a canned make transcript) and `test/compdb_test.c`, which runs the tool in-process over the fixture Makefiles in `test/fixtures/` (a fake `g++` that `make -n` never runs) and compares each result with `test/golden/<case>.txt`: in-directory compile, recursive make, libtool, ccache, quoted defines, continuation line, duplicate, `$(...)` leftover, empty project (exit 2), then `--check` fresh and stale, a missing build directory and a missing make (UNAVAILABLE). `zcl-compdb-test test/fixtures --update` rewrites the goldens.

