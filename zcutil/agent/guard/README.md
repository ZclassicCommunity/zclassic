# zcl-agent-guard

The Claude Code PreToolUse hook that refuses the never-do actions of `AGENTS.md`: touching a real
datadir or wallet, reindexing a node, spending or exporting keys, Python, git identity and push
rules, hosted CI, vendored code. It also warns (asks) for sealed consensus files and for edits of
the guard itself. Derived from Z23's `tools/agent_guard_rules.c`; see `zcutil/tools/NOTICE`.

```
make -C zcutil/agent/guard                                         # zcutil/bin/zcl-agent-guard
make -C zcutil/agent/guard check                                   # self-test (rule table), hook and replay tests
make -C zcutil/agent/guard CC=x86_64-w64-mingw32-gcc EXEEXT=.exe   # Windows build
```

Files: `rules.c` is the rule engine (Bash, PowerShell and path scanners), `zcl-agent-guard.c` the
hook, replay and CLI, `zcl-agent-guard.sh` the shim that runs when the binary is missing,
`test/selftest.c` the table of calls and the rule each must hit (allow rows count as much as
refusal rows), `test/run.sh` the hook tests, `test/transcript.jsonl` and `test/replay.golden` the
replay.

## What it reads

- Bash: segments, quoting, `sh -c`, `eval`, `ssh`, heredocs, `$( )`, `NAME=value`, `cd`, `xargs`
  and `cmd /c`, `cmd //c`, `cmd.exe /k` (rescanned with the cmd/PowerShell rules).
- PowerShell: `Remove-Item`, `Move-Item`, writers, `Start-Process`, `powershell -Command`,
  `$name = expr` (a string, `Join-Path`, `a + b`), `[IO.File]` and `[IO.Directory]` writes and
  deletes, and `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`, `curl`, `WebClient` and
  `HttpClient` calls that carry a spend or key-export method.
- `zclassic-cli`: the method must be visible on the command line. `-stdin`, `xargs zclassic-cli`,
  an xargs replace string (`-I{}`) or a variable or substitution in the method position hides the
  method, so the call is refused unless it is `-regtest` with an explicit test `-datadir` or `-conf`.
- A recursive delete whose PowerShell statement mentions APPDATA, ApplicationData, HOME or the
  profile together with a Zclassic or ZcashParams name is refused when the path cannot be resolved
  statically. Scratch names under a temp or test location, and repository clones such as
  `zclassic-c23-rust-removal`, are not datadir names.

## Known limits

These are not closed. The list is kept in the header of `rules.c`; the main ones:

- Aliases and shell functions are not expanded (`alias g=git; g push`).
- `rm -r "$(echo ~)"`: a substitution that computes an ancestor is not run.
- `sh script.sh` and `bash x.sh`: the script's content is not read; `curl -d @file`,
  `iwr -InFile` and `sqlq db < file.sql` do not read the file.
- PowerShell: `$d += x`, splatting, functions and aliases are not tracked. A path built from a
  command's output (`(Get-Item x).FullName`) is caught only by the statement rule above.
- `printf getinfo | xargs zclassic-cli getblockcount` is allowed: a visible method is the method.
- `tar --remove-files -C <ancestor> .` and `rsync --delete src/ <ancestor>/` are not ancestor checks.
- Bash and PowerShell writes to sealed consensus files (`sed -i`, `patch`, `git apply`) give no
  `guard.consensus_seal` warning; only Edit, Write and MultiEdit do. The sealed list is hard-coded
  (a selftest compares it with `zcutil/consensus.seal` when that file exists).
- Windows 8.3 names: `ZCLASS~N` and `ZCASHP~N` under AppData are matched, other short forms of a
  profile path are not.
- Git Bash consumes backslashes before the guard sees them, so backslash paths inside Bash are
  matched only where they survive.
- The mingw `.exe` is compiled with `-Werror` but not run in this tree.

A false refusal stalls the worker and a guard that blocks everyday commands gets switched off, so
every refusal row in `test/selftest.c` has allow rows next to it for the ordinary build and test
commands. Add both when you change a rule.
