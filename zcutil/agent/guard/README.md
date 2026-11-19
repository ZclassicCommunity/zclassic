# zcl-agent-guard

The Claude Code PreToolUse hook that refuses a short never-do list of `AGENTS.md`: touching a real
datadir or wallet, reindexing a node, spending or exporting keys on a real node, Python, git
identity and push rules, hosted CI, vendored code. It also asks (a warning) before an edit of a
sealed consensus file and of the guard's own switches. Derived from Z23's
`tools/agent_guard_rules.c`; see `zcutil/tools/NOTICE`. <!-- doc-path-ok -->

## What this is, and what it is not

**It guards against mistakes, not against an adversary.** It catches the command an agent types by
accident or out of habit: `rm -rf ~/.zclassic`, `zclassicd -reindex` on the real node, a
`dumpprivkey` against the real RPC port, `git push origin master`, a `python3` call. It is not a
security boundary and does not try to be one: anyone who wants to get around it can (encodings,
computed command text, a script built by another tool, aliases; see Known limits), and the guard
does not chase those.

The design follows from that:

- **A false refusal costs more than a missed exotic bypass.** A refusal stalls the worker, and a
  guard that blocks everyday work gets switched off. When a rule cannot tell a test from the real
  thing, it allows. Every refusal row in `test/selftest.c` has allow rows next to it.
- **What matters is running, not writing.** The text of a script written with Write (or echoed into
  a `.sh` file) is never refused: a finding is at most a note on stderr and the call is allowed. The
  Bash and PowerShell scans judge the command that runs it.
- **The guard never blocks work because it broke.** A missing binary, a crash, a timeout (it sets a
  4 s alarm; the hook timeout is 5 s) or any exit status other than 0 and 2 means allow, with a
  stderr note (`zcl-agent-guard.sh`).
- A refused call says which rule it broke and why. If a refusal is wrong, report it in your result
  and add the command to `test/ordinary.txt`; do not work around it.

```
make -C zcutil/agent/guard                                         # zcutil/bin/zcl-agent-guard
make -C zcutil/agent/guard check                                   # all the tests below
make -C zcutil/agent/guard CC=x86_64-w64-mingw32-gcc EXEEXT=.exe   # Windows build
```

Files: `rules.c` is the rule engine (Bash, PowerShell and path scanners), `zcl-agent-guard.c` the
hook, replay and CLI, `zcl-agent-guard.sh` the shim the hook runs, `test/selftest.c` the table of
calls and the rule each must hit, `test/ordinary.txt` the ordinary commands that must all be
allowed, `test/run.sh` the hook and shim tests (the hook calls are the table `test/hooks.txt`), `test/transcript.jsonl` and `test/replay.golden`
the replay.

## Tests

`make check` runs, in order:

1. the rule table (`test/selftest.c`, about 960 rows, allow rows count as much as refusal rows);
2. `test/ordinary.txt`: more than 140 Bash and 70 PowerShell scans of ordinary developer commands
   (builds, `make`, test scripts with `--bin/--work`, `zclassic-cli -regtest` including sends and
   key exports, `git` commit, fetch, branch and push of a feature branch, `rm -rf` of build and temp
   directories, `ssh host 'make ...'`, `devbuild --wait`, local-ci). Every one must be allowed;
3. every tracked `.sh`, `.ps1`, `.cmd` and `.bat` file of the repository, written back with its own
   content through the Write path under a neutral name, must be allowed (and under its own path it
   must give what an Edit of that path gives, so only a path rule can refuse);
4. `test/run.sh`: hook mode, the shim (missing binary, crash, timeout, exit codes), replay.

The ordinary list was also checked against about 7000 real agent transcripts (`--replay`): an earlier
build of this change refused 2069 of their tool calls (mostly the `git -c user.name=` commit idiom), this
one refuses 177, and those are real Python, real node-datadir work, `git push -f` and a few very large
scripts.

## What it reads

- Bash: segments, quoting, `sh -c`, `eval`, `ssh` (also `ssh host -- command`), heredocs, `$( )`,
  `NAME=value`, `cd`, `xargs` and `cmd /c`, `cmd //c`, `cmd.exe /k` (rescanned with the cmd/PowerShell
  rules).
- Pipelines: the literal text of `echo`, `printf`, `cat <<EOF` or a here-string that feeds `sh`,
  `bash`, `bash -s`, `dash` or `zsh` is scanned as commands, after decoding the escapes of `printf`
  (`\xHH`, octal, `%b`) and `echo -e`; any other producer feeding a shell (`curl ... | sh`,
  `base64 -d | sh`, `cat file | sh`) is `guard.too_complex`. A producer that lists or searches a
  datadir, an ancestor of one or a name such as `wallet.dat` and feeds `xargs rm`, a `while read`
  deleting loop or `Remove-Item` is refused like `find -delete`.
- PowerShell: `Remove-Item`, `Move-Item`, writers, `Start-Process`, `powershell -Command`,
  `$name = expr` (a string, `Join-Path`, `a + b`), `[IO.File]` and `[IO.Directory]` writes and
  deletes, and `Invoke-WebRequest`, `Invoke-RestMethod`, `iwr`, `irm`, `curl`, `WebClient` and
  `HttpClient` calls that carry a spend or key-export method. A spend or export name held as a
  quoted word (`@{method='dumpprivkey'}`, `@('sendtoaddress','t1')`) is a refusal when the command
  posts to a local production RPC port (or a port held in a variable), or when the same statement
  runs `zclassic-cli`, unless `-regtest` is explicit or the URL names a non-production port.
- `zclassic-cli`: a spend or key-export method refuses unless `-regtest` is explicit and no
  `-datadir` or `-conf` names a real node place and no `-rpcport` or `-rpcconnect` points at a
  production node. `-regtest -datadir="$dd"` (a variable) and `-regtest` alone are test calls: the
  regtest node has its own port and wallet. `curl -d '{"method":"sendtoaddress"}'` is a test call
  when the URL names a numeric port other than 8023, 8232, 8233, 8332 or 8033-8035.
- Datadir names: `.zclassic*` and `.zcash-params` count where the node keeps them (the home, `/home/u`,
  `/Users/u`, `/root`, the Windows spellings, a bare relative name after a `cd`); the same name under
  `/tmp`, `$TMPDIR`, `$(mktemp -d)` or an unknown variable (`$D/.zclassic`) is a scratch copy. A
  `-datadir` held in a variable is a test directory when its name says so (`$work`, `$tmp`,
  `$testdir`, `$dd`, `$scratch`).
- `git push`: a named branch other than master is ordinary, `--force-with-lease` too. Refused: master,
  `--force`, `-f`, `+ref`, `--delete`, `--all`, `--mirror`, and a push that names no branch (a bare
  `git push`, `origin`, `HEAD`) only when the repository at the hook's `cwd` is on master.
- Git identity: the fleet commits as the owner with `git -c user.name=... -c user.email=... commit` on
  hosts that carry no identity, so an override is ordinary and allowed. Refused is authoring as the
  tool itself: `-c user.*`, `git config user.*`, `--author`, `GIT_AUTHOR_*`, `GIT_COMMITTER_*` and `EMAIL`
  with a value that names Claude, Anthropic, Codex, OpenAI, GPT, Gemini, a bot or an agent, and an
  unset of the identity (`git config --unset user.name`). In a scratch repository (after a `git init`
  in the same command, with `-C` or `cwd` in a test directory) nothing is refused.
- `python3 --version` and `-V` alone are allowed (asking whether an interpreter exists); any other
  Python call is refused.
- A recursive delete whose PowerShell statement mentions APPDATA, ApplicationData, HOME or the
  profile together with a Zclassic or ZcashParams name is refused when the path cannot be resolved
  statically. Scratch names under a temp or test location, and repository clones such as
  `zclassic-c23-rust-removal`, are not datadir names.
- Script text from a pipe, a here-string or `<( )` is read into `sh`, `bash`, `dash`, `zsh`, `ksh`,
  `mksh`, `fish`, `ash`, `source`, `.` and `powershell -` when the producer is a literal `echo`,
  `printf` or `cat <<EOF`; any other producer (`bash <(curl URL)`) is `guard.too_complex`.
- The hook's `cwd` is where a command starts and what a relative Write or Edit path joins to.
- Copying a `wallet.dat` out of a datadir (`cp`, `rsync`, `scp`, `Copy-Item`) is a key export.
- Edit, Write and MultiEdit paths: a real datadir, `.github/workflows`, the vendored trees and <!-- doc-path-ok -->
  `.py` names are refused; the sealed consensus set and the guard's switches (`.claude/settings*.json`,
  the shim, the binaries) ask. The guard's own sources are an ordinary tree.

## Known limits

None of these is a security boundary, and none is planned to be closed (see the top). The list is
kept in the header of `rules.c`; the main ones:

- Aliases and shell functions are not expanded (`alias g=git; g push`); a function that wraps the
  client (`cli() { zclassic-cli ... "$@"; }`) is allowed, and so is its later call.
- Computed command text is not run: `eval "$(printf 'rm -rf %s' ~/.zclassic)"`, `bash -c "$(... |
  base64 -d)"`, `eval $(cat x)`, `$(echo cm0g | base64 -d)` as a command word, `iex $s`,
  `[scriptblock]::Create($s)`, `$ExecutionContext.InvokeCommand.InvokeScript($s)`. Only the simple
  `printf`/`echo -e` escapes piped to a shell are decoded.
- A datadir name split by an expansion or quoting is not rejoined: `~/.zcl${X}assic`,
  `$'rm' -rf ~/.zclassic`, `~/$'.zcl\x61ssic'`. A datadir under an unknown variable (`$D/.zclassic`)
  is allowed. Windows 8.3 short names (`APPDAT~1`) are only partly matched.
- Wrappers whose argument is a command line are not all rescanned: `env -S 'rm ...'`,
  `find -exec sh -c '...'`, `trap '...' EXIT`, `script -c`, `parallel`, `git -c core.sshCommand=...`,
  `GIT_SSH_COMMAND=... git fetch`, `make -f - <<< ...`, `less +'!...'`, `ssh h 'bash -s' < file`,
  `wsl -e sh -c '...'`.
- `sh script.sh` and `bash x.sh`: the script's content is not read, and neither is the text of a script
  written with Write (that is a note only). `curl -d @file`, `iwr -InFile` and `sqlq db < file.sql` do
  not read the file; `curl --data-binary @- <<< '{...}'` and httpie (`http POST ... method=...`) are
  not read.
- `zclassic-cli -stdin` and `xargs zclassic-cli` hide the method: refused without `-regtest`, allowed
  with it. `printf getinfo | xargs zclassic-cli getblockcount` is allowed (a visible method is the
  method). `zclassic-cli -regtest` with no `-datadir` reads the default conf, which could carry a
  production `rpcport`; `-regtest -conf=/tmp/x/zclassic.conf` can too.
- `nc`, `ncat`, `socat`, `telnet` to 8232 or 8233 are refused (`-z` probes pass); other ways to open
  a socket are not read.
- Key export by copy is caught for `cp`, `rsync`, `scp` and `Copy-Item` only: `tar czf x.tgz
  ~/.zclassic/wallet.dat`, `zip -r`, `cat wallet.dat | ssh h 'cat > w'` are allowed.
- PowerShell: `$d += x`, splatting, functions, aliases and `[Environment]::GetFolderPath` are not
  tracked; a path built from a command's output (`(Get-Item x).FullName`) is caught only by the
  statement rule above; `& (Get-Command python).Source` is not recognised as Python.
- Git: `gh api` is checked only for writes to `heads/master`; `gh pr merge` and other endpoints that
  land on master are not; `git push origin $(echo master)` is allowed; `git init x && git config
  user.name` in the real repository is allowed (the scratch-repository exemption is by the text);
  `git push origin HEAD` is judged by the branch of the repository at `cwd`, and allowed when it
  cannot be read; remote branch deletes and `--force` are refused even on a feature branch.
- Bash and PowerShell writes to sealed consensus files (`sed -i`, `patch`, `git apply`) give no
  `guard.consensus_seal` warning; only Edit, Write and MultiEdit do. The sealed list is hard-coded (a
  selftest compares it with `zcutil/consensus.seal` when that file exists).
- Python: `nix-shell -p python3 --run`, `docker run python:3`, `poetry run pytest` and the like are not
  recognised; `perl`, `node` and `ruby` inline code is checked only for a datadir name next to a
  deleting or writing call.
- `tar --remove-files -C <ancestor> .` and `rsync --delete src/ <ancestor>/` are not ancestor checks;
  `set -- ~/.zclassic; rm -rf "$1"` (positional parameters) and `ln -s` chains are not followed.
- Git Bash consumes backslashes before the guard sees them, so backslash paths inside Bash are matched
  only where they survive.
- A Bash command that needs more than 32768 words, 8192 segments, 4096 redirects, 2048 substitutions
  or 8 levels of nesting is `guard.too_complex` (a very large script run from a heredoc can hit it;
  split it, or run it from a file). One shape of nested `$(( ))` in a long script also trips it.
- Hook input over 32 MiB, or input that cannot be decoded for a checked tool, is refused
  (`guard.too_complex`); a hook JSON that cannot be read at all is not a crash, so it does not fall
  under the allow-on-crash rule.
- The mingw `.exe` is compiled with `-Werror` but not run in this tree.
