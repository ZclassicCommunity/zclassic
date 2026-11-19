/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: MIT
 *
 * Table-driven self-test for the zcl-agent-guard rule engine (rules.c). Every row is one call and
 * the rule it must hit (or NULL for allow). Quoting, env prefixes, sh -c nesting, ssh, heredocs and
 * && chains are covered on purpose: a missed refusal and a false refusal both fail the run. */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rules.h"

struct tcase {
    char kind;          /* 'B' bash, 'S' PowerShell, 'P' path */
    const char *tool;   /* P: tool name */
    const char *input;  /* B: command, P: file path */
    const char *extra;  /* P: Write content, else NULL */
    const char *want;   /* rule id, or NULL for allow */
};

#define B(cmd, want) {'B', NULL, cmd, NULL, want}
#define P(tool, path, want) {'P', tool, path, NULL, want}
#define S(cmd, want) {'S', NULL, cmd, NULL, want}

static const struct tcase cases[] = {
    /* guard.datadir: writes, rm and mv under a node datadir */
    B("rm -rf ~/.zclassic/blocks", R_DATADIR),
    B("rm -rf $HOME/.zclassic/chainstate", R_DATADIR),
    B("mv ~/.zclassic ~/old", R_DATADIR),
    B("mv ~/old ~/.zclassic", R_DATADIR),
    B("cp wallet.dat ~/.zclassic/wallet.dat", R_DATADIR),
    B("echo x > ~/.zclassic/zclassic.conf", R_DATADIR),
    B("echo x >> \"$HOME/.zclassic/zclassic.conf\"", R_DATADIR),
    B("tee ~/.zclassic-c23/x < /dev/null", R_DATADIR),
    B("sed -i 's/a/b/' ~/.zclassic/zclassic.conf", R_DATADIR),
    B("rm -rf ~/.zcash-params", R_DATADIR),
    B("rm ~/.zcash-params/sprout-groth16.params", R_DATADIR),
    B("rm -rf '%APPDATA%/Zclassic/blocks'", R_DATADIR),
    B("rm -rf \"$APPDATA/Zclassic\"", R_DATADIR),
    B("mv C:/Users/John/AppData/Roaming/Zclassic /tmp/x", R_DATADIR),
    B("cd ~/.zclassic && rm -rf blocks", R_DATADIR),
    B("cd ~/.zclassic; touch x", R_DATADIR),
    B("echo hi && rm -rf ~/.zclassic/peers.dat", R_DATADIR),
    B("sh -c 'rm -rf ~/.zclassic/blocks'", R_DATADIR),
    B("bash -lc \"mv ~/.zclassic/wallet.dat /tmp\"", R_DATADIR),
    B("ssh z23-r1 'rm -rf ~/.zclassic-c23/blocks'", R_DATADIR),
    B("env FOO=1 rm -rf ~/.zclassic/blocks", R_DATADIR),
    B("sudo rm -rf ~/.zclassic/blocks", R_DATADIR),
    B("nice -n 5 timeout 10 mv ~/.zclassic/x /tmp/y", R_DATADIR),
    B("dd if=/dev/zero of=$HOME/.zclassic/wallet.dat", R_DATADIR),
    B("zclassicd -datadir=/home/rhett/.zclassic -printtoconsole", R_DATADIR),
    B("zclassicd -datadir=/home/rhett/zdata", R_DATADIR),
    B("zclassicd -daemon", R_DATADIR),
    B("test_bitcoin -datadir=$HOME/.zclassic", R_DATADIR),
    P("Write", "/home/rhett/.zclassic/zclassic.conf", R_DATADIR),
    P("Edit", "C:\\Users\\John\\AppData\\Roaming\\Zclassic\\zclassic.conf", R_DATADIR),
    P("Edit", "C:\\Users\\John\\AppData\\Roaming\\ZcashParams\\x", R_DATADIR),
    /* datadir: allowed reads and test directories */
    B("ls ~/.zclassic", NULL),
    B("tail -n 50 ~/.zclassic/debug.log", NULL),
    B("cat ~/.zclassic/zclassic.conf | grep rpc", NULL),
    B("cp ~/.zclassic/zclassic.conf /tmp/zclassic.conf.copy", NULL),
    B("rm -rf /tmp/zcl-test.1234/blocks", NULL),
    B("zclassicd -regtest -datadir=/tmp/zcl-test.1234", NULL),
    B("zclassicd -datadir=$(mktemp -d) -regtest", NULL),
    B("zclassicd -datadir=\"$TMPDIR/node1\" -regtest", NULL),
    B("zclassicd -datadir=build/test-nodes/a -regtest", NULL),
    B("zclassicd -regtest", NULL),
    B("zclassicd -help", NULL),
    B("zclassicd --version", NULL),
    B("test_bitcoin --run_test=sighash_tests", NULL),
    B("echo '~/.zclassic is the datadir'", NULL),
    B("git commit -m 'document rm -rf ~/.zclassic'", NULL),

    /* guard.reindex */
    B("zclassicd -reindex", R_REINDEX),
    B("zclassicd -reindex-chainstate", R_REINDEX),
    B("zclassicd -daemon -rescan", R_REINDEX),
    B("zclassicd --reindex", R_REINDEX),
    B("zclassicd -reindex=1 -datadir=/home/rhett/zdata", R_REINDEX),
    B("/usr/local/bin/zclassicd -reindex", R_REINDEX),
    B("ssh node1 zclassicd -reindex", R_REINDEX),
    B("nohup zclassicd -reindex &", R_REINDEX),
    B("zclassicd -regtest -reindex", NULL),
    B("zclassicd -reindex -datadir=/tmp/zcl-test.9", NULL),
    B("zclassicd -rescan=0 -regtest", NULL),
    B("zclassicd -regtest=1 -rescan", NULL),

    /* guard.spend_or_key_export */
    B("zclassic-cli sendtoaddress t1abc 1", R_SPEND),
    B("zclassic-cli z_sendmany zs1abc '[]'", R_SPEND),
    B("zclassic-cli sendmany '' '{}'", R_SPEND),
    B("zclassic-cli -rpcwait z_mergetoaddress '[\"ANY_TADDR\"]' zs1x", R_SPEND),
    B("zclassic-cli z_shieldcoinbase '*' zs1x", R_SPEND),
    B("zclassic-cli dumpprivkey t1abc", R_SPEND),
    B("zclassic-cli dumpwallet /tmp/w", R_SPEND),
    B("zclassic-cli z_exportkey zs1abc", R_SPEND),
    B("zclassic-cli z_exportviewingkey zs1abc", R_SPEND),
    B("zclassic-cli z_exportwallet w", R_SPEND),
    B("zclassic-cli walletpassphrase secret 60", R_SPEND),
    B("zclassic-cli encryptwallet secret", R_SPEND),
    B("zclassic-cli.exe dumpprivkey t1abc", R_SPEND),
    B("zcash-cli -datadir=/tmp/x sendtoaddress t1 1", R_SPEND),
    B("echo go && zclassic-cli sendtoaddress t1abc 1", R_SPEND),
    B("sh -c 'zclassic-cli dumpprivkey t1abc'", R_SPEND),
    B("ssh node1 'zclassic-cli z_sendmany a b'", R_SPEND),
    B("curl --user u:p --data-binary '{\"method\":\"z_sendmany\",\"params\":[]}' http://127.0.0.1:8232/", R_SPEND),
    B("curl -d '{\"jsonrpc\":\"1.0\",\"method\": \"dumpprivkey\"}' localhost:8232", R_SPEND),
    B("zclassic-cli -regtest -datadir=/tmp/x sendtoaddress t1abc 1", NULL),
    B("zclassic-cli -regtest=1 -datadir=/tmp/x z_sendmany a b", NULL),
    B("zclassic-cli -regtest -datadir=/tmp/x dumpprivkey t1abc", NULL),
    B("C=\"zclassic-cli -regtest -datadir=/tmp/x\"; $C z_sendmany a b", NULL),
    B("C=zclassic-cli; $C z_sendmany a b", R_SPEND),
    B("zclassic-cli getinfo", NULL),
    B("zclassic-cli z_listreceivedbyaddress zs1abc", NULL),
    B("zclassic-cli getblockcount", NULL),
    B("echo sendtoaddress", NULL),
    B("grep -rn z_sendmany src/wallet", NULL),
    B("curl -s http://127.0.0.1:8232/ -d '{\"method\":\"getblockcount\"}'", NULL),

    /* guard.python */
    B("python script.py", R_PYTHON),
    B("python3 -c 'print(1)'", R_PYTHON),
    B("python3.12 x", R_PYTHON),
    B("pip install requests", R_PYTHON),
    B("pip3 install x", R_PYTHON),
    B("env PYTHONPATH=. python3 tool", R_PYTHON),
    B("cd src && python3 gen.py", R_PYTHON),
    B("sh -c \"python3 -V\"", R_PYTHON),
    B("ssh z23-r1 'python3 --version'", R_PYTHON),
    B("python.exe x.py", R_PYTHON),
    B("./gen.py", R_PYTHON),
    B("uv run tool", R_PYTHON),
    B("echo 'print(1)' > gen.py", R_PYTHON),
    B("cp tmpl gen.py", R_PYTHON),
    P("Write", "tools/gen.py", R_PYTHON),
    P("Edit", "src/util.PY", R_PYTHON),
    {'P', "Write", "tools/run", "#!/usr/bin/env python3\nprint(1)\n", R_PYTHON},
    {'P', "Write", "tools/run", "#!/bin/sh\necho ok\n", NULL},
    B("grep -rn python doc/", NULL),
    B("echo python", NULL),
    B("git commit -m 'drop the python helper'", NULL),
    B("rm obsolete.py", NULL),

    /* guard.git_identity */
    B("git config user.name Someone", R_IDENT),
    B("git config --global user.email a@b.c", R_IDENT),
    B("git config --unset user.name", R_IDENT),
    B("git -c user.name=x commit -m m", R_IDENT),
    B("git commit --author='A <a@b.c>' -m m", R_IDENT),
    B("git commit --author 'A <a@b.c>' -m m", R_IDENT),
    B("GIT_AUTHOR_NAME=x git commit -m m", R_IDENT),
    B("export GIT_COMMITTER_EMAIL=a@b.c", R_IDENT),
    B("env GIT_AUTHOR_EMAIL=a@b.c git commit -m m", R_IDENT),
    B("git config user.name", NULL),
    B("git config --get user.email", NULL),
    B("git config --list", NULL),
    B("git config core.autocrlf false", NULL),
    B("git commit -m 'user.name is preconfigured'", NULL),
    B("git log --author=rhett", NULL),

    /* guard.git_push */
    B("git push origin master", R_PUSH),
    B("git push origin HEAD:master", R_PUSH),
    B("git push origin HEAD:refs/heads/master", R_PUSH),
    B("git push --force origin factory/u12", R_PUSH),
    B("git push -f origin factory/u12", R_PUSH),
    B("git push --force-with-lease origin factory/u12", R_PUSH),
    B("git push origin +factory/u12", R_PUSH),
    B("git push --all origin", R_PUSH),
    B("git push --mirror backup", R_PUSH),
    B("git push", R_PUSH),
    B("git push origin", R_PUSH),
    B("git push origin HEAD", R_PUSH),
    B("git -C repo push origin master", R_PUSH),
    B("git add -A && git commit -m x && git push origin master", R_PUSH),
    B("sh -c 'git push -u origin master'", R_PUSH),
    B("git push -u origin factory/u12", NULL),
    B("git push origin factory/u12", NULL),
    B("git push origin HEAD:factory/u12", NULL),
    B("git push --tags origin", NULL),
    B("git push --dry-run origin master", NULL),
    B("git push --help", NULL),
    B("git log origin/master", NULL),
    B("git fetch origin master", NULL),
    B("git merge origin/master", NULL),
    B("echo git push origin master", NULL),

    /* guard.hosted_ci */
    B("gh workflow run build.yml", R_CI),
    B("gh workflow enable build.yml", R_CI),
    B("gh run rerun 123", R_CI),
    B("gh api repos/o/r/actions/workflows/x.yml/dispatches -f ref=master", R_CI),
    B("cd repo && gh workflow run ci.yml --ref master", R_CI),
    B("echo 'on: push' > .github/workflows/ci.yml", R_CI),
    B("cp ci.yml .github/workflows/ci.yml", R_CI),
    B("rm -rf .github/workflows", R_CI),
    P("Write", ".github/workflows/ci.yml", R_CI),
    P("Edit", "C:\\Users\\John\\repo\\.github\\workflows\\ci.yml", R_CI),
    B("gh pr list", NULL),
    B("gh run list", NULL),
    B("gh workflow list", NULL),
    B("cat .github/workflows/ci.yml", NULL),
    P("Edit", ".github/CODEOWNERS", NULL),

    /* guard.vendor_edit */
    P("Edit", "zcutil/tools/vendor/tools/jsonq.c", R_VENDOR),
    P("Write", "zcutil/tools/vendor/platform/modules/json/src/json.c", R_VENDOR),
    P("MultiEdit", "src/c23/vendor/x/y.c", R_VENDOR),
    P("Edit", "src/c23/services/vendor/z.c", R_VENDOR),
    P("Edit", "/home/rhett/work/zc23-factory/u12/zcutil/tools/vendor/tools/multicall.h", R_VENDOR),
    B("sed -i 's/a/b/' zcutil/tools/vendor/tools/jsonq.c", R_VENDOR),
    B("rm -rf src/c23/vendor", R_VENDOR),
    B("cp x.c zcutil/tools/vendor/tools/x.c", R_VENDOR),
    P("Edit", "zcutil/tools/Makefile", NULL),
    P("Edit", "zcutil/tools/vendor-files.txt", NULL),
    P("Edit", "src/c23/glue/glue.c", NULL),
    B("cat zcutil/tools/vendor/tools/jsonq.c", NULL),
    B("git grep -n json zcutil/tools/vendor", NULL),

    /* guard.consensus_seal: a warning, never a refusal */
    P("Edit", "src/pow.cpp", R_SEAL),
    P("Write", "src/pow.h", R_SEAL),
    P("Edit", "src/consensus/params.h", R_SEAL),
    P("Edit", "src/script/interpreter.cpp", R_SEAL),
    P("MultiEdit", "src/script/script.h", R_SEAL),
    P("Edit", "src/primitives/block.cpp", R_SEAL),
    P("Edit", "src/chainparams.cpp", R_SEAL),
    P("Edit", "src/zcash/IncrementalMerkleTree.cpp", R_SEAL),
    P("Edit", "src/zcash/NoteEncryption.h", R_SEAL),
    P("Edit", "src/pow/equihash.cpp", R_SEAL),
    P("Edit", "C:\\work\\zcl\\src\\pow.cpp", R_SEAL),
    P("Edit", "src/pow/tromp/equi_miner.h", NULL),
    P("Edit", "src/chainparamsbase.cpp", NULL),
    P("Edit", "src/script/sign.cpp", NULL),
    P("Edit", "src/main.cpp", NULL),
    P("Edit", "src/zcash/Zcash.h", NULL),
    P("Edit", "src/c23/consensus/x.c", NULL),
    P("Write", "zcutil/agent/guard/rules.c", R_SELF),
    B("sed -n 1,20p src/pow.cpp", NULL),

    /* an ancestor of a datadir: deleting, moving or recursively changing it reaches the datadir */
    B("rm -rf ~", R_DATADIR),
    B("rm -rf ~/", R_DATADIR),
    B("rm -rf ~/*", R_DATADIR),
    B("rm -rf ~/.*", R_DATADIR),
    B("rm -rf /home/rhett", R_DATADIR),
    B("rm -rf /home", R_DATADIR),
    B("rm -rf /", R_DATADIR),
    B("rm -rf /*", R_DATADIR),
    B("rm -rf /home/*", R_DATADIR),
    B("rm -rf $HOME", R_DATADIR),
    B("rm -rf ${HOME}/", R_DATADIR),
    B("rm -rf ~root", R_DATADIR),
    B("rm -rf /root", R_DATADIR),
    B("rm -rf /Users/john", R_DATADIR),
    B("rm -rf /Users", R_DATADIR),
    B("rm -rf C:/Users/John", R_DATADIR),
    B("rm -rf /c/Users/John", R_DATADIR),
    B("rm -rf /mnt/c/Users/John", R_DATADIR),
    B("rm -rf ~/AppData", R_DATADIR),
    B("rm -rf ~/AppData/Roaming", R_DATADIR),
    B("rm -rf ~/Library", R_DATADIR),
    B("rm -rf ~/Library/Application\\ Support", R_DATADIR),
    B("rm -rf '%APPDATA%'", R_DATADIR),
    B("rm -rf $APPDATA", R_DATADIR),
    B("rm -rf ~/..", R_DATADIR),
    B("rm -rf ~/x/../..", R_DATADIR),
    B("rmdir ~", R_DATADIR),
    B("mv ~ /tmp/x", R_DATADIR),
    B("mv /home/rhett /tmp/x", R_DATADIR),
    B("mv -t /tmp ~", R_DATADIR),
    B("chmod -R 000 ~", R_DATADIR),
    B("chown -R root /home/rhett", R_DATADIR),
    B("find ~ -delete", R_DATADIR),
    B("find ~ -name '*.log' -delete", R_DATADIR),
    B("find / -name wallet.dat -exec rm {} +", R_DATADIR),
    B("find /home -type f -exec mv {} /tmp \\;", R_DATADIR),
    B("cd /home && rm -rf rhett", R_DATADIR),
    B("cd ~ && rm -rf .zclassic", R_DATADIR),
    B("cd ~ && rm -rf .zcl*", R_DATADIR),
    B("cd && rm -rf .*", R_DATADIR),
    B("cd / && rm -rf home", R_DATADIR),
    B("cd ~/.. && rm -rf rhett", R_DATADIR),
    B("rm -rf ~/.zcl*", R_DATADIR),
    B("rm -rf ~/.zclassi?", R_DATADIR),
    B("rm -rf ~/.z[c]lassic", R_DATADIR),
    B("rm -rf ~/.{zclassic,foo}", R_DATADIR),
    B("rm -rf ~/.{foo,zclassic}/blocks", R_DATADIR),
    B("rm -rf ~/.z*", R_DATADIR),
    B("rm -rf /home/*/.zclassic", R_DATADIR),
    B("rm -rf /home/rhett/.zcash-par*", R_DATADIR),
    B("rm -rf ~/.zclassic*", R_DATADIR),
    B("sh -c 'rm -rf ~'", R_DATADIR),
    B("rm -rf ${HOME:?}/*", R_DATADIR),
    B("rm -rf \"$HOME\"/*", R_DATADIR),
    B("rm -rf ${HOME:?}/build", NULL),
    B("rm -rf ~/build", NULL),
    B("rm ~/notes.txt", NULL),
    B("rm -rf ~/.cache/x", NULL),
    B("rm ~/*.log", NULL),
    B("rm -rf ~/foo*", NULL),
    B("rm -rf ~/.zsh_history", NULL),
    B("mv a ~/", NULL),
    B("mv a ~", NULL),
    B("mv ~/a ~/b", NULL),
    B("rm -rf /tmp/x", NULL),
    B("rm -rf /tmp/*", NULL),
    B("rm -rf /home/rhett/projects/old", NULL),
    B("rm -rf /usr/local/zc", NULL),
    B("rm -rf build/*", NULL),
    B("find . -name '*.o' -delete", NULL),
    B("find /tmp -name '*.o' -delete", NULL),
    B("find ~ -name x", NULL),
    B("find ~ -name '*.c' -exec grep -l x {} +", NULL),
    B("chmod 600 ~/key", NULL),
    B("chmod -R u+rw build", NULL),
    B("cd /tmp && rm -rf work", NULL),
    S("Remove-Item -Recurse ~", R_DATADIR),
    S("Remove-Item -Recurse -Force $env:USERPROFILE", R_DATADIR),
    S("Remove-Item -Recurse $env:APPDATA", R_DATADIR),
    S("Remove-Item -Recurse -Path:~", R_DATADIR),
    S("rm -r -fo C:\\Users\\John", R_DATADIR),
    S("Set-Location $env:APPDATA; Remove-Item -Recurse Zclassic", R_DATADIR),
    S("cd ~; ri -r .zcl*", R_DATADIR),
    S("Move-Item ~ C:\\old", R_DATADIR),
    S("Remove-Item -Recurse $env:APPDATA\\Zcl*", R_DATADIR),
    S("Remove-Item -Recurse ~\\build", NULL),
    S("Move-Item a ~", NULL),
    S("Remove-Item -Recurse C:\\Windows\\Temp\\x", NULL),

    /* zclassicd parses argv until the first non-dash word, the last value wins */
    B("zclassic-cli sendtoaddress t1 1 -regtest", R_SPEND),
    B("zclassic-cli -datadir=/tmp/x z_sendmany x \"[]\" -regtest", R_SPEND),
    B("zclassic-cli -regtest -regtest=0 -datadir=/tmp/x sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli -regtest -noregtest -datadir=/tmp/x sendtoaddress t1 1", NULL),
    B("zclassic-cli -noregtest -datadir=/tmp/x sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli -regtest=abc -datadir=/tmp/x sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli --regtest -datadir=/tmp/x sendtoaddress t1 1", NULL),
    B("zclassic-cli -regtest -datadir /tmp/x sendtoaddress t1 1", R_SPEND),
    B("zclassicd -reindex foo -regtest", R_REINDEX),
    B("zclassicd -reindex -datadir=/tmp/x -datadir=/home/rhett/.zclassic", R_REINDEX),
    B("zclassicd -reindex -datadir=/home/rhett/.zclassic -datadir=/tmp/x", R_REINDEX),
    B("zclassicd -reindex -datadir /tmp/x", R_REINDEX),
    B("zclassicd -reindex -datadir= ", R_REINDEX),
    B("zclassicd -reindex -datadir", R_REINDEX),
    B("zclassicd -regtest -regtest=0 -reindex", R_REINDEX),
    B("zclassicd -regtest=false -reindex", R_REINDEX),
    B("zclassicd -reindex -datadir=/tmp/x -datadir=/tmp/y", NULL),
    B("zclassicd -reindex --datadir=/tmp/x", NULL),
    B("zclassicd -datadir=/tmp/x -datadir=/home/rhett/.zclassic -regtest", R_DATADIR),
    B("zclassicd -datadir /tmp/x -regtest", R_DATADIR),
    B("zclassicd -regtest -regtest=0 -datadir=/tmp/x", NULL),
    B("zclassicd -regtest -noregtest -datadir=/tmp/x", NULL),

    /* an RPC client in -regtest still goes where -rpcport, -rpcconnect or -conf point it */
    B("zclassic-cli -regtest -rpcport=8023 -datadir=/tmp/x sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli -regtest -rpcport=8023 sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli -regtest -rpcport=8023 dumpprivkey t1", R_SPEND),
    B("zclassic-cli -regtest -datadir=/tmp/x -rpcport=8232 dumpprivkey t1", R_SPEND),
    B("zclassic-cli -regtest -datadir=/tmp/x -rpcconnect=10.0.0.5 dumpprivkey t1", R_SPEND),
    B("zclassic-cli -regtest -conf=/home/rhett/.zclassic/zclassic.conf sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli -regtest -datadir=/tmp/x -conf=/home/rhett/zclassic.conf dumpprivkey t1", R_SPEND),
    B("zclassic-cli -regtest sendtoaddress t1 1", R_SPEND),
    B("zclassic-cli -regtest -datadir=/tmp/x -rpcport=18232 sendtoaddress t1 1", NULL),
    B("zclassic-cli -regtest -datadir=/tmp/x -rpcconnect=127.0.0.1 sendtoaddress t1 1", NULL),
    B("zclassic-cli -regtest -conf=/tmp/x/zclassic.conf sendtoaddress t1 1", NULL),

    /* variables set earlier in the same command */
    B("D=$HOME/.zclassic; zclassicd -datadir=$D -reindex", R_REINDEX),
    B("D=$HOME/.zclassic; zclassicd -datadir=\"$D\" -reindex", R_REINDEX),
    B("D=${HOME}/.zclassic && zclassicd -reindex -datadir=${D}", R_REINDEX),
    B("zclassicd -datadir=$D -reindex", R_REINDEX),
    B("zclassicd -datadir=$(echo ~/.zclassic) -reindex", R_REINDEX),
    B("D=~/.zclassic; rm -rf $D", R_DATADIR),
    B("x=.zclassic; rm -rf ~/$x", R_DATADIR),
    B("export D=~/.zclassic && rm -rf $D/blocks", R_DATADIR),
    B("declare D=~/.zclassic; mv $D /tmp/x", R_DATADIR),
    B("A=~; B=$A/.zclassic; rm -rf $B", R_DATADIR),
    B("D=~/.zclassic; echo x > $D/zclassic.conf", R_DATADIR),
    B("D=~; rm -rf $D", R_DATADIR),
    B("sh -c 'D=~/.zclassic; rm -rf $D'", R_DATADIR),
    B("D=$(mktemp -d); zclassicd -datadir=$D -reindex", NULL),
    B("D=/tmp/zt; zclassicd -datadir=$D -reindex", NULL),
    B("D=/tmp/zt; rm -rf $D", NULL),
    B("D=~/.zclassic; D=/tmp/zt; rm -rf $D", NULL),
    B("zclassicd -datadir=$D -regtest", NULL),
    B("zclassicd -datadir=${TMPDIR}/n1 -reindex", NULL),
    B("C=zclassic-cli; $C -regtest -datadir=/tmp/x sendtoaddress t 1", NULL),
    B("C=zclassic-cli; $C sendtoaddress t 1", R_SPEND),

    /* a datadir piped, substituted or fed into a deleter */
    B("echo ~/.zclassic | xargs rm -rf", R_DATADIR),
    B("ls -d ~/.zclassic | xargs rm -rf", R_DATADIR),
    B("find ~/.zclassic -name '*.dat' | xargs rm", R_DATADIR),
    B("printf '%s\\n' ~/.zclassic/blocks | xargs -I{} mv {} /tmp", R_DATADIR),
    B("xargs rm -rf <<< ~/.zclassic", R_DATADIR),
    B("rm -rf $(echo ~/.zclassic)", R_DATADIR),
    B("rm -rf `echo ~/.zclassic`", R_DATADIR),
    B("rm -rf \"$(echo ~/.zclassic)\"", R_DATADIR),
    B("mv $(ls -d ~/.zclassic) /tmp/x", R_DATADIR),
    B("echo ~/.zclassic | wc -c", NULL),
    B("ls ~/.zclassic | xargs echo", NULL),
    B("cat ~/.zclassic/debug.log | grep x | xargs ls", NULL),
    B("echo ~/.zclassic; echo x | xargs rm", NULL),
    B("echo x | xargs rm -rf", NULL),
    B("rm -rf $(mktemp -d)", NULL),
    B("echo $(ls ~/.zclassic) > /tmp/list", NULL),
    S("Get-ChildItem $env:APPDATA\\Zclassic | Remove-Item", R_DATADIR),
    S("gci $env:APPDATA\\Zclassic -Recurse | ri", R_DATADIR),
    S("Get-ChildItem $env:APPDATA\\Zclassic | Remove-Item -Recurse -Force", R_DATADIR),
    S("Get-ChildItem $env:APPDATA\\Zclassic | ForEach-Object { Remove-Item $_ }", R_DATADIR),
    S("Get-ChildItem $env:APPDATA\\Zclassic | Move-Item -Destination C:\\x", R_DATADIR),
    S("Remove-Item -Recurse (Get-Item $env:APPDATA\\Zclassic)", R_DATADIR),
    S("Remove-Item $(Get-Item $env:APPDATA\\Zclassic)", R_DATADIR),
    S("Get-ChildItem $env:APPDATA\\Zclassic | Select-Object -First 1", NULL),
    S("Get-ChildItem $env:APPDATA\\Zclassic; Remove-Item build", NULL),
    S("Get-ChildItem $env:APPDATA\\Zclassic | Measure-Object", NULL),
    S("Get-ChildItem build | Remove-Item", NULL),
    S("Get-ChildItem $env:APPDATA\\Zclassic | Out-File build\\list.txt", NULL),

    /* a cd target is a path prefix of relative write targets */
    B("cd .github && echo x > workflows/ci.yml", R_CI),
    B("cd .github/workflows && echo x > ci.yml", R_CI),
    B("cd .github && cd workflows && touch ci.yml", R_CI),
    B("cd zcutil/tools && echo > vendor/x.c", R_VENDOR),
    B("cd zcutil/tools; cp a vendor/b.c", R_VENDOR),
    B("cd zcutil && cd tools && sed -i s/a/b/ vendor/x.c", R_VENDOR),
    B("cd .github && echo x > CODEOWNERS", NULL),
    B("cd zcutil && echo x > tools/a.c", NULL),
    B("cd /tmp && echo x > a", NULL),
    B("cd .github && cd .. && echo x > workflows/ci.yml", NULL),
    S("Set-Location .github; Set-Content workflows\\ci.yml x", R_CI),

    /* more Python forms */
    B("py -3 x", R_PYTHON),
    B("py.exe -m pip install x", R_PYTHON),
    B("pythonw x", R_PYTHON),
    B("mv a b.py", R_PYTHON),
    B("tee a.py < /dev/null", R_PYTHON),
    B("echo x | tee gen.pyw", R_PYTHON),
    B("cp a gen.pyi", R_PYTHON),
    B("echo x > a.pyw", R_PYTHON),
    P("Write", "tools/x.pyw", R_PYTHON),
    P("Edit", "tools/x.pyi", R_PYTHON),
    B("mv a.py b.txt", NULL),
    B("git mv a.c b.c", NULL),
    S("py -3 x", R_PYTHON),
    S("Start-Process python -ArgumentList x", R_PYTHON),
    S("Start-Process -FilePath python.exe", R_PYTHON),
    S("start py", R_PYTHON),
    S("Start-Process notepad", NULL),
    S("Start-Process git -ArgumentList push,origin,master", R_PUSH),
    S("Move-Item a b.py", R_PYTHON),

    /* more git forms */
    B("git push origin foo --delete", R_PUSH),
    B("git push --delete origin foo", R_PUSH),
    B("git push -d origin foo", R_PUSH),
    B("git push origin 'refs/heads/*:refs/heads/*'", R_PUSH),
    B("git push origin '+refs/heads/*:refs/heads/*'", R_PUSH),
    B("git send-pack origin master", R_PUSH),
    B("git config remote.origin.push +refs/heads/*:refs/heads/*", R_PUSH),
    B("git config remote.origin.mirror true", R_PUSH),
    B("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=user.name GIT_CONFIG_VALUE_0=x git commit -m m", R_IDENT),
    B("GIT_CONFIG_PARAMETERS=\"'user.name=x'\" git commit -m m", R_IDENT),
    B("EMAIL=x git commit -m m", R_IDENT),
    B("export EMAIL=x@y.z", R_IDENT),
    B("git config alias.x \"!git config user.name x\"", R_IDENT),
    S("$env:EMAIL = 'x@y.z'", R_IDENT),
    B("git config alias.st status", NULL),
    B("git config remote.origin.url git@host:r.git", NULL),
    B("GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/x git status", NULL),
    B("git push --set-upstream origin factory/u12", NULL),
    B("git push origin factory/u12 --force-if-includes", R_PUSH),

    /* the guard protects itself: a warning (ask), and a refusal still wins over it */
    B("rm zcutil/bin/zcl-agent-guard", R_SELF),
    B("rm zcutil/bin/zcl-agent-guard.exe", R_SELF),
    B("mv zcutil/bin/zcl-agent-guard /tmp/x", R_SELF),
    B("rm -rf zcutil/agent/guard", R_SELF),
    B("echo x > .claude/settings.local.json", R_SELF),
    B("sed -i s/a/b/ .claude/settings.json", R_SELF),
    B("rm zcutil/bin/zcl-agent-guard; rm -rf ~/.zclassic", R_DATADIR),
    B("rm zcutil/bin/zcl-agent-guard && python3 x", R_PYTHON),
    P("Edit", ".claude/settings.json", R_SELF),
    P("Write", ".claude/settings.local.json", R_SELF),
    P("Edit", "zcutil/agent/guard/zcl-agent-guard.c", R_SELF),
    P("Write", "zcutil/agent/guard/gen.py", R_PYTHON),
    P("Edit", "zcutil/bin/zcl-agent-guard", R_SELF),
    P("Edit", ".claude/skills/x/SKILL.md", NULL),
    B("cat .claude/settings.json", NULL),
    B("ls zcutil/agent/guard", NULL),
    B("make -C zcutil/agent/guard check", NULL),
    S("Remove-Item zcutil\\bin\\zcl-agent-guard.exe", R_SELF),

    /* ordinary work stays allowed */
    B("make -C zcutil", NULL),
    B("make -C zcutil check", NULL),
    B("git status --short", NULL),
    B("git log --oneline -5", NULL),
    B("git commit -m 'add the guard' && git log -1", NULL),
    B("grep -rn zclassic src | head", NULL),
    B("find . -name '*.c' | xargs wc -l", NULL),
    B("ls -la; pwd", NULL),
    B("cat <<'EOF' > /tmp/notes.txt\nhello\nEOF", NULL),
    B("sh -c 'make && ./zcutil/bin/zcl-lint'", NULL),
    B("ssh z23-r1 'ls ~/work; df -h /'", NULL),
    B("devbuild --wait make -j8", NULL),
    B("timeout 60 sh test/run.sh", NULL),
    B("x=$(mktemp -d) && cd $x && git init", NULL),
    P("Edit", "zcutil/dev/zcl-dev.c", NULL),
    P("Write", "doc/agent/LESSONS.md", NULL),
    P("Edit", "src/wallet/wallet.cpp", NULL),
    /* heredoc feeding a shell is scanned as commands */
    B("sh <<'EOS'\nrm -rf ~/.zclassic/blocks\nEOS", R_DATADIR),
    B("bash <<EOS\npython3 x\nEOS", R_PYTHON),
    B("ssh z23-r1 sh <<'EOS'\ngit push origin master\nEOS", R_PUSH),
    B("cat <<'EOS'\nrm -rf ~/.zclassic/blocks\nEOS", NULL),
    /* command substitution inside double quotes is code */
    B("echo \"$(rm -rf ~/.zclassic/blocks)\"", R_DATADIR),
    B("echo \"`python3 -V`\"", R_PYTHON),
    B("echo '$(rm -rf ~/.zclassic/blocks)'", NULL),
    /* macOS default datadir and params dir: Library/Application Support/{ZClassic,ZcashParams} */
    B("rm -rf ~/Library/Application\\ Support/ZClassic/wallet.dat", R_DATADIR),
    B("rm -rf \"$HOME/Library/Application Support/ZcashParams\"", R_DATADIR),
    B("mv '/Users/x/Library/Application Support/zclassic' /tmp/old", R_DATADIR),
    P("Write", "/Users/x/Library/Application Support/Zclassic/wallet.dat", R_DATADIR),
    B("rm -rf ~/Library/Application\\ Support/Other", NULL),
    B("rm -rf ~/Library/Caches/ZClassic", NULL),
    P("Edit", "/Users/x/Library/Application Support/Code/settings.json", NULL),
    /* more writers and prefixes that reach a datadir */
    B("unlink ~/.zclassic/wallet.dat", R_DATADIR),
    B("mkdir ~/.zclassic/x", R_DATADIR),
    B("doas rm -rf ~/.zclassic", R_DATADIR),
    B("busybox rm -rf ~/.zclassic", R_DATADIR),
    B("stdbuf -o0 rm -rf ~/.zclassic", R_DATADIR),
    B("setsid rm -rf ~/.zclassic", R_DATADIR),
    B("watch -n 5 rm -rf ~/.zclassic", R_DATADIR),
    B("unzip -o x.zip -d ~/.zclassic", R_DATADIR),
    B("cd ~/.zclassic && unzip -o x.zip", R_DATADIR),
    B("git clean -fdx ~/.zclassic", R_DATADIR),
    B("git rm -r ~/.zclassic", R_DATADIR),
    B("git -C ~/.zclassic clean -fdx", R_DATADIR),
    B("for d in ~/.zclassic; do rm -rf $d; done", R_DATADIR),
    B("for d in ~/.zclassic; do rm -rf \"${d}/blocks\"; done", R_DATADIR),
    B("for d in a b; do rm -rf $d; done", NULL),
    B("unzip x.zip -d /tmp/x", NULL),
    B("git clean -fdx build", NULL),
    B("mkdir -p build/x", NULL),
    /* paths compare case-insensitively and after normalisation */
    P("Write", ".GitHub/Workflows/ci.yml", R_CI),
    P("Write", ".github//workflows/ci.yml", R_CI),
    P("Write", "./.github/./workflows/ci.yml", R_CI),
    P("Edit", "ZCUTIL/TOOLS/VENDOR/x.c", R_VENDOR),
    P("Edit", "zcutil/tools/../tools/vendor/x.c", R_VENDOR),
    P("Edit", "zcutil//tools/vendor/x.c", R_VENDOR),
    P("Edit", "zcutil\\Tools\\Vendor\\x.c", R_VENDOR),
    P("Edit", "SRC/POW.CPP", R_SEAL),
    P("Edit", "src/./script/../pow.cpp", R_SEAL),
    P("Edit", "zcutil/tools/vendor/../x.c", NULL),
    P("Edit", "zcutil/tools/vendorx/y.c", NULL),
    P("Edit", "src/powx.cpp", NULL),
    /* the -regtest hint counts only a -regtest word, not a comment or a path */
    B("C=zclassic-cli; $C dumpwallet /tmp/w # -regtest", R_SPEND),
    B("C=zclassic-cli; ls /tmp/-regtest; $C sendtoaddress t 1", R_SPEND),
    B("C=\"zclassic-cli -regtest -datadir=/tmp/x\"; $C sendtoaddress t 1", NULL),
    /* gh api endpoints that dispatch or rerun a workflow */
    B("gh api repos/a/b/actions/runs/1/rerun -X POST", R_CI),
    B("gh api repos/a/b/actions/runs/1/rerun-failed-jobs -X POST", R_CI),
    B("gh api repos/a/b/dispatches -f event_type=x", R_CI),
    B("gh api repos/a/b/actions/runs", NULL),
    /* PowerShell tool: program rules and PowerShell deleters and writers */
    S("git push --force origin master; python3 x", R_PUSH),
    S("git push origin feature", NULL),
    S("python x.py", R_PYTHON),
    S("pip install x", R_PYTHON),
    S("git config user.name x", R_IDENT),
    S("git commit --author=x -m m", R_IDENT),
    S("$env:GIT_AUTHOR_NAME = \"x\"", R_IDENT),
    S("gh workflow run ci.yml", R_CI),
    S("zclassic-cli sendtoaddress t 1", R_SPEND),
    S("& 'C:\\bin\\zclassic-cli.exe' dumpwallet w", R_SPEND),
    S("zclassic-cli -regtest -datadir=/tmp/x sendtoaddress t 1", NULL),
    S("zclassicd -reindex", R_REINDEX),
    S("zclassicd", R_DATADIR),
    S("Remove-Item -Recurse $env:APPDATA\\ZClassic", R_DATADIR),
    S("Remove-Item -Recurse -Force \"$env:APPDATA\\ZcashParams\"", R_DATADIR),
    S("ri -r ${env:APPDATA}\\Zclassic\\wallet.dat", R_DATADIR),
    S("del $HOME\\.zclassic\\wallet.dat", R_DATADIR),
    S("Remove-Item -Path:$env:USERPROFILE\\.zclassic -Recurse", R_DATADIR),
    S("rd /s /q %APPDATA%\\ZClassic", R_DATADIR),
    S("Move-Item $env:APPDATA\\ZClassic C:\\old", R_DATADIR),
    S("Copy-Item wallet.dat -Destination $env:APPDATA\\ZClassic\\", R_DATADIR),
    S("Copy-Item a.dat $env:APPDATA\\ZClassic\\", R_DATADIR),
    S("Out-File -FilePath x; echo hi > $env:APPDATA\\ZClassic\\a.txt", R_DATADIR),
    S("Set-Content -Path ..\\.github\\workflows\\ci.yml -Value x", R_CI),
    S("\"x\" | Out-File zcutil\\tools\\vendor\\a.c", R_VENDOR),
    S("Set-Content x.py 1", R_PYTHON),
    S("Set-Location $env:APPDATA\\ZClassic; Remove-Item wallet.dat", R_DATADIR),
    S("pwsh -NoProfile -Command \"Remove-Item -Recurse $env:APPDATA\\ZClassic\"", R_DATADIR),
    S("powershell -c 'python x'", R_PYTHON),
    S("iex \"python x\"", R_PYTHON),
    S("cmd /c \"rmdir /s /q %APPDATA%\\ZClassic\"", R_DATADIR),
    S("bash -c \"rm -rf ~/.zclassic\"", R_DATADIR),
    S("Write-Output \"$(Remove-Item -Recurse $env:APPDATA\\ZClassic)\"", R_DATADIR),
    S("Expand-Archive x.zip -DestinationPath $env:APPDATA\\ZClassic", R_DATADIR),
    S("Invoke-WebRequest http://x -OutFile $env:APPDATA\\ZClassic\\a", R_DATADIR),
    S("powershell -EncodedCommand AAAA", R_COMPLEX),
    S("Get-ChildItem $env:APPDATA\\ZClassic", NULL),
    S("Get-Content $env:APPDATA\\ZClassic\\debug.log | Select-Object -Last 5", NULL),
    S("Remove-Item -Recurse build\\tmp", NULL),
    S("Remove-Item old.py", NULL),
    S("Set-Content notes.txt hello", NULL),
    S("Write-Host \"python and Remove-Item are words\"", NULL),
    S("git status", NULL),
    S("Set-Location build; Remove-Item x", NULL),
};


/* A command past a tokeniser cap or the nesting limit must be refused as too complex: a guard
 * that silently drops the tail would allow `rm -rf ~/.zclassic` hidden behind it. */
static char *repeat(const char *unit, size_t times, const char *head, const char *tail)
{
    size_t ul = strlen(unit), hl = strlen(head), tl = strlen(tail);
    char *s = malloc(hl + ul * times + tl + 1);
    if (!s) return NULL;
    memcpy(s, head, hl);
    for (size_t i = 0; i < times; i++) memcpy(s + hl + i * ul, unit, ul);
    memcpy(s + hl + ul * times, tail, tl + 1);
    return s;
}

static int cap_case(const char *name, char *cmd, bool ps, const char *want)
{
    const char *got;
    int bad = 0;
    if (!cmd) {
        printf("FAIL cap %s: out of memory\n", name);
        return 1;
    }
    got = ps ? ag_eval_ps(cmd) : ag_eval_bash(cmd);
    if ((got == NULL) != (want == NULL) || (got && strcmp(got, want) != 0)) {
        printf("FAIL cap %s: want %s got %s\n", name, want ? want : "ALLOW", got ? got : "ALLOW");
        bad = 1;
    }
    free(cmd);
    return bad;
}

static int cap_cases(void)
{
    const char *rm = "rm -rf ~/.zclassic";
    int bad = 0;
    bad += cap_case("segments", repeat("true && ", 3000, "", rm), false, R_COMPLEX);
    bad += cap_case("words", repeat("a ", 20000, "echo ", "; rm -rf ~/.zclassic"), false, R_COMPLEX);
    bad += cap_case("subs", repeat("$(true)", 200, "echo \"", "$(rm -rf ~/.zclassic)\""), false,
                    R_COMPLEX);
    bad += cap_case("redirects", repeat(">/tmp/a ", 700, "echo x ", ">~/.zclassic/w"), false,
                    R_COMPLEX);
    bad += cap_case("heredocs", repeat("<<E ", 6, "cat ", "\nx\nE\nE\nE\nE\nE\nE\n"), false,
                    R_COMPLEX);
    bad += cap_case("nesting", repeat("eval ", 12, "", rm), false, R_COMPLEX);
    bad += cap_case("nesting ps", repeat("iex ", 12, "", "'python x'"), true, R_COMPLEX);
    bad += cap_case("nest ok", repeat("eval ", 3, "", rm), false, R_DATADIR);
    bad += cap_case("many words ok", repeat("a ", 1500, "ls ", ""), false, NULL);
    bad += cap_case("refusal first", repeat("true && ", 3000, "rm -rf ~/.zclassic && ", ""), false,
                    R_DATADIR);
    return bad;
}

/* The guard's sealed list is its own copy of zcutil/consensus.seal (U15). When the seal file is
 * present, every path it lists must warn, so the two cannot drift apart unnoticed. The seal
 * lines are "path<TAB>blob-sha1". Skipped (and said so) when the file is absent. */
static int seal_drift(void)
{
    static const char *const where[] = {"../../consensus.seal", "zcutil/consensus.seal"};
    FILE *f = NULL;
    char line[1024];
    int bad = 0;
    long n = 0;
    for (size_t i = 0; !f && i < sizeof where / sizeof where[0]; i++) f = fopen(where[i], "r");
    if (!f) {
        printf("agent-guard selftest: no consensus.seal here, seal drift check skipped\n");
        return 0;
    }
    while (fgets(line, sizeof line, f)) {
        char *tab = strchr(line, '\t');
        const char *got;
        if (line[0] == '#' || !tab) continue;
        *tab = '\0';
        n++;
        got = ag_eval_path("Edit", line, NULL);
        if (!got || strcmp(got, R_SEAL) != 0) {
            printf("FAIL seal drift: %s is sealed but the guard gives %s\n", line,
                   got ? got : "ALLOW");
            bad++;
        }
    }
    fclose(f);
    if (n == 0) {
        printf("FAIL seal drift: consensus.seal lists no paths\n");
        bad++;
    }
    return bad;
}

int main(void)
{
    int bad = cap_cases() + seal_drift();
    size_t n = sizeof cases / sizeof cases[0];
    size_t allow = 0, refuse = 0, warn = 0;
    for (size_t i = 0; i < n; i++) {
        const struct tcase *c = &cases[i];
        const char *got = c->kind == 'B'   ? ag_eval_bash(c->input)
                          : c->kind == 'S' ? ag_eval_ps(c->input)
                                         : ag_eval_path(c->tool, c->input, c->extra);
        if (!c->want) allow++;
        else if (ag_rule_is_warning(c->want)) warn++;
        else refuse++;
        if ((got == NULL) != (c->want == NULL) || (got && strcmp(got, c->want) != 0)) {
            printf("FAIL case %zu: %s %s\n  want %s got %s\n", i,
                   c->kind == 'B' ? "bash" : c->kind == 'S' ? "ps" : c->tool, c->input,
                   c->want ? c->want : "ALLOW",
                   got ? got : "ALLOW");
            bad++;
        }
    }
    if (allow < 30 || refuse < 30) {
        printf("FAIL: table too small (%zu allow, %zu refuse)\n", allow, refuse);
        return 1;
    }
    printf("agent-guard selftest: %zu cases (%zu allow, %zu refuse, %zu warn), %d failed\n", n,
           allow, refuse, warn, bad);
    return bad ? 1 : 0;
}
