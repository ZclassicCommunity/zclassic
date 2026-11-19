#!/bin/sh
# Test-isolation reaper. Started detached (own session) by isolation.sh; waits for
# its owner script to exit by ANY means (normal exit, trap, kill -9, timeout), then
# kills what the script started and releases its port leases.
# usage: iso-reaper.sh <owner-pid> <tag> <registry-file> <zcl-port|-> <port-owner>
# What it kills: pids/groups in the registry (start_node), and every process whose
# environment carries ZCL_ISO_TAG=<tag> (Linux /proc, macOS ps -E): the daemons of
# THIS script run only, including -daemon ones that left the process group.
owner=$1; tag=$2; reg=$3; zp=$4; powner=$5
me=$$
while kill -0 "$owner" 2>/dev/null; do sleep 0.25 2>/dev/null || sleep 1; done
case $(uname -s) in MINGW*|MSYS*|CYGWIN*) win=1 ;; *) win=0 ;; esac
killpid() {
    [ "$1" = "$me" ] && return 0
    if [ $win = 1 ]; then
        w=$(cat "/proc/$1/winpid" 2>/dev/null || echo "$1")
        taskkill //F //T //PID "$w" >/dev/null 2>&1
    else
        kill -9 -- "-$1" 2>/dev/null
    fi
    kill -9 "$1" 2>/dev/null
    return 0
}
if [ -f "$reg" ]; then
    while read -r p; do [ -n "$p" ] && killpid "$p"; done <"$reg"
    rm -f "$reg"
fi
if [ -d /proc/self ] && [ $win = 0 ]; then
    for f in $(grep -l -a -z -x "ZCL_ISO_TAG=$tag" /proc/[0-9]*/environ 2>/dev/null); do
        p=${f#/proc/}; killpid "${p%/environ}"
    done
elif [ $win = 0 ]; then
    for p in $(ps -axwwE -o pid=,command= 2>/dev/null | grep -F " ZCL_ISO_TAG=$tag" | awk '{print $1}'); do
        killpid "$p"
    done
fi
[ "$zp" != - ] && "$zp" release --owner "$powner" >/dev/null 2>&1
exit 0
