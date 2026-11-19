#!/bin/sh
# Inspect an `strace -f -e trace=network,clone,clone3,execve` log of a node
# that runs with -embeddedtor -onlynet=onion.
#
#   sh privacy_check.sh <strace log> [debug.log]
#
# Threads are split in two sets. Tor's set is the thread (or child process)
# that binds a loopback listener on port 0 (Tor's "127.0.0.1:auto" Socks and
# control ports; the daemon never binds port 0) and everything it creates.
# Every other thread belongs to the daemon and must:
#   - connect, bind and send only to loopback addresses,
#   - never touch port 53 (system resolver, including 127.0.0.53),
#   - never reach a running nscd (the other route getaddrinfo takes); a probe
#     of an absent nscd socket is counted and allowed.
# Tor's threads may reach the Tor network (some relays have their ORPort on
# 53), but never a system resolver (127.0.0.53 or a nameserver listed in
# /etc/resolv.conf) or nscd.
# Exit status 0 when all of that holds and Tor's set did connect out.
set -u
LOG=${1:?strace log}
DBG=${2:-}
RESOLVERS="127.0.0.53 $(awk '$1 == "nameserver" { printf "%s ", $2 }' /etc/resolv.conf 2>/dev/null)"
awk -v resolvers=" $RESOLVERS " '
function tid_of(line) { return line + 0 }
function is_tor(t,    g) {
    g = 0
    while (t != "" && g < 64) {
        if (t in root) return 1
        t = parent[t]; g++
    }
    return 0
}
{
    t = $1 + 0
    # thread and process creation: "... clone(...) = 123" / "<... clone3 resumed> ...) = 123"
    if ($0 ~ /clone3?[(]/ || $0 ~ /clone3? resumed/ || $0 ~ /v?fork[(]/ || $0 ~ /fork resumed/) {
        if ($0 ~ /= [0-9]+$/) { c = $NF + 0; if (c > 0 && !(c in parent)) parent[c] = t }
        next
    }
    if ($0 ~ /bind[(].*AF_INET, sin_port=htons[(]0[)], sin_addr=inet_addr[(]"127[.]0[.]0[.]1"[)]/) root[t] = 1
    if ($0 ~ /execve[(].*--zcl-embedded-tor/) root[t] = 1
    n++; line[n] = $0; who[n] = t
}
END {
    bad = 0
    for (i = 1; i <= n; i++) {
        l = line[i]; tor = is_tor(who[i])
        if (l !~ /(connect|bind|sendto|sendmsg|sendmmsg)[(]/) continue
        if (l ~ /sa_family=AF_NETLINK/) { netlink++; continue }
        if (l ~ /nscd/) {
            # glibc tries nscd for any getaddrinfo, numeric ones included (the
            # RPC server binding 127.0.0.1 does one). With no nscd on the host
            # the attempt fails and nothing left the process; a real lookup
            # then shows up below as port 53. A reachable nscd could resolve
            # on the process behalf, unseen here, so that case is a failure.
            if (l ~ /ENOENT|ECONNREFUSED/) { nscdmiss++; continue }
            printf "LEAK lookup handed to nscd: %s\n", l; bad++; continue
        }
        if (l ~ /sin6?_port=htons[(]53[)]/) {
            dst = l
            sub(/.*(inet_addr[(]"|inet_pton[(]AF_INET6, ")/, "", dst)
            sub(/".*/, "", dst)
            sub(/^::ffff:/, "", dst)
            if (!tor || index(resolvers, " " dst " ") > 0) { printf "LEAK port 53: %s\n", l; bad++; continue }
            torport53++
        }
        if (l ~ /sa_family=AF_UNIX/) { if (tor) torunix++; else { daemonunix++; printf "NOTE daemon unix socket: %s\n", l }; continue }
        if (l !~ /sa_family=AF_INET6?/) continue
        loop = (l ~ /inet_addr[(]"127[.]/ || l ~ /inet_pton[(]AF_INET6, "::1"/ || l ~ /"::ffff:127[.]/)
        if (tor) { if (loop) torloop++; else torext++; continue }
        if (loop) { daemonloop++; continue }
        printf "LEAK daemon thread reaches a non-loopback address: %s\n", l
        bad++
    }
    nroot = 0; for (r in root) nroot++
    printf "strace: %d network calls; Tor thread set roots=%d; daemon loopback calls=%d; Tor loopback calls=%d; Tor outbound calls=%d; netlink=%d; failed nscd probes=%d; Tor relay connects on port 53=%d; leaks=%d\n", n, nroot, daemonloop + 0, torloop + 0, torext + 0, netlink + 0, nscdmiss + 0, torport53 + 0, bad
    if (nroot == 0) { print "FAIL no Tor thread set found in the trace"; exit 1 }
    if (torext + 0 == 0) { print "FAIL Tor made no outbound connection (trace incomplete?)"; exit 1 }
    exit bad ? 1 : 0
}' "$LOG"
rc=$?
if [ -n "$DBG" ] && [ -f "$DBG" ]; then
    # The daemon's own view: every peer connection attempt in debug.log must
    # have gone to an onion address or a name handed to the proxy.
    n=$(grep -c 'trying connection' "$DBG" 2>/dev/null)
    printf 'debug.log: %s outbound connection attempt(s): %s\n' "$n" \
        "$(grep -o 'trying connection [^ ]*' "$DBG" | sort | uniq -c | tr '\n' ';')"
fi
exit $rc
