# Test isolation (sourced; POSIX sh; set -eu safe). One source line gives a script:
#   - lease_ports / iso_base: collision-free port blocks from zcl-port (no $$ guesses);
#   - start_node / kill_node: daemons in their own process group (zcl-run: setsid on
#     POSIX, a kill-on-close Job Object on Windows);
#   - a detached reaper that, when the script ends for ANY reason (including kill -9),
#     kills everything the script started and frees its leases.
# Explicit overrides still win: iso_base keeps a base given by --base / env.
# Tools build on first use into zcutil/bin (git-ignored) with the host cc; ZCL_ISO_BIN
# overrides the directory, ZCL_ISO_NOREAP=1 turns the reaper off.

case $(uname -s) in MINGW*|MSYS*|CYGWIN*) ISO_WIN=1; ISO_EXE=.exe ;; *) ISO_WIN=0; ISO_EXE= ;; esac

iso_find_root() {
    _d=$(cd "$(dirname "$0")" && pwd) || return 1
    _n=0
    while [ $_n -lt 8 ] && [ -n "$_d" ]; do
        if [ -f "$_d/zcutil/dev/zcl-port.c" ]; then printf '%s\n' "$_d"; return 0; fi
        _d=$(dirname "$_d"); _n=$((_n + 1))
    done
    return 1
}

# iso_cc <out> <src> [cc args...]: build once, atomically (parallel first uses are safe)
iso_cc() {
    _out=$1; _src=$2; shift 2
    if [ -x "$_out" ] && [ ! "$_src" -nt "$_out" ]; then return 0; fi
    mkdir -p "$(dirname "$_out")" || return 1
    _tmp=$_out.tmp.$$
    if ! ${CC:-cc} -std=gnu17 -O2 -o "$_tmp" "$_src" "$@" >/dev/null 2>"$_tmp.err"; then
        echo "isolation: cannot build $_out: $(head -n 3 "$_tmp.err" | tr '\n' ' ')" >&2
        rm -f "$_tmp" "$_tmp.err"; return 1
    fi
    rm -f "$_tmp.err"; mv -f "$_tmp" "$_out"
}

ISO_ROOT=$(iso_find_root) || ISO_ROOT=
ISO_BIN=${ZCL_ISO_BIN:-${ISO_ROOT:+$ISO_ROOT/zcutil/bin}}
ZCL_PORT=; ZCL_RUN=
if [ -n "$ISO_ROOT" ]; then
    _xl=; [ $ISO_WIN = 1 ] && _xl=-lws2_32
    if iso_cc "$ISO_BIN/zcl-port$ISO_EXE" "$ISO_ROOT/zcutil/dev/zcl-port.c" $_xl; then ZCL_PORT=$ISO_BIN/zcl-port$ISO_EXE; fi
    if iso_cc "$ISO_BIN/zcl-run$ISO_EXE" "$ISO_ROOT/zcutil/tools/vendor/tools/process_group_exec.c" -include stdbool.h; then
        ZCL_RUN=$ISO_BIN/zcl-run$ISO_EXE
    fi
fi
[ -n "$ZCL_RUN" ] || echo "isolation: zcl-run unavailable; daemons will not get their own process group" >&2

# The owner pid in the lease files: on Windows the native pid behind this shell.
ISO_OWNER=$$
[ $ISO_WIN = 1 ] && ISO_OWNER=$(cat "/proc/$$/winpid" 2>/dev/null || echo $$)
ISO_TAG=$$.$(date +%s)
ZCL_ISO_TAG=$ISO_TAG; export ZCL_ISO_TAG
ISO_REG=${TMPDIR:-/tmp}/zcl-iso-reg.$ISO_TAG

# Windows Git Bash: a POSIX kill -9 does not terminate a native process. Route SIGKILL
# requests (kill -9 / -KILL <pid>...) through taskkill /T, which also takes the
# process's children; everything else is the shell builtin.
if [ $ISO_WIN = 1 ]; then
    kill() {
        case ${1:-} in
            -9|-KILL|-SIGKILL)
                shift
                for _kp in "$@"; do
                    _kw=$(cat "/proc/$_kp/winpid" 2>/dev/null || echo "$_kp")
                    taskkill //F //T //PID "$_kw" >/dev/null 2>&1
                    builtin kill -9 "$_kp" 2>/dev/null
                done
                return 0 ;;
            *) builtin kill "$@" ;;
        esac
    }
fi

# lease_ports <count>: print the first port of a free block of <count> consecutive ports
lease_ports() {
    if [ -z "$ZCL_PORT" ]; then
        echo "isolation: zcl-port is not built (needs a C compiler: cc zcutil/dev/zcl-port.c); pass an explicit --base" >&2
        return 1
    fi
    _lp=$("$ZCL_PORT" lease "${1:-16}" --block --owner "$ISO_OWNER") || return 1
    printf '%s\n' "$_lp" | head -n 1
}

# release_ports <base> <count>
release_ports() {
    [ -n "$ZCL_PORT" ] || return 0
    "$ZCL_PORT" release $(awk -v b="$1" -v n="$2" 'BEGIN { for (i = 0; i < n; i++) print b + i }') >/dev/null 2>&1
    return 0
}

# iso_base <var> <explicit> <count>: <var> = the explicit base if one was given
# (--base, env), else a leased block. Exits the script (2) when no block is free.
iso_base() {
    if [ -n "$2" ]; then _ib=$2; eval "ISO_LEASED_$1=0"
    else _ib=$(lease_ports "$3") || exit 2; eval "ISO_LEASED_$1=1"; fi
    eval "$1=\$_ib"
}

# iso_rebase <var> <count> <step>: a fresh port block for the next scenario. A leased
# base is released and re-leased; an explicit base moves by <step> as before.
iso_rebase() {
    eval "_irb=\$$1; _irl=\${ISO_LEASED_$1:-0}"
    if [ "$_irl" = 1 ]; then
        release_ports "$_irb" "$2"
        _irb=$(lease_ports "$2") || exit 2
    else
        _irb=$((_irb + $3)); [ "$_irb" -lt 60000 ] || _irb=20000
    fi
    eval "$1=\$_irb"
}

# start_node <logfile> <cmd> [args...]: run in the background in its own process group
# (own Job Object on Windows), stdout+stderr appended to <logfile>. Sets ISO_PID.
start_node() {
    _sl=$1; shift
    $ZCL_RUN "$@" >>"$_sl" 2>&1 &
    ISO_PID=$!
    echo "$ISO_PID" >>"$ISO_REG"
}

# kill_node <pid>: SIGKILL the node and its whole process group, on every platform.
kill_node() {
    if [ $ISO_WIN = 1 ]; then
        _kw=$(cat "/proc/$1/winpid" 2>/dev/null || echo "$1")
        taskkill //F //T //PID "$_kw" >/dev/null 2>&1
        builtin kill -9 "$1" 2>/dev/null
    else
        command kill -9 -- "-$1" 2>/dev/null
        command kill -9 "$1" 2>/dev/null
    fi
    return 0
}

# Detached reaper: its own session (zcl-run), no inherited stdio, double-forked so
# the script's own `wait` never sees it.
if [ -z "${ZCL_ISO_NOREAP:-}" ] && [ -n "$ISO_ROOT" ]; then
    ( $ZCL_RUN sh "$ISO_ROOT/qa/lib/iso-reaper.sh" "$$" "$ISO_TAG" "$ISO_REG" "${ZCL_PORT:--}" "$ISO_OWNER" \
        </dev/null >/dev/null 2>&1 & )
fi
