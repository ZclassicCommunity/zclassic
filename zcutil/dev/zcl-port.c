/* zcl-port: collision-free TCP port leases for test scripts.
 *
 *   zcl-port lease <count> [--block] [--dir D] [--owner PID] [--range LO-HI]
 *   zcl-port release [--dir D] [--owner PID] [PORT ...]
 *   zcl-port list [--dir D]
 *
 * lease prints <count> ports, one per line (consecutive with --block), each
 * (a) bindable on 127.0.0.1 and 0.0.0.0 right now (SO_REUSEADDR off) and (b)
 * not leased by a live owner. A lease is one file <dir>/<port> holding
 * "owner start", created with O_EXCL, so two concurrent callers never get
 * the same port. A lease whose owner pid is dead (or over a day old) is
 * reclaimed, so a script that passes --owner $$ needs no cleanup trap.
 * Default range 20000-32000: below every OS ephemeral range and above the
 * node ports (8023, 8033, 8232, 8233, 18xxx). Override: --range or env
 * ZCL_PORT_RANGE=LO-HI. Default dir: <tmp>/zcl-port-<user> (env ZCL_PORT_DIR).
 * Plain C (gnu17), libc + sockets, POSIX and winsock.
 * Exit: 0 ok, 1 no free ports, 2 usage or I/O error. */
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <direct.h>
#include <io.h>
#define MKDIR(p) _mkdir(p)
#define SEP "\\"
#else
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <dirent.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#define MKDIR(p) mkdir((p), 0700)
#define SEP "/"
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef _WIN32
#define PID_SELF GetCurrentProcessId()
#else
#define PID_SELF getpid()
#endif
#define MAX_AGE_S (24L * 3600L)
#define GARBLED_AGE_S 60L

static char dir[512];
static long range_lo = 20000, range_hi = 32000;
static long owner_pid;
static unsigned long long rng = 88172645463325252ULL;

static unsigned long long next_rand(void)
{
    rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
    return rng;
}

static int pid_alive(long pid)
{
    if (pid <= 0) return 0;
#ifdef _WIN32
    DWORD code = 0;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    int alive;
    if (!h) return GetLastError() == ERROR_ACCESS_DENIED;
    alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
#else
    return kill((pid_t)pid, 0) == 0 || errno == EPERM;
#endif
}

/* Bind-and-close on 127.0.0.1 and 0.0.0.0, SO_REUSEADDR off. */
static int port_bindable(int port)
{
    static const unsigned long addrs[2] = { 0x7f000001UL, 0UL };
    for (int i = 0; i < 2; i++) {
        struct sockaddr_in sa;
        int ok;
#ifdef _WIN32
        SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
        BOOL one = TRUE;
        if (s == INVALID_SOCKET) return 0;
        setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&one, sizeof one);
#else
        int s = socket(AF_INET, SOCK_STREAM, 0);
        if (s < 0) return 0;
#endif
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl((unsigned long)addrs[i]);
        sa.sin_port = htons((unsigned short)port);
        ok = bind(s, (struct sockaddr *)&sa, (int)sizeof sa) == 0;
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
        if (!ok) return 0;
    }
    return 1;
}

static void lease_path(char *out, size_t cap, long port)
{
    snprintf(out, cap, "%s" SEP "%ld", dir, port);
}

/* Read "owner start". Returns 1 parsed, 0 unreadable or garbled (mtime in
 * *mt so the caller can age an empty file left by a crashed writer). */
static int read_lease(const char *path, long *owner, long *start, long *mt)
{
    struct stat st;
    char buf[64] = "";
    FILE *f;
    *owner = *start = 0;
    if (stat(path, &st) != 0) return -1;
    *mt = (long)st.st_mtime;
    f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(buf, sizeof buf, f)) buf[0] = 0;
    fclose(f);
    return sscanf(buf, "%ld %ld", owner, start) == 2 && *owner > 0;
}

/* 1 = removed a stale lease (caller may retry), 0 = live or gone. Rename
 * first so that of two racing reclaimers only one wins; if what we moved is
 * not what we judged stale, put it back. */
static int reclaim_if_stale(const char *path)
{
    long o, s, mt, o2, s2, mt2;
    char tmp[700];
    long now = (long)time(NULL);
    int rc = read_lease(path, &o, &s, &mt);
    if (rc < 0) return 1; /* vanished: retry the create */
    if (rc == 1 ? (pid_alive(o) && now - s < MAX_AGE_S) : now - mt < GARBLED_AGE_S)
        return 0;
    snprintf(tmp, sizeof tmp, "%s.rm%ld", path, (long)PID_SELF);
    if (rename(path, tmp) != 0) return 1;
    rc = read_lease(tmp, &o2, &s2, &mt2);
    if (rc >= 0 && (o2 != o || s2 != s)) { /* a fresh lease slipped in: restore it */
#ifdef _WIN32
        if (rename(tmp, path) != 0) remove(tmp);
#else
        if (link(tmp, path) != 0) { /* someone re-took it: theirs wins */ }
        remove(tmp);
#endif
        return 0;
    }
    remove(tmp);
    return 1;
}

static int take(long port)
{
    char path[600], body[64];
    int fd, tries;
    lease_path(path, sizeof path, port);
    for (tries = 0; tries < 2; tries++) {
        fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd >= 0) break;
        if (errno != EEXIST || !reclaim_if_stale(path)) return -1;
    }
    if (fd < 0) return -1;
    snprintf(body, sizeof body, "%ld %ld\n", owner_pid, (long)time(NULL));
    if (write(fd, body, strlen(body)) < 0) { /* empty lease ages out */ }
    close(fd);
    if (!port_bindable((int)port)) { remove(path); return -1; }
    return 0;
}

static void drop_ports(const long *ports, long n)
{
    char p[600];
    for (long i = 0; i < n; i++) { lease_path(p, sizeof p, ports[i]); remove(p); }
}

static int cmd_lease(long count, int block)
{
    long span = range_hi - range_lo + 1, tried, got = 0, base, cand, j;
    long ports[4096];
    if (count < 1 || count > 4096 || count > span) { fprintf(stderr, "zcl-port: bad count\n"); return 2; }
    base = (long)(next_rand() % (unsigned long long)span);
    for (tried = 0; tried < span && got < count; tried++) {
        cand = range_lo + (base + tried) % span;
        if (!block) { if (take(cand) == 0) ports[got++] = cand; continue; }
        if (cand + count - 1 > range_hi) continue;
        for (j = 0; j < count && take(cand + j) == 0; j++) ports[j] = cand + j;
        if (j == count) got = count; else drop_ports(ports, j);
    }
    if (got < count) {
        if (!block) drop_ports(ports, got);
        fprintf(stderr, "zcl-port: no %s%ld free ports in %ld-%ld\n", block ? "block of " : "", count, range_lo, range_hi);
        return 1;
    }
    for (long i = 0; i < got; i++) printf("%ld\n", ports[i]);
    return 0;
}

/* Visit every lease file in dir: fn(port, owner, start). */
static void each_lease(void (*fn)(long, long, long, void *), void *arg)
{
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    char pat[600];
    HANDLE h;
    snprintf(pat, sizeof pat, "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        const char *name = fd.cFileName;
#else
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d)) != NULL) {
        const char *name = e->d_name;
#endif
        char *end;
        long port = strtol(name, &end, 10), o, s, mt;
        char path[600];
        if (*name && !*end && port > 0) {
            lease_path(path, sizeof path, port);
            if (read_lease(path, &o, &s, &mt) >= 0) fn(port, o, s, arg);
        }
#ifdef _WIN32
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    }
    closedir(d);
#endif
}

static void print_one(long port, long o, long s, void *arg)
{
    (void)arg;
    printf("%ld owner=%ld start=%ld %s\n", port, o, s, pid_alive(o) ? "live" : "stale");
}

static void drop_owner(long port, long o, long s, void *arg)
{
    char p[600];
    (void)s;
    if (o == *(long *)arg) { lease_path(p, sizeof p, port); remove(p); }
}

static void ensure_dir(char *p)
{
    for (char *c = p + 1; *c; c++)
        if (*c == '/' || *c == '\\') { char k = *c; *c = 0; MKDIR(p); *c = k; }
    MKDIR(p);
}

static void default_dir(void)
{
    const char *d = getenv("ZCL_PORT_DIR"), *t;
    char user[64];
    if (d && *d) { snprintf(dir, sizeof dir, "%s", d); return; }
    t = getenv("TMPDIR"); if (!t || !*t) t = getenv("TEMP"); if (!t || !*t) t = "/tmp";
#ifdef _WIN32
    { const char *u = getenv("USERNAME"); snprintf(user, sizeof user, "%s", u ? u : "u"); }
#else
    snprintf(user, sizeof user, "%ld", (long)getuid());
#endif
    snprintf(dir, sizeof dir, "%s" SEP "zcl-port-%s", t, user);
}

int main(int argc, char **argv)
{
    const char *cmd, *r;
    char *pos[64];
    int npos = 0, block = 0, have_owner = 0;
    if (argc < 2) goto usage;
    cmd = argv[1];
    default_dir();
    r = getenv("ZCL_PORT_RANGE");
    if (r) sscanf(r, "%ld-%ld", &range_lo, &range_hi);
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--block")) block = 1;
        else if (!strcmp(argv[i], "--dir") && i + 1 < argc) snprintf(dir, sizeof dir, "%s", argv[++i]);
        else if (!strcmp(argv[i], "--owner") && i + 1 < argc) { owner_pid = atol(argv[++i]); have_owner = 1; }
        else if (!strcmp(argv[i], "--range") && i + 1 < argc) sscanf(argv[++i], "%ld-%ld", &range_lo, &range_hi);
        else if (argv[i][0] != '-' && npos < 64) pos[npos++] = argv[i];
        else goto usage;
    }
    if (range_lo < 1024 || range_hi > 65535 || range_lo > range_hi) { fprintf(stderr, "zcl-port: bad range\n"); return 2; }
#ifdef _WIN32
    { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); }
    if (!have_owner) owner_pid = (long)GetCurrentProcessId();
    rng ^= (unsigned long long)GetCurrentProcessId() * 2654435761ULL ^ ((unsigned long long)time(NULL) << 20) ^ (unsigned long long)GetTickCount();
#else
    if (!have_owner) owner_pid = (long)getppid();
    { struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
      rng ^= ((unsigned long long)getpid() * 2654435761ULL) ^ ((unsigned long long)ts.tv_nsec << 20) ^ (unsigned long long)ts.tv_sec; }
#endif
    for (int i = 0; i < 8; i++) next_rand();
    ensure_dir(dir);
    if (!strcmp(cmd, "lease") && npos == 1) return cmd_lease(atol(pos[0]), block);
    if (!strcmp(cmd, "list") && npos == 0) { each_lease(print_one, NULL); return 0; }
    if (!strcmp(cmd, "release")) {
        if (have_owner && npos == 0) each_lease(drop_owner, &owner_pid);
        else if (npos > 0) for (int i = 0; i < npos; i++) { char p[600]; lease_path(p, sizeof p, atol(pos[i])); remove(p); }
        else goto usage;
        return 0;
    }
usage:
    fprintf(stderr, "usage: zcl-port lease <count> [--block] [--dir D] [--owner PID] [--range LO-HI]\n"
                    "       zcl-port release [--dir D] [--owner PID | PORT ...]\n"
                    "       zcl-port list [--dir D]\n");
    return 2;
}
