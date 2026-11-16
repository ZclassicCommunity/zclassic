/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * zcl_tor_selftest: standalone proof program for zcl_tor_embed and keyfile.
 * Linux only (reads /proc for the socket and process checks).
 *
 *   zcl_tor_selftest offline    DisableNetwork runs, no network is touched
 *   zcl_tor_selftest orphan     kill -9 the parent, the Tor child must exit
 *   zcl_tor_selftest online     bootstrap, publish an onion service, reach it
 *   zcl_tor_selftest inproc     Tor on a thread of this process (DisableNetwork)
 *   zcl_tor_selftest all        offline + orphan + inproc (not online)
 *
 * All state lives in a fresh temporary directory that is removed at the end.
 * The binary is its own Tor child (zcl_tor_embed_dispatch runs first). */
#define _GNU_SOURCE 1
#include "keyfile.h"
#include "zcl_tor_embed.h"
#include "zcl_tor_proc.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

extern char **environ;

static int g_fail;
static int g_pass;

static void check(bool ok, const char *fmt, ...)
{
    va_list ap;
    char msg[512];
    va_start(ap, fmt);
    (void)vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (ok)
        g_pass++;
    else
        g_fail++;
    (void)printf("%s %s\n", ok ? "PASS" : "FAIL", msg);
    (void)fflush(stdout);
}

/* ------------------------------------------------------------ temp dirs */

static int rm_cb(const char *p, const struct stat *sb, int flag, struct FTW *f)
{
    (void)sb;
    (void)f;
    if (flag == FTW_DP || flag == FTW_D)
        (void)rmdir(p);
    else
        (void)unlink(p);
    return 0;
}

static void rm_rf(const char *path, const char *must_contain)
{
    if (!strstr(path, must_contain))
        return; /* never remove anything we did not create */
    (void)nftw(path, rm_cb, 16, FTW_DEPTH | FTW_PHYS);
}

static int make_tmp(char *out, size_t cap)
{
    const char *base = getenv("TMPDIR");
    int n;
    if (!base || !base[0])
        base = "/tmp";
    n = snprintf(out, cap, "%s/zcltor-selftest.XXXXXX", base);
    if (n < 0 || (size_t)n >= cap || !mkdtemp(out)) {
        (void)fprintf(stderr, "cannot create temp dir: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------- /proc checks */

static bool pid_gone(long pid)
{
    char p[64], buf[512];
    FILE *f;
    int n;
    n = snprintf(p, sizeof(p), "/proc/%ld/stat", pid);
    if (n < 0)
        return false;
    f = fopen(p, "r");
    if (!f)
        return true;
    if (!fgets(buf, sizeof(buf), f)) {
        (void)fclose(f);
        return true;
    }
    (void)fclose(f);
    {
        const char *r = strrchr(buf, ')');
        return r && r[1] == ' ' && r[2] == 'Z'; /* zombie counts as gone */
    }
}

static long ppid_of(long pid)
{
    char p[64], buf[512];
    FILE *f;
    const char *r;
    int st;
    long pp = -1;
    (void)snprintf(p, sizeof(p), "/proc/%ld/stat", pid);
    f = fopen(p, "r");
    if (!f)
        return -1;
    if (fgets(buf, sizeof(buf), f) && (r = strrchr(buf, ')')) != NULL) {
        char state;
        if (sscanf(r + 1, " %c %ld", &state, &pp) != 2)
            pp = -1;
        (void)st;
    }
    (void)fclose(f);
    return pp;
}

static bool addr_is_loopback(const char *hex)
{
    size_t n = strlen(hex);
    if (n == 8) {
        uint32_t v = (uint32_t)strtoul(hex, NULL, 16);
        unsigned char b[4];
        memcpy(b, &v, 4);
        return b[0] == 127;
    }
    if (n == 32) {
        uint32_t w[4];
        unsigned char b[4];
        char t[9];
        int i;
        for (i = 0; i < 4; i++) {
            memcpy(t, hex + 8 * i, 8);
            t[8] = '\0';
            w[i] = (uint32_t)strtoul(t, NULL, 16);
        }
        memcpy(b, &w[3], 4);
        return w[0] == 0 && w[1] == 0 && w[2] == 0 && b[0] == 0 && b[1] == 0 &&
               b[2] == 0 && b[3] == 1;
    }
    return false;
}

#define MAXSOCK 8192

static int child_socket_inodes(long pid, unsigned long *ino, int cap)
{
    char dir[64], link[384], tgt[128];
    DIR *d;
    struct dirent *e;
    int n = 0;
    (void)snprintf(dir, sizeof(dir), "/proc/%ld/fd", pid);
    d = opendir(dir);
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL && n < cap) {
        ssize_t r;
        unsigned long v;
        if (e->d_name[0] == '.')
            continue;
        (void)snprintf(link, sizeof(link), "%s/%s", dir, e->d_name);
        r = readlink(link, tgt, sizeof(tgt) - 1);
        if (r <= 0)
            continue;
        tgt[r] = '\0';
        if (sscanf(tgt, "socket:[%lu]", &v) == 1)
            ino[n++] = v;
    }
    (void)closedir(d);
    return n;
}

/* Returns the number of violations. A violation is a listening TCP socket or
 * a UDP socket of the child that is not bound to loopback, and, unless
 * allow_outbound, a TCP socket with a non-loopback remote end. *nlisten gets
 * the number of loopback TCP listeners; *has_port is set when a listener is
 * on `want_port`. */
static int check_sockets(long pid, uint16_t want_port, bool allow_outbound,
                         int *nlisten, bool *has_port)
{
    static const char *const files[] = {"/proc/net/tcp", "/proc/net/tcp6",
                                        "/proc/net/udp", "/proc/net/udp6"};
    unsigned long ino[MAXSOCK];
    int nino = child_socket_inodes(pid, ino, MAXSOCK);
    int viol = 0, f;
    *nlisten = 0;
    *has_port = false;
    if (nino < 0) {
        (void)printf("  cannot read /proc/%ld/fd\n", pid);
        return 1;
    }
    for (f = 0; f < 4; f++) {
        FILE *fp = fopen(files[f], "r");
        char line[512];
        bool tcp = f < 2;
        if (!fp) {
            (void)printf("  cannot read %s\n", files[f]);
            viol++;
            continue;
        }
        if (!fgets(line, sizeof(line), fp)) { /* header */
            (void)fclose(fp);
            continue;
        }
        while (fgets(line, sizeof(line), fp)) {
            char la[64], ra[64];
            unsigned lp, rp, st;
            unsigned long inode;
            int i;
            bool mine = false;
            if (sscanf(line, " %*d: %63[0-9A-Fa-f]:%x %63[0-9A-Fa-f]:%x %x %*s %*s %*s %*d %*d %lu",
                       la, &lp, ra, &rp, &st, &inode) != 6)
                continue;
            for (i = 0; i < nino; i++) {
                if (ino[i] == inode) {
                    mine = true;
                    break;
                }
            }
            if (!mine)
                continue;
            if (tcp && st == 0x0A) {
                if (!addr_is_loopback(la)) {
                    (void)printf("  VIOLATION non-loopback TCP listener %s:%u\n", la, lp);
                    viol++;
                } else {
                    (*nlisten)++;
                    if (lp == want_port)
                        *has_port = true;
                }
            } else if (!tcp) {
                if (!addr_is_loopback(la)) {
                    (void)printf("  VIOLATION UDP socket on non-loopback %s:%u\n", la, lp);
                    viol++;
                }
            } else if (!allow_outbound && !addr_is_loopback(ra) && st != 0x07 /*CLOSE*/) {
                (void)printf("  VIOLATION TCP connection to non-loopback remote %s:%u\n", ra, rp);
                viol++;
            }
        }
        (void)fclose(fp);
    }
    return viol;
}

/* ----------------------------------------------------------- helpers */

static bool file_mode_is(const char *path, mode_t want)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    return (st.st_mode & 07777) == want;
}

static bool extract_value(const char *reply, const char *key, char *out, size_t cap)
{
    const char *p = strstr(reply, key);
    size_t n = 0;
    if (!p)
        return false;
    p += strlen(key);
    while (p[n] && p[n] != '\r' && p[n] != '\n' && p[n] != ' ')
        n++;
    if (n == 0 || n >= cap)
        return false;
    memcpy(out, p, n);
    out[n] = '\0';
    return true;
}

static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--)
        *v++ = 0;
}

/* -------------------------------------------------------- keyfile tests */

static void test_keyfile(const char *dir)
{
    char p[1100], err[256] = "", buf[64];
    size_t got = 0;
    FILE *f;
    int rc;

    (void)snprintf(p, sizeof(p), "%s/secret.key", dir);
    /* pre-existing loose file with other content */
    f = fopen(p, "w");
    if (f) {
        (void)fputs("old-loose-content", f);
        (void)fclose(f);
    }
    (void)chmod(p, 0666);
    check(file_mode_is(p, 0666), "keyfile: fixture starts as 0666");
    rc = zcl_keyfile_tighten(p, err, sizeof(err));
    check(rc == 0 && file_mode_is(p, 0600), "keyfile: tighten 0666 -> 0600 (rc=%d %s)", rc, err);
    (void)chmod(p, 0644);
    rc = zcl_keyfile_write(p, "new-secret", 10, err, sizeof(err));
    check(rc == 0 && file_mode_is(p, 0600), "keyfile: atomic write replaces a 0644 file and result is 0600 (rc=%d %s)", rc, err);
    rc = zcl_keyfile_read(p, buf, sizeof(buf), &got, err, sizeof(err));
    check(rc == 0 && got == 10 && memcmp(buf, "new-secret", 10) == 0, "keyfile: content read back");
    {
        char tmpl[1200];
        DIR *d = opendir(dir);
        struct dirent *e;
        int leftovers = 0;
        (void)tmpl;
        while (d && (e = readdir(d)) != NULL) {
            if (strstr(e->d_name, ".tmp."))
                leftovers++;
        }
        if (d)
            (void)closedir(d);
        check(leftovers == 0, "keyfile: no temp file left behind (%d)", leftovers);
    }
    rc = zcl_keyfile_read(p, buf, 4, &got, err, sizeof(err));
    check(rc != 0, "keyfile: read refuses a file larger than the buffer");
    rc = zcl_keyfile_tighten("/nonexistent/zcl-keyfile-test", err, sizeof(err));
    check(rc == 1, "keyfile: tighten of a missing file returns 1 (rc=%d)", rc);
    {
        char lnk[1100];
        (void)snprintf(lnk, sizeof(lnk), "%s/link.key", dir);
        if (symlink(p, lnk) == 0) {
            rc = zcl_keyfile_tighten(lnk, err, sizeof(err));
            check(rc < 0, "keyfile: tighten refuses to follow a symlink (rc=%d)", rc);
        } else {
            check(false, "keyfile: could not create symlink fixture");
        }
    }
    rc = zcl_keyfile_write("/nonexistent-dir/zcl.key", "x", 1, err, sizeof(err));
    check(rc != 0 && err[0], "keyfile: write into a missing directory fails with a message");
}

/* ------------------------------------------------------- control helper */

static bool wait_gone(long pid, unsigned ms)
{
    uint64_t end = zcl_tor_now_ms() + ms;
    while (zcl_tor_now_ms() < end) {
        if (pid_gone(pid))
            return true;
        zcl_tor_sleep_ms(50);
    }
    return pid_gone(pid);
}

/* ---------------------------------------------------------------- offline */

static void test_start_failures(const char *tmp)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", dd[1100];
    int rc;

    memset(&o, 0, sizeof(o));
    (void)snprintf(dd, sizeof(dd), "%s/does-not-exist", tmp);
    o.datadir = dd;
    o.disable_network = true;
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL && err[0], "start: missing datadir fails cleanly (%s)", err);

    (void)snprintf(dd, sizeof(dd), "%s/badexe", tmp);
    (void)mkdir(dd, 0700);
    o.datadir = dd;
    o.exe_path = "/nonexistent/zcl-no-such-binary";
    err[0] = '\0';
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL && err[0], "start: missing executable fails cleanly (%s)", err);

    o.exe_path = "/bin/false";
    err[0] = '\0';
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL && strstr(err, "exited"), "start: child that exits at once is reported (%s)", err);

    (void)snprintf(dd, sizeof(dd), "%s/new\nline", tmp);
    (void)mkdir(dd, 0700);
    o.datadir = dd;
    o.exe_path = NULL;
    err[0] = '\0';
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL, "start: a newline in the datadir is refused, no torrc injection (%s)", err);
}

static int run_offline(const char *tmp)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", dd[1100], keyp[1200], reply[8192], id[128], pk[1024], cmd[1400];
    const zcl_tor_embed_info *info;
    zcl_tor_sock c;
    long pid;
    int rc, nl = 0;
    bool hasp = false;
    uint64_t t0;

    (void)printf("== offline ==\n");
    test_keyfile(tmp);
    test_start_failures(tmp);

    (void)snprintf(dd, sizeof(dd), "%s/node", tmp);
    (void)mkdir(dd, 0755); /* a loose datadir must not matter: <datadir>/tor is 0700 */
    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    o.disable_network = true;
    t0 = zcl_tor_now_ms();
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc == 0 && h, "start with DisableNetwork (rc=%d %s) in %llu ms", rc, err,
          (unsigned long long)(zcl_tor_now_ms() - t0));
    if (rc != 0 || !h)
        return 1;
    info = zcl_tor_embed_info_get(h);
    pid = info->pid;
    check(pid > 0 && info->control_port > 0 && info->socks_port == 0,
          "info: pid=%ld control_port=%u socks_port=%u (0 expected with DisableNetwork)", pid,
          (unsigned)info->control_port, (unsigned)info->socks_port);
    check(zcl_tor_embed_alive(h) && ppid_of(pid) == (long)getpid(), "child is alive and is our child (ppid=%ld, us=%ld)",
          ppid_of(pid), (long)getpid());
    check(file_mode_is(info->cookie_path, 0600), "cookie file is 0600");
    check(file_mode_is(info->tor_dir, 0700), "tor dir is 0700");
    {
        char t[1200];
        (void)snprintf(t, sizeof(t), "%s/torrc", info->tor_dir);
        check(file_mode_is(t, 0600), "torrc is 0600");
    }

    rc = zcl_tor_control_open(h, &c, err, sizeof(err));
    check(rc == 0, "control: cookie authentication (%s)", err);
    if (rc != 0) {
        zcl_tor_embed_free(h);
        return 1;
    }
    rc = zcl_tor_control_cmd(c, "GETINFO status/bootstrap-phase", reply, sizeof(reply), 5000);
    check(rc == 0 && strstr(reply, "PROGRESS="), "control: bootstrap status readable: %.100s", reply);
    {
        char *nl2 = strpbrk(reply, "\r\n");
        (void)nl2;
    }
    rc = zcl_tor_control_cmd(c, "GETINFO version", reply, sizeof(reply), 5000);
    check(rc == 0 && strstr(reply, "version=0.4"), "control: GETINFO version -> %.40s", reply);

    rc = zcl_tor_control_cmd(c, "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8333", reply,
                             sizeof(reply), 20000);
    id[0] = pk[0] = '\0';
    if (rc == 0)
        (void)extract_value(reply, "ServiceID=", id, sizeof(id));
    check(rc == 0 && strlen(id) == 56,
          "control: ADD_ONION NEW:ED25519-V3 returned a %zu-character service id", strlen(id));
    if (extract_value(reply, "PrivateKey=", pk, sizeof(pk))) {
        (void)snprintf(keyp, sizeof(keyp), "%s/onion_v3_private_key", dd);
        rc = zcl_keyfile_write(keyp, pk, strlen(pk), err, sizeof(err));
        check(rc == 0 && file_mode_is(keyp, 0600), "onion key written by keyfile is 0600 (%s)", err);
    } else {
        check(false, "ADD_ONION returned a PrivateKey");
    }
    wipe(pk, sizeof(pk));
    wipe(reply, sizeof(reply));
    if (id[0]) {
        (void)snprintf(cmd, sizeof(cmd), "DEL_ONION %s", id);
        rc = zcl_tor_control_cmd(c, cmd, reply, sizeof(reply), 5000);
        check(rc == 0, "control: DEL_ONION");
    }
    zcl_tor_control_close(c);

    rc = check_sockets(pid, info->control_port, false, &nl, &hasp);
    check(rc == 0 && hasp && nl >= 1,
          "sockets: only loopback listeners (%d), control port %u present, no outbound, no UDP off-loopback (violations=%d)",
          nl, (unsigned)info->control_port, rc);

    {
        uint64_t s0 = zcl_tor_now_ms(), took;
        rc = zcl_tor_embed_stop(h, 0);
        took = zcl_tor_now_ms() - s0;
        check(rc == 0 && wait_gone(pid, 10000) && took < 10000, "stop: child gone in %llu ms (rc=%d)",
              (unsigned long long)took, rc);
        check(!zcl_tor_embed_alive(h), "alive() is false after stop");
        rc = zcl_tor_embed_stop(h, 0);
        check(rc == 0, "stop is idempotent (second call rc=%d)", rc);
        rc = zcl_tor_embed_stop(h, 0);
        check(rc == 0, "stop is idempotent (third call rc=%d)", rc);
    }
    zcl_tor_embed_free(h);
    h = NULL;

    /* Restart in the same datadir and in one whose name needs torrc quoting. */
    (void)snprintf(dd, sizeof(dd), "%s/we ird \"q\" \\dir", tmp);
    check(mkdir(dd, 0700) == 0, "fixture: datadir with space, quotes and backslash");
    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    o.disable_network = true;
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc == 0 && h, "start in a datadir needing torrc quoting (%s)", err);
    if (rc == 0 && h) {
        long p2 = zcl_tor_embed_info_get(h)->pid;
        rc = zcl_tor_embed_stop(h, 0);
        check(rc == 0 && wait_gone(p2, 10000), "stop of the quoted-path run");
        zcl_tor_embed_free(h);
        h = NULL;
        rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
        check(rc == 0 && h, "restart in the same datadir (stale control_port and cookie replaced) (%s)", err);
        if (rc == 0 && h) {
            zcl_tor_sock c2;
            rc = zcl_tor_control_open(h, &c2, err, sizeof(err));
            check(rc == 0, "restart: control authenticates with the new cookie");
            if (rc == 0)
                zcl_tor_control_close(c2);
            zcl_tor_embed_free(h); /* free stops first */
        }
    }
    return 0;
}

/* ----------------------------------------------------------------- orphan */

static int run_holder(const char *dd, const char *flag)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "";
    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    o.disable_network = (strcmp(flag, "offline") == 0);
    if (zcl_tor_embed_start(&o, &h, err, sizeof(err)) != 0) {
        (void)fprintf(stderr, "holder: start failed: %s\n", err);
        return 1;
    }
    (void)printf("READY %ld\n", zcl_tor_embed_info_get(h)->pid);
    (void)fflush(stdout);
    for (;;)
        (void)pause();
    return 0;
}

static int run_orphan(const char *tmp, const char *self)
{
    char dd[1100], line[128];
    int pfd[2];
    pid_t holder = -1;
    posix_spawn_file_actions_t fa;
    char *av[5];
    long torpid = -1;
    uint64_t t0;
    int rc, st;
    size_t got = 0;
    struct pollfd p;

    (void)printf("== orphan (kill -9 the parent) ==\n");
    (void)snprintf(dd, sizeof(dd), "%s/orphan", tmp);
    check(mkdir(dd, 0700) == 0, "fixture: orphan datadir");
    if (pipe(pfd) != 0) {
        check(false, "pipe: %s", strerror(errno));
        return 1;
    }
    (void)posix_spawn_file_actions_init(&fa);
    (void)posix_spawn_file_actions_adddup2(&fa, pfd[1], 1);
    (void)posix_spawn_file_actions_addclose(&fa, pfd[0]);
    av[0] = (char *)self;
    av[1] = (char *)"holder";
    av[2] = dd;
    av[3] = (char *)"offline";
    av[4] = NULL;
    rc = posix_spawn(&holder, self, &fa, NULL, av, environ);
    (void)posix_spawn_file_actions_destroy(&fa);
    (void)close(pfd[1]);
    check(rc == 0, "spawned holder process (rc=%d)", rc);
    if (rc != 0) {
        (void)close(pfd[0]);
        return 1;
    }
    t0 = zcl_tor_now_ms();
    p.fd = pfd[0];
    p.events = POLLIN;
    while (got + 1 < sizeof(line) && zcl_tor_now_ms() - t0 < 60000) {
        ssize_t r;
        if (poll(&p, 1, 500) <= 0)
            continue;
        r = read(pfd[0], line + got, sizeof(line) - 1 - got);
        if (r <= 0)
            break;
        got += (size_t)r;
        line[got] = '\0';
        if (strchr(line, '\n'))
            break;
    }
    line[got] = '\0';
    (void)close(pfd[0]);
    if (sscanf(line, "READY %ld", &torpid) != 1 || torpid <= 0) {
        check(false, "holder reported its Tor child (got '%s')", line);
        (void)kill(holder, SIGKILL);
        (void)waitpid(holder, &st, 0);
        return 1;
    }
    check(!pid_gone(torpid) && ppid_of(torpid) == (long)holder, "Tor child %ld is alive under holder %ld", torpid,
          (long)holder);
    (void)kill(holder, SIGKILL);
    (void)waitpid(holder, &st, 0);
    check(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL, "holder was killed with SIGKILL");
    t0 = zcl_tor_now_ms();
    {
        bool gone = wait_gone(torpid, 10000);
        unsigned long long took = (unsigned long long)(zcl_tor_now_ms() - t0);
        check(gone, "Tor child exited by itself %llu ms after the parent was killed", took);
        if (!gone) {
            (void)kill((pid_t)torpid, SIGKILL); /* keep the host clean */
            return 1;
        }
    }
    return 0;
}

/* ----------------------------------------------------------------- online */

struct echo {
    int lfd;
    volatile int stop;
    unsigned long bytes;
};

static void *echo_main(void *arg)
{
    struct echo *e = (struct echo *)arg;
    while (!e->stop) {
        struct pollfd p;
        int c;
        p.fd = e->lfd;
        p.events = POLLIN;
        if (poll(&p, 1, 200) <= 0)
            continue;
        c = accept(e->lfd, NULL, NULL);
        if (c < 0)
            continue;
        while (!e->stop) {
            char b[4096];
            ssize_t r, off = 0;
            struct pollfd q;
            q.fd = c;
            q.events = POLLIN;
            if (poll(&q, 1, 200) <= 0)
                continue;
            r = read(c, b, sizeof(b));
            if (r <= 0)
                break;
            while (off < r) {
                ssize_t w = write(c, b + off, (size_t)(r - off));
                if (w <= 0)
                    break;
                off += w;
            }
            e->bytes += (unsigned long)r;
        }
        (void)close(c);
    }
    return NULL;
}

static bool read_full(int fd, void *buf, size_t n, int timeout_ms)
{
    size_t got = 0;
    uint64_t end = zcl_tor_now_ms() + (uint64_t)timeout_ms;
    while (got < n) {
        struct pollfd p;
        ssize_t r;
        uint64_t now = zcl_tor_now_ms();
        if (now >= end)
            return false;
        p.fd = fd;
        p.events = POLLIN;
        if (poll(&p, 1, (int)(end - now)) <= 0)
            return false;
        r = read(fd, (char *)buf + got, n - got);
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

/* SOCKS5 CONNECT to host:port through 127.0.0.1:socks. Returns a connected
 * descriptor or -1; *code gets the SOCKS reply code (or -1). */
static int socks5_connect(uint16_t socks, const char *host, uint16_t port, int *code)
{
    struct sockaddr_in a;
    unsigned char req[300], rep[10];
    size_t hl = strlen(host), n = 0;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    *code = -1;
    if (fd < 0)
        return -1;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(socks);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0)
        goto bad;
    req[0] = 5;
    req[1] = 1;
    req[2] = 0;
    if (write(fd, req, 3) != 3 || !read_full(fd, rep, 2, 10000) || rep[0] != 5 || rep[1] != 0)
        goto bad;
    req[n++] = 5;
    req[n++] = 1;
    req[n++] = 0;
    req[n++] = 3;
    req[n++] = (unsigned char)hl;
    memcpy(req + n, host, hl);
    n += hl;
    req[n++] = (unsigned char)(port >> 8);
    req[n++] = (unsigned char)(port & 255);
    if (write(fd, req, n) != (ssize_t)n || !read_full(fd, rep, 10, 90000))
        goto bad;
    *code = rep[1];
    if (rep[1] != 0)
        goto bad;
    return fd;
bad:
    (void)close(fd);
    return -1;
}

static int run_online(const char *tmp)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", dd[1100], reply[4096], id[128], cmd[512], host[128];
    const zcl_tor_embed_info *info;
    zcl_tor_sock c;
    struct sockaddr_in a;
    socklen_t al = sizeof(a);
    struct echo e;
    pthread_t th;
    int rc, boot = 0, nl = 0, code = -1, attempts = 0;
    bool hasp;
    uint64_t t_start, t_boot, t_add, t_reach = 0;
    long pid;

    (void)printf("== online ==\n");
    (void)snprintf(dd, sizeof(dd), "%s/online", tmp);
    check(mkdir(dd, 0700) == 0, "fixture: online datadir");
    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    t_start = zcl_tor_now_ms();
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc == 0 && h, "start with the network enabled (%s) in %llu ms", err,
          (unsigned long long)(zcl_tor_now_ms() - t_start));
    if (rc != 0 || !h)
        return 1;
    info = zcl_tor_embed_info_get(h);
    pid = info->pid;
    check(info->socks_port > 0 && info->control_port > 0, "ports: socks=%u control=%u", (unsigned)info->socks_port,
          (unsigned)info->control_port);

    rc = zcl_tor_embed_wait_bootstrap(h, 300000, &boot, err, sizeof(err));
    t_boot = zcl_tor_now_ms() - t_start;
    check(rc == 0 && boot == 100, "bootstrap reached %d%% (%s)", boot, err);
    (void)printf("TIME bootstrap_ms=%llu (from start)\n", (unsigned long long)t_boot);
    if (rc != 0) {
        zcl_tor_embed_free(h);
        return 1;
    }

    memset(&e, 0, sizeof(e));
    e.lfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (e.lfd < 0 || bind(e.lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(e.lfd, 4) != 0 ||
        getsockname(e.lfd, (struct sockaddr *)&a, &al) != 0 || pthread_create(&th, NULL, echo_main, &e) != 0) {
        check(false, "echo listener setup: %s", strerror(errno));
        zcl_tor_embed_free(h);
        return 1;
    }
    check(true, "echo listener on 127.0.0.1:%u", (unsigned)ntohs(a.sin_port));

    rc = zcl_tor_control_open(h, &c, err, sizeof(err));
    check(rc == 0, "control authenticates");
    (void)snprintf(cmd, sizeof(cmd), "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=80,127.0.0.1:%u",
                   (unsigned)ntohs(a.sin_port));
    t_add = zcl_tor_now_ms();
    rc = rc == 0 ? zcl_tor_control_cmd(c, cmd, reply, sizeof(reply), 30000) : -1;
    id[0] = '\0';
    check(rc == 0 && extract_value(reply, "ServiceID=", id, sizeof(id)) && strlen(id) == 56,
          "ADD_ONION returned a 56-character id");
    if (strlen(id) != 56) {
        zcl_tor_control_close(c);
        e.stop = 1;
        (void)pthread_join(th, NULL);
        (void)close(e.lfd);
        zcl_tor_embed_free(h);
        return 1;
    }
    (void)snprintf(host, sizeof(host), "%s.onion", id);

    /* The descriptor takes a while to reach the HSDirs; retry. */
    while (zcl_tor_now_ms() - t_add < 600000) {
        int fd = socks5_connect(info->socks_port, host, 80, &code);
        attempts++;
        if (fd >= 0) {
            unsigned char out[4096], in[4096];
            size_t i;
            for (i = 0; i < sizeof(out); i++)
                out[i] = (unsigned char)((i * 131u + 7u) & 255u);
            if (write(fd, out, sizeof(out)) == (ssize_t)sizeof(out) &&
                read_full(fd, in, sizeof(in), 30000) && memcmp(in, out, sizeof(out)) == 0) {
                t_reach = zcl_tor_now_ms();
                (void)close(fd);
                break;
            }
            (void)close(fd);
        }
        if (attempts % 5 == 1)
            (void)printf("  attempt %d: socks reply code %d, %llu s since ADD_ONION\n", attempts, code,
                         (unsigned long long)((zcl_tor_now_ms() - t_add) / 1000));
        zcl_tor_sleep_ms(2000);
    }
    check(t_reach != 0, "connected to %s.onion through the SocksPort and exchanged 4096 bytes (%d attempts)", "<id>",
          attempts);
    if (t_reach)
        (void)printf("TIME reachable_ms_after_add_onion=%llu reachable_ms_after_start=%llu echoed_bytes=%lu\n",
                     (unsigned long long)(t_reach - t_add), (unsigned long long)(t_reach - t_start), e.bytes);

    rc = check_sockets(pid, info->control_port, true, &nl, &hasp);
    check(rc == 0 && hasp, "sockets: all listeners and UDP sockets loopback-only (%d listeners, violations=%d)", nl, rc);

    zcl_tor_control_close(c);
    e.stop = 1;
    (void)pthread_join(th, NULL);
    (void)close(e.lfd);
    {
        uint64_t s0 = zcl_tor_now_ms();
        rc = zcl_tor_embed_stop(h, 0);
        check(rc == 0 && wait_gone(pid, 10000), "stop: child gone in %llu ms", (unsigned long long)(zcl_tor_now_ms() - s0));
    }
    zcl_tor_embed_free(h);
    return 0;
}

/* ------------------------------------------------------------- in-process */

/* Open descriptors of this process. Eventfds are counted apart: Tor leaves
 * one open per tor_run_main (its own leak, see README.md, In-process mode). */
static int count_fds(int *eventfds)
{
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    int n = 0, ev = 0;
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL) {
        char p[300], t[128];
        ssize_t k;
        if (e->d_name[0] == '.')
            continue;
        (void)snprintf(p, sizeof(p), "/proc/self/fd/%s", e->d_name);
        k = readlink(p, t, sizeof(t) - 1);
        t[k > 0 ? k : 0] = '\0';
        if (strcmp(t, "anon_inode:[eventfd]") == 0)
            ev++;
        else
            n++;
    }
    (void)closedir(d);
    if (eventfds)
        *eventfds = ev;
    return n - 1; /* minus the directory stream itself */
}

static void list_fds(void)
{
    DIR *d = opendir("/proc/self/fd");
    struct dirent *e;
    if (!d)
        return;
    while ((e = readdir(d)) != NULL) {
        char p[300], t[512];
        ssize_t n;
        if (e->d_name[0] == '.')
            continue;
        (void)snprintf(p, sizeof(p), "/proc/self/fd/%s", e->d_name);
        n = readlink(p, t, sizeof(t) - 1);
        if (n > 0) {
            t[n] = 0;
            (void)printf("  fd %s -> %s\n", e->d_name, t);
        }
    }
    (void)closedir(d);
}

static int count_threads(void)
{
    DIR *d = opendir("/proc/self/task");
    struct dirent *e;
    int n = 0;
    if (!d)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] != '.')
            n++;
    }
    (void)closedir(d);
    return n;
}

/* Tor on a thread of this process: start, control, onion service, stop; no
 * leaked descriptors or threads; a second start after stop works. */
static int run_inproc(const char *tmp)
{
    char dd[1100], err[256] = "", reply[8192], id[128], t[1300];
    int round, ev0 = 0, fd0 = count_fds(&ev0), th0 = count_threads();

    (void)printf("== inproc ==\n");
    (void)snprintf(dd, sizeof(dd), "%s/inproc node", tmp); /* space in the path */
    (void)mkdir(dd, 0755);
    for (round = 0; round < 2; round++) {
        zcl_tor_embed *h = NULL, *h2 = NULL;
        zcl_tor_embed_opts o;
        const zcl_tor_embed_info *info;
        zcl_tor_sock c;
        struct sigaction sa;
        uint64_t t0 = zcl_tor_now_ms();
        int rc;

        memset(&o, 0, sizeof(o));
        o.datadir = dd;
        o.disable_network = true;
        o.in_process = true;
        rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
        check(rc == 0 && h, "round %d: in-process start (rc=%d %s) in %llu ms", round, rc, err,
              (unsigned long long)(zcl_tor_now_ms() - t0));
        if (rc != 0 || !h)
            return 1;
        info = zcl_tor_embed_info_get(h);
        check(info->pid == 0 && info->control_port > 0 && zcl_tor_embed_alive(h),
              "round %d: no child pid, control_port=%u, alive", round,
              (unsigned)info->control_port);
        check(count_threads() > th0, "round %d: Tor runs on threads of this process (%d -> %d)",
              round, th0, count_threads());
        check(file_mode_is(info->cookie_path, 0600) && file_mode_is(info->tor_dir, 0700),
              "round %d: cookie 0600, tor dir 0700", round);
        (void)snprintf(t, sizeof(t), "%s/tor.log", info->tor_dir);
        check(access(t, R_OK) == 0, "round %d: notice log is a file in the tor dir (path with a space)", round);
        /* Tor must not have taken the process's signal handlers. */
        check(sigaction(SIGTERM, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL &&
                  sigaction(SIGINT, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL &&
                  sigaction(SIGHUP, NULL, &sa) == 0 && sa.sa_handler == SIG_DFL,
              "round %d: SIGTERM/SIGINT/SIGHUP handlers untouched", round);
        rc = zcl_tor_embed_start(&o, &h2, err, sizeof(err));
        check(rc != 0 && !h2, "round %d: a second in-process Tor is refused (%s)", round, err);
        rc = zcl_tor_control_open(h, &c, err, sizeof(err));
        check(rc == 0, "round %d: control cookie authentication (%s)", round, err);
        if (rc == 0) {
            rc = zcl_tor_control_cmd(c, "GETINFO version", reply, sizeof(reply), 5000);
            check(rc == 0 && strstr(reply, "version=0.4"), "round %d: GETINFO version -> %.40s", round, reply);
            rc = zcl_tor_control_cmd(c, "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8333", reply,
                                     sizeof(reply), 20000);
            id[0] = '\0';
            if (rc == 0)
                (void)extract_value(reply, "ServiceID=", id, sizeof(id));
            check(rc == 0 && strlen(id) == 56, "round %d: ADD_ONION returned a %zu-character service id",
                  round, strlen(id));
            zcl_tor_control_close(c);
        }
        t0 = zcl_tor_now_ms();
        rc = zcl_tor_embed_stop(h, 15000);
        check(rc == 0 && !zcl_tor_embed_alive(h), "round %d: stop joined the Tor thread in %llu ms (rc=%d)",
              round, (unsigned long long)(zcl_tor_now_ms() - t0), rc);
        zcl_tor_embed_free(h);
        zcl_tor_sleep_ms(200);
        {
            int ev = 0, fds = count_fds(&ev);
            check(fds == fd0,
                  "round %d: no leaked sockets, files or pipes (%d before, %d after)", round, fd0, fds);
            check(ev - ev0 <= round + 1,
                  "round %d: at most one eventfd left open per Tor run (%d left by %d run(s))", round,
                  ev - ev0, round + 1);
            if (fds != fd0)
                list_fds();
        }
        check(count_threads() == th0, "round %d: no leaked threads (%d before, %d after)", round, th0,
              count_threads());
    }
    return 0;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    char tmp[512];
    const char *mode;
    int rc = 0, dr;
    char self[1100];

    dr = zcl_tor_embed_dispatch(argc, argv);
    if (dr >= 0)
        return dr;
    mode = argc > 1 ? argv[1] : "all";
    {
        ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
        if (n <= 0) {
            (void)fprintf(stderr, "cannot resolve own path\n");
            return 2;
        }
        self[n] = '\0';
    }
    if (strcmp(mode, "holder") == 0 && argc >= 4)
        return run_holder(argv[2], argv[3]);
    if (make_tmp(tmp, sizeof(tmp)) != 0)
        return 2;
    (void)printf("tmp dir %s\n", tmp);
    if (strcmp(mode, "offline") == 0 || strcmp(mode, "all") == 0)
        rc |= run_offline(tmp);
    if (strcmp(mode, "orphan") == 0 || strcmp(mode, "all") == 0)
        rc |= run_orphan(tmp, self);
    if (strcmp(mode, "inproc") == 0 || strcmp(mode, "all") == 0)
        rc |= run_inproc(tmp);
    if (strcmp(mode, "online") == 0)
        rc |= run_online(tmp);
    if (strcmp(mode, "offline") && strcmp(mode, "all") && strcmp(mode, "orphan") && strcmp(mode, "online") &&
        strcmp(mode, "inproc")) {
        (void)fprintf(stderr, "usage: %s [offline|orphan|inproc|online|all]\n", argv[0]);
        rm_rf(tmp, "zcltor-selftest.");
        return 2;
    }
    (void)printf("RESULT pass=%d fail=%d\n", g_pass, g_fail);
    if (rc != 0 || g_fail != 0)
        (void)printf("kept failing run state in %s\n", tmp);
    else
        rm_rf(tmp, "zcltor-selftest.");
    return (rc != 0 || g_fail != 0) ? 1 : 0;
}
