/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * zcl_tor_embed: launch and supervise an embedded Tor child. See the header.
 * The torrc body and the owner-exit policy are Z23's (Apache-2.0,
 * (c) 2026 Rhett Creighton); see README.md. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* strict _POSIX_C_SOURCE hides O_NOFOLLOW etc. on Darwin */
#endif
#endif

#include "zcl_tor_embed.h"
#include "keyfile.h"
#include "zcl_tor_inproc.h"
#include "zcl_tor_proc.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define ZSOCK SOCKET
#define ZCLOSE(s) closesocket(s)
#define ZPOLL(fds, n, t) WSAPoll((fds), (n), (t))
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#define ZSOCK int
#define ZCLOSE(s) close(s)
#define ZPOLL(fds, n, t) poll((fds), (nfds_t)(n), (t))
#endif

#define PATHCAP 1024
#define REPLYCAP 16384

struct zcl_tor_embed {
    struct zcl_tor_proc proc;
    struct zcl_tor_inproc *inproc; /* non-NULL in in-process mode */
    zcl_tor_embed_info info;
    bool disable_network;
    bool stopped;
    char control_file[PATHCAP + 32];
};

static void seterr(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || errsz == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

static void wipe(void *p, size_t n)
{
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--)
        *v++ = 0;
}

/* ------------------------------------------------------------------ torrc */

/* Append `s` as a torrc quoted string. Returns false on overflow or when `s`
 * holds a control character (a newline would inject torrc lines). */
static bool torrc_quote(char *out, size_t cap, size_t *len, const char *s)
{
    size_t n = *len;
    if (n + 1 >= cap)
        return false;
    out[n++] = '"';
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c < 0x20 || c == 0x7f)
            return false;
        if (c == '"' || c == '\\') {
            if (n + 2 >= cap)
                return false;
            out[n++] = '\\';
        }
        if (n + 1 >= cap)
            return false;
        out[n++] = (char)c;
    }
    if (n + 2 >= cap)
        return false;
    out[n++] = '"';
    out[n] = '\0';
    *len = n;
    return true;
}

static bool torrc_line(char *out, size_t cap, size_t *len, const char *key,
                       const char *path)
{
    size_t n = *len;
    int w = snprintf(out + n, cap - n, "%s ", key);
    if (w < 0 || (size_t)w >= cap - n)
        return false;
    n += (size_t)w;
    if (!torrc_quote(out, cap, &n, path))
        return false;
    if (n + 2 >= cap)
        return false;
    out[n++] = '\n';
    out[n] = '\0';
    *len = n;
    return true;
}

/* The body follows Z23's tor_write_torrc_ex (core/modules/net/src/
 * tor_config_log.c): loopback SocksPort, DataDirectory, notice log to a
 * file, Schedulers KISTLite,Vanilla, optional DisableNetwork. Differences:
 * both listeners use auto ports (the control port is read back from
 * ControlPortWriteToFile), cookie authentication is on, and in child mode the
 * signal handlers stay on because Tor is its own process there. */
static int build_torrc(char *out, size_t cap, const char *tor_dir,
                       const char *cookie, const char *ctlfile,
                       bool disable_network, const char *inproc_log)
{
    size_t n = 0;
    int w;
    out[0] = '\0';
    if (!torrc_line(out, cap, &n, "DataDirectory", tor_dir))
        return -1;
    w = snprintf(out + n, cap - n,
                 "SocksPort 127.0.0.1:auto\n"
                 "ControlPort 127.0.0.1:auto\n"
                 "CookieAuthentication 1\n"
                 "CookieAuthFileGroupReadable 0\n"
                 "ClientOnly 1\n"
                 "ExitRelay 0\n"
                 "Schedulers KISTLite,Vanilla\n"
                 "SafeLogging 1\n");
    if (w < 0 || (size_t)w >= cap - n)
        return -1;
    n += (size_t)w;
    /* Log level: notice, except the APP domain at warn. The pinned Tor fork
     * logs one notice line per DATA cell a stream receives (src/core/or/
     * relay.c, "DATA cell received for stream ..."), in the APP domain: at
     * notice a block download would write about a quarter of its size to the
     * log. */
#define ZCL_TOR_LOG_LEVELS "[app]warn [~app]notice"
    if (inproc_log) {
        /* In-process: stdout belongs to the daemon, so the log goes to a
         * file. The whole value is one quoted string ("... file <path>"),
         * which keeps spaces and '#' in the path intact. Signal handlers stay
         * with the daemon. */
        char val[PATHCAP + 64];
        w = snprintf(val, sizeof(val), ZCL_TOR_LOG_LEVELS " file %s", inproc_log);
        if (w < 0 || (size_t)w >= sizeof(val) ||
            !torrc_line(out, cap, &n, "Log", val))
            return -1;
        w = snprintf(out + n, cap - n, "__DisableSignalHandlers 1\n");
    } else {
        /* Child: Tor's stdout is the tor-child.log the process layer opened,
         * so the log lands there. */
        w = snprintf(out + n, cap - n, "Log " ZCL_TOR_LOG_LEVELS " stdout\n");
    }
#undef ZCL_TOR_LOG_LEVELS
    if (w < 0 || (size_t)w >= cap - n)
        return -1;
    n += (size_t)w;
    if (!torrc_line(out, cap, &n, "CookieAuthFile", cookie) ||
        !torrc_line(out, cap, &n, "ControlPortWriteToFile", ctlfile))
        return -1;
    if (disable_network) {
        w = snprintf(out + n, cap - n, "DisableNetwork 1\n");
        if (w < 0 || (size_t)w >= cap - n)
            return -1;
    }
    return 0;
}

/* ---------------------------------------------------------- control client */

#ifdef _WIN32
static int net_up(void)
{
    static int done;
    WSADATA d;
    if (done)
        return 0;
    if (WSAStartup(MAKEWORD(2, 2), &d) != 0)
        return -1;
    done = 1;
    return 0;
}
#else
static int net_up(void)
{
    return 0;
}
#endif

static int sock_wait(ZSOCK s, short ev, int ms)
{
    struct pollfd p;
    int r;
    p.fd = s;
    p.events = ev;
    p.revents = 0;
    do {
        r = ZPOLL(&p, 1, ms);
    } while (r < 0 && errno == EINTR);
    return r; /* 1 ready, 0 timeout, <0 error */
}

static ZSOCK loopback_connect(uint16_t port, unsigned timeout_ms)
{
    struct sockaddr_in a;
    ZSOCK s;
    (void)timeout_ms;
    if (net_up() != 0)
        return (ZSOCK)-1;
    s = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
    if (s == INVALID_SOCKET)
        return (ZSOCK)-1;
#else
    if (s < 0)
        return (ZSOCK)-1;
#endif
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        (void)ZCLOSE(s);
        return (ZSOCK)-1;
    }
    return s;
}

/* 1 final line seen, 0 need more, -1 malformed. */
static int reply_complete(const char *b, size_t n)
{
    size_t i = 0;
    bool data = false;
    while (i < n) {
        const char *l = b + i;
        const char *e = (const char *)memchr(l, '\n', n - i);
        size_t ll;
        if (!e)
            return 0;
        ll = (size_t)(e - l) + 1;
        if (data) {
            if (ll >= 2 && l[0] == '.' && (l[1] == '\r' || l[1] == '\n'))
                data = false;
        } else {
            if (ll < 4 || l[0] < '0' || l[0] > '9' || l[1] < '0' || l[1] > '9' ||
                l[2] < '0' || l[2] > '9')
                return -1;
            if (l[3] == ' ')
                return 1;
            if (l[3] == '+')
                data = true;
            else if (l[3] != '-')
                return -1;
        }
        i += ll;
    }
    return 0;
}

int zcl_tor_control_cmd(zcl_tor_sock sock, const char *cmd, char *reply,
                        size_t cap, unsigned timeout_ms)
{
    ZSOCK s = (ZSOCK)sock;
    size_t len = strlen(cmd), off = 0, got = 0;
    char line[2048];
    uint64_t end = zcl_tor_now_ms() + timeout_ms;
    int status = -1;

    if (cap == 0 || !reply)
        return -1;
    reply[0] = '\0';
    if (len + 2 >= sizeof(line) || strpbrk(cmd, "\r\n"))
        return -1;
    memcpy(line, cmd, len);
    line[len++] = '\r';
    line[len++] = '\n';
    while (off < len) {
        int w = (int)send(s, line + off, (int)(len - off), 0);
        if (w < 0) {
#ifndef _WIN32
            if (errno == EINTR)
                continue;
#endif
            wipe(line, sizeof(line));
            return -1;
        }
        off += (size_t)w;
    }
    wipe(line, sizeof(line));
    for (;;) {
        uint64_t now = zcl_tor_now_ms();
        int r, rc;
        if (now >= end)
            return -1;
        r = sock_wait(s, POLLIN, (int)(end - now));
        if (r <= 0)
            return -1;
        if (got + 1 >= cap)
            return -1; /* reply larger than the buffer */
        r = (int)recv(s, reply + got, (int)(cap - 1 - got), 0);
        if (r <= 0)
            return -1;
        got += (size_t)r;
        reply[got] = '\0';
        rc = reply_complete(reply, got);
        if (rc < 0)
            return -1;
        if (rc == 1)
            break;
    }
    {
        /* status comes from the final line */
        const char *p = reply, *last = reply;
        while ((p = strchr(p, '\n')) != NULL) {
            p++;
            if (*p)
                last = p;
        }
        status = (last[0] - '0') * 100 + (last[1] - '0') * 10 + (last[2] - '0');
    }
    return (status >= 200 && status < 300) ? 0 : -1;
}

void zcl_tor_control_close(zcl_tor_sock sock)
{
    if (sock != ZCL_TOR_BADSOCK)
        (void)ZCLOSE((ZSOCK)sock);
}

int zcl_tor_control_open(const zcl_tor_embed *h, zcl_tor_sock *out, char *err,
                         size_t errsz)
{
    static const char hexd[] = "0123456789abcdef";
    unsigned char cookie[64];
    char cmd[16 + 2 * sizeof(cookie)];
    char reply[512];
    size_t clen = 0, i;
    ZSOCK s;

    *out = ZCL_TOR_BADSOCK;
    if (h->info.control_port == 0) {
        seterr(err, errsz, "control port not known");
        return -1;
    }
    if (zcl_keyfile_read(h->info.cookie_path, cookie, sizeof(cookie), &clen, err,
                         errsz) != 0)
        return -1;
    if (clen != 32) {
        wipe(cookie, sizeof(cookie));
        seterr(err, errsz, "control cookie has %zu bytes, expected 32", clen);
        return -1;
    }
    s = loopback_connect(h->info.control_port, 2000);
    if (s == (ZSOCK)-1) {
        wipe(cookie, sizeof(cookie));
        seterr(err, errsz, "cannot connect to control port %u",
               (unsigned)h->info.control_port);
        return -1;
    }
    memcpy(cmd, "AUTHENTICATE ", 13);
    for (i = 0; i < clen; i++) {
        cmd[13 + 2 * i] = hexd[cookie[i] >> 4];
        cmd[14 + 2 * i] = hexd[cookie[i] & 15];
    }
    cmd[13 + 2 * clen] = '\0';
    wipe(cookie, sizeof(cookie));
    if (zcl_tor_control_cmd((zcl_tor_sock)s, cmd, reply, sizeof(reply), 5000) != 0) {
        wipe(cmd, sizeof(cmd));
        (void)ZCLOSE(s);
        seterr(err, errsz, "control authentication refused");
        return -1;
    }
    wipe(cmd, sizeof(cmd));
    *out = (zcl_tor_sock)s;
    return 0;
}

static int parse_port_after(const char *s, const char *needle, uint16_t *port)
{
    const char *p = strstr(s, needle);
    char *end = NULL;
    unsigned long v;
    if (!p)
        return -1;
    p += strlen(needle);
    v = strtoul(p, &end, 10);
    if (end == p || v == 0 || v > 65535)
        return -1;
    *port = (uint16_t)v;
    return 0;
}

/* ------------------------------------------------------------------ start */

static int join(char *out, size_t cap, const char *a, const char *b)
{
#ifdef _WIN32
    int n = snprintf(out, cap, "%s\\%s", a, b);
#else
    int n = snprintf(out, cap, "%s/%s", a, b);
#endif
    return (n > 0 && (size_t)n < cap) ? 0 : -1;
}

static bool tor_alive(zcl_tor_embed *h)
{
    return h->inproc ? zcl_tor_inproc_alive(h->inproc)
                     : zcl_tor_proc_alive(&h->proc);
}

/* Ask a running Tor to stop through its control port. */
static void control_halt(zcl_tor_embed *h)
{
    zcl_tor_sock c;
    if (h->info.control_port != 0 && zcl_tor_control_open(h, &c, NULL, 0) == 0) {
        char reply[256];
        (void)zcl_tor_control_cmd(c, "SIGNAL HALT", reply, sizeof(reply), 1000);
        zcl_tor_control_close(c);
    }
}

/* Stop an in-process Tor. A thread cannot be killed, so on timeout the
 * (small) state stays allocated and false is returned. */
static bool inproc_stop(zcl_tor_embed *h, unsigned timeout_ms)
{
    if (zcl_tor_inproc_alive(h->inproc))
        control_halt(h);
    zcl_tor_inproc_release_owner(h->inproc);
    if (!zcl_tor_inproc_wait(h->inproc, timeout_ms))
        return false;
    zcl_tor_inproc_close(h->inproc);
    h->inproc = NULL;
    return true;
}

static void fail_cleanup(zcl_tor_embed *h)
{
    if (h->inproc) {
        if (inproc_stop(h, 10000))
            free(h);
        return;
    }
    if (h->proc.pid != 0
#ifdef _WIN32
        || h->proc.process
#endif
    ) {
        zcl_tor_proc_release_owner(&h->proc);
        zcl_tor_proc_kill(&h->proc);
        (void)zcl_tor_proc_wait(&h->proc, 5000);
        zcl_tor_proc_close(&h->proc);
    }
    free(h);
}

int zcl_tor_embed_start(const zcl_tor_embed_opts *opts, zcl_tor_embed **out,
                        char *err, size_t errsz)
{
    zcl_tor_embed *h;
    char torrc[PATHCAP + 32], defaults[PATHCAP + 32],
        stdlog[PATHCAP + 32], exe[PATHCAP];
    char ttor[PATHCAP + 32], tcookie[PATHCAP + 32], tctl[PATHCAP + 32], ttorrc[PATHCAP + 32],
        tdefaults[PATHCAP + 32], tlog[PATHCAP + 32];
    char body[8192], e2[256];
    const char *args[6];
    unsigned tmo;
    uint64_t t0, end;
    bool have_ctl = false;

    if (out)
        *out = NULL;
    if (!opts || !out || !opts->datadir || !opts->datadir[0]) {
        seterr(err, errsz, "tor embed: datadir is required");
        return -1;
    }
    if (strlen(opts->datadir) + 40 >= PATHCAP) {
        seterr(err, errsz, "tor embed: datadir path too long");
        return -1;
    }
    /* Before any file is touched: a second in-process start must not remove
     * the cookie and control-port file of the instance that is running. */
    if (opts->in_process && zcl_tor_inproc_busy()) {
        seterr(err, errsz, "tor embed: an in-process Tor is already running in this "
                           "process");
        return -1;
    }
    h = (zcl_tor_embed *)calloc(1, sizeof(*h));
    if (!h) {
        seterr(err, errsz, "tor embed: out of memory");
        return -1;
    }
    h->disable_network = opts->disable_network;
    tmo = opts->start_timeout_ms ? opts->start_timeout_ms : 30000;

    if (join(h->info.tor_dir, sizeof(h->info.tor_dir), opts->datadir, "tor") != 0 ||
        join(h->info.cookie_path, sizeof(h->info.cookie_path), h->info.tor_dir,
             "control_auth_cookie") != 0 ||
        join(h->control_file, sizeof(h->control_file), h->info.tor_dir,
             "control_port") != 0 ||
        join(torrc, sizeof(torrc), h->info.tor_dir, "torrc") != 0 ||
        join(defaults, sizeof(defaults), h->info.tor_dir, "torrc-defaults") != 0 ||
        join(stdlog, sizeof(stdlog), h->info.tor_dir, "tor-child.log") != 0) {
        seterr(err, errsz, "tor embed: path too long");
        free(h);
        return -1;
    }
    if (zcl_keyfile_mkdir_private(h->info.tor_dir, e2, sizeof(e2)) != 0) {
        seterr(err, errsz, "tor embed: %s", e2);
        free(h);
        return -1;
    }
    /* Stale state from a previous run must not be mistaken for this one. */
    if (zcl_keyfile_remove(h->control_file, e2, sizeof(e2)) != 0 ||
        zcl_keyfile_remove(h->info.cookie_path, e2, sizeof(e2)) != 0) {
        seterr(err, errsz, "tor embed: %s", e2);
        free(h);
        return -1;
    }
    if (opts->in_process &&
        join(stdlog, sizeof(stdlog), h->info.tor_dir, "tor.log") != 0) {
        seterr(err, errsz, "tor embed: path too long");
        free(h);
        return -1;
    }
    /* The paths Tor itself opens (torrc body and command line). Tor uses the
     * narrow ANSI file APIs on Windows: unless the process runs with a UTF-8
     * active code page (manifest, Windows 10 1903+) a non-ASCII directory is
     * handed over by its ASCII 8.3 short name, or refused with a clear error. */
    if (zcl_tor_proc_tor_path(h->info.tor_dir, ttor, sizeof(ttor), e2, sizeof(e2)) != 0) {
        seterr(err, errsz, "tor embed: %s", e2);
        free(h);
        return -1;
    }
    if (join(tcookie, sizeof(tcookie), ttor, "control_auth_cookie") != 0 ||
        join(tctl, sizeof(tctl), ttor, "control_port") != 0 ||
        join(ttorrc, sizeof(ttorrc), ttor, "torrc") != 0 ||
        join(tdefaults, sizeof(tdefaults), ttor, "torrc-defaults") != 0 ||
        join(tlog, sizeof(tlog), ttor, "tor.log") != 0) {
        seterr(err, errsz, "tor embed: path too long");
        free(h);
        return -1;
    }
    if (build_torrc(body, sizeof(body), ttor, tcookie, tctl, h->disable_network,
                    opts->in_process ? tlog : NULL) != 0) {
        seterr(err, errsz, "tor embed: torrc does not fit or the path has a control "
                           "character");
        free(h);
        return -1;
    }
    if (zcl_keyfile_write(torrc, body, strlen(body), e2, sizeof(e2)) != 0 ||
        zcl_keyfile_write(defaults, "", 0, e2, sizeof(e2)) != 0) {
        seterr(err, errsz, "tor embed: %s", e2);
        free(h);
        return -1;
    }
    args[0] = "-f";
    args[1] = ttorrc;
    args[2] = "--defaults-torrc";
    args[3] = tdefaults;
    if (opts->in_process) {
        if (zcl_tor_inproc_start(&h->inproc, args, 4, e2, sizeof(e2)) != 0) {
            seterr(err, errsz, "tor embed: %s", e2);
            free(h);
            return -1;
        }
        h->info.pid = 0;
    } else {
        if (opts->exe_path && opts->exe_path[0]) {
            if (strlen(opts->exe_path) >= sizeof(exe)) {
                seterr(err, errsz, "tor embed: exe_path too long");
                free(h);
                return -1;
            }
            memcpy(exe, opts->exe_path, strlen(opts->exe_path) + 1);
        } else if (zcl_tor_proc_self_exe(exe, sizeof(exe)) != 0) {
            seterr(err, errsz, "tor embed: cannot locate this binary; set exe_path");
            free(h);
            return -1;
        }
        if (zcl_tor_proc_spawn(&h->proc, exe, args, 4, stdlog, e2, sizeof(e2)) != 0) {
            seterr(err, errsz, "tor embed: %s", e2);
            free(h);
            return -1;
        }
        h->info.pid = (long)h->proc.pid;
    }

    t0 = zcl_tor_now_ms();
    end = t0 + tmo;
    /* Wait for Tor to write the control port file ("PORT=127.0.0.1:N"). */
    for (;;) {
        char buf[128];
        size_t got = 0;
        uint16_t port = 0;
        if (!tor_alive(h)) {
            seterr(err, errsz, "tor embed: Tor exited during startup (see %s)",
                   stdlog);
            fail_cleanup(h);
            return -1;
        }
        if (zcl_keyfile_read(h->control_file, buf, sizeof(buf) - 1, &got, NULL, 0) == 0 &&
            got > 0 && memchr(buf, '\n', got)) {
            buf[got] = '\0';
            if (strncmp(buf, "PORT=127.0.0.1:", 15) != 0 ||
                parse_port_after(buf, "PORT=127.0.0.1:", &port) != 0) {
                seterr(err, errsz, "tor embed: unexpected control port file (not "
                                   "loopback)");
                fail_cleanup(h);
                return -1;
            }
            h->info.control_port = port;
            have_ctl = true;
            break;
        }
        if (zcl_tor_now_ms() >= end) {
            seterr(err, errsz, "tor embed: control port not ready after %u ms", tmo);
            fail_cleanup(h);
            return -1;
        }
        zcl_tor_sleep_ms(25);
    }
    (void)have_ctl;

    /* Authenticate, and (network enabled) learn the Socks port. */
    for (;;) {
        zcl_tor_sock c;
        if (zcl_tor_control_open(h, &c, e2, sizeof(e2)) == 0) {
            char reply[1024];
            if (h->disable_network) {
                zcl_tor_control_close(c);
                break;
            }
            if (zcl_tor_control_cmd(c, "GETINFO net/listeners/socks", reply,
                                    sizeof(reply), 3000) == 0 &&
                parse_port_after(reply, "\"127.0.0.1:", &h->info.socks_port) == 0) {
                zcl_tor_control_close(c);
                break;
            }
            zcl_tor_control_close(c);
        }
        if (!tor_alive(h)) {
            seterr(err, errsz, "tor embed: Tor exited during startup");
            fail_cleanup(h);
            return -1;
        }
        if (zcl_tor_now_ms() >= end) {
            seterr(err, errsz, "tor embed: control/Socks not ready after %u ms: %s",
                   tmo, e2);
            fail_cleanup(h);
            return -1;
        }
        zcl_tor_sleep_ms(50);
    }
    *out = h;
    return 0;
}

const zcl_tor_embed_info *zcl_tor_embed_info_get(const zcl_tor_embed *h)
{
    return h ? &h->info : NULL;
}

bool zcl_tor_embed_alive(zcl_tor_embed *h)
{
    return h && !h->stopped && tor_alive(h);
}

int zcl_tor_embed_wait_bootstrap(zcl_tor_embed *h, unsigned timeout_ms,
                                 int *progress, char *err, size_t errsz)
{
    uint64_t end = zcl_tor_now_ms() + timeout_ms;
    int last = 0;
    char e2[256] = "";
    if (progress)
        *progress = 0;
    if (!h || h->stopped) {
        seterr(err, errsz, "tor embed: not running");
        return -1;
    }
    if (h->disable_network) {
        seterr(err, errsz, "tor embed: DisableNetwork is set; Tor will not bootstrap");
        return -1;
    }
    for (;;) {
        zcl_tor_sock c;
        if (!tor_alive(h)) {
            seterr(err, errsz, "tor embed: Tor exited (last progress %d)", last);
            return -1;
        }
        if (zcl_tor_control_open(h, &c, e2, sizeof(e2)) == 0) {
            char reply[2048];
            if (zcl_tor_control_cmd(c, "GETINFO status/bootstrap-phase", reply,
                                    sizeof(reply), 3000) == 0) {
                const char *p = strstr(reply, "PROGRESS=");
                if (p) {
                    last = atoi(p + 9);
                    if (progress)
                        *progress = last;
                    if (last >= 100) {
                        zcl_tor_control_close(c);
                        return 0;
                    }
                }
            }
            zcl_tor_control_close(c);
        }
        if (zcl_tor_now_ms() >= end) {
            seterr(err, errsz, "tor embed: bootstrap at %d%% after %u ms", last,
                   timeout_ms);
            return -1;
        }
        zcl_tor_sleep_ms(250);
    }
}

int zcl_tor_embed_stop(zcl_tor_embed *h, unsigned timeout_ms)
{
    unsigned t1, t2;
    if (!h)
        return 0;
    if (h->stopped)
        return 0;
    if (timeout_ms == 0)
        timeout_ms = 10000;
    t1 = timeout_ms * 4 / 10;
    t2 = timeout_ms * 3 / 10;
    if (h->inproc) {
        if (!inproc_stop(h, timeout_ms))
            return -1;
        h->stopped = true;
        return 0;
    }
    if (zcl_tor_proc_alive(&h->proc)) {
        zcl_tor_sock c;
        /* Graceful: SIGNAL HALT over the control port, then drop the owner
         * channel (EOF there also makes Tor exit). */
        if (zcl_tor_control_open(h, &c, NULL, 0) == 0) {
            char reply[256];
            (void)zcl_tor_control_cmd(c, "SIGNAL HALT", reply, sizeof(reply), 1000);
            zcl_tor_control_close(c);
        }
        zcl_tor_proc_release_owner(&h->proc);
        if (!zcl_tor_proc_wait(&h->proc, t1)) {
            zcl_tor_proc_terminate(&h->proc);
            if (!zcl_tor_proc_wait(&h->proc, t2)) {
                zcl_tor_proc_kill(&h->proc);
                if (!zcl_tor_proc_wait(&h->proc, timeout_ms - t1 - t2))
                    return -1;
            }
        }
    }
    zcl_tor_proc_close(&h->proc);
    h->stopped = true;
    return 0;
}

void zcl_tor_embed_free(zcl_tor_embed *h)
{
    if (!h)
        return;
    if (zcl_tor_embed_stop(h, 10000) != 0) {
        /* Could not reap: leave the (tiny) handle rather than free state that
         * the OS still associates with a live pid. The owner channel is
         * closed, so Tor exits as soon as it can. */
        return;
    }
    free(h);
}
