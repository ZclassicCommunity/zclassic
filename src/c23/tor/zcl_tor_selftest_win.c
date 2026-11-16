/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * zcl_tor_selftest_win: Windows proof program for zcl_tor_embed and keyfile.
 * The Windows counterpart of zcl_tor_selftest.c (Linux, reads /proc).
 *
 *   zcl_tor_selftest_win offline    DisableNetwork runs, no network is touched
 *   zcl_tor_selftest_win orphan     TerminateProcess the parent, Tor must exit
 *   zcl_tor_selftest_win online     bootstrap, publish an onion service, reach it
 *   zcl_tor_selftest_win all        offline + orphan (not online)
 *
 * Windows equivalents of the Linux checks:
 *   /proc socket inspection        -> GetExtendedTcpTable / GetExtendedUdpTable
 *   file modes 0600 / 0700         -> GetNamedSecurityInfoW DACL inspection
 *   kill -9 the parent             -> TerminateProcess on a holder process
 *   ppid                           -> CreateToolhelp32Snapshot
 *
 * State lives in a fresh directory below %TMP% (GetTempPathW), removed at the
 * end on success. The binary is its own Tor child (dispatch runs first). */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#include "keyfile.h"
#include "zcl_tor_embed.h"
#include "zcl_tor_proc.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <aclapi.h>
#include <iphlpapi.h>
#include <sddl.h>
#include <tlhelp32.h>

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

static int g_fail;
static int g_pass;

static void check(bool ok, const char *fmt, ...)
{
    va_list ap;
    char msg[768];
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

/* ------------------------------------------------------------ utf-8 <-> 16 */

static wchar_t *wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0)
        return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (w && MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
        free(w);
        w = NULL;
    }
    return w;
}

static bool narrow(const wchar_t *w, char *out, size_t cap)
{
    return WideCharToMultiByte(CP_UTF8, 0, w, -1, out, (int)cap, NULL, NULL) > 0;
}

/* ------------------------------------------------------------ temp dirs */

static bool is_dir(const char *path)
{
    wchar_t *w = wide(path);
    DWORD a = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    free(w);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static bool path_exists(const char *path)
{
    wchar_t *w = wide(path);
    DWORD a = w ? GetFileAttributesW(w) : INVALID_FILE_ATTRIBUTES;
    free(w);
    return a != INVALID_FILE_ATTRIBUTES;
}

static bool mkdir_utf8(const char *path)
{
    wchar_t *w = wide(path);
    BOOL ok = w ? CreateDirectoryW(w, NULL) : FALSE;
    free(w);
    return ok != 0;
}

static void rm_rf_w(const wchar_t *dir)
{
    WIN32_FIND_DATAW fd;
    wchar_t pat[MAX_PATH * 4], sub[MAX_PATH * 4];
    HANDLE h;
    if (swprintf(pat, sizeof(pat) / sizeof(pat[0]), L"%ls\\*", dir) < 0)
        return;
    h = FindFirstFileW(pat, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L".."))
                continue;
            if (swprintf(sub, sizeof(sub) / sizeof(sub[0]), L"%ls\\%ls", dir, fd.cFileName) < 0)
                continue;
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                !(fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
                rm_rf_w(sub);
            } else {
                (void)SetFileAttributesW(sub, FILE_ATTRIBUTE_NORMAL);
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
                    (void)RemoveDirectoryW(sub);
                else
                    (void)DeleteFileW(sub);
            }
        } while (FindNextFileW(h, &fd));
        (void)FindClose(h);
    }
    (void)RemoveDirectoryW(dir);
}

static void rm_rf(const char *path, const char *must_contain)
{
    wchar_t *w;
    if (!strstr(path, must_contain))
        return; /* never remove anything we did not create */
    w = wide(path);
    if (w)
        rm_rf_w(w);
    free(w);
}

static int make_tmp(char *out, size_t cap)
{
    wchar_t base[MAX_PATH + 1], full[MAX_PATH * 2];
    DWORD n = GetTempPathW((DWORD)(sizeof(base) / sizeof(base[0])), base);
    if (n == 0 || n >= sizeof(base) / sizeof(base[0])) {
        (void)fprintf(stderr, "cannot resolve the temp directory\n");
        return -1;
    }
    if (n > 0 && (base[n - 1] == L'\\' || base[n - 1] == L'/'))
        base[n - 1] = 0;
    if (swprintf(full, sizeof(full) / sizeof(full[0]), L"%ls\\zcltor-selftest.%lu.%lu", base,
                 GetCurrentProcessId(), (unsigned long)GetTickCount()) < 0 ||
        !CreateDirectoryW(full, NULL)) {
        (void)fprintf(stderr, "cannot create temp dir (%lu)\n", GetLastError());
        return -1;
    }
    return narrow(full, out, cap) ? 0 : -1;
}

/* --------------------------------------------------------- process checks */

static bool pid_gone(unsigned long pid)
{
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    bool gone;
    if (!h)
        return GetLastError() == ERROR_INVALID_PARAMETER; /* no such pid */
    gone = WaitForSingleObject(h, 0) == WAIT_OBJECT_0;
    (void)CloseHandle(h);
    return gone;
}

static bool wait_gone(unsigned long pid, unsigned ms)
{
    uint64_t end = zcl_tor_now_ms() + ms;
    while (zcl_tor_now_ms() < end) {
        if (pid_gone(pid))
            return true;
        zcl_tor_sleep_ms(50);
    }
    return pid_gone(pid);
}

static long ppid_of(unsigned long pid)
{
    PROCESSENTRY32W e;
    long pp = -1;
    HANDLE s = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (s == INVALID_HANDLE_VALUE)
        return -1;
    memset(&e, 0, sizeof(e));
    e.dwSize = sizeof(e);
    if (Process32FirstW(s, &e)) {
        do {
            if (e.th32ProcessID == pid) {
                pp = (long)e.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(s, &e));
    }
    (void)CloseHandle(s);
    return pp;
}

/* ----------------------------------------------------- socket inspection */

static bool v4_loopback(DWORD addr_net)
{
    return (addr_net & 0xffu) == 127u; /* first octet, network order in memory */
}

static bool v6_loopback(const UCHAR a[16])
{
    static const UCHAR lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    return memcmp(a, lo, 16) == 0;
}

typedef ULONG (WINAPI *table_fn)(PVOID, PDWORD, WINBOOL, ULONG, ULONG, ULONG);
static void *table_get(table_fn fn,
                       ULONG af, ULONG cls, ULONG kind)
{
    DWORD sz = 0;
    void *buf = NULL;
    int tries;
    for (tries = 0; tries < 8; tries++) {
        ULONG r = fn(buf, &sz, FALSE, af, kind, 0);
        if (r == NO_ERROR)
            return buf;
        free(buf);
        buf = NULL;
        if (r != ERROR_INSUFFICIENT_BUFFER)
            return NULL;
        buf = malloc(sz + 4096);
        sz += 4096;
        if (!buf)
            return NULL;
    }
    (void)cls;
    free(buf);
    return NULL;
}

/* Returns the number of violations. A violation is a listening TCP socket or
 * a UDP socket of the child that is not bound to loopback and, unless
 * allow_outbound, a TCP connection with a non-loopback remote end. *nlisten
 * gets the number of loopback TCP listeners; *has_port is set when a listener
 * is on `want_port`. -1 listeners means a table could not be read (counted as
 * a violation). */
static int check_sockets(unsigned long pid, uint16_t want_port, bool allow_outbound, int *nlisten,
                         bool *has_port)
{
    int viol = 0;
    DWORD i;
    MIB_TCPTABLE_OWNER_PID *t4 = (MIB_TCPTABLE_OWNER_PID *)table_get(
        (table_fn)GetExtendedTcpTable, AF_INET, 0, TCP_TABLE_OWNER_PID_ALL);
    MIB_TCP6TABLE_OWNER_PID *t6 = (MIB_TCP6TABLE_OWNER_PID *)table_get(
        (table_fn)GetExtendedTcpTable, AF_INET6, 0, TCP_TABLE_OWNER_PID_ALL);
    MIB_UDPTABLE_OWNER_PID *u4 = (MIB_UDPTABLE_OWNER_PID *)table_get(
        (table_fn)GetExtendedUdpTable, AF_INET, 0, UDP_TABLE_OWNER_PID);
    MIB_UDP6TABLE_OWNER_PID *u6 = (MIB_UDP6TABLE_OWNER_PID *)table_get(
        (table_fn)GetExtendedUdpTable, AF_INET6, 0, UDP_TABLE_OWNER_PID);
    int total = 0;

    *nlisten = 0;
    *has_port = false;
    if (!t4 || !t6 || !u4 || !u6) {
        (void)printf("  cannot read an extended socket table (v4tcp=%p v6tcp=%p v4udp=%p v6udp=%p)\n",
                     (void *)t4, (void *)t6, (void *)u4, (void *)u6);
        viol++;
    }
    for (i = 0; t4 && i < t4->dwNumEntries; i++) {
        const MIB_TCPROW_OWNER_PID *r = &t4->table[i];
        unsigned lp = ntohs((u_short)r->dwLocalPort);
        if (r->dwOwningPid != pid)
            continue;
        total++;
        if (r->dwState == MIB_TCP_STATE_LISTEN) {
            if (!v4_loopback(r->dwLocalAddr)) {
                (void)printf("  VIOLATION non-loopback TCP listener %lu.%lu.%lu.%lu:%u\n",
                             r->dwLocalAddr & 255u, (r->dwLocalAddr >> 8) & 255u,
                             (r->dwLocalAddr >> 16) & 255u, (r->dwLocalAddr >> 24) & 255u, lp);
                viol++;
            } else {
                (*nlisten)++;
                if (lp == want_port)
                    *has_port = true;
            }
        } else if (!allow_outbound && r->dwRemoteAddr != 0 && !v4_loopback(r->dwRemoteAddr) &&
                   r->dwState != MIB_TCP_STATE_CLOSED) {
            (void)printf("  VIOLATION TCP connection to non-loopback remote (state %lu)\n",
                         (unsigned long)r->dwState);
            viol++;
        }
    }
    for (i = 0; t6 && i < t6->dwNumEntries; i++) {
        const MIB_TCP6ROW_OWNER_PID *r = &t6->table[i];
        unsigned lp = ntohs((u_short)r->dwLocalPort);
        if (r->dwOwningPid != pid)
            continue;
        total++;
        if (r->dwState == MIB_TCP_STATE_LISTEN) {
            if (!v6_loopback(r->ucLocalAddr)) {
                (void)printf("  VIOLATION non-loopback IPv6 TCP listener port %u\n", lp);
                viol++;
            } else {
                (*nlisten)++;
                if (lp == want_port)
                    *has_port = true;
            }
        } else if (!allow_outbound && !v6_loopback(r->ucRemoteAddr)) {
            static const UCHAR zero[16];
            if (memcmp(r->ucRemoteAddr, zero, 16) != 0 && r->dwState != MIB_TCP_STATE_CLOSED) {
                (void)printf("  VIOLATION IPv6 TCP connection to non-loopback remote\n");
                viol++;
            }
        }
    }
    for (i = 0; u4 && i < u4->dwNumEntries; i++) {
        const MIB_UDPROW_OWNER_PID *r = &u4->table[i];
        if (r->dwOwningPid != pid)
            continue;
        total++;
        if (!v4_loopback(r->dwLocalAddr)) {
            (void)printf("  VIOLATION UDP socket on non-loopback address, port %u\n",
                         (unsigned)ntohs((u_short)r->dwLocalPort));
            viol++;
        }
    }
    for (i = 0; u6 && i < u6->dwNumEntries; i++) {
        const MIB_UDP6ROW_OWNER_PID *r = &u6->table[i];
        if (r->dwOwningPid != pid)
            continue;
        total++;
        if (!v6_loopback(r->ucLocalAddr)) {
            (void)printf("  VIOLATION IPv6 UDP socket on non-loopback address, port %u\n",
                         (unsigned)ntohs((u_short)r->dwLocalPort));
            viol++;
        }
    }
    (void)printf("  socket tables: %d socket(s) owned by pid %lu\n", total, pid);
    free(t4);
    free(t6);
    free(u4);
    free(u6);
    return viol;
}

/* ------------------------------------------------------------ ACL checks */

static TOKEN_USER *g_user;

static bool load_user(void)
{
    HANDLE tok = NULL;
    DWORD need = 0;
    if (g_user)
        return true;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok))
        return false;
    (void)GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    g_user = (TOKEN_USER *)malloc(need ? need : 1);
    if (!g_user || !GetTokenInformation(tok, TokenUser, g_user, need, &need)) {
        free(g_user);
        g_user = NULL;
    }
    (void)CloseHandle(tok);
    return g_user != NULL;
}

/* True when the DACL of `path` grants access only to the current user: no NULL
 * DACL, every ACE an ACCESS_ALLOWED ACE for the current user's SID, at least
 * one such ACE. With `strict` the DACL must also be one single ACE and
 * protected (no inheritance from the parent). `why` explains a failure. */
static bool acl_user_only(const char *path, bool strict, char *why, size_t cap, int *nace)
{
    wchar_t *wp = wide(path);
    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_DESCRIPTOR_CONTROL ctl = 0;
    DWORD rev = 0, r, i;
    bool ok = false;
    int allowed = 0;

    why[0] = 0;
    if (nace)
        *nace = -1;
    if (!wp || !load_user()) {
        (void)snprintf(why, cap, "cannot resolve path or current user");
        free(wp);
        return false;
    }
    r = GetNamedSecurityInfoW(wp, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl,
                              NULL, &sd);
    free(wp);
    if (r != ERROR_SUCCESS) {
        (void)snprintf(why, cap, "GetNamedSecurityInfo failed (%lu)", (unsigned long)r);
        return false;
    }
    if (!dacl) {
        (void)snprintf(why, cap, "NULL DACL (everyone has full access)");
        goto out;
    }
    if (nace)
        *nace = (int)dacl->AceCount;
    (void)GetSecurityDescriptorControl(sd, &ctl, &rev);
    for (i = 0; i < dacl->AceCount; i++) {
        void *ace = NULL;
        ACE_HEADER *h;
        if (!GetAce(dacl, i, &ace)) {
            (void)snprintf(why, cap, "GetAce failed");
            goto out;
        }
        h = (ACE_HEADER *)ace;
        if (h->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            ACCESS_ALLOWED_ACE *a = (ACCESS_ALLOWED_ACE *)ace;
            if (!EqualSid((PSID)&a->SidStart, g_user->User.Sid)) {
                LPWSTR s = NULL;
                char sn[128] = "?";
                if (ConvertSidToStringSidW((PSID)&a->SidStart, &s)) {
                    (void)narrow(s, sn, sizeof(sn));
                    LocalFree(s);
                }
                (void)snprintf(why, cap, "ACE %lu grants access to another principal (%s)",
                               (unsigned long)i, sn);
                goto out;
            }
            allowed++;
        } else if (h->AceType != ACCESS_DENIED_ACE_TYPE) {
            (void)snprintf(why, cap, "ACE %lu has unexpected type %u", (unsigned long)i,
                           (unsigned)h->AceType);
            goto out;
        }
    }
    if (allowed < 1) {
        (void)snprintf(why, cap, "no ACE grants the current user access");
        goto out;
    }
    if (strict && (dacl->AceCount != 1 || !(ctl & SE_DACL_PROTECTED))) {
        (void)snprintf(why, cap, "expected one protected ACE, have %u ACEs, protected=%d",
                       (unsigned)dacl->AceCount, (ctl & SE_DACL_PROTECTED) ? 1 : 0);
        goto out;
    }
    ok = true;
out:
    LocalFree(sd);
    return ok;
}

/* Apply a permissive DACL (inherit from the parent, add Everyone: full). Used
 * to prove that tighten() really takes access away. */
static bool loosen(const char *path)
{
    wchar_t *wp = wide(path);
    PSECURITY_DESCRIPTOR sd = NULL;
    PACL dacl = NULL;
    BOOL present = FALSE, def = FALSE;
    DWORD r = ERROR_INVALID_DATA;
    if (wp && ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;FA;;;WD)",
                                                                   SDDL_REVISION_1, &sd, NULL) &&
        GetSecurityDescriptorDacl(sd, &present, &dacl, &def) && present) {
        r = SetNamedSecurityInfoW(wp, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, dacl,
                                  NULL);
    }
    if (sd)
        LocalFree(sd);
    free(wp);
    return r == ERROR_SUCCESS;
}

/* ----------------------------------------------------------- helpers */

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

static bool write_plain(const char *path, const char *text)
{
    wchar_t *w = wide(path);
    HANDLE h;
    DWORD n = 0;
    bool ok;
    if (!w)
        return false;
    h = CreateFileW(w, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    free(w);
    if (h == INVALID_HANDLE_VALUE)
        return false;
    ok = WriteFile(h, text, (DWORD)strlen(text), &n, NULL) && n == strlen(text);
    (void)CloseHandle(h);
    return ok;
}

static int count_tmp_leftovers(const char *dir)
{
    wchar_t *wd = wide(dir);
    wchar_t pat[MAX_PATH * 4];
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int n = 0;
    if (!wd)
        return -1;
    (void)swprintf(pat, sizeof(pat) / sizeof(pat[0]), L"%ls\\*.tmp.*", wd);
    free(wd);
    h = FindFirstFileW(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    do {
        n++;
    } while (FindNextFileW(h, &fd));
    (void)FindClose(h);
    return n;
}

static void dump_log(const char *tor_dir)
{
    char p[1200], buf[2048];
    size_t got = 0;
    (void)snprintf(p, sizeof(p), "%s/tor-child.log", tor_dir);
    if (zcl_keyfile_read(p, buf, sizeof(buf) - 1, &got, NULL, 0) == 0 && got) {
        buf[got] = 0;
        (void)printf("  --- tor-child.log ---\n%s\n  ---\n", buf);
    } else {
        /* log larger than the buffer: show its head by reading in a fresh call */
        wchar_t *w;
        HANDLE h;
        (void)snprintf(p, sizeof(p), "%s/tor-child.log", tor_dir);
        w = wide(p);
        h = w ? CreateFileW(w, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
              : INVALID_HANDLE_VALUE;
        free(w);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD n = 0;
            if (ReadFile(h, buf, sizeof(buf) - 1, &n, NULL) && n) {
                buf[n] = 0;
                (void)printf("  --- tor-child.log (head) ---\n%s\n  ---\n", buf);
            }
            (void)CloseHandle(h);
        }
    }
}

/* -------------------------------------------------------- keyfile tests */

static void test_keyfile(const char *dir)
{
    char p[1100], err[256] = "", buf[64], why[256];
    size_t got = 0;
    int rc, nace = 0;
    bool ok;

    (void)snprintf(p, sizeof(p), "%s\\secret.key", dir);
    /* pre-existing loose file with other content and an Everyone ACE */
    check(write_plain(p, "old-loose-content") && loosen(p), "keyfile: fixture file carries an Everyone:Full DACL");
    ok = acl_user_only(p, false, why, sizeof(why), &nace);
    check(!ok, "keyfile: ACL check detects the loose fixture (%s)", why);
    rc = zcl_keyfile_tighten(p, err, sizeof(err));
    ok = acl_user_only(p, true, why, sizeof(why), &nace);
    check(rc == 0 && ok, "keyfile: tighten leaves one protected ACE for the current user (rc=%d aces=%d %s %s)", rc,
          nace, err, why);
    (void)loosen(p);
    rc = zcl_keyfile_write(p, "new-secret", 10, err, sizeof(err));
    ok = acl_user_only(p, true, why, sizeof(why), &nace);
    check(rc == 0 && ok, "keyfile: atomic write replaces a loose file; result is current-user only (rc=%d aces=%d %s %s)",
          rc, nace, err, why);
    rc = zcl_keyfile_read(p, buf, sizeof(buf), &got, err, sizeof(err));
    check(rc == 0 && got == 10 && memcmp(buf, "new-secret", 10) == 0, "keyfile: content read back");
    {
        int left = count_tmp_leftovers(dir);
        check(left == 0, "keyfile: no temp file left behind (%d)", left);
    }
    rc = zcl_keyfile_read(p, buf, 4, &got, err, sizeof(err));
    check(rc != 0, "keyfile: read refuses a file larger than the buffer");
    rc = zcl_keyfile_tighten("C:\\nonexistent\\zcl-keyfile-test", err, sizeof(err));
    check(rc == 1, "keyfile: tighten of a missing file returns 1 (rc=%d)", rc);
    {
        /* tighten must not follow or touch a reparse point; a symlink needs a
         * privilege or Developer Mode, so a refusal to create one is reported
         * as skipped, not as a pass. */
        char lnk[1100];
        wchar_t *wl, *wt;
        BOOLEAN made = FALSE;
        (void)snprintf(lnk, sizeof(lnk), "%s\\link.key", dir);
        wl = wide(lnk);
        wt = wide(p);
        if (wl && wt)
            made = CreateSymbolicLinkW(wl, wt, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE);
        free(wl);
        free(wt);
        if (made) {
            rc = zcl_keyfile_tighten(lnk, err, sizeof(err));
            check(rc < 0, "keyfile: tighten refuses to follow a symlink (rc=%d)", rc);
        } else {
            (void)printf("SKIP keyfile: tighten vs symlink (cannot create a symlink here, error %lu)\n",
                         GetLastError());
        }
    }
    {
        char dd[1100];
        (void)snprintf(dd, sizeof(dd), "%s\\priv", dir);
        rc = zcl_keyfile_mkdir_private(dd, err, sizeof(err));
        ok = acl_user_only(dd, true, why, sizeof(why), &nace);
        check(rc == 0 && ok, "keyfile: mkdir_private makes a current-user-only directory (rc=%d aces=%d %s)", rc, nace,
              why);
        (void)snprintf(dd, sizeof(dd), "%s\\priv\\child.key", dir);
        rc = zcl_keyfile_write(dd, "x", 1, err, sizeof(err));
        ok = acl_user_only(dd, false, why, sizeof(why), &nace);
        check(rc == 0 && ok, "keyfile: file written in the private directory is current-user only (%s)", why);
    }
    rc = zcl_keyfile_write("C:\\nonexistent-dir\\zcl.key", "x", 1, err, sizeof(err));
    check(rc != 0 && err[0], "keyfile: write into a missing directory fails with a message");
    {
        /* non-ASCII file name through the UTF-8 API */
        char u[1100];
        (void)snprintf(u, sizeof(u), "%s\\k\xc3\xa9y-\xe9\xab\x98.key", dir);
        rc = zcl_keyfile_write(u, "uni", 3, err, sizeof(err));
        got = 0;
        check(rc == 0 && zcl_keyfile_read(u, buf, sizeof(buf), &got, NULL, 0) == 0 && got == 3,
              "keyfile: write and read a non-ASCII file name (%s)", err);
    }
}

/* ------------------------------------------------------------ offline */

static void test_start_failures(const char *tmp)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", dd[1100];
    int rc;

    memset(&o, 0, sizeof(o));
    (void)snprintf(dd, sizeof(dd), "%s\\does-not-exist", tmp);
    o.datadir = dd;
    o.disable_network = true;
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL && err[0], "start: missing datadir fails cleanly (%s)", err);

    (void)snprintf(dd, sizeof(dd), "%s\\badexe", tmp);
    (void)mkdir_utf8(dd);
    o.datadir = dd;
    o.exe_path = "C:\\nonexistent\\zcl-no-such-binary.exe";
    err[0] = '\0';
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL && err[0], "start: missing executable fails cleanly (%s)", err);

    o.exe_path = "C:\\Windows\\System32\\hostname.exe"; /* ignores its arguments badly and exits */
    err[0] = '\0';
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL && strstr(err, "exited"), "start: child that exits at once is reported (%s)", err);

    (void)snprintf(dd, sizeof(dd), "%s\\new\nline", tmp);
    /* CreateDirectory would reject the newline; the library must refuse it anyway */
    o.datadir = dd;
    o.exe_path = NULL;
    err[0] = '\0';
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc != 0 && h == NULL, "start: a newline in the datadir is refused, no torrc injection (%s)", err);
}

static void file_acl_checks(const zcl_tor_embed_info *info, const char *what)
{
    char t[1200], why[256];
    int nace = 0;
    bool ok;
    ok = acl_user_only(info->tor_dir, true, why, sizeof(why), &nace);
    check(ok, "%s: tor dir grants only the current user (aces=%d %s)", what, nace, why);
    ok = acl_user_only(info->cookie_path, false, why, sizeof(why), &nace);
    check(ok, "%s: control cookie grants only the current user (aces=%d %s)", what, nace, why);
    (void)snprintf(t, sizeof(t), "%s/torrc", info->tor_dir);
    ok = acl_user_only(t, true, why, sizeof(why), &nace);
    check(ok, "%s: torrc grants only the current user, protected single ACE (aces=%d %s)", what, nace, why);
}

/* A full start / control / stop cycle in `dd`; used for the plain and the
 * non-ASCII datadir. Returns 0 when the cycle ran. */
static int cycle_in(const char *dd, const char *what, bool addonion)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", reply[8192], id[128], cmd[1400];
    zcl_tor_sock c;
    unsigned long pid;
    int rc;

    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    o.disable_network = true;
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc == 0 && h, "%s: start (%s)", what, err);
    if (rc != 0 || !h) {
        char tor[1200];
        (void)snprintf(tor, sizeof(tor), "%s/tor", dd);
        dump_log(tor);
        return 1;
    }
    pid = (unsigned long)zcl_tor_embed_info_get(h)->pid;
    check(path_exists(zcl_tor_embed_info_get(h)->cookie_path), "%s: Tor wrote its cookie inside the datadir", what);
    rc = zcl_tor_control_open(h, &c, err, sizeof(err));
    check(rc == 0, "%s: control cookie authentication (%s)", what, err);
    if (rc == 0) {
        rc = zcl_tor_control_cmd(c, "GETINFO status/bootstrap-phase", reply, sizeof(reply), 5000);
        check(rc == 0 && strstr(reply, "PROGRESS="), "%s: bootstrap status readable", what);
        if (addonion) {
            id[0] = 0;
            rc = zcl_tor_control_cmd(c, "ADD_ONION NEW:ED25519-V3 Flags=DiscardPK Port=8333,127.0.0.1:8333", reply,
                                     sizeof(reply), 20000);
            check(rc == 0 && extract_value(reply, "ServiceID=", id, sizeof(id)) && strlen(id) == 56,
                  "%s: ADD_ONION returned a 56-character service id", what);
            (void)snprintf(cmd, sizeof(cmd), "DEL_ONION %s", id);
            if (id[0])
                (void)zcl_tor_control_cmd(c, cmd, reply, sizeof(reply), 5000);
        }
        zcl_tor_control_close(c);
    }
    rc = zcl_tor_embed_stop(h, 0);
    check(rc == 0 && wait_gone(pid, 10000), "%s: stop reaped the child", what);
    zcl_tor_embed_free(h);
    return 0;
}

static int run_offline(const char *tmp)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", dd[1100], keyp[1200], reply[8192], id[128], pk[1024], cmd[1400], why[256];
    const zcl_tor_embed_info *info;
    zcl_tor_sock c;
    unsigned long pid;
    int rc, nl = 0, nace = 0;
    bool hasp = false;
    uint64_t t0;

    (void)printf("== offline ==\n");
    test_keyfile(tmp);
    test_start_failures(tmp);

    (void)snprintf(dd, sizeof(dd), "%s\\node", tmp);
    (void)mkdir_utf8(dd); /* a loose datadir must not matter: <datadir>\tor is private */
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
    pid = (unsigned long)info->pid;
    check(pid > 0 && info->control_port > 0 && info->socks_port == 0,
          "info: pid=%lu control_port=%u socks_port=%u (0 expected with DisableNetwork)", pid,
          (unsigned)info->control_port, (unsigned)info->socks_port);
    check(zcl_tor_embed_alive(h) && ppid_of(pid) == (long)GetCurrentProcessId(),
          "child is alive and is our child (ppid=%ld, us=%lu)", ppid_of(pid), GetCurrentProcessId());
    file_acl_checks(info, "offline");

    rc = zcl_tor_control_open(h, &c, err, sizeof(err));
    check(rc == 0, "control: cookie authentication (%s)", err);
    if (rc != 0) {
        dump_log(info->tor_dir);
        zcl_tor_embed_free(h);
        return 1;
    }
    rc = zcl_tor_control_cmd(c, "GETINFO status/bootstrap-phase", reply, sizeof(reply), 5000);
    check(rc == 0 && strstr(reply, "PROGRESS="), "control: bootstrap status readable: %.100s", reply);
    rc = zcl_tor_control_cmd(c, "GETINFO version", reply, sizeof(reply), 5000);
    check(rc == 0 && strstr(reply, "version=0.4"), "control: GETINFO version -> %.40s", reply);

    rc = zcl_tor_control_cmd(c, "ADD_ONION NEW:ED25519-V3 Port=8333,127.0.0.1:8333", reply, sizeof(reply),
                             20000);
    id[0] = pk[0] = '\0';
    if (rc == 0)
        (void)extract_value(reply, "ServiceID=", id, sizeof(id));
    check(rc == 0 && strlen(id) == 56, "control: ADD_ONION NEW:ED25519-V3 returned a %zu-character service id",
          strlen(id));
    if (extract_value(reply, "PrivateKey=", pk, sizeof(pk))) {
        (void)snprintf(keyp, sizeof(keyp), "%s\\onion_v3_private_key", dd);
        rc = zcl_keyfile_write(keyp, pk, strlen(pk), err, sizeof(err));
        check(rc == 0 && acl_user_only(keyp, true, why, sizeof(why), &nace),
              "onion key written by keyfile is current-user only, one protected ACE (%s %s)", err, why);
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

    /* Datadir with spaces, accented Latin, CJK, Cyrillic and Greek; UTF-8
     * escapes keep this file free of source-encoding questions. */
    (void)snprintf(dd, sizeof(dd),
                   "%s\\w\xc3\xa9ird d\xc3\xafr \xe6\x97\xa5\xe6\x9c\xac\xe8\xaa\x9e "
                   "\xd0\xba\xd0\xb0\xd1\x82\xd0\xb0\xd0\xbb\xd0\xbe\xd0\xb3 "
                   "\xce\xb1\xce\xb2\xce\xb3 (x86)",
                   tmp);
    check(mkdir_utf8(dd), "fixture: datadir with space, accents, CJK, Cyrillic, Greek and parentheses");
    if (is_dir(dd)) {
        (void)printf("  datadir (UTF-8): %s\n", dd);
        if (cycle_in(dd, "unicode datadir", true) == 0) {
            /* restart in the same datadir: stale control_port and cookie replaced */
            (void)cycle_in(dd, "unicode datadir restart", false);
            {
                char t[1300];
                (void)snprintf(t, sizeof(t), "%s\\tor\\control_port", dd);
                check(path_exists(t), "unicode datadir: Tor created control_port inside it");
            }
        }
    }

    /* Forward slashes and a trailing-dot-free long-ish path, as boost would hand over. */
    {
        char dd2[1100], fwd[1100];
        size_t i;
        (void)snprintf(dd2, sizeof(dd2), "%s\\fwd slash", tmp);
        (void)mkdir_utf8(dd2);
        (void)snprintf(fwd, sizeof(fwd), "%s", dd2);
        for (i = 0; fwd[i]; i++) {
            if (fwd[i] == '\\')
                fwd[i] = '/';
        }
        (void)cycle_in(fwd, "forward-slash datadir", false);
    }
    return 0;
}

/* ----------------------------------------------------------------- orphan */

static int run_holder(const char *dd, const char *flag, const char *readyfile)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", line[64];
    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    o.disable_network = (strcmp(flag, "offline") == 0);
    if (zcl_tor_embed_start(&o, &h, err, sizeof(err)) != 0) {
        (void)fprintf(stderr, "holder: start failed: %s\n", err);
        return 1;
    }
    (void)snprintf(line, sizeof(line), "READY %ld\n", zcl_tor_embed_info_get(h)->pid);
    if (!write_plain(readyfile, line))
        return 1;
    for (;;)
        Sleep(INFINITE);
    return 0;
}

static int run_orphan(const char *tmp, const char *self)
{
    char dd[1100], ready[1200], line[128] = "", cmdline[4096];
    wchar_t *wself, *wcmd;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    unsigned long torpid = 0;
    uint64_t t0;
    DWORD code = 0;

    (void)printf("== orphan (TerminateProcess the parent) ==\n");
    (void)snprintf(dd, sizeof(dd), "%s\\orph\xc3\xa1n \xe6\x97\xa5", tmp);
    check(mkdir_utf8(dd), "fixture: orphan datadir (non-ASCII, with space)");
    (void)snprintf(ready, sizeof(ready), "%s\\ready.txt", tmp);
    (void)snprintf(cmdline, sizeof(cmdline), "\"%s\" holder \"%s\" offline \"%s\"", self, dd, ready);
    wself = wide(self);
    wcmd = wide(cmdline);
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!wself || !wcmd || !CreateProcessW(wself, wcmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        check(false, "spawn holder process (%lu)", GetLastError());
        free(wself);
        free(wcmd);
        return 1;
    }
    free(wself);
    free(wcmd);
    check(true, "spawned holder process %lu", pi.dwProcessId);
    t0 = zcl_tor_now_ms();
    while (zcl_tor_now_ms() - t0 < 60000) {
        size_t got = 0;
        if (zcl_keyfile_read(ready, line, sizeof(line) - 1, &got, NULL, 0) == 0 && got && memchr(line, '\n', got)) {
            line[got] = 0;
            break;
        }
        if (WaitForSingleObject(pi.hProcess, 0) == WAIT_OBJECT_0)
            break;
        zcl_tor_sleep_ms(100);
    }
    if (sscanf(line, "READY %lu", &torpid) != 1 || torpid == 0) {
        check(false, "holder reported its Tor child (got '%s')", line);
        (void)TerminateProcess(pi.hProcess, 9);
        (void)CloseHandle(pi.hProcess);
        (void)CloseHandle(pi.hThread);
        return 1;
    }
    check(!pid_gone(torpid) && ppid_of(torpid) == (long)pi.dwProcessId, "Tor child %lu is alive under holder %lu",
          torpid, pi.dwProcessId);
    check(TerminateProcess(pi.hProcess, 9) != 0, "TerminateProcess on the holder");
    (void)WaitForSingleObject(pi.hProcess, 5000);
    check(GetExitCodeProcess(pi.hProcess, &code) && code == 9, "holder was terminated (exit code %lu)", (unsigned long)code);
    (void)CloseHandle(pi.hProcess);
    (void)CloseHandle(pi.hThread);
    t0 = zcl_tor_now_ms();
    {
        bool gone = wait_gone(torpid, 10000);
        unsigned long long took = (unsigned long long)(zcl_tor_now_ms() - t0);
        check(gone, "Tor child exited by itself %llu ms after the parent was terminated", took);
        if (!gone) {
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)torpid);
            if (h) { /* keep the host clean */
                (void)TerminateProcess(h, 1);
                (void)CloseHandle(h);
            }
            return 1;
        }
    }
    return 0;
}

/* ----------------------------------------------------------------- online */

struct echo {
    SOCKET lfd;
    volatile LONG stop;
    volatile LONG bytes;
};

static DWORD WINAPI echo_main(LPVOID arg)
{
    struct echo *e = (struct echo *)arg;
    while (!e->stop) {
        fd_set rs;
        struct timeval tv;
        SOCKET c;
        FD_ZERO(&rs);
        FD_SET(e->lfd, &rs);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        if (select(0, &rs, NULL, NULL, &tv) <= 0)
            continue;
        c = accept(e->lfd, NULL, NULL);
        if (c == INVALID_SOCKET)
            continue;
        while (!e->stop) {
            char b[4096];
            int r, off = 0;
            fd_set q;
            FD_ZERO(&q);
            FD_SET(c, &q);
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
            if (select(0, &q, NULL, NULL, &tv) <= 0)
                continue;
            r = recv(c, b, sizeof(b), 0);
            if (r <= 0)
                break;
            while (off < r) {
                int w = send(c, b + off, r - off, 0);
                if (w <= 0)
                    break;
                off += w;
            }
            (void)InterlockedExchangeAdd(&e->bytes, r);
        }
        (void)closesocket(c);
    }
    return 0;
}

static bool read_full(SOCKET fd, void *buf, size_t n, int timeout_ms)
{
    size_t got = 0;
    uint64_t end = zcl_tor_now_ms() + (uint64_t)timeout_ms;
    while (got < n) {
        fd_set q;
        struct timeval tv;
        uint64_t now = zcl_tor_now_ms();
        int r;
        if (now >= end)
            return false;
        FD_ZERO(&q);
        FD_SET(fd, &q);
        tv.tv_sec = (long)((end - now) / 1000);
        tv.tv_usec = (long)(((end - now) % 1000) * 1000);
        if (select(0, &q, NULL, NULL, &tv) <= 0)
            return false;
        r = recv(fd, (char *)buf + got, (int)(n - got), 0);
        if (r <= 0)
            return false;
        got += (size_t)r;
    }
    return true;
}

static SOCKET socks5_connect(uint16_t socks, const char *host, uint16_t port, int *code)
{
    struct sockaddr_in a;
    unsigned char req[300], rep[10];
    size_t hl = strlen(host), n = 0;
    SOCKET fd = socket(AF_INET, SOCK_STREAM, 0);
    *code = -1;
    if (fd == INVALID_SOCKET)
        return INVALID_SOCKET;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(socks);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0)
        goto bad;
    req[0] = 5;
    req[1] = 1;
    req[2] = 0;
    if (send(fd, (char *)req, 3, 0) != 3 || !read_full(fd, rep, 2, 10000) || rep[0] != 5 || rep[1] != 0)
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
    if (send(fd, (char *)req, (int)n, 0) != (int)n || !read_full(fd, rep, 10, 90000))
        goto bad;
    *code = rep[1];
    if (rep[1] != 0)
        goto bad;
    return fd;
bad:
    (void)closesocket(fd);
    return INVALID_SOCKET;
}

static int run_online(const char *tmp)
{
    zcl_tor_embed *h = NULL;
    zcl_tor_embed_opts o;
    char err[256] = "", dd[1100], reply[4096], id[128], cmd[512], host[128];
    const zcl_tor_embed_info *info;
    zcl_tor_sock c;
    struct sockaddr_in a;
    int al = sizeof(a);
    struct echo e;
    HANDLE th;
    int rc, boot = 0, nl = 0, code = -1, attempts = 0;
    bool hasp;
    uint64_t t_start, t_boot, t_add, t_reach = 0;
    unsigned long pid;

    (void)printf("== online ==\n");
    (void)snprintf(dd, sizeof(dd), "%s\\online \xc3\xa9\xe6\x97\xa5", tmp);
    check(mkdir_utf8(dd), "fixture: online datadir (non-ASCII, with space)");
    memset(&o, 0, sizeof(o));
    o.datadir = dd;
    t_start = zcl_tor_now_ms();
    rc = zcl_tor_embed_start(&o, &h, err, sizeof(err));
    check(rc == 0 && h, "start with the network enabled (%s) in %llu ms", err,
          (unsigned long long)(zcl_tor_now_ms() - t_start));
    if (rc != 0 || !h)
        return 1;
    info = zcl_tor_embed_info_get(h);
    pid = (unsigned long)info->pid;
    check(info->socks_port > 0 && info->control_port > 0, "ports: socks=%u control=%u", (unsigned)info->socks_port,
          (unsigned)info->control_port);
    file_acl_checks(info, "online");

    rc = zcl_tor_embed_wait_bootstrap(h, 300000, &boot, err, sizeof(err));
    t_boot = zcl_tor_now_ms() - t_start;
    check(rc == 0 && boot == 100, "bootstrap reached %d%% (%s)", boot, err);
    (void)printf("TIME bootstrap_ms=%llu (from start)\n", (unsigned long long)t_boot);
    if (rc != 0) {
        dump_log(info->tor_dir);
        zcl_tor_embed_free(h);
        return 1;
    }

    memset(&e, 0, sizeof(e));
    e.lfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    th = NULL;
    if (e.lfd != INVALID_SOCKET && bind(e.lfd, (struct sockaddr *)&a, sizeof(a)) == 0 && listen(e.lfd, 4) == 0 &&
        getsockname(e.lfd, (struct sockaddr *)&a, &al) == 0)
        th = CreateThread(NULL, 0, echo_main, &e, 0, NULL);
    if (!th) {
        check(false, "echo listener setup (%d)", WSAGetLastError());
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
        (void)WaitForSingleObject(th, 5000);
        (void)closesocket(e.lfd);
        zcl_tor_embed_free(h);
        return 1;
    }
    (void)snprintf(host, sizeof(host), "%s.onion", id);

    /* The descriptor takes a while to reach the HSDirs; retry. */
    while (zcl_tor_now_ms() - t_add < 600000) {
        SOCKET fd = socks5_connect(info->socks_port, host, 80, &code);
        attempts++;
        if (fd != INVALID_SOCKET) {
            unsigned char out[4096], in[4096];
            size_t i;
            for (i = 0; i < sizeof(out); i++)
                out[i] = (unsigned char)((i * 131u + 7u) & 255u);
            if (send(fd, (char *)out, (int)sizeof(out), 0) == (int)sizeof(out) &&
                read_full(fd, in, sizeof(in), 30000) && memcmp(in, out, sizeof(out)) == 0) {
                t_reach = zcl_tor_now_ms();
                (void)closesocket(fd);
                break;
            }
            (void)closesocket(fd);
        }
        if (attempts % 5 == 1)
            (void)printf("  attempt %d: socks reply code %d, %llu s since ADD_ONION\n", attempts, code,
                         (unsigned long long)((zcl_tor_now_ms() - t_add) / 1000));
        zcl_tor_sleep_ms(2000);
    }
    check(t_reach != 0, "connected to <id>.onion through the SocksPort and exchanged 4096 bytes (%d attempts)",
          attempts);
    if (t_reach)
        (void)printf("TIME reachable_ms_after_add_onion=%llu reachable_ms_after_start=%llu echoed_bytes=%ld\n",
                     (unsigned long long)(t_reach - t_add), (unsigned long long)(t_reach - t_start), (long)e.bytes);

    rc = check_sockets(pid, info->control_port, true, &nl, &hasp);
    check(rc == 0 && hasp, "sockets: all listeners and UDP sockets loopback-only (%d listeners, violations=%d)", nl, rc);

    zcl_tor_control_close(c);
    e.stop = 1;
    (void)WaitForSingleObject(th, 5000);
    (void)CloseHandle(th);
    (void)closesocket(e.lfd);
    {
        uint64_t s0 = zcl_tor_now_ms();
        rc = zcl_tor_embed_stop(h, 0);
        check(rc == 0 && wait_gone(pid, 10000), "stop: child gone in %llu ms", (unsigned long long)(zcl_tor_now_ms() - s0));
    }
    zcl_tor_embed_free(h);
    return 0;
}

/* ------------------------------------------------------------------- main */

int main(int argc, char **argv)
{
    char tmp[1100], self[1100];
    const char *mode;
    int rc = 0, dr;
    WSADATA wsa;

    dr = zcl_tor_embed_dispatch(argc, argv);
    if (dr >= 0)
        return dr;
    (void)WSAStartup(MAKEWORD(2, 2), &wsa);
    mode = argc > 1 ? argv[1] : "all";
    if (zcl_tor_proc_self_exe(self, sizeof(self)) != 0) {
        (void)fprintf(stderr, "cannot resolve own path\n");
        return 2;
    }
    if (strcmp(mode, "holder") == 0 && argc >= 5)
        return run_holder(argv[2], argv[3], argv[4]);
    /* argv is ANSI on Windows; the holder arguments are re-read as UTF-16 */
    if (strcmp(mode, "holder") == 0) {
        int wc = 0, i;
        LPWSTR *wv = CommandLineToArgvW(GetCommandLineW(), &wc);
        char a[3][1100];
        if (!wv || wc < 5)
            return 2;
        for (i = 0; i < 3; i++) {
            if (!narrow(wv[2 + i], a[i], sizeof(a[i])))
                return 2;
        }
        return run_holder(a[0], a[1], a[2]);
    }
    if (make_tmp(tmp, sizeof(tmp)) != 0)
        return 2;
    (void)printf("tmp dir %s\n", tmp);
    if (strcmp(mode, "offline") == 0 || strcmp(mode, "all") == 0)
        rc |= run_offline(tmp);
    if (strcmp(mode, "orphan") == 0 || strcmp(mode, "all") == 0)
        rc |= run_orphan(tmp, self);
    if (strcmp(mode, "online") == 0)
        rc |= run_online(tmp);
    if (strcmp(mode, "offline") && strcmp(mode, "all") && strcmp(mode, "orphan") && strcmp(mode, "online")) {
        (void)fprintf(stderr, "usage: %s [offline|orphan|online|all]\n", argv[0]);
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
