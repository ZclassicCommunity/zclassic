/* Copyright (c) 2026 The ZClassic developers. MIT licence. */
#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#endif

#include "keyfile.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

static void kf_err(char *err, size_t errsz, const char *fmt, ...)
{
    va_list ap;
    if (!err || errsz == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errsz, fmt, ap);
    va_end(ap);
}

#ifndef _WIN32
/* ------------------------------------------------------------------ POSIX */

static int kf_split(const char *path, char *dir, size_t dirsz)
{
    const char *slash = strrchr(path, '/');
    size_t n;
    if (!slash) {
        if (dirsz < 2)
            return -1;
        dir[0] = '.';
        dir[1] = '\0';
        return 0;
    }
    n = (size_t)(slash - path);
    if (n == 0)
        n = 1; /* "/name": the directory is "/" */
    if (n >= dirsz)
        return -1;
    memcpy(dir, path, n);
    dir[n] = '\0';
    return 0;
}

static int kf_sync_dir(const char *path)
{
    char dir[1024];
    int fd, rc;
    if (kf_split(path, dir, sizeof(dir)) != 0)
        return -1;
    fd = open(dir, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    rc = fsync(fd);
    if (close(fd) != 0)
        rc = -1;
    return rc;
}

int zcl_keyfile_write(const char *path, const void *data, size_t len,
                      char *err, size_t errsz)
{
    char tmp[1100];
    const unsigned char *p = (const unsigned char *)data;
    size_t off = 0;
    int fd, n;

    if (!path || !path[0] || (!data && len > 0)) {
        kf_err(err, errsz, "keyfile write: bad arguments");
        return -1;
    }
    n = snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path);
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        kf_err(err, errsz, "keyfile write: path too long");
        return -1;
    }
    fd = mkstemp(tmp); /* created 0600 */
    if (fd < 0) {
        kf_err(err, errsz, "keyfile write: cannot create temp file next to %s: %s",
               path, strerror(errno));
        return -1;
    }
    if (fchmod(fd, 0600) != 0) {
        kf_err(err, errsz, "keyfile write: fchmod temp file: %s", strerror(errno));
        goto fail;
    }
    while (off < len) {
        ssize_t w = write(fd, p + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            kf_err(err, errsz, "keyfile write: write %s: %s", tmp, strerror(errno));
            goto fail;
        }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) {
        kf_err(err, errsz, "keyfile write: fsync %s: %s", tmp, strerror(errno));
        goto fail;
    }
    if (close(fd) != 0) {
        fd = -1;
        kf_err(err, errsz, "keyfile write: close %s: %s", tmp, strerror(errno));
        goto fail;
    }
    fd = -1;
    if (rename(tmp, path) != 0) {
        kf_err(err, errsz, "keyfile write: rename to %s: %s", path, strerror(errno));
        goto fail;
    }
    if (kf_sync_dir(path) != 0) {
        /* The file is in place with full contents; only the durability of
         * the directory entry is in doubt. Report it. */
        kf_err(err, errsz, "keyfile write: fsync directory of %s: %s", path,
               strerror(errno));
        return -1;
    }
    return 0;
fail:
    if (fd >= 0)
        (void)close(fd);
    (void)unlink(tmp);
    return -1;
}

int zcl_keyfile_tighten(const char *path, char *err, size_t errsz)
{
    struct stat st;
    int fd, rc = 0;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        if (errno == ENOENT)
            return 1;
        kf_err(err, errsz, "keyfile tighten: open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        kf_err(err, errsz, "keyfile tighten: fstat %s: %s", path, strerror(errno));
        rc = -1;
    } else if (!S_ISREG(st.st_mode)) {
        kf_err(err, errsz, "keyfile tighten: %s is not a regular file", path);
        rc = -1;
    } else if (st.st_uid != geteuid()) {
        kf_err(err, errsz, "keyfile tighten: %s is not owned by this user", path);
        rc = -1;
    } else if ((st.st_mode & 07777) != 0600 && fchmod(fd, 0600) != 0) {
        kf_err(err, errsz, "keyfile tighten: fchmod %s: %s", path, strerror(errno));
        rc = -1;
    }
    if (close(fd) != 0 && rc == 0) {
        kf_err(err, errsz, "keyfile tighten: close %s: %s", path, strerror(errno));
        rc = -1;
    }
    return rc;
}

int zcl_keyfile_read(const char *path, void *buf, size_t cap, size_t *len,
                     char *err, size_t errsz)
{
    unsigned char *b = (unsigned char *)buf;
    size_t off = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        kf_err(err, errsz, "keyfile read: open %s: %s", path, strerror(errno));
        return -1;
    }
    for (;;) {
        ssize_t r;
        if (off == cap) {
            unsigned char extra;
            r = read(fd, &extra, 1);
            if (r == 0)
                break;
            kf_err(err, errsz, "keyfile read: %s larger than %zu bytes", path, cap);
            (void)close(fd);
            return -1;
        }
        r = read(fd, b + off, cap - off);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            kf_err(err, errsz, "keyfile read: read %s: %s", path, strerror(errno));
            (void)close(fd);
            return -1;
        }
        if (r == 0)
            break;
        off += (size_t)r;
    }
    (void)close(fd);
    if (len)
        *len = off;
    return 0;
}

int zcl_keyfile_remove(const char *path, char *err, size_t errsz)
{
    if (unlink(path) != 0 && errno != ENOENT) {
        kf_err(err, errsz, "remove %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

int zcl_keyfile_mkdir_private(const char *path, char *err, size_t errsz)
{
    struct stat st;
    if (mkdir(path, 0700) == 0)
        return 0;
    if (errno != EEXIST) {
        kf_err(err, errsz, "mkdir %s: %s", path, strerror(errno));
        return -1;
    }
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        kf_err(err, errsz, "%s exists and is not a directory", path);
        return -1;
    }
    if (st.st_uid != geteuid()) {
        kf_err(err, errsz, "directory %s is not owned by this user", path);
        return -1;
    }
    if ((st.st_mode & 07777) != 0700 && chmod(path, 0700) != 0) {
        kf_err(err, errsz, "chmod %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

#else
/* ---------------------------------------------------------------- Windows */

static wchar_t *kf_wide(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, NULL, 0);
    wchar_t *w;
    if (n <= 0)
        return NULL;
    w = (wchar_t *)malloc((size_t)n * sizeof(wchar_t));
    if (!w)
        return NULL;
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s, -1, w, n) != n) {
        free(w);
        return NULL;
    }
    return w;
}

/* Build an SD whose protected DACL has exactly one ACE: full control for the
 * current user. `inherit` adds OI/CI for directories. Caller LocalFree()s. */
static PSECURITY_DESCRIPTOR kf_user_sd(int inherit, char *err, size_t errsz)
{
    HANDLE tok = NULL;
    DWORD need = 0;
    TOKEN_USER *tu = NULL;
    LPWSTR sidstr = NULL;
    wchar_t sddl[256];
    PSECURITY_DESCRIPTOR sd = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        kf_err(err, errsz, "OpenProcessToken failed (%lu)", GetLastError());
        return NULL;
    }
    (void)GetTokenInformation(tok, TokenUser, NULL, 0, &need);
    tu = (TOKEN_USER *)malloc(need ? need : 1);
    if (!tu || !GetTokenInformation(tok, TokenUser, tu, need, &need)) {
        kf_err(err, errsz, "GetTokenInformation failed (%lu)", GetLastError());
        goto out;
    }
    if (!ConvertSidToStringSidW(tu->User.Sid, &sidstr)) {
        kf_err(err, errsz, "ConvertSidToStringSid failed (%lu)", GetLastError());
        goto out;
    }
    if (swprintf(sddl, sizeof(sddl) / sizeof(sddl[0]), L"D:P(A;%ls;FA;;;%ls)",
                 inherit ? L"OICI" : L"", sidstr) < 0) {
        kf_err(err, errsz, "SDDL does not fit");
        goto out;
    }
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                              &sd, NULL)) {
        kf_err(err, errsz, "ConvertStringSecurityDescriptor failed (%lu)",
               GetLastError());
        sd = NULL;
    }
out:
    if (sidstr)
        LocalFree(sidstr);
    free(tu);
    CloseHandle(tok);
    return sd;
}

static int kf_apply_dacl(const wchar_t *wpath, int inherit, char *err, size_t errsz)
{
    PSECURITY_DESCRIPTOR sd = kf_user_sd(inherit, err, errsz);
    PACL dacl = NULL;
    BOOL present = FALSE, defaulted = FALSE;
    DWORD rc;
    if (!sd)
        return -1;
    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaulted) || !present) {
        kf_err(err, errsz, "security descriptor has no DACL");
        LocalFree(sd);
        return -1;
    }
    rc = SetNamedSecurityInfoW((LPWSTR)wpath, SE_FILE_OBJECT,
                               DACL_SECURITY_INFORMATION |
                                   PROTECTED_DACL_SECURITY_INFORMATION,
                               NULL, NULL, dacl, NULL);
    LocalFree(sd);
    if (rc != ERROR_SUCCESS) {
        kf_err(err, errsz, "SetNamedSecurityInfo failed (%lu)", rc);
        return -1;
    }
    return 0;
}

int zcl_keyfile_write(const char *path, const void *data, size_t len,
                      char *err, size_t errsz)
{
    wchar_t *wpath = NULL, *wtmp = NULL;
    size_t wl;
    PSECURITY_DESCRIPTOR sd = NULL;
    SECURITY_ATTRIBUTES sa;
    HANDLE h = INVALID_HANDLE_VALUE;
    const unsigned char *p = (const unsigned char *)data;
    size_t off = 0;
    int rc = -1;

    if (!path || !path[0] || (!data && len > 0)) {
        kf_err(err, errsz, "keyfile write: bad arguments");
        return -1;
    }
    wpath = kf_wide(path);
    if (!wpath) {
        kf_err(err, errsz, "keyfile write: path is not valid UTF-8");
        return -1;
    }
    wl = wcslen(wpath);
    wtmp = (wchar_t *)malloc((wl + 48) * sizeof(wchar_t));
    if (!wtmp) {
        kf_err(err, errsz, "keyfile write: out of memory");
        goto out;
    }
    (void)swprintf(wtmp, wl + 48, L"%ls.tmp.%lu.%lu", wpath, GetCurrentProcessId(),
                   GetTickCount());
    sd = kf_user_sd(0, err, errsz);
    if (!sd)
        goto out;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    h = CreateFileW(wtmp, GENERIC_WRITE, 0, &sa, CREATE_NEW,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        kf_err(err, errsz, "keyfile write: CreateFile temp failed (%lu)", GetLastError());
        goto out;
    }
    while (off < len) {
        DWORD chunk = (len - off > 0x100000u) ? 0x100000u : (DWORD)(len - off), w = 0;
        if (!WriteFile(h, p + off, chunk, &w, NULL) || w == 0) {
            kf_err(err, errsz, "keyfile write: WriteFile failed (%lu)", GetLastError());
            goto fail;
        }
        off += w;
    }
    if (!FlushFileBuffers(h)) {
        kf_err(err, errsz, "keyfile write: FlushFileBuffers failed (%lu)", GetLastError());
        goto fail;
    }
    if (!CloseHandle(h)) {
        h = INVALID_HANDLE_VALUE;
        kf_err(err, errsz, "keyfile write: CloseHandle failed (%lu)", GetLastError());
        goto fail;
    }
    h = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(wtmp, wpath, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        kf_err(err, errsz, "keyfile write: MoveFileEx failed (%lu)", GetLastError());
        goto fail;
    }
    /* A replaced file may keep the old DACL on some volumes; set it again. */
    if (kf_apply_dacl(wpath, 0, err, errsz) != 0)
        goto out;
    rc = 0;
    goto out;
fail:
    if (h != INVALID_HANDLE_VALUE)
        (void)CloseHandle(h);
    (void)DeleteFileW(wtmp);
out:
    if (sd)
        LocalFree(sd);
    free(wtmp);
    free(wpath);
    return rc;
}

int zcl_keyfile_tighten(const char *path, char *err, size_t errsz)
{
    wchar_t *wpath = kf_wide(path);
    DWORD attr;
    int rc;
    if (!wpath) {
        kf_err(err, errsz, "keyfile tighten: path is not valid UTF-8");
        return -1;
    }
    attr = GetFileAttributesW(wpath);
    if (attr == INVALID_FILE_ATTRIBUTES) {
        DWORD e = GetLastError();
        free(wpath);
        if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
            return 1;
        kf_err(err, errsz, "keyfile tighten: GetFileAttributes failed (%lu)", e);
        return -1;
    }
    if (attr & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) {
        free(wpath);
        kf_err(err, errsz, "keyfile tighten: %s is not a regular file", path);
        return -1;
    }
    rc = kf_apply_dacl(wpath, 0, err, errsz);
    free(wpath);
    return rc;
}

int zcl_keyfile_read(const char *path, void *buf, size_t cap, size_t *len,
                     char *err, size_t errsz)
{
    wchar_t *wpath = kf_wide(path);
    HANDLE h;
    size_t off = 0;
    unsigned char *b = (unsigned char *)buf;
    if (!wpath) {
        kf_err(err, errsz, "keyfile read: path is not valid UTF-8");
        return -1;
    }
    h = CreateFileW(wpath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wpath);
    if (h == INVALID_HANDLE_VALUE) {
        kf_err(err, errsz, "keyfile read: open failed (%lu)", GetLastError());
        return -1;
    }
    for (;;) {
        DWORD got = 0;
        unsigned char extra;
        if (off == cap) {
            if (!ReadFile(h, &extra, 1, &got, NULL) || got == 0)
                break;
            kf_err(err, errsz, "keyfile read: file larger than %zu bytes", cap);
            CloseHandle(h);
            return -1;
        }
        if (!ReadFile(h, b + off, (DWORD)(cap - off), &got, NULL)) {
            kf_err(err, errsz, "keyfile read: ReadFile failed (%lu)", GetLastError());
            CloseHandle(h);
            return -1;
        }
        if (got == 0)
            break;
        off += got;
    }
    CloseHandle(h);
    if (len)
        *len = off;
    return 0;
}

int zcl_keyfile_remove(const char *path, char *err, size_t errsz)
{
    wchar_t *wpath = kf_wide(path);
    DWORD e;
    if (!wpath) {
        kf_err(err, errsz, "remove: path is not valid UTF-8");
        return -1;
    }
    if (DeleteFileW(wpath)) {
        free(wpath);
        return 0;
    }
    e = GetLastError();
    free(wpath);
    if (e == ERROR_FILE_NOT_FOUND || e == ERROR_PATH_NOT_FOUND)
        return 0;
    kf_err(err, errsz, "remove failed (%lu)", e);
    return -1;
}

int zcl_keyfile_mkdir_private(const char *path, char *err, size_t errsz)
{
    wchar_t *wpath = kf_wide(path);
    PSECURITY_DESCRIPTOR sd;
    SECURITY_ATTRIBUTES sa;
    int rc = 0;
    if (!wpath) {
        kf_err(err, errsz, "mkdir: path is not valid UTF-8");
        return -1;
    }
    sd = kf_user_sd(1, err, errsz);
    if (!sd) {
        free(wpath);
        return -1;
    }
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = sd;
    sa.bInheritHandle = FALSE;
    if (!CreateDirectoryW(wpath, &sa)) {
        if (GetLastError() == ERROR_ALREADY_EXISTS)
            rc = kf_apply_dacl(wpath, 1, err, errsz);
        else {
            kf_err(err, errsz, "CreateDirectory failed (%lu)", GetLastError());
            rc = -1;
        }
    }
    LocalFree(sd);
    free(wpath);
    return rc;
}
#endif
