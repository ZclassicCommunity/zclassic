/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: Open read-only stdio streams without an inheritable descriptor
 * window on POSIX or Windows. */
#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "platform/file_stream.h"
#include "base/safe_alloc.h"

#include <fcntl.h>

#ifdef _WIN32
#include <io.h>
#include <errno.h>
#include <stdlib.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

FILE *platform_file_stream_open_read(const char *path)
{
    if (!path || !path[0])
        return NULL;
#ifdef _WIN32
    int count = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path,
                                    -1, NULL, 0);
    if (count <= 0) { errno = EILSEQ; return NULL; }
    if (count > 32767) { errno = ENAMETOOLONG; return NULL; }
    wchar_t *wide = zcl_malloc((size_t)count * sizeof(*wide),
                               "file_stream_utf8_path");
    if (!wide) { errno = ENOMEM; return NULL; }
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1,
                             wide, count)) {
        free(wide);
        errno = EILSEQ;
        return NULL;
    }
    int fd = _wopen(wide, _O_RDONLY | _O_BINARY | _O_NOINHERIT);
    int saved_errno = errno;
    free(wide);
    errno = saved_errno;
    if (fd < 0)
        return NULL;
    FILE *stream = _fdopen(fd, "rb");
    if (!stream)
        (void)_close(fd);
#else
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    FILE *stream = fdopen(fd, "r");
    if (!stream)
        (void)close(fd);
#endif
    return stream;
}
