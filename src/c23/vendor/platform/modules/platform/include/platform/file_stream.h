/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Read-only stdio streams with atomic descriptor inheritance refusal. */
#ifndef ZCL_PLATFORM_FILE_STREAM_H
#define ZCL_PLATFORM_FILE_STREAM_H

#include <stdio.h>

/* Open path read-only.  The underlying descriptor/handle is never inherited
 * by a later exec/CreateProcess boundary.  The caller owns the returned
 * stream and closes it with fclose(). */
FILE *platform_file_stream_open_read(const char *path);

#endif
