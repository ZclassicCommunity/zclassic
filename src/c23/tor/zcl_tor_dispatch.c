/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * Tor child entry point. Separate from zcl_tor_embed.c so only this file
 * needs tor_api.h and libtor.
 *
 * Child argv: <exe> --zcl-embedded-tor <keepfd|-> <tor args...>
 * It runs Tor's stock embedding API (tor_main_configuration_new,
 * tor_main_configuration_set_command_line, tor_run_main), the same calls Z23
 * makes on a thread (core/modules/net/src/tor_config_log.c), here in a
 * process of its own. */
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <shellapi.h>
#else
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE 1
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1 /* strict _POSIX_C_SOURCE hides O_NOFOLLOW etc. on Darwin */
#endif
#include <unistd.h>
#endif

#include "zcl_tor_embed.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <tor_api.h>

#ifndef _WIN32
/* The daemon may have leaked descriptors (sockets, wallet files) into this
 * process across exec. Tor needs none of them: close all but 0-2 and the
 * owner channel. */
static void close_inherited(int keep)
{
    long lim = sysconf(_SC_OPEN_MAX);
    long fd;
    if (lim < 0 || lim > 65536)
        lim = 65536;
    for (fd = 3; fd < lim; fd++) {
        if (fd != keep)
            (void)close((int)fd);
    }
}
#endif

static int run_tor(int ac, char **av)
{
    tor_main_configuration_t *cfg = tor_main_configuration_new();
    int rc;
    if (!cfg) {
        (void)fprintf(stderr, "zcl_tor_embed: tor_main_configuration_new failed\n");
        return 70;
    }
    if (tor_main_configuration_set_command_line(cfg, ac, av) != 0) {
        (void)fprintf(stderr, "zcl_tor_embed: set_command_line failed\n");
        tor_main_configuration_free(cfg);
        return 70;
    }
    rc = tor_run_main(cfg);
    tor_main_configuration_free(cfg);
    return rc < 0 ? 1 : rc;
}

#ifdef _WIN32
int zcl_tor_embed_dispatch(int argc, char **argv)
{
    LPWSTR *wv;
    int wc, i, rc;
    char **av;
    if (argc < 3 || strcmp(argv[1], ZCL_TOR_EMBED_ARG) != 0)
        return -1;
    /* Re-read the command line as UTF-16 so non-ASCII datadir paths survive. */
    wv = CommandLineToArgvW(GetCommandLineW(), &wc);
    if (!wv || wc < 4) {
        (void)fprintf(stderr, "zcl_tor_embed: cannot read command line\n");
        return 70;
    }
    av = (char **)calloc((size_t)wc, sizeof(char *));
    if (!av)
        return 70;
    av[0] = _strdup("tor");
    for (i = 3; i < wc; i++) {
        int n = WideCharToMultiByte(CP_UTF8, 0, wv[i], -1, NULL, 0, NULL, NULL);
        av[i - 2] = (n > 0) ? (char *)malloc((size_t)n) : NULL;
        if (!av[i - 2] ||
            WideCharToMultiByte(CP_UTF8, 0, wv[i], -1, av[i - 2], n, NULL, NULL) <= 0) {
            (void)fprintf(stderr, "zcl_tor_embed: bad argument\n");
            return 70; /* process exits; no need to free */
        }
    }
    rc = run_tor(wc - 2, av);
    LocalFree(wv);
    return rc;
}
#else
int zcl_tor_embed_dispatch(int argc, char **argv)
{
    char **av;
    int i, rc, keep = -1;
    if (argc < 4 || strcmp(argv[1], ZCL_TOR_EMBED_ARG) != 0)
        return -1;
    if (strcmp(argv[2], "-") != 0) {
        char *end = NULL;
        long v = strtol(argv[2], &end, 10);
        if (!end || *end || v < 3 || v > 65535) {
            (void)fprintf(stderr, "zcl_tor_embed: bad owner descriptor\n");
            return 70;
        }
        keep = (int)v;
    }
    close_inherited(keep);
    av = (char **)calloc((size_t)argc, sizeof(char *));
    if (!av)
        return 70;
    av[0] = (char *)"tor";
    for (i = 3; i < argc; i++)
        av[i - 2] = argv[i];
    rc = run_tor(argc - 2, av);
    free(av);
    return rc;
}
#endif
