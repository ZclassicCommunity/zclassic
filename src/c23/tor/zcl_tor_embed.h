/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 *
 * Embedded Tor for zclassicd: run the Tor linked into this binary as a child
 * process (the binary re-executes itself with a private first argument) and
 * hand back the loopback Socks and control ports and the cookie path.
 *
 * The torrc body and the "Tor exits when its owner goes away" policy follow
 * Z23 (core/modules/net/src/tor_config_log.c, tor_integration.c; Apache-2.0,
 * (c) 2026 Rhett Creighton). The code here is new.
 *
 * Threading: one handle must be used by one thread at a time. Different
 * handles are independent.
 */
#ifndef ZCL_C23_TOR_EMBED_H
#define ZCL_C23_TOR_EMBED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The private first argument that selects the Tor child role. */
#define ZCL_TOR_EMBED_ARG "--zcl-embedded-tor"

typedef struct zcl_tor_embed zcl_tor_embed;

typedef struct {
    /* Node datadir. Must exist. Tor state lives in <datadir>/tor. UTF-8. */
    const char *datadir;
    /* Binary to re-execute as the Tor child. NULL means this process's own
     * binary (/proc/self/exe, GetModuleFileNameW). */
    const char *exe_path;
    /* DisableNetwork 1: control port and onion-service configuration work,
     * but no listener but control is opened and nothing touches the network.
     * Used by tests. */
    bool disable_network;
    /* How long start() waits for the control port (and, with the network
     * enabled, the Socks listener). 0 means 30000. */
    unsigned start_timeout_ms;
} zcl_tor_embed_opts;

typedef struct {
    long pid;                 /* child process id */
    uint16_t socks_port;      /* 127.0.0.1 Socks port; 0 when disable_network */
    uint16_t control_port;    /* 127.0.0.1 control port */
    char cookie_path[1024];   /* control_auth_cookie, mode 0600 */
    char tor_dir[1024];       /* <datadir>/tor */
} zcl_tor_embed_info;

/* Launch Tor. Returns 0 and a handle, or -1 with `err` filled. */
int zcl_tor_embed_start(const zcl_tor_embed_opts *opts, zcl_tor_embed **out,
                        char *err, size_t errsz);

/* Ports, pid and paths of a started handle. */
const zcl_tor_embed_info *zcl_tor_embed_info_get(const zcl_tor_embed *h);

/* True while the child is running. */
bool zcl_tor_embed_alive(zcl_tor_embed *h);

/* Wait until Tor reports bootstrap progress 100. Returns 0 when done, -1 on
 * timeout or child exit; `*progress` (optional) gets the last progress seen.
 * Returns -1 at once if disable_network was set. */
int zcl_tor_embed_wait_bootstrap(zcl_tor_embed *h, unsigned timeout_ms,
                                 int *progress, char *err, size_t errsz);

/* Stop Tor: control SIGNAL HALT, close the owner channel, then terminate and
 * kill if it has not exited. Idempotent. Returns 0 once the child is gone,
 * -1 if it could not be reaped within `timeout_ms` (0 means 10000). */
int zcl_tor_embed_stop(zcl_tor_embed *h, unsigned timeout_ms);

/* Free the handle (stops Tor first if still running). Safe on NULL. */
void zcl_tor_embed_free(zcl_tor_embed *h);

/* ------------------------------------------------------------ control port
 * Minimal authenticated control client over the cookie. `sock` is a socket
 * descriptor (SOCKET on Windows). */
typedef intptr_t zcl_tor_sock;
#define ZCL_TOR_BADSOCK ((zcl_tor_sock)-1)

int zcl_tor_control_open(const zcl_tor_embed *h, zcl_tor_sock *out,
                         char *err, size_t errsz);
/* Send one command line (without CRLF) and read the whole reply into
 * `reply` (NUL-terminated, CRLF kept). Returns 0 when the reply status is
 * 2xx, -1 otherwise (reply still filled when one was read). */
int zcl_tor_control_cmd(zcl_tor_sock sock, const char *cmd, char *reply,
                        size_t cap, unsigned timeout_ms);
void zcl_tor_control_close(zcl_tor_sock sock);

/* ---------------------------------------------------------------- dispatch
 * Call first thing in main(). If argv[1] is ZCL_TOR_EMBED_ARG this process is
 * the Tor child: it runs Tor and returns Tor's exit status (>= 0), which main
 * must return. Otherwise it returns -1 and main continues normally. */
int zcl_tor_embed_dispatch(int argc, char **argv);

#ifdef __cplusplus
}
#endif
#endif
