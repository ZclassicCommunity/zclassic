/* Copyright (c) 2026 The ZClassic developers. MIT licence.
 * Internal: run Tor on a thread of this process (tor_run_main), for
 * zcl_tor_embed's in-process mode. Tor allows one instance per process, so a
 * second start while one is running is refused. */
#ifndef ZCL_C23_TOR_INPROC_H
#define ZCL_C23_TOR_INPROC_H

#include <stdbool.h>
#include <stddef.h>

struct zcl_tor_inproc;

/* Start Tor with `tor_args` (the arguments after the program name). On POSIX
 * an owner channel is added (__OwningControllerFD): closing our end makes Tor
 * leave its main loop. Returns 0 and a handle, or -1 with `err` filled. */
int zcl_tor_inproc_start(struct zcl_tor_inproc **out,
                         const char *const *tor_args, size_t ntor_args,
                         char *err, size_t errsz);

/* True while an in-process Tor exists in this process (running or not yet
 * closed). */
bool zcl_tor_inproc_busy(void);

/* True while tor_run_main has not returned. */
bool zcl_tor_inproc_alive(struct zcl_tor_inproc *p);

/* Close the owner channel (POSIX). No-op on Windows, where Tor is stopped
 * with SIGNAL HALT on the control port. */
void zcl_tor_inproc_release_owner(struct zcl_tor_inproc *p);

/* Wait up to timeout_ms for tor_run_main to return and join the thread; true
 * once joined. */
bool zcl_tor_inproc_wait(struct zcl_tor_inproc *p, unsigned timeout_ms);

/* Free the handle. Only after zcl_tor_inproc_wait returned true; otherwise it
 * does nothing (a running Tor thread still uses the state). */
void zcl_tor_inproc_close(struct zcl_tor_inproc *p);

#endif
