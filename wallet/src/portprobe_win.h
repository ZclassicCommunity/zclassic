#ifndef PORTPROBE_WIN_H
#define PORTPROBE_WIN_H

// Windows only, plain Winsock and no Qt, so the same file builds into a console
// check with the mingw cross compiler (see doc/restart-speed.md).
//
// True only when nothing at all is bound to TCP `port` on this host: an exclusive
// bind (SO_EXCLUSIVEADDRUSE) of the dual-stack wildcard [::] with IPV6_V6ONLY off
// succeeds. On Windows that bind fails against every listener on the port:
// 127.0.0.1, 0.0.0.0, [::] (dual-stack or v6-only), [::1], and the node's default
// pair 127.0.0.1 + [::1]. A host without IPv6 falls back to an exclusive bind of
// 0.0.0.0. Every other failure, including a port held in TIME_WAIT, returns
// false, which keeps the wallet's old getinfo probe. The socket never listens, so
// it raises no firewall prompt, and it is closed before returning.
bool windowsPortUnbound(unsigned short port);

#endif // PORTPROBE_WIN_H
