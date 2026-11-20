#include "portprobe_win.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN   // windows.h must not pull <rpc.h>, which the wallet also names
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstring>

namespace {

// 1: bound (port free), 0: bind refused or failed (treat as busy), -1: this
// address family is not available on the host.
int exclusiveBind(int family, unsigned short port)
{
    SOCKET s = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET)
        return WSAGetLastError() == WSAEAFNOSUPPORT ? -1 : 0;
    int result = 0;
    BOOL on = TRUE;
    if (setsockopt(s, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&on), sizeof(on)) == 0) {
        if (family == AF_INET6) {
            DWORD v6only = 0;
            if (setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6only), sizeof(v6only)) != 0) {
                closesocket(s);
                return -1;   // no dual-stack socket: test IPv4 instead
            }
            sockaddr_in6 a;
            std::memset(&a, 0, sizeof(a));
            a.sin6_family = AF_INET6;
            a.sin6_addr = in6addr_any;
            a.sin6_port = htons(port);
            result = bind(s, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) == 0 ? 1 : 0;
        } else {
            sockaddr_in a;
            std::memset(&a, 0, sizeof(a));
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_ANY);
            a.sin_port = htons(port);
            result = bind(s, reinterpret_cast<const sockaddr*>(&a), sizeof(a)) == 0 ? 1 : 0;
        }
    }
    closesocket(s);
    return result;
}

} // namespace

bool windowsPortUnbound(unsigned short port)
{
    if (port == 0)
        return false;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        return false;
    int r = exclusiveBind(AF_INET6, port);
    if (r < 0)
        r = exclusiveBind(AF_INET, port);   // IPv6 disabled: IPv4 only
    WSACleanup();
    return r == 1;
}

#endif // _WIN32
