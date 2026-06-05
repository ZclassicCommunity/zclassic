// Copyright (c) 2011-2021 The Bitcoin Core developers
// Copyright (c) 2026 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "mapport.h"

#include "compat.h"
#include "net.h"
#include "netbase.h"
#include "random.h"
#include "util.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <boost/bind.hpp>
#include <boost/thread.hpp>

// All platform socket headers (winsock2 on Windows, sys/socket.h etc. on POSIX)
// are pulled in transitively by compat.h, so no per-platform includes here.

// ---------------------------------------------------------------------------
// Protocol constants. We speak two protocols to the gateway:
//
//   - NAT-PMP (RFC 6886): UDP/5351, opcode 1 (UDP map) / 2 (TCP map). We only
//     ever map TCP (our P2P listener is TCP).
//   - PCP (RFC 6887): UDP/5351, MAP opcode, IPv4-mapped IPv6 addressing. PCP is
//     a strict superset that supersedes NAT-PMP; we try it as a fallback when
//     the gateway answers NAT-PMP with UNSUPPORTED VERSION.
//
// Both can ONLY map the requesting host's own address: the gateway derives the
// internal address from the UDP source of our request, so a node can never open
// a port for any host but itself. That is the whole security story.
// ---------------------------------------------------------------------------

namespace {

static const uint16_t PORT_MAPPING_PORT = 5351;       // NAT-PMP / PCP server port
static const uint8_t NATPMP_VERSION = 0;
static const uint8_t PCP_VERSION = 2;

// NAT-PMP opcodes (requests).
static const uint8_t NATPMP_OP_MAP_TCP = 2;
// NAT-PMP response opcode flag: server adds 128 to the request opcode.
static const uint8_t NATPMP_RESPONSE_FLAG = 128;
// NAT-PMP result codes we care about.
static const uint16_t NATPMP_RESULT_SUCCESS = 0;
static const uint16_t NATPMP_RESULT_UNSUPPORTED_VERSION = 1;

// PCP opcodes / result codes.
static const uint8_t PCP_OP_MAP = 1;
static const uint8_t PCP_RESPONSE_FLAG = 128; // R bit (top bit of the opcode octet)
static const uint8_t PCP_RESULT_SUCCESS = 0;
static const uint8_t PCP_RESULT_UNSUPP_VERSION = 1;

// Protocol number for TCP (used in the PCP MAP protocol field, IANA).
static const uint8_t IANA_PROTO_TCP = 6;

// Requested external-mapping lifetime, in seconds. We refresh well before this
// expires so the hole never closes while we are running.
static const uint32_t PORT_MAPPING_LEASE_SECONDS = 3600;       // 1 hour
static const int PORT_MAPPING_REANNOUNCE_SECONDS = 1200;       // refresh every 20 min
// How long to wait for a single datagram reply before giving up on this attempt.
static const int PORT_MAPPING_REPLY_TIMEOUT_MS = 1000;
// On total failure (no gateway / no answer), back off and retry on this cadence.
static const int PORT_MAPPING_RETRY_SECONDS = 600;             // 10 min

// ---------------------------------------------------------------------------
// Worker-thread lifecycle. We deliberately do NOT rely on boost thread
// interruption points for the wait: a raw recv()/sleep is not an interruption
// point, and that is exactly how a shutdown hang would creep in. Instead the
// loop waits on an interruptible condition variable that InterruptMapPort()
// notifies, and every blocking syscall is bounded by a short timeout. This is
// the #1 risk called out in the task, so it is handled explicitly.
// ---------------------------------------------------------------------------
static boost::thread g_mapport_thread;
static boost::mutex g_mapport_mutex;
static boost::condition_variable g_mapport_cv;
static bool g_mapport_interrupt = false;

// Interruptible sleep: returns true if we were asked to stop while waiting.
// Uses timed_wait + posix_time to match net.cpp's proven idiom and dodge the
// cv_status/void wait_for overload ambiguity that bites on some boost versions
// (see the note in scheduler.cpp). A notify from InterruptMapPort() wakes it
// immediately; a spurious wakeup just re-checks the flag and loops harmlessly.
static bool MapPortInterruptibleSleep(int seconds)
{
    boost::unique_lock<boost::mutex> lock(g_mapport_mutex);
    if (g_mapport_interrupt) return true;
    g_mapport_cv.timed_wait(lock,
        boost::posix_time::microsec_clock::universal_time() +
        boost::posix_time::seconds(seconds));
    return g_mapport_interrupt;
}

static bool MapPortShouldStop()
{
    boost::unique_lock<boost::mutex> lock(g_mapport_mutex);
    return g_mapport_interrupt;
}

// ---------------------------------------------------------------------------
// Default-gateway discovery (Linux/BSD). We need the gateway IPv4 address to
// address our unicast NAT-PMP/PCP request. On Linux we parse /proc/net/route;
// elsewhere we fall back to a UDP-connect trick to learn our own egress
// interface address and assume the gateway is the .1 of that /24 only as a last
// resort. On failure we simply skip the attempt and retry later — never fatal.
// ---------------------------------------------------------------------------
static bool GetDefaultGateway(struct in_addr& gateway_out)
{
#ifdef __linux__
    // /proc/net/route columns: Iface Destination Gateway Flags ...
    // The default route is the row whose Destination is 00000000. Gateway is a
    // little-endian hex IPv4. We read the file with stdio to avoid pulling in
    // rtnetlink here.
    FILE* f = fopen("/proc/net/route", "r");
    if (!f) return false;
    char line[256];
    bool found = false;
    // Skip header line.
    if (fgets(line, sizeof(line), f) == NULL) { fclose(f); return false; }
    while (fgets(line, sizeof(line), f) != NULL) {
        char iface[64];
        unsigned long dest = 0, gw = 0, flags = 0;
        // iface dest gateway flags refcnt use metric mask ...
        int n = sscanf(line, "%63s %lx %lx %lx", iface, &dest, &gw, &flags);
        if (n < 4) continue;
        // RTF_UP (0x1) and RTF_GATEWAY (0x2) and the all-zero destination.
        if (dest == 0 && (flags & 0x1) && (flags & 0x2) && gw != 0) {
            // gw is in network byte order already as stored by the kernel
            // (little-endian-host hex of the in_addr, i.e. already net order
            // when read into an unsigned long on LE hosts). Assign directly.
            gateway_out.s_addr = (uint32_t)gw;
            found = true;
            break;
        }
    }
    fclose(f);
    return found;
#else
    // Portable best-effort fallback: discover our egress interface address by
    // UDP-connecting to a public address (no packets are sent by connect() on a
    // datagram socket) and reading back the chosen local address, then assume
    // the gateway is x.x.x.1 of that subnet. This is a heuristic only.
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return false;
    struct sockaddr_in probe;
    memset(&probe, 0, sizeof(probe));
    probe.sin_family = AF_INET;
    probe.sin_port = htons(53);
    probe.sin_addr.s_addr = htonl(0x08080808); // 8.8.8.8, never actually contacted
    if (connect(s, (struct sockaddr*)&probe, sizeof(probe)) != 0) { CloseSocket(s); return false; }
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(s, (struct sockaddr*)&local, &local_len) != 0) { CloseSocket(s); return false; }
    CloseSocket(s);
    uint32_t host = ntohl(local.sin_addr.s_addr);
    host = (host & 0xFFFFFF00u) | 0x01u; // .1 of the local /24
    gateway_out.s_addr = htonl(host);
    return true;
#endif
}

// Open a connected UDP socket to gateway:5351 with a short receive timeout, and
// also report the local address the kernel bound (that is the internal address
// the gateway will map). Returns -1 on failure.
static SOCKET OpenGatewaySocket(const struct in_addr& gateway, struct in_addr& local_out)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(PORT_MAPPING_PORT);
    dst.sin_addr = gateway;
    if (connect(s, (struct sockaddr*)&dst, sizeof(dst)) != 0) {
        CloseSocket(s);
        return INVALID_SOCKET;
    }

    // Learn the local address chosen for this route — this is exactly the
    // internal address the gateway is allowed to map (self-only).
    struct sockaddr_in local;
    socklen_t local_len = sizeof(local);
    if (getsockname(s, (struct sockaddr*)&local, &local_len) != 0) {
        CloseSocket(s);
        return INVALID_SOCKET;
    }
    local_out = local.sin_addr;

#ifdef WIN32
    DWORD tv = PORT_MAPPING_REPLY_TIMEOUT_MS;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
    struct timeval tv;
    tv.tv_sec = PORT_MAPPING_REPLY_TIMEOUT_MS / 1000;
    tv.tv_usec = (PORT_MAPPING_REPLY_TIMEOUT_MS % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#endif
    return s;
}

static void PutUint16BE(unsigned char* p, uint16_t v) { p[0] = (v >> 8) & 0xff; p[1] = v & 0xff; }
static void PutUint32BE(unsigned char* p, uint32_t v) { p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff; p[2] = (v >> 8) & 0xff; p[3] = v & 0xff; }
static uint16_t GetUint16BE(const unsigned char* p) { return (uint16_t(p[0]) << 8) | uint16_t(p[1]); }
static uint32_t GetUint32BE(const unsigned char* p) { return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | uint32_t(p[3]); }

// Advertise a successfully mapped external address so peers learn how to reach
// us, mirroring how the old UPnP path used the (now unused) LOCAL_UPNP slot.
static void AdvertiseMappedAddress(uint32_t external_ip_net_order, uint16_t external_port)
{
    if (external_ip_net_order == 0 || external_port == 0) return;
    struct in_addr ext;
    ext.s_addr = external_ip_net_order;
    CService extService(ext, external_port);
    if (extService.IsRoutable()) {
        AddLocal(extService, LOCAL_UPNP);
        LogPrintf("mapport: external address %s announced via port mapping\n", extService.ToString());
    }
}

// ---------------------------------------------------------------------------
// NAT-PMP: send a MAP-TCP request and parse the reply. Returns:
//    1  = success (and fills external_port/external_ip)
//    0  = gateway answered but does not support NAT-PMP (caller should try PCP)
//   -1  = transport failure / no answer
// ---------------------------------------------------------------------------
static int NatpmpMap(SOCKET s, uint16_t internal_port, uint16_t& external_port, uint32_t& external_ip)
{
    // Request layout (RFC 6886 §3.3): ver(0) op(2) reserved(2) intport(2)
    //   suggested-extport(2) lease(4)
    unsigned char req[12];
    memset(req, 0, sizeof(req));
    req[0] = NATPMP_VERSION;
    req[1] = NATPMP_OP_MAP_TCP;
    // req[2..3] reserved = 0
    PutUint16BE(req + 4, internal_port);
    PutUint16BE(req + 6, internal_port); // suggest same external port
    PutUint32BE(req + 8, PORT_MAPPING_LEASE_SECONDS);

    if (send(s, (const char*)req, sizeof(req), 0) != (int)sizeof(req))
        return -1;

    unsigned char resp[16];
    int got = recv(s, (char*)resp, sizeof(resp), 0);
    if (got < 16)
        return -1; // timeout or short read -> transport failure

    if (resp[0] != NATPMP_VERSION)
        return -1;
    uint16_t result = GetUint16BE(resp + 2);
    // Check the result code BEFORE being strict about the echoed opcode: a
    // gateway rejecting the version may not echo a meaningful opcode, and we
    // want that case to fall through to PCP rather than be treated as garbage.
    if (result == NATPMP_RESULT_UNSUPPORTED_VERSION)
        return 0; // let the caller fall back to PCP
    if (resp[1] != (NATPMP_OP_MAP_TCP | NATPMP_RESPONSE_FLAG)) {
        // Not the MAP response we expected.
        return -1;
    }
    if (result != NATPMP_RESULT_SUCCESS)
        return -1;

    // resp: ver op result epoch(4) intport(2) extport(2) lease(4)
    external_port = GetUint16BE(resp + 10);

    // NAT-PMP success does not include the external IP in the MAP response;
    // a separate opcode-0 query would be required. We leave external_ip at 0
    // and rely on normal peer-side address discovery; the hole is open, which
    // is what matters. (Setting external_ip=0 simply skips local advertisement.)
    external_ip = 0;
    return 1;
}

// ---------------------------------------------------------------------------
// PCP: send a MAP request (RFC 6887 §11) and parse the reply. PCP carries the
// internal client address (IPv4-mapped IPv6) and a per-mapping nonce, and the
// success reply DOES include the assigned external address. Returns 1/0/-1 as
// NatpmpMap.
// ---------------------------------------------------------------------------
static int PcpMap(SOCKET s, const struct in_addr& internal_ip, uint16_t internal_port,
                  uint16_t& external_port, uint32_t& external_ip)
{
    // PCP request common header (24 bytes) + MAP opcode body (36 bytes) = 60.
    //   ver(1) R|opcode(1) reserved(2) lifetime(4) client-ip(16)
    //   mapping-nonce(12) protocol(1) reserved(3) internal-port(2)
    //   suggested-external-port(2) suggested-external-ip(16)
    unsigned char req[60];
    memset(req, 0, sizeof(req));
    req[0] = PCP_VERSION;
    req[1] = PCP_OP_MAP;             // R bit clear (request)
    PutUint32BE(req + 4, PORT_MAPPING_LEASE_SECONDS);

    // Client IP as IPv4-mapped IPv6: ::ffff:a.b.c.d
    req[8 + 10] = 0xff;
    req[8 + 11] = 0xff;
    memcpy(req + 8 + 12, &internal_ip.s_addr, 4);

    // 96-bit mapping nonce — random, per RFC, used by the server to match the
    // mapping. Use GetRandBytes (NOT GetStrongRandBytes; that symbol does not
    // exist in this codebase and would be a compile blocker).
    unsigned char nonce[12];
    GetRandBytes(nonce, sizeof(nonce));
    memcpy(req + 24, nonce, 12);

    req[36] = IANA_PROTO_TCP;
    // req[37..39] reserved
    PutUint16BE(req + 40, internal_port);
    PutUint16BE(req + 42, internal_port); // suggested external port
    // req[44..59] suggested external IP = 0 (let the gateway choose)

    if (send(s, (const char*)req, sizeof(req), 0) != (int)sizeof(req))
        return -1;

    unsigned char resp[1100];
    int got = recv(s, (char*)resp, sizeof(resp), 0);
    if (got < 60)
        return -1; // timeout or short -> transport failure

    if (resp[0] != PCP_VERSION)
        return -1;
    if (resp[1] != (PCP_OP_MAP | PCP_RESPONSE_FLAG))
        return -1;
    uint8_t result = resp[3];
    if (result == PCP_RESULT_UNSUPP_VERSION)
        return 0;
    if (result != PCP_RESULT_SUCCESS)
        return -1;

    // Response MAP body begins at packet offset 24. Field offsets RELATIVE to
    // that body start (RFC 6887 §11.1, mirroring the request layout exactly):
    //   mapping-nonce(12)            body off 0   -> packet 24
    //   protocol(1)                  body off 12  -> packet 36
    //   reserved(3)                  body off 13  -> packet 37
    //   internal-port(2)             body off 16  -> packet 40
    //   assigned-external-port(2)    body off 18  -> packet 42
    //   assigned-external-ip(16)     body off 20  -> packet 44
    if (memcmp(resp + 24, nonce, 12) != 0)
        return -1; // nonce mismatch: not our mapping
    // assigned-external-port is at body offset 18 (packet 42), NOT 16 (that is
    // the echoed internal-port). Matches the request side's ext-port@40-42.
    external_port = GetUint16BE(resp + 24 + 18);

    // Assigned external IP: an IPv4-mapped IPv6 (::ffff:a.b.c.d) for IPv4,
    // at body offset 20 (packet 44).
    const unsigned char* ext = resp + 24 + 20;
    static const unsigned char v4mapped_prefix[12] =
        {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
    if (memcmp(ext, v4mapped_prefix, 12) == 0) {
        memcpy(&external_ip, ext + 12, 4);
    } else {
        external_ip = 0;
    }
    return 1;
}

// One full mapping attempt: discover gateway, open socket, try NAT-PMP, then
// fall back to PCP whenever NAT-PMP did not succeed (UNSUPPORTED_VERSION OR no
// reply -- many PCP-only/CGNAT routers silently drop the legacy NAT-PMP
// datagram). Returns true if a mapping was established.
static bool TryMapOnce()
{
    const uint16_t port = (uint16_t)GetListenPort();
    if (port == 0) return false;

    struct in_addr gateway;
    memset(&gateway, 0, sizeof(gateway));
    if (!GetDefaultGateway(gateway)) {
        LogPrint("net", "mapport: no default gateway found; skipping\n");
        return false;
    }

    struct in_addr local;
    memset(&local, 0, sizeof(local));
    SOCKET s = OpenGatewaySocket(gateway, local);
    if (s == INVALID_SOCKET) {
        LogPrint("net", "mapport: could not open socket to gateway\n");
        return false;
    }

    uint16_t external_port = 0;
    uint32_t external_ip = 0;

    int r = NatpmpMap(s, port, external_port, external_ip);
    if (r <= 0) {
        // Fall back to PCP whenever legacy NAT-PMP did NOT succeed: r==0 is an
        // explicit UNSUPPORTED_VERSION, but r==-1 (no reply / recv timeout /
        // non-MAP opcode) is the common case for PCP-only, CGNAT and IPv6-era
        // routers that simply DROP a legacy NAT-PMP v0 datagram. Those gateways
        // would never answer NAT-PMP yet will honor PCP, so always try PCP on the
        // same already-connected socket before giving up. Still pure net plumbing,
        // still maps only our own listen port; PcpMap is bounds-checked the same
        // way and verifies the per-mapping nonce before trusting any reply.
        external_port = 0;
        external_ip = 0;
        r = PcpMap(s, local, port, external_port, external_ip);
        if (r == 1)
            LogPrintf("mapport: PCP mapped external port %u -> internal %u\n",
                      (unsigned)external_port, (unsigned)port);
    } else if (r == 1) {
        LogPrintf("mapport: NAT-PMP mapped external port %u -> internal %u\n",
                  (unsigned)external_port, (unsigned)port);
    }

    CloseSocket(s);

    if (r == 1) {
        AdvertiseMappedAddress(external_ip, external_port);
        return true;
    }
    return false;
}

// The worker loop. Refreshes on PORT_MAPPING_REANNOUNCE_SECONDS while a mapping
// is healthy, and falls back to PORT_MAPPING_RETRY_SECONDS when no gateway/no
// answer. EVERY wait is via MapPortInterruptibleSleep so the thread exits
// promptly on InterruptMapPort() — there is no unbounded blocking call.
static void ThreadMapPort()
{
    LogPrintf("mapport: port mapping thread started (mapping port %u)\n",
              (unsigned)GetListenPort());
    while (!MapPortShouldStop()) {
        bool ok = false;
        try {
            ok = TryMapOnce();
        } catch (const std::exception& e) {
            LogPrintf("mapport: attempt failed: %s\n", e.what());
            ok = false;
        }
        // Sleep until the next refresh (if healthy) or the next retry (if not).
        int wait = ok ? PORT_MAPPING_REANNOUNCE_SECONDS : PORT_MAPPING_RETRY_SECONDS;
        if (MapPortInterruptibleSleep(wait))
            break;
    }
    LogPrintf("mapport: port mapping thread exiting\n");
}

} // anonymous namespace

void StartMapPort(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    (void)threadGroup; // worker is privately joined for a deterministic shutdown
    (void)scheduler;
    {
        boost::unique_lock<boost::mutex> lock(g_mapport_mutex);
        g_mapport_interrupt = false;
    }
    if (g_mapport_thread.joinable()) {
        // Already running; nothing to do.
        return;
    }
    g_mapport_thread = boost::thread(
        boost::bind(&TraceThread<void (*)()>, "mapport", &ThreadMapPort));
}

void InterruptMapPort()
{
    {
        boost::unique_lock<boost::mutex> lock(g_mapport_mutex);
        g_mapport_interrupt = true;
    }
    // Wake the worker out of its interruptible sleep right away.
    g_mapport_cv.notify_all();
}

void StopMapPort()
{
    if (g_mapport_thread.joinable()) {
        // InterruptMapPort() must have been called first; notify again to be
        // safe in case Stop is called without a preceding Interrupt.
        {
            boost::unique_lock<boost::mutex> lock(g_mapport_mutex);
            g_mapport_interrupt = true;
        }
        g_mapport_cv.notify_all();
        g_mapport_thread.join();
        g_mapport_thread = boost::thread(); // reset to a non-joinable handle
    }
}
