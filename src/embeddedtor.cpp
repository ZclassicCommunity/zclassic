// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "embeddedtor.h"

#include "httpserver.h"
#include "init.h"
#include "netbase.h"
#include "scheduler.h"
#include "sync.h"
#include "torcontrol.h"
#include "util.h"
#include "utiltime.h"

#include <atomic>

#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <boost/thread.hpp>

#ifdef ENABLE_EMBEDDED_TOR
#include "c23/tor/zcl_tor_embed.h"
#endif

// Release default: Tor in its own process where this build can start it (Linux, via
// /proc/self/exe), so a Tor assert or memory bug cannot abort or read the process that
// holds the wallet, and a Tor crash costs only the onion side: the restart driver below
// starts it again. Elsewhere (mingw, macOS) the in-process mode, which needs no exe path.
#if defined(__linux__)
const char* const DEFAULT_EMBEDDED_TOR_MODE = "child";
#else
const char* const DEFAULT_EMBEDDED_TOR_MODE = "inprocess";
#endif

bool EmbeddedTorOnionOnlyRequested()
{
    if (!GetBoolArg("-embeddedtor", DEFAULT_EMBEDDED_TOR))
        return false;
    std::map<std::string, std::vector<std::string> >::const_iterator it = mapMultiArgs.find("-onlynet");
    if (it == mapMultiArgs.end() || it->second.empty())
        return false;
    BOOST_FOREACH(const std::string& snet, it->second) {
        enum Network net = ParseNetwork(snet);
        if (net == NET_IPV4 || net == NET_IPV6)
            return false;
    }
    return true;
}

bool ParseEmbeddedTorMode(const std::string& str, EmbeddedTorMode& mode)
{
    if (str == "inprocess") {
        mode = EMBEDDED_TOR_INPROCESS;
        return true;
    }
    if (str == "child") {
        mode = EMBEDDED_TOR_CHILD;
        return true;
    }
    return false;
}

// ---------------------------------------------------------------- the instance
//
// Readers (net, torcontrol, RPC, the watchdog) take cs_embeddedTor for a
// moment. Start and stop are serialised by cs_embeddedTorLifecycle and do the
// slow part (up to the 30 s start timeout, the 15 s stop timeout) without
// cs_embeddedTor, so a restart never stalls a reader. The handle is published
// only once started and taken out before it is stopped, so the alive check and
// a stop never use it at the same time.

#ifdef ENABLE_EMBEDDED_TOR

static CCriticalSection cs_embeddedTorLifecycle;
static CCriticalSection cs_embeddedTor;
static zcl_tor_embed* g_embeddedTor = NULL;
static uint16_t g_socksPort = 0;
static uint16_t g_controlPort = 0;
static std::string g_cookiePath;
static long g_childPid = 0;
static bool g_inProcess = false;
static std::string g_testExePath;        // guarded by cs_embeddedTorLifecycle
static bool g_testDisableNetwork = false; // guarded by cs_embeddedTorLifecycle

bool EmbeddedTorAvailable()
{
    return true;
}

int EmbeddedTorDispatch(int argc, char* argv[])
{
    return zcl_tor_embed_dispatch(argc, argv);
}

void SetEmbeddedTorTestOptions(const std::string& exePath, bool disableNetwork)
{
    LOCK(cs_embeddedTorLifecycle);
    g_testExePath = exePath;
    g_testDisableNetwork = disableNetwork;
}

static void PublishEmbeddedTor(zcl_tor_embed* h, bool inProcess)
{
    const zcl_tor_embed_info* info = zcl_tor_embed_info_get(h);
    LOCK(cs_embeddedTor);
    g_embeddedTor = h;
    g_inProcess = inProcess;
    g_socksPort = info->socks_port;
    g_controlPort = info->control_port;
    g_cookiePath = info->cookie_path;
    g_childPid = info->pid;
}

bool StartEmbeddedTor(const std::string& datadir, EmbeddedTorMode mode, std::string& strError)
{
    LOCK(cs_embeddedTorLifecycle);
    if (EmbeddedTorRunning()) {
        strError = "embedded Tor is already running";
        return false;
    }
    zcl_tor_embed_opts opts = zcl_tor_embed_opts();
    opts.datadir = datadir.c_str();
    opts.in_process = (mode == EMBEDDED_TOR_INPROCESS);
    opts.exe_path = g_testExePath.empty() ? NULL : g_testExePath.c_str();
    opts.disable_network = g_testDisableNetwork;
    char err[256] = "";
    zcl_tor_embed* h = NULL;
    int64_t nStart = GetTimeMillis();
    const bool ok = zcl_tor_embed_start(&opts, &h, err, sizeof(err)) == 0 && h;
    // In-process Tor redirects libevent's log callback while it starts.
    if (opts.in_process)
        RestoreLibeventLogging();
    if (!ok) {
        strError = err;
        return false;
    }
    PublishEmbeddedTor(h, opts.in_process);
    const zcl_tor_embed_info* info = zcl_tor_embed_info_get(h);
    LogPrintf("tor: embedded Tor started (%s, %s) in %dms: SOCKS 127.0.0.1:%u, control 127.0.0.1:%u, state in %s\n",
              opts.in_process ? "in-process" : "child process",
              opts.in_process ? "thread" : strprintf("pid %d", (int)info->pid),
              GetTimeMillis() - nStart, info->socks_port, info->control_port, info->tor_dir);
    return true;
}

/** Take the handle out of the published state; NULL when nothing runs. */
static zcl_tor_embed* UnpublishEmbeddedTor(bool& inProcess)
{
    LOCK(cs_embeddedTor);
    zcl_tor_embed* h = g_embeddedTor;
    inProcess = g_inProcess;
    g_embeddedTor = NULL;
    g_socksPort = 0;
    g_controlPort = 0;
    g_cookiePath.clear();
    g_childPid = 0;
    return h;
}

void StopEmbeddedTor()
{
    LOCK(cs_embeddedTorLifecycle);
    bool inProcess = false;
    zcl_tor_embed* h = UnpublishEmbeddedTor(inProcess);
    if (!h)
        return;
    int64_t nStart = GetTimeMillis();
    if (zcl_tor_embed_stop(h, 15000) == 0) {
        zcl_tor_embed_free(h);
        LogPrintf("tor: embedded Tor stopped in %dms\n", GetTimeMillis() - nStart);
    } else {
        // The handle is left allocated: Tor still uses the state behind it.
        LogPrintf("tor: embedded Tor did not stop within 15s\n");
    }
    if (inProcess)
        RestoreLibeventLogging();
}

std::string EmbeddedTorCookiePath()
{
    LOCK(cs_embeddedTor);
    return g_cookiePath;
}

bool EmbeddedTorAlive()
{
    LOCK(cs_embeddedTor);
    return g_embeddedTor != NULL && zcl_tor_embed_alive(g_embeddedTor);
}

bool EmbeddedTorRunning()
{
    LOCK(cs_embeddedTor);
    return g_embeddedTor != NULL;
}

uint16_t EmbeddedTorSocksPort()
{
    LOCK(cs_embeddedTor);
    return g_socksPort;
}

uint16_t EmbeddedTorControlPort()
{
    LOCK(cs_embeddedTor);
    return g_controlPort;
}

long EmbeddedTorChildPid()
{
    LOCK(cs_embeddedTor);
    return g_childPid;
}

#else // !ENABLE_EMBEDDED_TOR

bool EmbeddedTorAvailable()
{
    return false;
}

int EmbeddedTorDispatch(int, char*[])
{
    return -1;
}

void SetEmbeddedTorTestOptions(const std::string&, bool)
{
}

bool StartEmbeddedTor(const std::string&, EmbeddedTorMode, std::string& strError)
{
    strError = "this binary was built without embedded Tor (configure --with-embedded-tor)";
    return false;
}

void StopEmbeddedTor()
{
}

bool EmbeddedTorRunning()
{
    return false;
}

uint16_t EmbeddedTorSocksPort()
{
    return 0;
}

uint16_t EmbeddedTorControlPort()
{
    return 0;
}

std::string EmbeddedTorCookiePath()
{
    return std::string();
}

bool EmbeddedTorAlive()
{
    return false;
}

long EmbeddedTorChildPid()
{
    return 0;
}

#endif // ENABLE_EMBEDDED_TOR

// ------------------------------------------------- fail-soft restart driver
//
// The scheduler job (EmbeddedTorWatchTick, every 5 s) only evaluates the
// policy in torwatch.cpp and raises a flag; the zcl-torwatch thread does the
// stopping and starting, which can block for seconds. A restart never shuts
// the node down: losing Tor costs onion reachability, nothing else.

enum EmbeddedTorStatusCode {
    TOR_STATUS_OFF,
    TOR_STATUS_RUNNING,
    TOR_STATUS_RESTARTING,
    TOR_STATUS_FAILED,
};

/** Where the proxies point while Tor is down: a privileged loopback port that
 * nothing listens on and an unprivileged local process cannot take over, so
 * proxied connections fail closed instead of reaching whoever grabbed Tor's
 * old SOCKS port. */
static const char* const TOR_DOWN_PROXY_HOST = "127.0.0.1";
static const int TOR_DOWN_PROXY_PORT = 1;

struct EmbeddedTorWatch {
    std::string datadir;
    EmbeddedTorMode mode;
    bool rewireOnion;    //!< init pointed the onion proxy at the embedded Tor
    bool rewireClearnet; //!< init also sent IPv4, IPv6 and names through it (onion-only)
    bool randomize;      //!< -proxyrandomize
    std::string logPath;
    uint64_t logOffset;  //!< log bytes before this belong to an earlier instance
    TorRestartPolicy policy;
};

static std::atomic<int> g_torStatus(TOR_STATUS_OFF);
static std::atomic<int> g_torFault(static_cast<int>(TorFault::NONE));
static std::atomic<bool> g_torWatchStopRequest(false);
static std::atomic<bool> g_torWatchStartRequest(false);
static CCriticalSection cs_torWatch;
static EmbeddedTorWatch g_torWatch; // guarded by cs_torWatch

std::string EmbeddedTorStatus()
{
    switch (g_torStatus.load()) {
    case TOR_STATUS_RUNNING: return "running";
    case TOR_STATUS_RESTARTING: return "restarting";
    case TOR_STATUS_FAILED: return "failed";
    default: return "off";
    }
}

TorFault EmbeddedTorFault()
{
    return static_cast<TorFault>(g_torFault.load());
}

std::string EmbeddedTorStatusToken()
{
    const std::string status = EmbeddedTorStatus();
    if (status != "failed")
        return status;
    return status + ":" + TorFaultToken(EmbeddedTorFault());
}

bool EmbeddedTorManaged()
{
    return g_torStatus.load() != TOR_STATUS_OFF;
}

static std::string EmbeddedTorLogPath(const std::string& datadir, EmbeddedTorMode mode)
{
    // A child's stdout is <datadir>/tor/tor-child.log; an in-process Tor
    // writes <datadir>/tor/tor.log (src/c23/tor/zcl_tor_embed.c).
    const char* name = mode == EMBEDDED_TOR_CHILD ? "tor-child.log" : "tor.log";
    return (boost::filesystem::path(datadir) / "tor" / name).string();
}

static void EmbeddedTorWatchArm(const std::string& datadir, EmbeddedTorMode mode, bool rewireOnion,
                                bool rewireClearnet, bool randomize)
{
    LOCK(cs_torWatch);
    g_torWatch.datadir = datadir;
    g_torWatch.mode = mode;
    g_torWatch.rewireOnion = rewireOnion;
    g_torWatch.rewireClearnet = rewireClearnet;
    g_torWatch.randomize = randomize;
    g_torWatch.logPath = EmbeddedTorLogPath(datadir, mode);
    g_torWatch.logOffset = 0;
    TorScanLogTail(g_torWatch.logPath, 0, &g_torWatch.logOffset);
    g_torWatch.policy = TorRestartPolicy();
    g_torWatch.policy.inProcess = (mode == EMBEDDED_TOR_INPROCESS);
    g_torFault = static_cast<int>(TorFault::NONE);
    g_torStatus = TOR_STATUS_RUNNING;
}

/** Point every proxy init gave the embedded Tor at `addr`. */
static void PointEmbeddedTorProxies(const CService& addr)
{
    bool onion, clearnet, randomize;
    {
        LOCK(cs_torWatch);
        onion = g_torWatch.rewireOnion;
        clearnet = g_torWatch.rewireClearnet;
        randomize = g_torWatch.randomize;
    }
    const proxyType proxy(addr, randomize);
    if (onion)
        SetProxy(NET_ONION, proxy);
    if (clearnet) {
        SetProxy(NET_IPV4, proxy);
        SetProxy(NET_IPV6, proxy);
        SetNameProxy(proxy);
    }
}

/** Tor just died: record why, fence its old ports, hand the stop to the thread. */
static void EmbeddedTorWatchOnStop(int64_t delayMs)
{
    TorFault fault;
    {
        LOCK(cs_torWatch);
        fault = TorScanLogTail(g_torWatch.logPath, g_torWatch.logOffset, &g_torWatch.logOffset);
    }
    if (fault == TorFault::NONE)
        fault = TorFault::EXITED;
    g_torFault = static_cast<int>(fault);
    g_torStatus = TOR_STATUS_RESTARTING;
    LogPrintf("tor: embedded Tor stopped (fault=%s); restarting in %ds, node keeps running\n",
              TorFaultToken(fault), (int)((delayMs + 999) / 1000));
    PointEmbeddedTorProxies(CService(TOR_DOWN_PROXY_HOST, TOR_DOWN_PROXY_PORT));
    g_torWatchStopRequest = true;
}

/** Scheduler job (every 5 s): evaluates the policy; never blocks on Tor. */
static void EmbeddedTorWatchTick()
{
    if (ShutdownRequested() || g_torStatus.load() == TOR_STATUS_OFF)
        return;
    const bool alive = EmbeddedTorAlive();
    const int64_t now = GetTimeMillis();
    TorRestartDecision d;
    int64_t delayMs;
    {
        LOCK(cs_torWatch);
        d = TorRestartStep(g_torWatch.policy, alive, now);
        delayMs = g_torWatch.policy.nextAttemptMs - now;
    }
    if (d == TorRestartDecision::STOP_AND_SCHEDULE) {
        EmbeddedTorWatchOnStop(delayMs);
    } else if (d == TorRestartDecision::START_NOW) {
        g_torWatchStartRequest = true;
    } else if (d == TorRestartDecision::GIVE_UP) {
        g_torFault = static_cast<int>(TorFault::START_LIMIT);
        g_torStatus = TOR_STATUS_FAILED;
        LogPrintf("tor: embedded Tor restarted %d times in this process (inprocess mode); not restarting it again, the node keeps running without its onion service until it is restarted\n",
                  TOR_MAX_RESTARTS_IN_PROCESS);
    }
}

/** One START_NOW: start Tor, report to the policy, re-wire on success. */
static void EmbeddedTorWatchRestart()
{
    std::string datadir;
    EmbeddedTorMode mode;
    {
        LOCK(cs_torWatch);
        datadir = g_torWatch.datadir;
        mode = g_torWatch.mode;
    }
    StopEmbeddedTor(); // idempotent; releases a handle the stop request left
    std::string err;
    const bool ok = StartEmbeddedTor(datadir, mode, err);
    int attempt;
    int64_t delayMs;
    TorFault fault;
    {
        LOCK(cs_torWatch);
        const int64_t now = GetTimeMillis();
        TorRestartStarted(g_torWatch.policy, ok, now);
        attempt = g_torWatch.policy.attempts;
        delayMs = g_torWatch.policy.nextAttemptMs - now;
        fault = TorScanLogTail(g_torWatch.logPath, g_torWatch.logOffset, &g_torWatch.logOffset);
    }
    if (!ok) {
        if (fault != TorFault::NONE)
            g_torFault = static_cast<int>(fault);
        LogPrintf("tor: embedded Tor restart %d failed (fault=%s): %s; next attempt in %ds\n", attempt,
                  TorFaultToken(EmbeddedTorFault()), TorRedactOnion(err), (int)((delayMs + 999) / 1000));
        return;
    }
    PointEmbeddedTorProxies(CService("127.0.0.1", EmbeddedTorSocksPort()));
    g_torFault = static_cast<int>(TorFault::NONE);
    g_torStatus = TOR_STATUS_RUNNING;
    LogPrintf("tor: embedded Tor restarted (attempt %d); re-creating the onion service\n", attempt);
    TorControlKick();
}

/** Body of the zcl-torwatch thread: performs the stops and starts the tick asks for. */
static void EmbeddedTorWatchThread()
{
    while (true) {
        MilliSleep(250); // interruption point: join_all before Shutdown() stops the thread here
        if (g_torWatchStopRequest.exchange(false))
            StopEmbeddedTor();
        if (g_torWatchStartRequest.exchange(false))
            EmbeddedTorWatchRestart();
    }
}

void EmbeddedTorWatchStart(boost::thread_group& threadGroup, CScheduler& scheduler,
                           const std::string& datadir, EmbeddedTorMode mode, bool rewireOnion,
                           bool rewireClearnet, bool randomize)
{
    EmbeddedTorWatchArm(datadir, mode, rewireOnion, rewireClearnet, randomize);
    scheduler.scheduleEvery(&EmbeddedTorWatchTick, 5);
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "torwatch", &EmbeddedTorWatchThread));
}
