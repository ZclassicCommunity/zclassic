// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "embeddedtor.h"

#include "httpserver.h"
#include "netbase.h"
#include "sync.h"
#include "util.h"

#include <boost/foreach.hpp>

#ifdef ENABLE_EMBEDDED_TOR
#include "c23/tor/zcl_tor_embed.h"
#endif

// Release default: Tor in its own process where this build can start it (Linux, via
// /proc/self/exe), so a Tor assert or memory bug cannot abort or read the process that
// holds the wallet, and a Tor crash becomes a clean shutdown (see EmbeddedTorWatchdog in
// init.cpp). Elsewhere (mingw, macOS) the in-process mode, which needs no exe path.
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

#ifdef ENABLE_EMBEDDED_TOR

static CCriticalSection cs_embeddedTor;
static zcl_tor_embed* g_embeddedTor = NULL;
static uint16_t g_socksPort = 0;
static uint16_t g_controlPort = 0;
static std::string g_cookiePath;
static bool g_inProcess = false;

bool EmbeddedTorAvailable()
{
    return true;
}

int EmbeddedTorDispatch(int argc, char* argv[])
{
    return zcl_tor_embed_dispatch(argc, argv);
}

bool StartEmbeddedTor(const std::string& datadir, EmbeddedTorMode mode, std::string& strError)
{
    LOCK(cs_embeddedTor);
    if (g_embeddedTor) {
        strError = "embedded Tor is already running";
        return false;
    }
    zcl_tor_embed_opts opts = zcl_tor_embed_opts();
    opts.datadir = datadir.c_str();
    opts.in_process = (mode == EMBEDDED_TOR_INPROCESS);
    char err[256] = "";
    zcl_tor_embed* h = NULL;
    int64_t nStart = GetTimeMillis();
    if (zcl_tor_embed_start(&opts, &h, err, sizeof(err)) != 0 || !h) {
        strError = err;
        // In-process Tor redirects libevent's log callback while it starts.
        if (opts.in_process)
            RestoreLibeventLogging();
        return false;
    }
    if (opts.in_process)
        RestoreLibeventLogging();
    const zcl_tor_embed_info* info = zcl_tor_embed_info_get(h);
    g_embeddedTor = h;
    g_inProcess = opts.in_process;
    g_socksPort = info->socks_port;
    g_controlPort = info->control_port;
    g_cookiePath = info->cookie_path;
    LogPrintf("tor: embedded Tor started (%s, %s) in %dms: SOCKS 127.0.0.1:%u, control 127.0.0.1:%u, state in %s\n",
              opts.in_process ? "in-process" : "child process",
              opts.in_process ? "thread" : strprintf("pid %d", (int)info->pid),
              GetTimeMillis() - nStart, g_socksPort, g_controlPort, info->tor_dir);
    return true;
}

void StopEmbeddedTor()
{
    LOCK(cs_embeddedTor);
    if (!g_embeddedTor)
        return;
    int64_t nStart = GetTimeMillis();
    if (zcl_tor_embed_stop(g_embeddedTor, 15000) == 0) {
        zcl_tor_embed_free(g_embeddedTor);
        LogPrintf("tor: embedded Tor stopped in %dms\n", GetTimeMillis() - nStart);
    } else {
        // The handle is left allocated: Tor still uses the state behind it.
        LogPrintf("tor: embedded Tor did not stop within 15s\n");
    }
    g_embeddedTor = NULL;
    g_socksPort = 0;
    g_controlPort = 0;
    g_cookiePath.clear();
    if (g_inProcess)
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

#else // !ENABLE_EMBEDDED_TOR

bool EmbeddedTorAvailable()
{
    return false;
}

int EmbeddedTorDispatch(int, char*[])
{
    return -1;
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

#endif // ENABLE_EMBEDDED_TOR
