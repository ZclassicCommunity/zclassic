// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .
//
// The ONLY translation unit that touches libtor. Everything Tor-specific stays
// behind ENABLE_TOR; when Tor is not compiled in, every entry point is a safe stub.
//
// T2 engine core: run libtor on a dedicated thread with a generated torrc, learn the
// SOCKS port + bootstrap %% by tailing tor's log, point NET_ONION outbound at our own
// in-process SOCKS, and shut down cleanly via the owning-controller socket. The onion
// service itself is created by the EXISTING torcontrol.cpp (ADD_ONION over the control
// port, which init.cpp HARD-points at our ControlPort); embedtor only owns the engine,
// the proxy wiring, and lifecycle. The DEANON advertise-guard lives in net.cpp/init.cpp.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "torembed.h"

#include "compat.h"
#include "net.h"       // SetLimited(NET_ONION,...) (mirrors torcontrol.cpp)
#include "netbase.h"
#include "sync.h"
#include "util.h"
#include "utiltime.h"

#include <atomic>
#include <cstdio>
#include <string>
#include <vector>

#if ENABLE_TOR
#include <boost/bind.hpp>
#include <boost/chrono/chrono.hpp>
#include <boost/filesystem.hpp>
#include <boost/thread.hpp>
extern "C" {
#include <tor_api.h>
}
#endif

namespace {
std::atomic<int> g_state(EMBEDTOR_DISABLED);
std::atomic<int> g_bootstrapPct(-1);
std::atomic<int> g_inboundOnionPeers(0);
CCriticalSection cs_torembed;
std::string g_onion;        // guarded by cs_torembed (set by torcontrol via a future hook)
uint16_t    g_ctrlPort = 0; // guarded by cs_torembed
uint16_t    g_socksPort = 0;// guarded by cs_torembed

#if ENABLE_TOR
tor_main_configuration_t* g_cfg = NULL;
tor_control_socket_t      g_ctrlSock = INVALID_SOCKET;
boost::thread             g_torThread;
boost::thread             g_monThread;
std::atomic<bool>         g_interrupt(false);
std::atomic<bool>         g_socksReady(false);
// argv storage MUST outlive tor_run_main() (tor_api.h contract): keep it global.
std::vector<std::string>  g_argvStore;
std::vector<char*>        g_argv;
std::string               g_torLogPath;

//! Derive 127.0.0.1-only control/socks ports from the P2P port so multiple instances
//! (regtest) don't collide. Kept well clear of the P2P/RPC ranges.
void DerivePorts(uint16_t p2pPort, uint16_t& ctrlOut, uint16_t& socksOut)
{
    int base = (p2pPort == 0) ? 8033 : (int)p2pPort;
    ctrlOut  = (uint16_t)(((base + 1018) % 55000) + 10000);
    socksOut = (uint16_t)(((base + 11966) % 55000) + 10000);
    if (socksOut == ctrlOut) socksOut = (uint16_t)(socksOut == 65535 ? 10000 : socksOut + 1);
}

bool WriteTorrc(const std::string& torDir, uint16_t ctrlPort, uint16_t socksPort,
                const std::string& torrcPath)
{
    FILE* f = fopen(torrcPath.c_str(), "w");
    if (f == NULL) return false;
    fprintf(f, "DataDirectory %s\n", torDir.c_str());
    fprintf(f, "Log notice file %s\n", g_torLogPath.c_str());
    fprintf(f, "ControlPort 127.0.0.1:%u\n", ctrlPort);   // for the reused torcontrol.cpp (ADD_ONION)
    fprintf(f, "CookieAuthentication 1\n");
    fprintf(f, "SocksPort 127.0.0.1:%u\n", socksPort);     // our outbound NET_ONION path
    // The daemon — never Tor — owns process signals (avoids clobbering the SIGTERM
    // handler that flushes leveldb). Tor exits if our owning-controller socket closes
    // or our process dies. Both are deliberate (see §3.4 of the blueprint).
    fprintf(f, "__DisableSignalHandlers 1\n");
    fprintf(f, "__OwningControllerProcess %d\n", (int)getpid());
    fprintf(f, "AvoidDiskWrites 0\n");
    fclose(f);
    return true;
}

void TorThreadMain()
{
    RenameThread("zcl-embedtor");
    int rc = tor_run_main(g_cfg);
    LogPrintf("EmbeddedTor: tor_run_main exited (rc=%d)\n", rc);
    g_state.store(EMBEDTOR_DISABLED);
}

//! Tail tor's notice log for the two facts embedtor needs: SOCKS-listener-bound (so we
//! can wire the proxy) and bootstrap percentage (telemetry for the GUI). No control
//! socket needed for these — keeps the start path simple and robust.
void BootstrapMonitor()
{
    RenameThread("zcl-embedtor-mon");
    FILE* f = NULL;
    int reopenTries = 0;
    while (!g_interrupt.load()) {
        if (f == NULL) {
            f = fopen(g_torLogPath.c_str(), "r");
            if (f == NULL) {
                if (++reopenTries > 600) return; // ~60s: tor never created its log
                MilliSleep(100);
                continue;
            }
        }
        char line[1024];
        if (fgets(line, sizeof(line), f) != NULL) {
            std::string s(line);
            size_t bp = s.find("Bootstrapped ");
            if (bp != std::string::npos) {
                int pct = atoi(s.c_str() + bp + 13);
                if (pct >= 0 && pct <= 100) g_bootstrapPct.store(pct);
                if (pct >= 100 && g_state.load() == EMBEDTOR_READY)
                    g_state.store(EMBEDTOR_PUBLISHED);
            }
            if (s.find("Opened Socks listener") != std::string::npos)
                g_socksReady.store(true);
        } else {
            clearerr(f);   // hit EOF on a live log; wait for more
            MilliSleep(200);
        }
    }
    if (f != NULL) fclose(f);
}
#endif // ENABLE_TOR
} // anonymous namespace

bool TorEmbedAvailable()
{
#if ENABLE_TOR
    return true;
#else
    return false;
#endif
}

std::string TorEmbedProviderVersion()
{
#if ENABLE_TOR
    const char* v = tor_api_get_provider_version();
    return v ? std::string(v) : std::string("tor (version unknown)");
#else
    return std::string();
#endif
}

bool StartEmbeddedTor(const std::string& datadir, uint16_t p2pPort)
{
#if ENABLE_TOR
    if (g_state.load() != EMBEDTOR_DISABLED) return true; // idempotent

    uint16_t ctrlPort = 0, socksPort = 0;
    DerivePorts(p2pPort, ctrlPort, socksPort);
    boost::filesystem::path torDir = boost::filesystem::path(datadir) / "tor";
    boost::system::error_code ec;
    boost::filesystem::create_directories(torDir, ec);
    boost::filesystem::permissions(torDir, boost::filesystem::owner_all, ec); // 0700
    std::string torrcPath = (torDir / "torrc").string();
    {
        LOCK(cs_torembed);
        g_ctrlPort = ctrlPort;
        g_socksPort = socksPort;
        g_torLogPath = (torDir / "tor.log").string();
    }
    if (!WriteTorrc(torDir.string(), ctrlPort, socksPort, torrcPath)) {
        LogPrintf("EmbeddedTor: failed to write torrc at %s\n", torrcPath);
        g_state.store(EMBEDTOR_FAILED);
        return false;
    }

    g_cfg = tor_main_configuration_new();
    if (g_cfg == NULL) { g_state.store(EMBEDTOR_FAILED); return false; }

    // Owning-controller socket: pre-authenticated control connection; closing it (or
    // our process dying) makes tor shut its event loop down cleanly — our clean stop.
    g_ctrlSock = tor_main_configuration_setup_control_socket(g_cfg);

    g_argvStore.clear();
    g_argvStore.push_back("tor");
    g_argvStore.push_back("-f");
    g_argvStore.push_back(torrcPath);
    g_argv.clear();
    for (size_t i = 0; i < g_argvStore.size(); ++i) g_argv.push_back(&g_argvStore[i][0]);
    if (tor_main_configuration_set_command_line(g_cfg, (int)g_argv.size(), &g_argv[0]) < 0) {
        LogPrintf("EmbeddedTor: tor_main_configuration_set_command_line failed\n");
        tor_main_configuration_free(g_cfg); g_cfg = NULL;
        g_state.store(EMBEDTOR_FAILED);
        return false;
    }

    g_interrupt.store(false);
    g_socksReady.store(false);
    g_state.store(EMBEDTOR_BOOTSTRAP);
    g_bootstrapPct.store(0);
    LogPrintf("EmbeddedTor: starting %s (control 127.0.0.1:%u, socks 127.0.0.1:%u)\n",
              TorEmbedProviderVersion(), ctrlPort, socksPort);
    g_torThread = boost::thread(boost::bind(&TorThreadMain));
    g_monThread = boost::thread(boost::bind(&BootstrapMonitor));

    // Wait (bounded) for the SOCKS listener to bind, then wire NET_ONION outbound
    // SYNCHRONOUSLY before StartNode — NOT after full bootstrap (§3.4).
    const int64_t deadline = GetTimeMillis() + 90 * 1000;
    while (!g_socksReady.load() && !g_interrupt.load() && GetTimeMillis() < deadline)
        MilliSleep(100);

    if (g_socksReady.load()) {
        SetProxy(NET_ONION, proxyType(CService("127.0.0.1", socksPort), true));
        SetLimited(NET_ONION, false);
        proxyType chk;
        bool okProxy = GetProxy(NET_ONION, chk) && chk.proxy.GetPort() == socksPort;
        if (!okProxy) LogPrintf("EmbeddedTor: WARNING NET_ONION proxy assertion failed\n");
        if (g_state.load() == EMBEDTOR_BOOTSTRAP) g_state.store(EMBEDTOR_READY);
        LogPrintf("EmbeddedTor: SOCKS ready; NET_ONION outbound -> 127.0.0.1:%u\n", socksPort);
    } else {
        LogPrintf("EmbeddedTor: SOCKS not ready before deadline; staying on clearnet\n");
        g_state.store(EMBEDTOR_FAILED);
    }
    return true;
#else
    (void)datadir; (void)p2pPort;
    return false;
#endif
}

void InterruptEmbeddedTor()
{
#if ENABLE_TOR
    g_interrupt.store(true);
#endif
}

void StopEmbeddedTor()
{
#if ENABLE_TOR
    g_interrupt.store(true);
    // Ask tor to halt via the owning-controller socket, then bounded-join so a tor hang
    // can never block or interleave with the leveldb close that follows in Shutdown().
    if (g_ctrlSock != (tor_control_socket_t)INVALID_SOCKET) {
        const char* halt = "SIGNAL HALT\r\n";
        ::send(g_ctrlSock, halt, 13, 0);
        SOCKET s = (SOCKET)g_ctrlSock;
        CloseSocket(s);
        g_ctrlSock = (tor_control_socket_t)INVALID_SOCKET;
    }
    if (g_monThread.joinable()) {
        if (!g_monThread.try_join_for(boost::chrono::seconds(2))) g_monThread.detach();
    }
    if (g_torThread.joinable()) {
        if (!g_torThread.try_join_for(boost::chrono::seconds(6))) {
            LogPrintf("EmbeddedTor: tor thread did not exit in time; detaching\n");
            g_torThread.detach();
        }
    }
    if (g_cfg != NULL) { tor_main_configuration_free(g_cfg); g_cfg = NULL; }
    g_state.store(EMBEDTOR_DISABLED);
#endif
}

EmbeddedTorState GetEmbeddedTorState() { return (EmbeddedTorState)g_state.load(); }
int GetEmbeddedTorBootstrapPct() { return g_bootstrapPct.load(); }
std::string GetEmbeddedTorOnion() { LOCK(cs_torembed); return g_onion; }
uint16_t GetEmbeddedTorControlPort() { LOCK(cs_torembed); return g_ctrlPort; }
uint16_t GetEmbeddedTorSocksPort() { LOCK(cs_torembed); return g_socksPort; }
int GetEmbeddedTorInboundOnionPeers() { return g_inboundOnionPeers.load(); }
