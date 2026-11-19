// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "init.h"
#include "crypto/common.h"
#include "addrman.h"
#include "amount.h"
#include "bootstrap.h"
#include "bootstrapvalidation.h"
#include "checkpoints.h"
#include "compat/sanity.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
#include "embeddedtor.h"
#include "httpserver.h"
#include "httprpc.h"
#include "key.h"
#ifdef ENABLE_MINING
#include "key_io.h"
#endif
#include "main.h"
#include "metrics.h"
#include "miner.h"
#include "net.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "script/standard.h"
#include "script/sigcache.h"
#include "scheduler.h"
#include "dbwrapper.h"
#include "txdb.h"
#include "mapport.h"
#include "torcontrol.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#include "transaction_builder.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include <stdint.h>
#include <stdio.h>

#ifndef WIN32
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/bind.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/interprocess/sync/file_lock.hpp>
#include <boost/thread.hpp>
#include <openssl/crypto.h>

#if ENABLE_ZMQ
#include "zmq/zmqnotificationinterface.h"
#endif

#include <fstream>
#include <thread>
#include <future>
#include <exception>
#include <chrono>
#include "librustzcash.h"
#include "c23/glue/zcl_c23_glue.h"
#include "crypto/sha256.h"
#include "utilstrencodings.h"
#include "startuptimer.h"
#include "zslp/zslpservice.h"
#include "znam/znamservice.h"

#ifdef ZCL_C23_HAVE_PROVER_THREADS
// Total physical memory in bytes, 0 when the platform cannot say.
static uint64_t PhysicalMemoryBytes()
{
#if defined(WIN32)
    MEMORYSTATUSEX st;
    st.dwLength = sizeof(st);
    return GlobalMemoryStatusEx(&st) ? (uint64_t)st.ullTotalPhys : 0;
#elif defined(_SC_PHYS_PAGES) && defined(_SC_PAGESIZE)
    long pages = sysconf(_SC_PHYS_PAGES);
    long size = sysconf(_SC_PAGESIZE);
    return pages > 0 && size > 0 ? (uint64_t)pages * (uint64_t)size : 0;
#else
    return 0;
#endif
}

// Prover thread budget: -proverthreads=<n>, 0 = auto (min(8, hardware threads)).
static unsigned ProverThreadBudget()
{
    int64_t n = GetArg("-proverthreads", 0);
    if (n > 0)
        return n > 64 ? 64u : (unsigned)n;
    unsigned hw = std::thread::hardware_concurrency();
    if (hw == 0) hw = GetNumCores() > 0 ? (unsigned)GetNumCores() : 1;
    return hw < 8 ? hw : 8u;
}
#endif

using namespace std;

ZCJoinSplit* pzcashParams = NULL;

#ifdef ENABLE_WALLET
CWallet* pwalletMain = NULL;
#endif
bool fFeeEstimatesInitialized = false;

#if ENABLE_ZMQ
static CZMQNotificationInterface* pzmqNotificationInterface = NULL;
#endif

#ifdef WIN32
// Win32 LevelDB doesn't use file descriptors, and the ones used for
// accessing block files don't count towards the fd_set size limit
// anyway.
#define MIN_CORE_FILEDESCRIPTORS 0
#else
#define MIN_CORE_FILEDESCRIPTORS 150
#endif

/** Used to pass flags to the Bind() function */
enum BindFlags {
    BF_NONE         = 0,
    BF_EXPLICIT     = (1U << 0),
    BF_REPORT_ERROR = (1U << 1),
    BF_WHITELIST    = (1U << 2),
};

static const char* FEE_ESTIMATES_FILENAME="fee_estimates.dat";
// Default for -bootstrapservefreezeinterval: seconds between freezing a fresh
// self-snapshot of this node's own tip to serve with -bootstrapserve=auto.
// (The other BOOTSTRAP_SERVE_DEFAULT_* constants live in bootstrap.h.)
static const int64_t BOOTSTRAP_SERVE_DEFAULT_FREEZE_INTERVAL = 21600;
CClientUIInterface uiInterface; // Declared but not defined in ui_interface.h

//////////////////////////////////////////////////////////////////////////////
//
// Shutdown
//

//
// Thread management and startup/shutdown:
//
// The network-processing threads are all part of a thread group
// created by AppInit().
//
// A clean exit happens when StartShutdown() or the SIGTERM
// signal handler sets fRequestShutdown, which triggers
// the DetectShutdownThread(), which interrupts the main thread group.
// DetectShutdownThread() then exits, which causes AppInit() to
// continue (it .joins the shutdown thread).
// Shutdown() is then
// called to clean up database connections, and stop other
// threads that should only be stopped after the main network-processing
// threads have exited.
//
// Note that if running -daemon the parent process returns from AppInit2
// before adding any threads to the threadGroup, so .join_all() returns
// immediately and the parent exits from main().
//

std::atomic<bool> fRequestShutdown(false);

void StartShutdown()
{
    fRequestShutdown = true;
}
bool ShutdownRequested()
{
    return fRequestShutdown;
}

class CCoinsViewErrorCatcher : public CCoinsViewBacked
{
public:
    CCoinsViewErrorCatcher(CCoinsView* view) : CCoinsViewBacked(view) {}
    bool GetCoins(const uint256 &txid, CCoins &coins) const {
        try {
            return CCoinsViewBacked::GetCoins(txid, coins);
        } catch(const std::runtime_error& e) {
            uiInterface.ThreadSafeMessageBox(_("Error reading from database, shutting down."), "", CClientUIInterface::MSG_ERROR);
            LogPrintf("Error reading from database: %s\n", e.what());
            // Starting the shutdown sequence and returning false to the caller would be
            // interpreted as 'entry not found' (as opposed to unable to read data), and
            // could lead to invalid interpretation. Just exit immediately, as we can't
            // continue anyway, and all writes should be atomic.
            abort();
        }
    }
    // Writes do not need similar protection, as failure to write is handled by the caller.
};

static CCoinsViewDB *pcoinsdbview = NULL;
static CCoinsViewErrorCatcher *pcoinscatcher = NULL;
static boost::scoped_ptr<ECCVerifyHandle> globalVerifyHandle;

void Interrupt(boost::thread_group& threadGroup)
{
    InterruptHTTPServer();
    InterruptHTTPRPC();
    InterruptRPC();
    InterruptREST();
    InterruptTorControl();
    InterruptMapPort();
    threadGroup.interrupt_all();
}

static void InterruptBootstrapServeFreeze();

// GROWABLE v3 server-side helpers. These live in bootstrap.cpp and are part of the
// shared bootstrap contract; bootstrap.h is the canonical home for their
// declarations. Declared here too (identical signatures, so the redundant
// declaration is harmless) so this translation unit always compiles independently:
//   - ExtendServedBlocksForServe: append-only extend of the retained anchor serve
//     copy's block bundle toward the live tip, chainstate kept pinned at the anchor.
//   - BuildAnchorServeSnapshotFromGenesis: for a node that synced from genesis with
//     no retained chainstate@anchor, re-derive one by replaying genesis..anchor and
//     install it as a v3-servable ".anchor" serve dir.
bool ExtendServedBlocksForServe(const boost::filesystem::path& data_dir, int minAdvanceBlocks, std::string& error);
bool BuildAnchorServeSnapshotFromGenesis(const boost::filesystem::path& data_dir, std::string& error);

#ifdef WIN32
static std::atomic<bool> fWinShutdownDone(false);
#endif

#ifdef ENABLE_WALLET
/** True once the wallet was loaded, checked against the chain and rescanned, so Shutdown() may checkpoint it. */
static bool fWalletInitComplete = false;
#endif

void Shutdown()
{
    LogPrintf("%s: In progress...\n", __func__);
    static CCriticalSection cs_Shutdown;
    TRY_LOCK(cs_Shutdown, lockShutdown);
    if (!lockShutdown)
        return;

    /// Note: Shutdown() must be able to handle cases in which AppInit2() failed part of the way,
    /// for example if the data directory was found to be locked.
    /// Be sure that anything that writes files or flushes caches only does this if the respective
    /// module was initialized.
    RenameThread("zcl-shutoff");
    mempool.AddTransactionsUpdated(1);

    StopHTTPRPC();
    StopREST();
    StopRPC();
    StopHTTPServer();
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(false);
#endif
#ifdef ENABLE_MINING
    // AppInit() can fail (unusable data or params directory, bad option) before SelectParams(); no miner
    // threads exist then and Params() would assert.
    if (ParamsAreSelected())
        GenerateBitcoins(false, 0, Params());
#endif
    StopNode();
    StopTorControl();
    // After the P2P threads and the control client are gone, and before the
    // datadir lock is released at exit. No-op unless -embeddedtor started it,
    // including when AppInit2() failed part of the way.
    StopEmbeddedTor();
    StopMapPort();
    UnregisterNodeSignals(GetNodeSignals());

    // Stop the trustless-bootstrap background validator BEFORE the chain DBs are
    // freed below. It is not in the init thread_group, so the init-failure path
    // (which skips thread_group join) would otherwise let it race into freed
    // pblocktree/pcoinsTip. No-op when no trustless snapshot is being validated.
    InterruptBootstrapValidation();

    // Likewise stop the -bootstrapserve=auto self-snapshot freeze worker before
    // the chain DBs are freed: it takes cs_main and reads chainActive/
    // mapBlockIndex/pcoinsTip, so it must not outlive them. No-op when no freeze
    // is in flight (and when -bootstrapserve=auto is not in use).
    InterruptBootstrapServeFreeze();

    // The ZSLP index worker reads blocks and takes cs_main: stop it before the chain DBs are freed below.
    zslp::StopService();
    znam::StopService();

    if (fFeeEstimatesInitialized)
    {
        boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
        CAutoFile est_fileout(fopen(est_path.string().c_str(), "wb"), SER_DISK, CLIENT_VERSION);
        if (!est_fileout.IsNull())
            mempool.WriteFeeEstimates(est_fileout);
        else
            LogPrintf("%s: Failed to write fee estimates to %s\n", __func__, est_path.string());
        fFeeEstimatesInitialized = false;
    }

    {
        LOCK(cs_main);
        if (pcoinsTip != NULL) {
            FlushStateToDisk();
#ifdef ENABLE_WALLET
            // The coin database was just flushed to this tip. Write the wallet's checkpoint (note
            // witnesses, nullifiers and the best-block locator, atomically) at the same point, so
            // the next start does not have to rely on rescanning from an older locator.
            if (pwalletMain && fWalletInitComplete && chainActive.Tip()) {
                pwalletMain->SetBestChain(chainActive.GetLocator());
            }
#endif
        }
        delete pcoinsTip;
        pcoinsTip = NULL;
        delete pcoinscatcher;
        pcoinscatcher = NULL;
        delete pcoinsdbview;
        pcoinsdbview = NULL;
        delete pblocktree;
        pblocktree = NULL;
    }
#ifdef ENABLE_WALLET
    if (pwalletMain)
        pwalletMain->Flush(true);
#endif

#if ENABLE_ZMQ
    if (pzmqNotificationInterface) {
        UnregisterValidationInterface(pzmqNotificationInterface);
        delete pzmqNotificationInterface;
        pzmqNotificationInterface = NULL;
    }
#endif

#ifndef WIN32
    // The pid file is written only after the network is selected; the net-specific data directory
    // (and so GetPidFile()) is not available before that.
    if (ParamsAreSelected()) {
        try {
            boost::filesystem::remove(GetPidFile());
        } catch (const boost::filesystem::filesystem_error& e) {
            LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
        }
    }
#endif
    UnregisterAllValidationInterfaces();
#ifdef ENABLE_WALLET
    delete pwalletMain;
    pwalletMain = NULL;
#endif
    delete pzcashParams;
    pzcashParams = NULL;
    globalVerifyHandle.reset();
    ECC_Stop();
    LogPrintf("%s: done\n", __func__);
#ifdef WIN32
    fWinShutdownDone = true;
#endif
}

/**
 * Signal handlers are very limited in what they are allowed to do, so:
 */
void HandleSIGTERM(int)
{
    fRequestShutdown = true;
}

void HandleSIGHUP(int)
{
    fReopenDebugLog = true;
}

#ifdef WIN32
/**
 * Console control events (Ctrl+C, Ctrl+Break, closing the console window, system
 * shutdown). Without a handler Windows ends the process immediately, without
 * flushing the chain state, wallet and block index, as if it had been killed.
 * Request the normal clean shutdown instead. For the events after which Windows
 * terminates the process as soon as this handler returns, wait (bounded) for the
 * shutdown to finish.
 */
static BOOL WINAPI WinConsoleCtrlHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        StartShutdown();
        return TRUE;
    case CTRL_LOGOFF_EVENT:
        // Delivered only to processes outside the interactive session that is
        // ending (a service, or a node started under a service wrapper) when
        // some user logs off: not a reason to stop the node. Pass it on to the
        // next (default) handler, exactly as before this handler existed.
        return FALSE;
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        StartShutdown();
        for (int i = 0; i < 200 && !fWinShutdownDone; i++) // up to 20 s (the OS may cut this short)
            Sleep(100);
        return TRUE;
    default:
        return FALSE;
    }
}
#endif

#if defined(WIN32) && defined(ENABLE_EMBEDDED_TOR)
/**
 * The datadir in the form the embedded Tor glue (src/c23/tor) expects on Windows.
 * - UTF-8: the glue converts paths with CP_UTF8, while path::string() is in the
 *   ANSI code page, which is UTF-8 only under the manifest on Windows 10 1903+.
 * - Absolute, backslash-separated, no trailing separator: the glue hands Tor
 *   GetFullPathNameW() of <datadir>\tor, and the control-port check in
 *   torcontrol.cpp compares the COOKIEFILE Tor reports with the cookie path
 *   built from this string, so both must be the same spelling.
 * - When the ANSI code page is not UTF-8, the 8.3 short name of a non-ASCII path,
 *   which is what the glue hands Tor in that case (same reason).
 * Falls back to path::string() if a conversion fails; the glue then reports it.
 */
static std::string EmbeddedTorDataDir(const boost::filesystem::path& p)
{
    std::wstring w = p.wstring();
    std::vector<wchar_t> buf(32768);
    DWORD n = GetFullPathNameW(w.c_str(), (DWORD)buf.size(), buf.data(), NULL);
    if (n == 0 || n >= buf.size())
        return p.string();
    w.assign(buf.data());
    while (w.size() > 3 && (w[w.size() - 1] == L'\\' || w[w.size() - 1] == L'/'))
        w.erase(w.size() - 1);
    bool fAscii = true;
    for (size_t i = 0; i < w.size(); i++)
        if (w[i] > 0x7f) fAscii = false;
    if (!fAscii && GetACP() != CP_UTF8) {
        n = GetShortPathNameW(w.c_str(), buf.data(), (DWORD)buf.size());
        if (n > 0 && n < buf.size())
            w.assign(buf.data());
    }
    int u = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, NULL, 0, NULL, NULL);
    if (u <= 0)
        return p.string();
    std::vector<char> out(u);
    if (WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, out.data(), u, NULL, NULL) != u)
        return p.string();
    return std::string(out.data());
}
#endif

bool static InitError(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_ERROR);
    return false;
}

bool static InitWarning(const std::string &str)
{
    uiInterface.ThreadSafeMessageBox(str, "", CClientUIInterface::MSG_WARNING);
    return true;
}

bool static Bind(const CService &addr, unsigned int flags) {
    if (!(flags & BF_EXPLICIT) && IsLimited(addr))
        return false;
    std::string strError;
    if (!BindListenPort(addr, strError, (flags & BF_WHITELIST) != 0)) {
        if (flags & BF_REPORT_ERROR)
            return InitError(strError);
        return false;
    }
    return true;
}

void OnRPCStopped()
{
    cvBlockChange.notify_all();
    LogPrint("rpc", "RPC stopped.\n");
}

void OnRPCPreCommand(const CRPCCommand& cmd)
{
    // Observe safe mode
    string strWarning = GetWarnings("rpc");
    if (strWarning != "" && !GetBoolArg("-disablesafemode", false) &&
        !cmd.okSafeMode)
        throw JSONRPCError(RPC_FORBIDDEN_BY_SAFE_MODE, string("Safe mode: ") + strWarning);
}

std::string HelpMessage(HelpMessageMode mode)
{
    const bool showDebug = GetBoolArg("-help-debug", false);

    // When adding new options to the categories, please keep and ensure alphabetical ordering.
    // Do not translate _(...) -help-debug options, many technical terms, and only a very small audience, so is unnecessary stress to translators

    string strUsage = HelpMessageGroup(_("Options:"));
    strUsage += HelpMessageOpt("-?", _("This help message"));
    strUsage += HelpMessageOpt("-alertnotify=<cmd>", _("Execute command when a relevant local warning is raised or we see a really long fork (%s in cmd is replaced by message)"));
    strUsage += HelpMessageOpt("-blocknotify=<cmd>", _("Execute command when the best block changes (%s in cmd is replaced by block hash)"));
    strUsage += HelpMessageOpt("-checkblocks=<n>", strprintf(_("How many blocks to check at startup (default: %u, 0 = all)"), 288));
    strUsage += HelpMessageOpt("-checklevel=<n>", strprintf(_("How thorough the block verification of -checkblocks is (0-4, default: %u)"), 3));
    strUsage += HelpMessageOpt("-conf=<file>", strprintf(_("Specify configuration file (default: %s)"), "zclassic.conf"));
    if (mode == HMM_BITCOIND)
    {
#if !defined(WIN32)
        strUsage += HelpMessageOpt("-daemon", _("Run in the background as a daemon and accept commands"));
#endif
    }
    strUsage += HelpMessageOpt("-datadir=<dir>", _("Specify data directory"));
    strUsage += HelpMessageOpt("-exportdir=<dir>", _("Specify directory to be used when exporting data and wallet backups (default: the \"backups\" directory inside the data directory)"));
    strUsage += HelpMessageOpt("-dbcache=<n>", strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), nMinDbCache, nMaxDbCache, nDefaultDbCache));
    strUsage += HelpMessageOpt("-loadblock=<file>", _("Imports blocks from external blk000??.dat file") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-maxorphantx=<n>", strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-mempoolmaxbytes=<n>", strprintf(_("Maximum total size in bytes of transactions held in the mempool; a new transaction that would exceed it is refused with reason \"mempool full\" and nothing is evicted (default: %u, minimum: %u)"), DEFAULT_MEMPOOL_MAX_BYTES, MIN_MEMPOOL_MAX_BYTES));
    strUsage += HelpMessageOpt("-mempooltxinputlimit=<n>", _("[DEPRECATED FROM OVERWINTER] Set the maximum number of transparent inputs in a transaction that the mempool will accept (default: 0 = no limit applied)"));
    strUsage += HelpMessageOpt("-par=<n>", strprintf(_("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
        -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS));
#ifdef ZCL_C23_HAVE_PROVER_THREADS
    strUsage += HelpMessageOpt("-proverthreads=<n>", _("Set the number of threads used to create Sapling proofs (1 to 64, 0 = auto: the lesser of 8 and the hardware threads, default: 0). Left automatic, a send also makes only as many proofs at once as fit in about 340 MB or an eighth of physical memory, whichever is less; an explicit value lifts that limit"));
#endif
#ifndef WIN32
    strUsage += HelpMessageOpt("-pid=<file>", strprintf(_("Specify pid file (default: %s)"), "zclassicd.pid"));
#endif
    strUsage += HelpMessageOpt("-prune=<n>", strprintf(_("Reduce storage requirements by pruning (deleting) old blocks. This mode disables wallet support and is incompatible with -txindex. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, >%u = target size in MiB to use for block files)"), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
    strUsage += HelpMessageOpt("-reindex", _("Rebuild block chain index from current blk000??.dat files on startup"));
    strUsage += HelpMessageOpt("-reindex-chainstate", _("Rebuild only the chainstate (UTXO set) from the existing block index and blk000??.dat files on startup, without rebuilding the block index. Much faster than -reindex; use it to recover a corrupted/desynced chainstate when the block index is intact."));
    strUsage += HelpMessageOpt("-bootstrapdatadir=<dir>", _("Import blocks/ and chainstate/ from a prepared snapshot directory before opening databases"));
    strUsage += HelpMessageOpt("-bootstrapforce", _("When used with -bootstrapdatadir, move existing blocks/ and chainstate/ to a timestamped backup before import"));
    strUsage += HelpMessageOpt("-bootstrappeer=<host>", _("Download an initial bootstrap snapshot from a trusted NODE_BOOTSTRAP peer into a fresh datadir before opening databases (experimental)"));
    strUsage += HelpMessageOpt("-bootstrapdiscover", _("If the compiled/explicit bootstrap peer is unavailable, discover NODE_BOOTSTRAP peers from the network and fast-sync from them. Off by default; the imported snapshot is still verified against the compiled anchor, but a default node avoids the discovery network code entirely and simply falls back to normal P2P sync."));
    strUsage += HelpMessageOpt("-bootstrapstreams=<n>", _("Number of parallel connections to download a bootstrap snapshot over (default: 4, max: 16). A single TCP connection is throughput-limited by packet loss on the path; multiple streams each get their own congestion window and together fill a fast link. Use 1 for the legacy single-stream download."));
    strUsage += HelpMessageOpt("-bootstrapserve", _("Serve bootstrap snapshots to peers. Set -bootstrapserve=auto to retain and serve the snapshot this node fast-syncs (no -bootstrapsourcedir needed, uses extra disk); otherwise pass -bootstrapsourcedir=<dir> to serve a prepared snapshot."));
    strUsage += HelpMessageOpt("-bootstrapsourcedir=<dir>", _("Prepared snapshot directory containing blocks/ and chainstate/ to serve to bootstrap peers"));
    strUsage += HelpMessageOpt("-bootstrapservemaxbytesperday=<n>", strprintf(_("When serving bootstrap snapshots, bytes one IP may download per 24h before it is throttled (default: %d, 0 = unlimited)"), BOOTSTRAP_SERVE_DEFAULT_MAX_BYTES_PER_DAY));
    strUsage += HelpMessageOpt("-bootstrapservethrottlekbps=<n>", strprintf(_("Rate in KiB/s to serve a bootstrap IP that is over its daily cap (default: %d, 0 = stop serving it until the next day)"), BOOTSTRAP_SERVE_DEFAULT_THROTTLE_KBPS));
    strUsage += HelpMessageOpt("-bootstrapservemaxtotalkbps=<n>", _("Process-wide aggregate cap (Kbit/s) on bootstrap-snapshot serving across ALL peers, bounding worst-case upload independent of source-address count (default: 0 = unlimited). Whitelisted peers are exempt."));
    strUsage += HelpMessageOpt("-bootstrapservemaxpeers=<n>", _("Maximum number of peers served bootstrap-snapshot chunks concurrently; further peers are deferred until a slot frees (default: 0 = unlimited). Whitelisted peers are exempt."));
    strUsage += HelpMessageOpt("-bootstrapservefreezeinterval=<n>", strprintf(_("With -bootstrapserve=auto, seconds between refreshing the served snapshot toward this node's live tip (default: %d, 0 = never refresh, serve only the fast-synced anchor copy as-is). In the default anchor mode this EXTENDS the served block bundle append-only while keeping the chainstate pinned at the compiled anchor (GROWABLE v3). Under -bootstrapmode=trustless it instead freezes a fresh self-snapshot at this node's own tip (EXPERIMENTAL, option B)."), BOOTSTRAP_SERVE_DEFAULT_FREEZE_INTERVAL));
    strUsage += HelpMessageOpt("-bootstrapmode=<anchor|trustless>", _("How to accept a downloaded bootstrap snapshot: 'anchor' (default) requires it to match the compiled fast-sync anchor; 'trustless' (EXPERIMENTAL, option B) accepts a peer's self-snapshot at its own tip, then re-derives the UTXO set from genesis in the background and reindexes if it does not match."));
#if !defined(WIN32)
    strUsage += HelpMessageOpt("-sysperms", _("Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)"));
#endif
    strUsage += HelpMessageOpt("-txindex", strprintf(_("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"), 1));
    strUsage += HelpMessageOpt("-zslpindex", _("Maintain a read-only ZSLP token index in <datadir>/zslpindex, used by the zslp_* rpc calls and the GUI Tokens view. Built in the background; never touches consensus or wallet.dat (default: 0). Not compatible with -prune. See doc/zslp.md"));
    strUsage += HelpMessageOpt("-zslpindexstart=<n>", _("First block height the ZSLP index reads (default: the first block with a ZSLP transaction on mainnet, 0 on testnet and regtest)"));
    strUsage += HelpMessageOpt("-znamindex", _("Maintain a read-only ZNAM name index in <datadir>/znamindex, used by the znam_* rpc calls and the GUI's resolve-a-name step. Built in the background; never touches consensus or wallet.dat (default: 0). Not compatible with -prune. See doc/znam.md"));
    strUsage += HelpMessageOpt("-znamindexstart=<n>", _("First block height the ZNAM index reads (default: 0, so no registration is missed)"));
    strUsage += HelpMessageOpt("-bootstrap", strprintf(_("On a fresh datadir, fetch zk-SNARK params and the chain snapshot from a bootstrap peer before normal sync (default: %u)"), 1));

    strUsage += HelpMessageGroup(_("Connection options:"));
    strUsage += HelpMessageOpt("-addnode=<ip>", _("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-banscore=<n>", strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"), 100));
    strUsage += HelpMessageOpt("-bantime=<n>", strprintf(_("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"), 86400));
    strUsage += HelpMessageOpt("-bind=<addr>", _("Bind to given address and always listen on it. Use [host]:port notation for IPv6. Append =onion (-bind=<addr>=onion) to make it the listener that the onion service points at (default port: the P2P port + 1)"));
    strUsage += HelpMessageOpt("-connect=<ip>", _("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt("-discover", _("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-dns", _("Allow DNS lookups for -addnode, -seednode and -connect") + " " + _("(default: 1)"));
    strUsage += HelpMessageOpt("-dnsseed", _("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)"));
    strUsage += HelpMessageOpt("-externalip=<ip>", _("Specify your own public address"));
    strUsage += HelpMessageOpt("-forcednsseed", strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"), 0));
    strUsage += HelpMessageOpt("-listen", _("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    if (EmbeddedTorAvailable()) {
        strUsage += HelpMessageOpt("-embeddedtor", strprintf(_("Run the Tor built into this binary: state in <datadir>/tor, SOCKS and control on loopback ports chosen at runtime, used for .onion peers and for the node's own onion service (default: %u)"), DEFAULT_EMBEDDED_TOR));
        strUsage += HelpMessageOpt("-embeddedtormode=<mode>", strprintf(_("How the embedded Tor runs: inprocess (a thread of this process) or child (a separate process) (default: %s)"), DEFAULT_EMBEDDED_TOR_MODE));
    }
    strUsage += HelpMessageOpt("-listenonion", strprintf(_("Automatically create Tor hidden service (default: %d)"), DEFAULT_LISTEN_ONION));
    strUsage += HelpMessageOpt("-natpmp", strprintf(_("Open the listen port on the router automatically via NAT-PMP/PCP, so peers can reach you (no UPnP). Maps only your own listen port (default: %d)"), DEFAULT_NATPMP));
    strUsage += HelpMessageOpt("-maxconnections=<n>", strprintf(_("Maintain at most <n> connections to peers (default: %u)"), DEFAULT_MAX_PEER_CONNECTIONS));
    strUsage += HelpMessageOpt("-maxreceivebuffer=<n>", strprintf(_("Maximum per-connection receive buffer, <n>*1000 bytes (default: %u)"), 5000));
    strUsage += HelpMessageOpt("-maxsendbuffer=<n>", strprintf(_("Maximum per-connection send buffer, <n>*1000 bytes (default: %u)"), 1000));
    strUsage += HelpMessageOpt("-onion=<ip:port>", strprintf(_("Use separate SOCKS5 proxy to reach peers via Tor hidden services (default: %s)"), "-proxy"));
    strUsage += HelpMessageOpt("-onlynet=<net>", _("Only connect to nodes in network <net> (ipv4, ipv6 or onion)"));
    strUsage += HelpMessageOpt("-permitbaremultisig", strprintf(_("Relay non-P2SH multisig (default: %u)"), 1));
    strUsage += HelpMessageOpt("-peerbloomfilters", strprintf(_("Support filtering of blocks and transaction with Bloom filters (default: %u)"), 1));
    if (showDebug)
        strUsage += HelpMessageOpt("-enforcenodebloom", strprintf("Enforce minimum protocol version to limit use of Bloom filters (default: %u)", 0));
    strUsage += HelpMessageOpt("-port=<port>", strprintf(_("Listen for connections on <port> (default: %u or testnet: %u)"), 8033, 18033));
    strUsage += HelpMessageOpt("-proxy=<ip:port>", _("Connect through SOCKS5 proxy"));
    strUsage += HelpMessageOpt("-proxyrandomize", strprintf(_("Randomize credentials for every proxy connection. This enables Tor stream isolation (default: %u)"), 1));
    strUsage += HelpMessageOpt("-seednode=<ip>", _("Connect to a node to retrieve peer addresses, and disconnect"));
    strUsage += HelpMessageOpt("-timeout=<n>", strprintf(_("Specify connection timeout in milliseconds (minimum: 1, default: %d)"), DEFAULT_CONNECT_TIMEOUT));
    strUsage += HelpMessageOpt("-torcontrol=<ip>:<port>", strprintf(_("Tor control port to use if onion listening enabled (default: %s)"), DEFAULT_TOR_CONTROL));
    strUsage += HelpMessageOpt("-torpassword=<pass>", _("Tor control port password (default: empty)"));
    strUsage += HelpMessageOpt("-whitebind=<addr>", _("Bind to given address and whitelist peers connecting to it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-whitelist=<netmask>", _("Whitelist peers connecting from the given netmask or IP address. Can be specified multiple times.") +
        " " + _("Whitelisted peers cannot be DoS banned and their transactions are always relayed, even if they are already in the mempool, useful e.g. for a gateway"));

#ifdef ENABLE_WALLET
    strUsage += HelpMessageGroup(_("Wallet options:"));
    strUsage += HelpMessageOpt("-disablewallet", _("Do not load the wallet and disable wallet RPC calls"));
    strUsage += HelpMessageOpt("-keypool=<n>", strprintf(_("Set key pool size to <n> (default: %u)"), 100));
    if (showDebug)
        strUsage += HelpMessageOpt("-mintxfee=<amt>", strprintf("Fees (in %s/kB) smaller than this are considered zero fee for transaction creation (default: %s)",
            CURRENCY_UNIT, FormatMoney(CWallet::minTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-paytxfee=<amt>", strprintf(_("Fee (in %s/kB) to add to transactions you send (default: %s)"),
        CURRENCY_UNIT, FormatMoney(payTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-nowalletparallel", _("Disable parallel Sapling trial-decryption during wallet rescan (forces the single-threaded scan path; default: off)"));
    strUsage += HelpMessageOpt("-rescan", _("Rescan the block chain for missing wallet transactions") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-salvagewallet", _("Attempt to recover private keys from a corrupt wallet.dat") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-sendfreetransactions", strprintf(_("Send transactions as zero-fee transactions if possible (default: %u)"), 0));
    strUsage += HelpMessageOpt("-spendzeroconfchange", strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"), 1));
    strUsage += HelpMessageOpt("-tokenguard", strprintf(_("Keep outputs that carry ZSLP tokens or a mint baton out of automatic coin selection and out of explicit coin-control selections, so ordinary sends never burn them. -tokenguard=0 turns this off for the whole wallet: any such output, including a payment that merely looks like a token output, is then spent like an ordinary coin (default: %u)"), 1));
    strUsage += HelpMessageOpt("-txconfirmtarget=<n>", strprintf(_("If paytxfee is not set, include enough fee so transactions begin confirmation on average within n blocks (default: %u)"), DEFAULT_TX_CONFIRM_TARGET));
    strUsage += HelpMessageOpt("-txexpirydelta", strprintf(_("Set the number of blocks after which a transaction that has not been mined will become invalid (min: %u, default: %u (pre-Buttercup) or %u (post-Buttercup))"), TX_EXPIRING_SOON_THRESHOLD + 1, DEFAULT_PRE_BUTTERCUP_TX_EXPIRY_DELTA, DEFAULT_POST_BUTTERCUP_TX_EXPIRY_DELTA));
    strUsage += HelpMessageOpt("-maxtxfee=<amt>", strprintf(_("Maximum total fees (in %s) to use in a single wallet transaction; setting this too low may abort large transactions (default: %s)"),
        CURRENCY_UNIT, FormatMoney(maxTxFee)));
    strUsage += HelpMessageOpt("-upgradewallet", _("Upgrade wallet to latest format") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-wallet=<file>", _("Specify wallet file (within data directory)") + " " + strprintf(_("(default: %s)"), "wallet.dat"));
    strUsage += HelpMessageOpt("-walletbroadcast", _("Make the wallet broadcast transactions") + " " + strprintf(_("(default: %u)"), true));
    strUsage += HelpMessageOpt("-walletnotify=<cmd>", _("Execute command when a wallet transaction changes (%s in cmd is replaced by TxID)"));
    strUsage += HelpMessageOpt("-zapwallettxes=<mode>", _("Delete all wallet transactions and only recover those parts of the blockchain through -rescan on startup") +
        " " + _("(1 = keep tx meta data e.g. account owner and payment request information, 2 = drop tx meta data)"));
#endif

#if ENABLE_ZMQ
    strUsage += HelpMessageGroup(_("ZeroMQ notification options:"));
    strUsage += HelpMessageOpt("-zmqpubhashblock=<address>", _("Enable publish hash block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubhashtx=<address>", _("Enable publish hash transaction in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawblock=<address>", _("Enable publish raw block in <address>"));
    strUsage += HelpMessageOpt("-zmqpubrawtx=<address>", _("Enable publish raw transaction in <address>"));
#endif

    strUsage += HelpMessageGroup(_("Debugging/Testing options:"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-checkpoints", strprintf("Disable expensive verification for known chain history (default: %u)", 1));
        strUsage += HelpMessageOpt("-dblogsize=<n>", strprintf("Flush database activity from memory pool to disk log every <n> megabytes (default: %u)", 100));
        strUsage += HelpMessageOpt("-disablesafemode", strprintf("Disable safemode, override a real safe mode event (default: %u)", 0));
        strUsage += HelpMessageOpt("-testsafemode", strprintf("Force safe mode (default: %u)", 0));
        strUsage += HelpMessageOpt("-dropmessagestest=<n>", "Randomly drop 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-fuzzmessagestest=<n>", "Randomly fuzz 1 of every <n> network messages");
        strUsage += HelpMessageOpt("-flushwallet", strprintf("Run a thread to flush wallet periodically (default: %u)", 1));
        strUsage += HelpMessageOpt("-testsetchaininterval=<n>", strprintf("Test only: write the wallet checkpoint (locator and note state) at most every <n> seconds while running (default: %u)", DATABASE_WRITE_INTERVAL));
        strUsage += HelpMessageOpt("-testblockindexinterval=<n>", "Test only: write the block index at most every <n> seconds while running (default: 3600, 300 during initial block download)");
        strUsage += HelpMessageOpt("-testcrashpoint=<name>[:<n>]", "Test only: _exit(77) the <n>th time the named wallet or chain-state write point is reached; the name any matches every point (default: off)");
        strUsage += HelpMessageOpt("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", 0));
        strUsage += HelpMessageOpt("-nuparams=hexBranchId:activationHeight", "Use given activation height for specified network upgrade (regtest-only)");
        strUsage += HelpMessageOpt("-eqparams=hexBranchId:N:K", "Use given equihash parameters for specified network upgrade"); 
    }
    string debugCategories = "addrman, bench, coindb, db, estimatefee, http, libevent, lock, mempool, net, partitioncheck, pow, proxy, prune, "
                             "rand, reindex, rpc, selectcoins, tor, zmq, zrpc, zrpcunsafe (implies zrpc)"; // Don't translate these
    strUsage += HelpMessageOpt("-debug=<category>", strprintf(_("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
        _("If <category> is not supplied or if <category> = 1, output all debugging information.") + " " + _("<category> can be:") + " " + debugCategories + ".");
    strUsage += HelpMessageOpt("-experimentalfeatures", _("Enable use of experimental features"));
    strUsage += HelpMessageOpt("-help-debug", _("Show all debugging options (usage: --help -help-debug)"));
    strUsage += HelpMessageOpt("-logips", strprintf(_("Include IP addresses in debug output (default: %u)"), 0));
    strUsage += HelpMessageOpt("-debuglogfile", _("Write debug output to debug.log file (default: 0, disabled for privacy)"));
    strUsage += HelpMessageOpt("-logtimestamps", strprintf(_("Prepend debug output with timestamp (default: %u)"), 1));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-limitfreerelay=<n>", strprintf("Continuously rate-limit free transactions to <n>*1000 bytes per minute (default: %u)", 15));
        strUsage += HelpMessageOpt("-relaypriority", strprintf("Require high priority for relaying free or low-fee transactions (default: %u)", 0));
        strUsage += HelpMessageOpt("-maxsigcachesize=<n>", strprintf("Limit size of signature cache to <n> MiB (default: %u)", DEFAULT_MAX_SIG_CACHE_SIZE));
        strUsage += HelpMessageOpt("-maxtipage=<n>", strprintf("Maximum tip age in seconds to consider node in initial block download (default: %u)", DEFAULT_MAX_TIP_AGE));
    }
    strUsage += HelpMessageOpt("-minrelaytxfee=<amt>", strprintf(_("Fees (in %s/kB) smaller than this are considered zero fee for relaying (default: %s)"),
        CURRENCY_UNIT, FormatMoney(::minRelayTxFee.GetFeePerK())));
    strUsage += HelpMessageOpt("-printtoconsole", _("Send trace/debug info to console instead of debug.log file"));
    if (showDebug)
    {
        strUsage += HelpMessageOpt("-printpriority", strprintf("Log transaction priority and fee per kB when mining blocks (default: %u)", 0));
        strUsage += HelpMessageOpt("-privdb", strprintf("Sets the DB_PRIVATE flag in the wallet db environment (default: %u)", 1));
        strUsage += HelpMessageOpt("-regtest", "Enter regression test mode, which uses a special chain in which blocks can be solved instantly. "
            "This is intended for regression testing tools and app development.");
    }
    // strUsage += HelpMessageOpt("-shrinkdebugfile", _("Shrink debug.log file on client startup (default: 1 when no -debug)"));
    strUsage += HelpMessageOpt("-testnet", _("Use the test network"));

    strUsage += HelpMessageGroup(_("Node relay options:"));
    strUsage += HelpMessageOpt("-datacarrier", strprintf(_("Relay and mine data carrier transactions (default: %u)"), 1));
    strUsage += HelpMessageOpt("-datacarriersize", strprintf(_("Maximum size of data in data carrier transactions we relay and mine (default: %u)"), MAX_OP_RETURN_RELAY));

    strUsage += HelpMessageGroup(_("Block creation options:"));
    strUsage += HelpMessageOpt("-blockminsize=<n>", strprintf(_("Set minimum block size in bytes (default: %u)"), 0));
    strUsage += HelpMessageOpt("-blockmaxsize=<n>", strprintf(_("Set maximum block size in bytes (default: %d)"), DEFAULT_BLOCK_MAX_SIZE));
    strUsage += HelpMessageOpt("-blockprioritysize=<n>", strprintf(_("Set maximum size of high-priority/low-fee transactions in bytes (default: %d)"), DEFAULT_BLOCK_PRIORITY_SIZE));
    if (GetBoolArg("-help-debug", false))
        strUsage += HelpMessageOpt("-blockversion=<n>", strprintf("Override block version to test forking scenarios (default: %d)", (int)CBlock::CURRENT_VERSION));

#ifdef ENABLE_MINING
    strUsage += HelpMessageGroup(_("Mining options:"));
    strUsage += HelpMessageOpt("-gen", strprintf(_("Generate coins (default: %u)"), 0));
    strUsage += HelpMessageOpt("-genproclimit=<n>", strprintf(_("Set the number of threads for coin generation if enabled (-1 = all cores, default: %d)"), 1));
    strUsage += HelpMessageOpt("-equihashsolver=<name>", _("Specify the Equihash solver to be used if enabled (default: \"default\")"));
    strUsage += HelpMessageOpt("-mineraddress=<addr>", _("Send mined coins to a specific single address"));
    strUsage += HelpMessageOpt("-minetolocalwallet", strprintf(
            _("Require that mined blocks use a coinbase address in the local wallet (default: %u)"),
 #ifdef ENABLE_WALLET
            1
 #else
            0
 #endif
            ));
#endif

    strUsage += HelpMessageGroup(_("RPC server options:"));
    strUsage += HelpMessageOpt("-server", _("Accept command line and JSON-RPC commands"));
    strUsage += HelpMessageOpt("-rest", strprintf(_("Accept public REST requests (default: %u)"), 0));
    strUsage += HelpMessageOpt("-rpcbind=<addr>", _("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for IPv6. This option can be specified multiple times (default: bind to localhost only, ::1 and 127.0.0.1; this option is ignored unless -rpcallowip is also given, and -rpcallowip without -rpcbind binds all interfaces)"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"), 8023, 18023));
    strUsage += HelpMessageOpt("-rpcallowip=<ip>", _("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcthreads=<n>", strprintf(_("Set the number of threads to service RPC calls (default: %d)"), DEFAULT_HTTP_THREADS));
    if (showDebug) {
        strUsage += HelpMessageOpt("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT));
    }

    // Disabled until we can lock notes
    //strUsage += HelpMessageOpt("-rpcasyncthreads=<n>", strprintf(_("Set the number of threads to service Async RPC calls (default: %d)"), 1));

    if (mode == HMM_BITCOIND) {
        strUsage += HelpMessageGroup(_("Metrics Options (only if -daemon and -printtoconsole are not set):"));
        strUsage += HelpMessageOpt("-showmetrics", _("Show metrics on stdout (default: 1 if running in a console, 0 otherwise)"));
        strUsage += HelpMessageOpt("-metricsui", _("Set to 1 for a persistent metrics screen, 0 for sequential metrics output (default: 1 if running in a console, 0 otherwise)"));
        strUsage += HelpMessageOpt("-metricsrefreshtime", strprintf(_("Number of seconds between metrics refreshes (default: %u if running in a console, %u otherwise)"), 1, 600));
    }

    return strUsage;
}

static void BlockNotifyCallback(const uint256& hashNewTip)
{
    std::string strCmd = GetArg("-blocknotify", "");

    boost::replace_all(strCmd, "%s", hashNewTip.GetHex());
    boost::thread t(runCommand, strCmd); // thread runs free
}

struct CImportingNow
{
    CImportingNow() {
        assert(fImporting == false);
        fImporting = true;
    }

    ~CImportingNow() {
        assert(fImporting == true);
        fImporting = false;
    }
};


// If we're using -prune with -reindex, then delete block files that will be ignored by the
// reindex.  Since reindexing works by starting at block file 0 and looping until a blockfile
// is missing, do the same here to delete any later block files after a gap.  Also delete all
// rev files since they'll be rewritten by the reindex anyway.  This ensures that vinfoBlockFile
// is in sync with what's actually on disk by the time we start downloading, so that pruning
// works correctly.
void CleanupBlockRevFiles()
{
    using namespace boost::filesystem;
    map<string, path> mapBlockFiles;

    // Glob all blk?????.dat and rev?????.dat files from the blocks directory.
    // Remove the rev files immediately and insert the blk file paths into an
    // ordered map keyed by block file index.
    LogPrintf("Removing unusable blk?????.dat and rev?????.dat files for -reindex with -prune\n");
    path blocksdir = GetDataDir() / "blocks";
    for (directory_iterator it(blocksdir); it != directory_iterator(); it++) {
        if (is_regular_file(*it) &&
            it->path().filename().string().length() == 12 &&
            it->path().filename().string().substr(8,4) == ".dat")
        {
            if (it->path().filename().string().substr(0,3) == "blk")
                mapBlockFiles[it->path().filename().string().substr(3,5)] = it->path();
            else if (it->path().filename().string().substr(0,3) == "rev")
                remove(it->path());
        }
    }

    // Remove all block files that aren't part of a contiguous set starting at
    // zero by walking the ordered map (keys are block file indices) by
    // keeping a separate counter.  Once we hit a gap (or if 0 doesn't exist)
    // start removing block files.
    int nContigCounter = 0;
    BOOST_FOREACH(const PAIRTYPE(string, path)& item, mapBlockFiles) {
        if (atoi(item.first) == nContigCounter) {
            nContigCounter++;
            continue;
        }
        remove(item.second);
    }
}

void ThreadImport(std::vector<boost::filesystem::path> vImportFiles)
{
    RenameThread("zcl-loadblk");
    bool fImported = false;
    // -reindex
    if (fReindex) {
        CImportingNow imp;
        int nFile = 0;
        fImported = true;
        while (true) {
            CDiskBlockPos pos(nFile, 0);
            if (!boost::filesystem::exists(GetBlockPosFilename(pos, "blk")))
                break; // No block files left to reindex
            FILE *file = OpenBlockFile(pos, true);
            if (!file)
                break; // This error is logged in OpenBlockFile
            LogPrintf("Reindexing block file blk%05u.dat...\n", (unsigned int)nFile);
            LoadExternalBlockFile(file, &pos);
            nFile++;
        }
        // The reindex flag is the record that the block index and the chainstate are not
        // complete on disk. Both live in memory until a flush, so make them durable before
        // the flag goes: a kill between the two left the flag cleared, an empty block index
        // next to full block files and a node that started from genesis.
        FlushStateToDisk();
        pblocktree->WriteReindexing(false);
        fReindex = false;
        LogPrintf("Reindexing finished\n");
        // To avoid ending up in a situation without genesis block, re-try initializing (no-op if reindexing worked):
        InitBlockIndex();
    }

    // hardcoded $DATADIR/bootstrap.dat
    boost::filesystem::path pathBootstrap = GetDataDir() / "bootstrap.dat";
    if (boost::filesystem::exists(pathBootstrap)) {
        FILE *file = fopen(pathBootstrap.string().c_str(), "rb");
        if (file) {
            CImportingNow imp;
            boost::filesystem::path pathBootstrapOld = GetDataDir() / "bootstrap.dat.old";
            LogPrintf("Importing bootstrap.dat...\n");
            fImported = true;
            LoadExternalBlockFile(file);
            RenameOver(pathBootstrap, pathBootstrapOld);
        } else {
            LogPrintf("Warning: Could not open bootstrap file %s\n", pathBootstrap.string());
        }
    }

    // -loadblock=
    BOOST_FOREACH(const boost::filesystem::path& path, vImportFiles) {
        FILE *file = fopen(path.string().c_str(), "rb");
        if (file) {
            CImportingNow imp;
            LogPrintf("Importing blocks file %s...\n", path.string());
            fImported = true;
            LoadExternalBlockFile(file);
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

#ifdef ENABLE_WALLET
    // Init offered the wallet's pending transactions to the mempool while the import
    // was still filling the chain (empty at the start of -reindex): they were refused
    // or could not be judged, and nothing else offers them again, so their inputs
    // would count as unspent. Mempool admission only, nothing is relayed.
    if (fImported && pwalletMain && !ShutdownRequested()) {
        pwalletMain->ReacceptWalletTransactions();
    }
#endif

    if (GetBoolArg("-stopafterblockimport", false)) {
        LogPrintf("Stopping after block import\n");
        StartShutdown();
    }
}

void ThreadNotifyRecentlyAdded()
{
    while (true) {
        // Run the notifier on an integer second in the steady clock.
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto nextFire = std::chrono::duration_cast<std::chrono::seconds>(
            now + std::chrono::seconds(1));
        std::this_thread::sleep_until(
            std::chrono::time_point<std::chrono::steady_clock>(nextFire));

        boost::this_thread::interruption_point();

        mempool.NotifyRecentlyAdded();
    }
}

static bool check_file_hash(const std::string& path, const std::string& hash)
{
    std::string buff_hash, error;
    if (!HashFileSHA256(path, buff_hash, error)) {
        LogPrintf("%s\n", error);
        uiInterface.ThreadSafeMessageBox(error, "", CClientUIInterface::MSG_ERROR);
        // NB: do NOT StartShutdown() here. check_file_hash() runs inside the
        // self-heal loop in InitSanityCheck(); returning false lets that loop
        // re-fetch the param from a bootstrap peer and re-verify. The caller
        // aborts (via InitError) only if the file is STILL bad after the heal.
        // Calling StartShutdown() here latches the sticky shutdown flag, so the
        // node would exit even after a successful self-heal (heals-then-exits).
        return false;
    }
    LogPrintf("%s: %s\n", path, buff_hash);
    if(buff_hash != hash){
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("hash of %s is not correct:\n"
              "%s\n\n expecting:\n%s\n"),
                path, buff_hash, hash),
            "", CClientUIInterface::MSG_ERROR);
        // See the failure path above: the caller (InitSanityCheck's
        // self-heal loop) owns the abort decision, so a corrupted-but-healable
        // param re-fetches and re-verifies instead of latching shutdown here.
        return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Verified-params cache (params-verify.cache, 0600 in DATADIR)
//
// PURPOSE: turn the dominant cold-start cost -- re-hashing ~1.69 GB of zk-SNARK
// params on EVERY launch (param-hash-loop ~= 5.1 s / 80.8% of AppInit2) -- into
// ~stat-cost on the common, unchanged case, WITHOUT ever loading an unverified
// param.
//
// SAFETY INVARIANT (load-bearing): a re-hash is SKIPPED for a param ONLY when
// ALL of these hold, otherwise we run the FULL check_file_hash exactly as today:
//   (a) file_size(path) == spec.nSize                 (the COMPILED size)
//   (b) cache record exists with size==cur_size AND mtime==cur_mtime
//   (c) record.verifiedHash == spec.sha256hex          (the LIVE COMPILED hash)
//   (d) cache file's binary-epoch == this binary's compiled-table epoch
//   (e) cache file is owner-only (st_uid==geteuid, no group/other write bits)
// The cache NEVER supplies a hash to trust: (c) compares the cached hash to the
// compiled constant (.rodata, not attacker-writable). The cache only answers
// "did THIS (size,mtime) already hash to the value the binary already requires".
// Forging a skip-and-load of malicious identical-size content requires a SHA-256
// second preimage (infeasible). A different-uid planted cache is rejected by (e).
//
// KNOWN, ACCEPTED RESIDUAL: a bit-rot/torn write that preserves BOTH size AND
// mtime is skipped and the corrupt param loads -- a regression of today's
// every-launch hash. This is BOUNDED and NON-CONSENSUS: zk params are firewalled
// from block/tx/PoW; a corrupt param makes a shielded proof FAIL/REJECT (never
// forges one or forks the chain), fails LOUDLY at use, and self-heals via the
// existing bootstrap re-fetch. Pass -noparamcache to force today's full hash.
namespace {

struct ParamCacheRecord {
    uint64_t size;
    int64_t  mtime;            // std::time_t, 1s granularity (boost last_write_time)
    std::string verifiedHash;  // 64-hex lowercase
};

// Cheap epoch over the COMPILED spec table: name|hash|size per file. A binary
// with any different compiled hash/size yields a different epoch, invalidating
// the entire cache (Model 4: downgrade / multi-version).
static std::string CompiledParamEpoch()
{
    std::string acc;
    BOOST_FOREACH(const ZcashParamSpec& s, GetZcashParamSpecs()) {
        acc += s.name;
        acc += '|';
        acc += s.sha256hex;
        acc += '|';
        acc += std::to_string((unsigned long long)s.nSize);
        acc += '\n';
    }
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(acc.data()), acc.size()).Finalize(digest);
    return HexStr(digest, digest + sizeof(digest));
}

static boost::filesystem::path ParamVerifyCachePath()
{
    return GetDataDir() / "params-verify.cache";
}

// Returns true and fills `out` ONLY if the cache file is present, owner-only
// (st_uid==geteuid, no group/other WRITE bits), strictly well-formed, and its
// stored epoch equals the freshly-computed compiled epoch. ANY doubt => false
// (caller treats as a cold cache and full-hashes every file).
static bool LoadVerifiedParamCache(std::map<std::string, ParamCacheRecord>& out)
{
    out.clear();
    const boost::filesystem::path p = ParamVerifyCachePath();
#ifndef WIN32
    // Mandatory on-READ ownership/mode gate: a cache writable by anyone other
    // than us (group/other-writable, or owned by a different uid) is ignored.
    // 0600-on-write is not enough; an attacker of a DIFFERENT uid must never be
    // able to plant a honored cache in a misconfigured/shared DATADIR.
    struct stat st;
    if (::stat(p.string().c_str(), &st) != 0) return false;
    if (!S_ISREG(st.st_mode)) return false;
    if (st.st_uid != geteuid()) return false;
    if (st.st_mode & (S_IWGRP | S_IWOTH)) return false;
#endif
    std::ifstream in(p.string().c_str());
    if (!in.good()) return false;

    std::string line;
    bool epochOk = false;
    const std::string wantEpoch = CompiledParamEpoch();
    std::map<std::string, ParamCacheRecord> recs;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::istringstream ls(line);
        std::string key;
        if (!(ls >> key)) return false;
        if (key == "v") {
            std::string v;
            if (!(ls >> v) || v != "1") return false;  // unknown format => fail closed
        } else if (key == "epoch") {
            std::string e;
            if (!(ls >> e) || e.size() != 64) return false;
            epochOk = (e == wantEpoch);                 // mismatch => discard whole cache
        } else if (key == "p") {
            std::string name, hash;
            unsigned long long sz; long long mt;
            if (!(ls >> name >> sz >> mt >> hash)) return false;
            if (hash.size() != 64) return false;
            for (char c : hash)
                if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            if (recs.count(name)) return false;          // duplicate => malformed
            ParamCacheRecord r;
            r.size = (uint64_t)sz;
            r.mtime = (int64_t)mt;
            r.verifiedHash = hash;
            recs[name] = r;
        } else {
            return false;                                // unknown key => fail closed
        }
    }
    if (!epochOk) return false;                          // missing or wrong epoch line
    out.swap(recs);
    return true;
}

// Atomically rewrite the whole cache 0600 in DATADIR: tmp (O_CREAT|O_WRONLY|
// O_TRUNC, 0600) -> FileCommit(fdatasync) -> RenameOver. A kill mid-write can
// never leave a half-record a future parse misreads as a valid skip.
static void StoreVerifiedParamCache(const std::map<std::string, ParamCacheRecord>& recs)
{
    const boost::filesystem::path finalPath = ParamVerifyCachePath();
    const boost::filesystem::path tmpPath = finalPath.string() + ".tmp";
#ifndef WIN32
    int fd = ::open(tmpPath.string().c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0) return;
    FILE* f = fdopen(fd, "wb");
    if (!f) { ::close(fd); return; }
#else
    FILE* f = fopen(tmpPath.string().c_str(), "wb");
    if (!f) return;
#endif
    fprintf(f, "v 1\n");
    fprintf(f, "epoch %s\n", CompiledParamEpoch().c_str());
    for (std::map<std::string, ParamCacheRecord>::const_iterator it = recs.begin();
         it != recs.end(); ++it) {
        fprintf(f, "p %s %llu %lld %s\n",
                it->first.c_str(),
                (unsigned long long)it->second.size,
                (long long)it->second.mtime,
                it->second.verifiedHash.c_str());
    }
    FileCommit(f);
    fclose(f);
    if (!RenameOver(tmpPath, finalPath)) {
        boost::filesystem::remove(tmpPath);
    }
}

} // anonymous namespace

static bool VerifyImportedBootstrapAnchor(std::string& error)
{
    if (chainActive.Tip() == NULL) {
        error = "bootstrap snapshot verification failed: active chain is empty";
        return false;
    }
    // Match the imported tip against the full set of compiled fast-sync anchors.
    // The node accepts a snapshot whose tip matches ANY one of the compiled
    // anchors (rolling anchors / smooth release rollout), not just the primary.
    int importedHeight = chainActive.Height();
    uint256 importedHash = chainActive.Tip()->GetBlockHash();
    const CFastSyncAnchorData* anchor = Params().FindFastSyncAnchor(importedHeight, importedHash);
    if (anchor == NULL) {
        // FindFastSyncAnchor returns NULL both when no anchor is compiled in at
        // all and when the imported tip matches none of the compiled anchors.
        error = strprintf(
            "bootstrap snapshot verification failed: imported tip (height %d, %s) matches no compiled fast-sync anchor",
            importedHeight,
            importedHash.ToString());
        return false;
    }
    // Content-trust check: recompute the commitment over the whole imported UTXO
    // set and compare it to the value compiled into this binary for the matched
    // anchor. A malicious or compromised serving peer cannot substitute a forged
    // chainstate, because it cannot reproduce a UTXO set that hashes to one of
    // the compiled commitments. A null commitment would silently disable this,
    // the only forgery check, so a matched anchor MUST carry one (defense in
    // depth; Checkpoints::ValidateFastSyncAnchor already rejects null-commitment
    // anchors at startup).
    if (anchor->hashChainstateSerialized.IsNull()) {
        error = strprintf(
            "bootstrap snapshot verification failed: matched anchor (height %d, %s) has no chainstate commitment",
            importedHeight,
            importedHash.ToString());
        return false;
    }
    // Re-hashing the whole imported UTXO set runs for minutes with no other
    // status update, so the GUI warmup message would otherwise freeze on the
    // prior "Verifying blocks..." string and the GUI watchdog could misfire.
    // Change the status string right before the re-hash so the GUI sees progress
    // (getbootstrapinfo.verify_pending also stays true throughout this window).
    uiInterface.InitMessage(_("Verifying downloaded blockchain (this can take a few minutes)..."));
    CCoinsStats stats;
    if (!pcoinsTip->GetStats(stats)) {
        error = "bootstrap snapshot verification failed: could not compute imported chainstate hash";
        return false;
    }
    if (stats.hashSerializedFull != anchor->hashChainstateSerialized) {
        error = strprintf(
            "bootstrap snapshot verification failed: imported chainstate hash is %s, expected %s",
            stats.hashSerializedFull.ToString(),
            anchor->hashChainstateSerialized.ToString());
        return false;
    }
    LogPrintf("Bootstrap snapshot chainstate commitment verified: %s\n", stats.hashSerializedFull.ToString());
    return true;
}

static void CloseBootstrapChainDatabases()
{
    UnloadBlockIndex();
    delete pcoinsTip;
    pcoinsTip = NULL;
    delete pcoinscatcher;
    pcoinscatcher = NULL;
    delete pcoinsdbview;
    pcoinsdbview = NULL;
    delete pblocktree;
    pblocktree = NULL;
}

static void RemoveFailedPeerBootstrapChainData(const boost::filesystem::path& data_dir)
{
    try {
        boost::filesystem::remove_all(data_dir / "blocks");
        boost::filesystem::remove_all(data_dir / "chainstate");
        // Also drop any scratch UTXO re-derivation DB left by an earlier
        // (aborted) trustless-validation run, so a rejected snapshot leaves no
        // stale chainstate-verify dir behind for the next start to resume from.
        boost::filesystem::remove_all(data_dir / "chainstate-verify");
        // With -bootstrapserve=auto the staged chainstate is retained into the
        // serve dir BEFORE the anchor is verified, so a rejected/forged snapshot
        // must not leave a serve copy behind to be re-served to peers. Drop the
        // retained copy and its sibling .anchor/.meta markers as well.
        const boost::filesystem::path serveSrc = BootstrapAutoServeSourceDir(data_dir);
        boost::filesystem::remove_all(serveSrc);
        boost::filesystem::remove(serveSrc.string() + ".anchor");
        boost::filesystem::remove(serveSrc.string() + ".meta");
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("Failed to remove rejected bootstrap chain data from %s: %s\n", data_dir.string(), e.what());
    }
}

// Periodic self-snapshot for -bootstrapserve=auto (option B): once the node is
// fully synced, freeze its own chainstate into the serve dir and advertise
// NODE_BOOTSTRAP. Skips while in IBD and skips a re-copy while the current serve
// copy is already near the tip. The manifest is pre-built here (off the
// message-handler thread) so a peer's first request does not trigger a multi-GiB
// hash on the net thread.
//
// The freeze (a multi-GiB recursive copy) and the preflight (a SHA-256 over the
// whole snapshot) take minutes, so they run on a DEDICATED worker thread rather
// than the shared scheduler thread; otherwise every freeze interval would starve
// PartitionCheck and the rest of the scheduled tasks for minutes. The worker is
// owned by a file-static handle (mirroring g_bsvalThread) so Shutdown() can
// interrupt+join it before the chain DBs are freed: the freeze takes cs_main and
// reads chainActive/mapBlockIndex/pcoinsTip, so it must never outlive them.
static const int BOOTSTRAP_SELF_SNAPSHOT_MIN_ADVANCE_BLOCKS = 500;
static boost::thread* g_serveFreezeThread = NULL;
static std::atomic<bool> g_serveFreezeInProgress(false);
// Guards the g_serveFreezeThread handle swap only (never held across a join), so
// the scheduler thread's reap+respawn and Shutdown()'s interrupt+join cannot
// race into a double-free of the handle. Unlike the one-shot g_bsvalThread, the
// freeze worker is re-spawned every interval, so the handle is mutated repeatedly.
static CCriticalSection cs_serveFreeze;

static void BootstrapServeFreezeWorker()
{
    // Clear the single-in-flight guard on EVERY exit path (normal return or a
    // throwing freeze), so an exception can never permanently wedge future
    // freezes.
    class InProgressGuard {
    public:
        ~InProgressGuard() { g_serveFreezeInProgress.store(false); }
    } guard;

    // Neutralize a late spawn that raced teardown: if we are already shutting
    // down, do not touch chainstate (it may be about to be freed).
    if (ShutdownRequested()) {
        return;
    }
    // Only scheduled when -bootstrapserve=auto with a positive freeze interval, so
    // no need to re-check the (init-rewritten) -bootstrapserve arg here.
    //
    // DEFAULT (v3 GROWABLE, anchor mode): EXTEND the retained anchor serve copy's
    // block bundle append-only toward this node's live tip, keeping its chainstate
    // PINNED at the compiled anchor (its compiled commitment still verifies on the
    // client with zero server trust). This fixes SCALE-1: the previous default froze
    // a fresh chainstate@tip into a v2 self-snapshot that anchor-mode clients reject.
    // ExtendServedBlocksForServe self-gates: it requires a retained ".anchor" serve
    // dir, refuses a v2 self-snapshot dir, and skips a re-copy while the served
    // bundle is already within minAdvanceBlocks of the tip — so it is a clean no-op
    // (logged at "net") when there is nothing to extend.
    //
    // The v2 self-snapshot path (FreezeLiveChainstateForServe, which re-freezes
    // chainstate at the node's own recent tip with no compiled anchor) is now ONLY
    // reachable behind the explicit EXPERIMENTAL -bootstrapmode=trustless opt-in.
    const bool fTrustlessServe = (GetArg("-bootstrapmode", "anchor") == "trustless");
    std::string err;
    if (fTrustlessServe) {
        if (!FreezeLiveChainstateForServe(GetDataDir(), BOOTSTRAP_SELF_SNAPSHOT_MIN_ADVANCE_BLOCKS, err)) {
            LogPrint("net", "Auto-serve self-snapshot skipped: %s\n", err);
            return;
        }
    } else {
        // SNAPSHOT-AT-ANCHOR: a node that synced from genesis (rather than
        // fast-syncing a snapshot) has NO retained chainstate@anchor for the extend
        // to grow on top of. Produce one ONCE by replaying genesis..anchor into a
        // verified scratch chainstate (BuildAnchorServeSnapshotFromGenesis), so this
        // node can serve a v3 GROWABLE snapshot too. This is CPU-heavy and holds
        // cs_main across the replay, which is exactly why it runs HERE on the
        // dedicated freeze worker thread rather than inline in init — it must never
        // block normal startup. Best-effort: on failure we just skip serving this
        // interval and retry next time. Only attempted when nothing is retained yet;
        // once built, the cheap append-only extend below takes over.
        if (!BootstrapSnapshotPathsExist(BootstrapAutoServeSourceDir(GetDataDir()))) {
            std::string buildErr;
            if (!BuildAnchorServeSnapshotFromGenesis(GetDataDir(), buildErr)) {
                LogPrint("net", "Auto-serve anchor snapshot build skipped: %s\n", buildErr);
                return;
            }
            LogPrintf("Auto-serve: built a chainstate@anchor serve copy by replaying from genesis; now serving v3 growable snapshots\n");
        }
        if (!ExtendServedBlocksForServe(GetDataDir(), BOOTSTRAP_SELF_SNAPSHOT_MIN_ADVANCE_BLOCKS, err)) {
            LogPrint("net", "Auto-serve block-bundle extend skipped: %s\n", err);
            return;
        }
    }
    if (!PreflightBootstrapSnapshotService(err)) {
        LogPrintf("Auto-serve: refreshed the served snapshot but cannot build its manifest: %s\n", err);
        return;
    }
    // Benign 64-bit store: readers see either value, both valid (advertise or not).
    if (!(nLocalServices & NODE_BOOTSTRAP)) {
        nLocalServices |= NODE_BOOTSTRAP;
        LogPrintf("Auto bootstrap-serve active: now serving the %s to peers\n",
            fTrustlessServe ? "self-snapshot" : "growing anchor snapshot");
    }
}

// Scheduler poll: returns immediately. Launches the freeze worker only when one
// is not already running, so a freeze spanning more than one interval does not
// stack. Runs on the shared scheduler thread; only this (single) thread flips the
// guard false->true, so there is no double-spawn.
static void BootstrapServeFreezeCheck()
{
    if (ShutdownRequested()) {
        return;
    }
    if (g_serveFreezeInProgress.load()) {
        return;
    }
    boost::thread* reap = NULL;
    {
        LOCK(cs_serveFreeze);
        // Re-check under the lock: InterruptBootstrapServeFreeze() takes the same
        // lock at shutdown, so this guarantees we never spawn a new worker after
        // (or concurrently with) the shutdown interrupt+join.
        if (ShutdownRequested()) {
            return;
        }
        // Claim the previous (finished — in-progress is false here) handle to reap
        // after we release the lock, so the thread object is not leaked across
        // intervals and the join (instant, the worker already returned) never runs
        // under the lock.
        reap = g_serveFreezeThread;
        g_serveFreezeInProgress.store(true);
        g_serveFreezeThread = new boost::thread(boost::bind(&BootstrapServeFreezeWorker));
    }
    if (reap != NULL) {
        try {
            reap->join();
        } catch (...) {}
        delete reap;
    }
}

// Interrupt+join the freeze worker before the chain DBs are freed (mirror of
// InterruptBootstrapValidation). No-op when no freeze worker exists.
static void InterruptBootstrapServeFreeze()
{
    // Claim the handle under the lock, then interrupt+join OUTSIDE the lock (the
    // join can block for the freeze duration; holding cs_serveFreeze across it
    // could stall the scheduler thread's launcher).
    boost::thread* t = NULL;
    {
        LOCK(cs_serveFreeze);
        t = g_serveFreezeThread;
        g_serveFreezeThread = NULL;
    }
    if (t == NULL) {
        return;
    }
    try {
        t->interrupt();
        t->join();
    } catch (...) {}
    delete t;
    g_serveFreezeInProgress.store(false);
}



/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
/** Scheduled every few seconds while -embeddedtor is on (see Step 6). */
static void EmbeddedTorWatchdog()
{
    if (ShutdownRequested() || !EmbeddedTorRunning() || EmbeddedTorAlive())
        return;
    LogPrintf("tor: the embedded Tor has exited; shutting down (-embeddedtor never continues without Tor)\n");
    StartShutdown();
}

bool InitSanityCheck(void)
{

    boost::filesystem::path sapling_output = ZC_GetParamsDir() / "sapling-output.params";
    boost::filesystem::path sapling_spend = ZC_GetParamsDir() / "sapling-spend.params";
    boost::filesystem::path sprout_groth16 = ZC_GetParamsDir() / "sprout-groth16.params";
    boost::filesystem::path vk_path = ZC_GetParamsDir() / "sprout-verifying.key";

    // If parameters are missing, fetch them from a bootstrap peer over the P2P
    // protocol (verified against compiled hashes) instead of requiring an
    // external download. Uses -bootstrappeer if set, else the compiled default
    // peers; disable with -bootstrap=0.
    // Use the cheap existence+size predicate here (no hashing): this only gates
    // whether we trigger the bootstrap-peer auto-fetch. The size it compares is
    // the COMPILED ZcashParamAt(i).nSize, never a disk/peer-supplied size. The
    // authoritative per-file SHA-256 verification is the GetZcashParamSpecs()
    // check_file_hash loop below, run on every required file before
    // ZC_LoadParams loads them -- so each param is still hash-verified exactly
    // once before use. A corrupted-but-correct-size param slips past this gate
    // but is caught by that loop, which then re-fetches (self-heal) before
    // failing.
    // A node told to use a proxy (-proxy) or to stay onion-only (-onlynet
    // without ipv4/ipv6, with or without -embeddedtor) never fetches here: this
    // runs before Step 6 starts Tor and sets the proxies, so the fetch would
    // dial the bootstrap peers directly and expose the node's address.
    const bool fParamFetchAllowed = GetBoolArg("-bootstrap", true) && !ZcashParamFetchWouldBypassProxy();
    if (!ZcashParamsPresent() && GetBoolArg("-bootstrap", true) && !fParamFetchAllowed)
        LogPrintf("Zcash parameters are missing; not fetching them from a bootstrap peer before the proxy is set up (-proxy, or -onlynet without ipv4/ipv6): run zcutil/fetch-params.sh\n");
    if (!ZcashParamsPresent() && fParamFetchAllowed) {
        std::string paramError = "no bootstrap peer configured";
        BOOST_FOREACH(const std::string& peer, GetBootstrapPeerList()) {
            fprintf(stdout, "Fetching Zcash parameters from peer %s...\n", peer.c_str());
            LogPrintf("Fetching Zcash parameters from bootstrap peer %s...\n", peer);
            if (FetchZcashParamsFromPeer(peer, paramError)) {
                break;
            }
            LogPrintf("Zcash param fetch from %s failed: %s\n", peer, paramError);
        }
        // If it still failed, the existence check below reports the error.
    }

    if (!(
        boost::filesystem::exists(vk_path) &&
        boost::filesystem::exists(sapling_spend) &&
        boost::filesystem::exists(sapling_output) &&
        boost::filesystem::exists(sprout_groth16)
    )) {
        InitError(strprintf(
            "Zcash parameter files are missing from %s. Run zcutil/fetch-params.sh before starting zclassicd, or pass -bootstrappeer=<host> to fetch them from a peer.",
            ZC_GetParamsDir().string()));
        return false;
    }


    // Validate every required Zcash parameter file against the single
    // compiled SHA-256 table in bootstrap.cpp. Keeping one source of truth
    // means a future hash update can't silently disagree between startup
    // validation and the bootstrap-snapshot fetch path. This GetZcashParamSpecs()
    // check_file_hash loop is the SOLE pre-load hash barrier: ZC_LoadParams only
    // does exists() on the files, so every param must be hash-verified here
    // before it is handed to the prover/verifier.
    //
    // Self-heal: because the auto-fetch gate above is now a cheap presence+size
    // check (it does NOT hash), a corrupted-but-correct-size param file reaches
    // this loop without having triggered a re-fetch. To preserve the old
    // auto-heal behavior, on a hash mismatch -- if -bootstrap is enabled and we
    // have not already retried -- trigger FetchZcashParamsFromPeer once. That
    // fetch re-hashes each on-disk file and only re-downloads the one(s) that do
    // not match the compiled hash, then we re-run this loop and fail only if the
    // file is still bad. On the healthy path each file is still hashed exactly
    // once.
    const std::vector<ZcashParamSpec>& zcash_param_specs = GetZcashParamSpecs();
    bool fParamRefetched = false;

    // Verified-params cache (see helpers above check_file_hash). Load once; an
    // empty map (missing/garbage/foreign-owner/epoch-mismatch cache, or the
    // -noparamcache escape hatch) means every file is full-hashed exactly as
    // before. A SKIP is permitted ONLY when current size==compiled size AND a
    // record's (size,mtime) matches the file AND record.verifiedHash equals the
    // LIVE compiled spec.sha256hex -- the cache can never widen what counts as
    // valid, only avoid recomputing a match it already proved.
    const bool fUseParamCache = GetBoolArg("-paramcache", true) && !GetBoolArg("-noparamcache", false);
    std::map<std::string, ParamCacheRecord> paramCache;
    if (fUseParamCache) {
        (void)LoadVerifiedParamCache(paramCache); // empty on any doubt
    }
    std::map<std::string, ParamCacheRecord> verifiedRecords;
    bool fCacheDirty = false;
    int nSkipped = 0, nHashed = 0;

    for (size_t i = 0; i < zcash_param_specs.size(); ++i) {
        const ZcashParamSpec& spec = zcash_param_specs[i];
        const boost::filesystem::path path = ZC_GetParamsDir() / spec.name;

        // FOLLOW-UP C: sprout-verifying.key is the SOLE consensus-relevant zk param
        // whose only pre-load integrity gate is the SHA-256 below (the 3 Sapling/
        // Groth16 params have an independent BLAKE2b gate in the C23 core; there is
        // no PHGR13 proving key any more: nothing here creates Sprout proofs). The vk is
        // tiny (1449 bytes), so re-hashing it every launch is free, and it is the
        // key consumed by JoinSplit verify() during tx/block validation -- so we
        // never honor a cached skip for it: a same-size+same-mtime silent on-disk
        // corruption must be re-detected here, not loaded unverified. This keeps
        // the cache (and ~all of the startup speedup) for the other four params.
        const bool fAllowCacheSkip =
            std::string(spec.name) != "sprout-verifying.key";

        if (fUseParamCache && fAllowCacheSkip) {
            boost::system::error_code ec1, ec2;
            const uintmax_t curSize = boost::filesystem::file_size(path, ec1);
            const std::time_t curMtime = boost::filesystem::last_write_time(path, ec2);
            std::map<std::string, ParamCacheRecord>::const_iterator it = paramCache.find(spec.name);
            std::string compiledHash(spec.sha256hex);
            std::transform(compiledHash.begin(), compiledHash.end(), compiledHash.begin(), ::tolower);
            if (!ec1 && !ec2 &&
                (uint64_t)curSize == spec.nSize &&            // (a) compiled size
                it != paramCache.end() &&
                it->second.size == (uint64_t)curSize &&       // (b) unchanged since verify
                it->second.mtime == (int64_t)curMtime &&
                it->second.verifiedHash == compiledHash) {    // (c) == LIVE compiled hash
                verifiedRecords[spec.name] = it->second;      // carry forward, no re-hash
                ++nSkipped;
                continue;
            }
        }

        if (!check_file_hash(path.string(), spec.sha256hex)) {
            // A present, correct-size, but wrong-hash (corrupted/forged) file.
            // Self-heal once via the bootstrap-peer fetch, then re-verify.
            if (!fParamRefetched && fParamFetchAllowed) {
                fParamRefetched = true;
                std::string paramError = "no bootstrap peer configured";
                BOOST_FOREACH(const std::string& peer, GetBootstrapPeerList()) {
                    fprintf(stdout, "Re-fetching corrupted Zcash parameter from peer %s...\n", peer.c_str());
                    LogPrintf("Param hash mismatch for %s; re-fetching from bootstrap peer %s...\n",
                              spec.name, peer);
                    if (FetchZcashParamsFromPeer(peer, paramError)) {
                        break;
                    }
                    LogPrintf("Zcash param re-fetch from %s failed: %s\n", peer, paramError);
                }
                // Restart the verification from the first file: the re-fetch
                // re-hashes and may have repaired any of them. Drop staged
                // records: a healed file is re-stat'd/re-hashed on the restart.
                verifiedRecords.clear();
                nSkipped = 0;
                nHashed = 0;
                i = (size_t)-1; // ++i -> 0 on the next iteration
                continue;
            }
            return false;
        }

        // Full hash passed: stage a fresh record from the file's CURRENT
        // (size,mtime), pinning the verifiedHash to the COMPILED hash we just
        // matched. last_write_time is re-read post-verify so a file rewritten
        // during this run records its new mtime.
        {
            boost::system::error_code ec1, ec2;
            const uintmax_t curSize = boost::filesystem::file_size(path, ec1);
            const std::time_t curMtime = boost::filesystem::last_write_time(path, ec2);
            if (!ec1 && !ec2) {
                std::string compiledHash(spec.sha256hex);
                std::transform(compiledHash.begin(), compiledHash.end(), compiledHash.begin(), ::tolower);
                ParamCacheRecord r;
                r.size = (uint64_t)curSize;
                r.mtime = (int64_t)curMtime;
                r.verifiedHash = compiledHash;
                verifiedRecords[spec.name] = r;
            }
            fCacheDirty = true;
            ++nHashed;
        }
    }

    // Persist the cache only when something was (re)hashed or the on-disk set
    // differs from what we verified this run (also rewrites a stale/cold cache).
    if (fUseParamCache &&
        (fCacheDirty || verifiedRecords.size() != paramCache.size())) {
        StoreVerifiedParamCache(verifiedRecords);
    }
    LogPrintf("param-cache: %d skipped, %d hashed (cache %s)\n",
              nSkipped, nHashed, fUseParamCache ? "on" : "off");

    // Isolate the param SHA-256 hashing (the dominant cost in InitSanityCheck)
    // from the cheap tail below (fast-sync anchor validate + ECC/glibc sanity).
    g_startupTimer.mark("param-hash-loop");

    boost::filesystem::path data_dir = GetDataDir();
    {
        boost::system::error_code dirEc;
        if (!boost::filesystem::is_directory(data_dir, dirEc)) {
            boost::filesystem::create_directories(data_dir, dirEc);
            if (dirEc)
                return InitError(strprintf(_("Cannot create the data directory \"%s\": %s"), data_dir.string(), dirEc.message()));
        }
    }

    fprintf(stdout, "Network: %s\n", Params().NetworkIDString().c_str());

    std::string fastSyncAnchorError;
    if (!Checkpoints::ValidateFastSyncAnchor(Params(), fastSyncAnchorError)) {
        InitError(fastSyncAnchorError);
        return false;
    }
    const CFastSyncAnchorData& fastSyncAnchor = Params().FastSyncAnchor();
    if (!fastSyncAnchor.hashBlock.IsNull()) {
        LogPrintf("Fast-sync anchor: network=%s height=%d block=%s sha256=%s sha3=%s\n",
            Params().NetworkIDString(),
            fastSyncAnchor.nHeight,
            fastSyncAnchor.hashBlock.ToString(),
            fastSyncAnchor.hashAnchorSha256.ToString(),
            fastSyncAnchor.hashAnchorSha3.ToString());
    }

    if(!ECC_InitSanityCheck()) {
        InitError("Elliptic curve cryptography sanity check failure. Aborting.");
        return false;
    }
    if (!glibc_sanity_test() || !glibcxx_sanity_test())
        return false;

    return true;
}


static void ZC_LoadParams(
    const CChainParams& chainparams
)
{
    struct timeval tv_start, tv_end;
    float elapsed;

    boost::filesystem::path sapling_output = ZC_GetParamsDir() / "sapling-output.params";
    boost::filesystem::path sapling_spend = ZC_GetParamsDir() / "sapling-spend.params";
    boost::filesystem::path sprout_groth16 = ZC_GetParamsDir() / "sprout-groth16.params";
    boost::filesystem::path vk_path = ZC_GetParamsDir() / "sprout-verifying.key";

    // redundant checks on startup is ok and more secure
    if (!(
        boost::filesystem::exists(vk_path) &&
        boost::filesystem::exists(sapling_spend) &&
        boost::filesystem::exists(sapling_output) &&
        boost::filesystem::exists(sprout_groth16)
    )) {
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("Cannot find the Zcash network parameters in the following directory:\n"
              "%s\n"
              "Please run 'zclassic-fetch-params' or './zcutil/fetch-params.sh' and then restart."),
                ZC_GetParamsDir()),
            "", CClientUIInterface::MSG_ERROR);
        StartShutdown();
        return;
    }

    LogPrintf("Loading verifying key from %s\n", vk_path.string().c_str());
    gettimeofday(&tv_start, 0);

    pzcashParams = ZCJoinSplit::Prepared(vk_path.string());

    gettimeofday(&tv_end, 0);
    elapsed = float(tv_end.tv_sec-tv_start.tv_sec) + (tv_end.tv_usec-tv_start.tv_usec)/float(1000000);
    LogPrintf("Loaded verifying key in %fs seconds.\n", elapsed);

    static_assert(
        sizeof(boost::filesystem::path::value_type) == sizeof(codeunit),
        "librustzcash not configured correctly");
    auto sapling_spend_str = sapling_spend.native();
    auto sapling_output_str = sapling_output.native();
    auto sprout_groth16_str = sprout_groth16.native();

     LogPrintf("Loading Sapling (Spend) parameters from %s\n", sapling_spend.string().c_str());
     LogPrintf("Loading Sapling (Output) parameters from %s\n", sapling_output.string().c_str());
     LogPrintf("Loading Sapling (Sprout Groth16) parameters from %s\n", sprout_groth16.string().c_str());


    gettimeofday(&tv_start, 0);

    librustzcash_init_zksnark_params(
        reinterpret_cast<const codeunit*>(sapling_spend_str.c_str()),
        sapling_spend_str.length(),
        "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c",
        reinterpret_cast<const codeunit*>(sapling_output_str.c_str()),
        sapling_output_str.length(),
        "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028",
        reinterpret_cast<const codeunit*>(sprout_groth16_str.c_str()),
        sprout_groth16_str.length(),
        "e9b238411bd6c0ec4791e9d04245ec350c9c5744f5610dfcce4365d5ca49dfefd5054e371842b3f88fa1b9d7e8e075249b3ebabd167fa8b0f3161292d36c180a"
    );

    gettimeofday(&tv_end, 0);
    elapsed = float(tv_end.tv_sec-tv_start.tv_sec) + (tv_end.tv_usec-tv_start.tv_usec)/float(1000000);
    LogPrintf("Loaded Sapling parameters in %fs seconds.\n", elapsed);
}

// Loading and hash-checking the Sapling parameter files takes most of a second and
// is independent of the block-index load that follows it, so AppInit2 runs it on a
// helper thread and joins before anything that can create or verify a proof. The
// files are still hash-checked in full before use; only the wait is overlapped.
// The guard joins on every exit path so the thread never outlives AppInit2.
class ZcParamsLoader
{
    std::future<void> fut;
public:
    void Start(const CChainParams& chainparams)
    {
        fut = std::async(std::launch::async, [&chainparams]() { ZC_LoadParams(chainparams); });
    }
    // Wait for the load to finish; rethrows what ZC_LoadParams threw, as the
    // synchronous call did.
    void Join()
    {
        if (fut.valid())
            fut.get();
    }
    ~ZcParamsLoader()
    {
        if (fut.valid())
            fut.wait();
    }
};

bool AppInitServers(boost::thread_group& threadGroup)
{
    RPCServer::OnStopped(&OnRPCStopped);
    RPCServer::OnPreCommand(&OnRPCPreCommand);
    if (!InitHTTPServer())
        return false;
    if (!StartRPC())
        return false;
    if (!StartHTTPRPC())
        return false;
    if (GetBoolArg("-rest", false) && !StartREST())
        return false;
    if (!StartHTTPServer())
        return false;
    return true;
}

/** Initialize bitcoin.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInit2(boost::thread_group& threadGroup, CScheduler& scheduler)
{
    // ALWAYS-ON startup instrumentation: anchor the cumulative baseline at
    // AppInit2 entry. Each g_startupTimer.mark() below records the time since
    // the previous mark; g_startupTimer.summary() at "Done loading" prints the
    // per-phase table. Pure instrumentation -- no behavior change.
    g_startupTimer.begin();
    // ********************************************************* Step 1: setup
#ifdef _MSC_VER
    // Turn off Microsoft heap dump noise
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, CreateFileA("NUL", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, 0));
#endif
#if _MSC_VER >= 1400
    // Disable confusing "helpful" text message on abort, Ctrl-C
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
#endif
#ifdef WIN32
    // Enable Data Execution Prevention (DEP)
    // Minimum supported OS versions: WinXP SP3, WinVista >= SP1, Win Server 2008
    // A failure is non-critical and needs no further attention!
#ifndef PROCESS_DEP_ENABLE
    // We define this here, because GCCs winbase.h limits this to _WIN32_WINNT >= 0x0601 (Windows 7),
    // which is not correct. Can be removed, when GCCs winbase.h is fixed!
#define PROCESS_DEP_ENABLE 0x00000001
#endif
    typedef BOOL (WINAPI *PSETPROCDEPPOL)(DWORD);
    PSETPROCDEPPOL setProcDEPPol = (PSETPROCDEPPOL)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "SetProcessDEPPolicy");
    if (setProcDEPPol != NULL) setProcDEPPol(PROCESS_DEP_ENABLE);
#endif

    if (!SetupNetworking())
        return InitError("Error: Initializing networking failed");

#ifndef WIN32
    if (GetBoolArg("-sysperms", false)) {
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false))
            return InitError("Error: -sysperms is not allowed in combination with enabled wallet functionality");
#endif
    } else {
        umask(077);
    }

    // Clean shutdown on SIGTERM
    struct sigaction sa;
    sa.sa_handler = HandleSIGTERM;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);

    // Reopen debug.log on SIGHUP
    struct sigaction sa_hup;
    sa_hup.sa_handler = HandleSIGHUP;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Ignore SIGPIPE, otherwise it will bring the daemon down if the client closes unexpectedly
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef WIN32
    // Clean shutdown on Ctrl+C, Ctrl+Break and console close instead of an abrupt exit
    SetConsoleCtrlHandler(WinConsoleCtrlHandler, TRUE);
#endif

    std::set_new_handler(new_handler_terminate);

    // ********************************************************* Step 2: parameter interactions
    const CChainParams& chainparams = Params();

    // Set this early so that experimental features are correctly enabled/disabled
    fExperimentalMode = GetBoolArg("-experimentalfeatures", false);

    // Fail early if user has set experimental options without the global flag
    if (!fExperimentalMode) {
        if (mapArgs.count("-developerencryptwallet")) {
            return InitError(_("Wallet encryption requires -experimentalfeatures."));
        }
        else if (mapArgs.count("-paymentdisclosure")) {
            return InitError(_("Payment disclosure requires -experimentalfeatures."));
        } else if (mapArgs.count("-zmergetoaddress")) {
            return InitError(_("RPC method z_mergetoaddress requires -experimentalfeatures."));
        }
    }

    // Set this early so that parameter interactions go to console
    fPrintToConsole = GetBoolArg("-printtoconsole", false);
    fLogTimestamps = GetBoolArg("-logtimestamps", true);
    fPrintToDebugLog = GetBoolArg("-debuglogfile", false);
    fLogIPs = GetBoolArg("-logips", false);

    LogPrintf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n");
    LogPrintf("ZClassic version %s (%s)\n", FormatFullVersion(), CLIENT_DATE);

    // when specifying an explicit binding address, you want to listen on it
    // even when -connect or -proxy is specified
    if (mapArgs.count("-bind")) {
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -bind set -> setting -listen=1\n", __func__);
    }
    if (mapArgs.count("-whitebind")) {
        if (SoftSetBoolArg("-listen", true))
            LogPrintf("%s: parameter interaction: -whitebind set -> setting -listen=1\n", __func__);
    }

    if (mapArgs.count("-connect") && mapMultiArgs["-connect"].size() > 0) {
        // when only connecting to trusted nodes, do not seed via DNS, or listen by default
        if (SoftSetBoolArg("-dnsseed", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -dnsseed=0\n", __func__);
        if (SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -connect set -> setting -listen=0\n", __func__);
    }

    if (mapArgs.count("-proxy")) {
        // to protect privacy, do not listen by default if a default proxy server is specified
        if (SoftSetBoolArg("-listen", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -listen=0\n", __func__);
        // to protect privacy, do not discover addresses by default
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -proxy set -> setting -discover=0\n", __func__);
    }

    if (!GetBoolArg("-listen", DEFAULT_LISTEN)) {
        // do not try to retrieve public IP when not listening (pointless)
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -discover=0\n", __func__);
        if (SoftSetBoolArg("-listenonion", false))
            LogPrintf("%s: parameter interaction: -listen=0 -> setting -listenonion=0\n", __func__);
    }

    if (mapArgs.count("-externalip")) {
        // if an explicit public IP is specified, do not try to find others
        if (SoftSetBoolArg("-discover", false))
            LogPrintf("%s: parameter interaction: -externalip set -> setting -discover=0\n", __func__);
    }

    if (GetBoolArg("-salvagewallet", false)) {
        // Rewrite just private keys: rescan to find transactions
        if (SoftSetBoolArg("-rescan", true))
            LogPrintf("%s: parameter interaction: -salvagewallet=1 -> setting -rescan=1\n", __func__);
    }

    // -zapwallettx implies a rescan
    if (GetBoolArg("-zapwallettxes", false)) {
        if (SoftSetBoolArg("-rescan", true))
            LogPrintf("%s: parameter interaction: -zapwallettxes=<mode> -> setting -rescan=1\n", __func__);
    }

    // Make sure enough file descriptors are available
    int nBind = std::max((int)mapArgs.count("-bind") + (int)mapArgs.count("-whitebind"), 1);
    nMaxConnections = GetArg("-maxconnections", DEFAULT_MAX_PEER_CONNECTIONS);
    nMaxConnections = std::max(std::min(nMaxConnections, (int)(FD_SETSIZE - nBind - MIN_CORE_FILEDESCRIPTORS)), 0);
    int nFD = RaiseFileDescriptorLimit(nMaxConnections + MIN_CORE_FILEDESCRIPTORS);
    if (nFD < MIN_CORE_FILEDESCRIPTORS)
        return InitError(_("Not enough file descriptors available."));
    if (nFD - MIN_CORE_FILEDESCRIPTORS < nMaxConnections)
        nMaxConnections = nFD - MIN_CORE_FILEDESCRIPTORS;

    // if using block pruning, then disable txindex
    // also disable the wallet (for now, until SPV support is implemented in wallet)
    if (GetArg("-prune", 0)) {
        // -txindex now DEFAULTS to true (a bootstrap snapshot ships a txindex'd
        // chainstate), so a pruned node started with just -prune=N would hard-fail
        // on the default alone — a regression from upstream, where the default was
        // false. Mirror the -disablewallet handling below: soft-set -txindex off
        // under -prune, and only refuse to start when the operator EXPLICITLY asked
        // for -txindex=1. SoftSetBoolArg also makes the later GetBoolArg("-txindex",
        // true) reads (block-tree cache cap, fTxIndex) see the pruned value.
        if (mapArgs.count("-txindex") && GetBoolArg("-txindex", false))
            return InitError(_("Prune mode is incompatible with -txindex."));
        if (SoftSetBoolArg("-txindex", false))
            LogPrintf("%s : parameter interaction: -prune -> setting -txindex=0\n", __func__);
#ifdef ENABLE_WALLET
        if (!GetBoolArg("-disablewallet", false)) {
            if (SoftSetBoolArg("-disablewallet", true))
                LogPrintf("%s : parameter interaction: -prune -> setting -disablewallet=1\n", __func__);
            else
                return InitError(_("Can't run with a wallet in prune mode."));
        }
#endif
    }

    // ********************************************************* Step 3: parameter-to-internal-flags

    fDebug = !mapMultiArgs["-debug"].empty();
    // Special-case: if -debug=0/-nodebug is set, turn off debugging messages
    const vector<string>& categories = mapMultiArgs["-debug"];
    if (GetBoolArg("-nodebug", false) || find(categories.begin(), categories.end(), string("0")) != categories.end())
        fDebug = false;
    // The C23 crypto core logs its reject reasons only under -debug=zc23 (or -debug=1).
    zcl_c23_log_refresh();

    // Special case: if debug=zrpcunsafe, implies debug=zrpc, so add it to debug categories
    if (find(categories.begin(), categories.end(), string("zrpcunsafe")) != categories.end()) {
        if (find(categories.begin(), categories.end(), string("zrpc")) == categories.end()) {
            LogPrintf("%s: parameter interaction: setting -debug=zrpcunsafe -> -debug=zrpc\n", __func__);
            vector<string>& v = mapMultiArgs["-debug"];
            v.push_back("zrpc");
        }
    }

    // Check for -debugnet
    if (GetBoolArg("-debugnet", false))
        InitWarning(_("Warning: Unsupported argument -debugnet ignored, use -debug=net."));
    // Check for -socks - as this is a privacy risk to continue, exit here
    if (mapArgs.count("-socks"))
        return InitError(_("Error: Unsupported argument -socks found. Setting SOCKS version isn't possible anymore, only SOCKS5 proxies are supported."));
    // Check for -tor - as this is a privacy risk to continue, exit here
    if (GetBoolArg("-tor", false))
        return InitError(_("Error: Unsupported argument -tor found, use -onion."));

    // Embedded Tor is opt-in. Refuse to start rather than fall back to an
    // unproxied node when it was asked for and cannot be provided.
    const bool fEmbeddedTor = GetBoolArg("-embeddedtor", DEFAULT_EMBEDDED_TOR);
    EmbeddedTorMode embeddedTorMode = EMBEDDED_TOR_INPROCESS;
    if (fEmbeddedTor) {
        if (!EmbeddedTorAvailable())
            return InitError(_("Error: -embeddedtor needs a build with embedded Tor (configure --with-embedded-tor)."));
        if (!ParseEmbeddedTorMode(GetArg("-embeddedtormode", DEFAULT_EMBEDDED_TOR_MODE), embeddedTorMode))
            return InitError(strprintf(_("Invalid -embeddedtormode: '%s' (use inprocess or child)"), GetArg("-embeddedtormode", "")));
        if (GetArg("-onion", "") == "0")
            return InitError(_("Error: -embeddedtor cannot be combined with -onion=0."));
    }

    if (GetBoolArg("-benchmark", false))
        InitWarning(_("Warning: Unsupported argument -benchmark ignored, use -debug=bench."));

    // Checkmempool and checkblockindex default to true in regtest mode
    int ratio = std::min<int>(std::max<int>(GetArg("-checkmempool", chainparams.DefaultConsistencyChecks() ? 1 : 0), 0), 1000000);
    if (ratio != 0) {
        mempool.setSanityCheck(1.0 / ratio);
    }
    fCheckBlockIndex = GetBoolArg("-checkblockindex", chainparams.DefaultConsistencyChecks());
    fCheckpointsEnabled = GetBoolArg("-checkpoints", true);

    // -par=0 means autodetect, but nScriptCheckThreads==0 means no concurrency
    nScriptCheckThreads = GetArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (nScriptCheckThreads <= 0)
        nScriptCheckThreads += GetNumCores();
    if (nScriptCheckThreads <= 1)
        nScriptCheckThreads = 0;
    else if (nScriptCheckThreads > MAX_SCRIPTCHECK_THREADS)
        nScriptCheckThreads = MAX_SCRIPTCHECK_THREADS;

#ifdef ZCL_C23_HAVE_PROVER_THREADS
    zcl_c23_set_prover_threads(ProverThreadBudget());
    // Left automatic, a send also makes only as many proofs at once as fit in
    // the prover's memory allowance (about 340 MB, or an eighth of physical
    // memory), the thread budget then spread over fewer proofs; an explicit
    // -proverthreads is the person's own choice and is not capped.
    if (GetArg("-proverthreads", 0) > 0) {
        SetProverWorkerCap(0);
    } else {
        const size_t proofsAtOnce = ProverWorkerLimit(PhysicalMemoryBytes());
        SetProverWorkerCap(proofsAtOnce);
        LogPrintf("Prover memory allowance: at most %u proofs at once (%u MiB of physical memory)\n",
                  (unsigned)proofsAtOnce, (unsigned)(PhysicalMemoryBytes() >> 20));
    }
#endif

    fServer = GetBoolArg("-server", false);

    // block pruning; get the amount of disk space (in MB) to allot for block & undo files
    int64_t nSignedPruneTarget = GetArg("-prune", 0) * 1024 * 1024;
    if (nSignedPruneTarget < 0) {
        return InitError(_("Prune cannot be configured with a negative value."));
    }
    nPruneTarget = (uint64_t) nSignedPruneTarget;
    if (nPruneTarget) {
        if (nPruneTarget < MIN_DISK_SPACE_FOR_BLOCK_FILES) {
            return InitError(strprintf(_("Prune configured below the minimum of %d MB.  Please use a higher number."), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
        }
        LogPrintf("Prune configured to target %uMiB on disk for block and undo files.\n", nPruneTarget / 1024 / 1024);
        fPruneMode = true;
    }

    RegisterAllCoreRPCCommands(tableRPC);
#ifdef ENABLE_WALLET
    bool fDisableWallet = GetBoolArg("-disablewallet", false);
    if (!fDisableWallet)
        RegisterWalletRPCCommands(tableRPC);
#endif

    nConnectTimeout = GetArg("-timeout", DEFAULT_CONNECT_TIMEOUT);
    if (nConnectTimeout <= 0)
        nConnectTimeout = DEFAULT_CONNECT_TIMEOUT;

    // Fee-per-kilobyte amount considered the same as "free"
    // If you are mining, be careful setting this:
    // if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    if (mapArgs.count("-minrelaytxfee"))
    {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-minrelaytxfee"], n) && n > 0)
            ::minRelayTxFee = CFeeRate(n);
        else
            return InitError(strprintf(_("Invalid amount for -minrelaytxfee=<amount>: '%s'"), mapArgs["-minrelaytxfee"]));
    }

#ifdef ENABLE_WALLET
    if (mapArgs.count("-mintxfee"))
    {
        CAmount n = 0;
        if (ParseMoney(mapArgs["-mintxfee"], n) && n > 0)
            CWallet::minTxFee = CFeeRate(n);
        else
            return InitError(strprintf(_("Invalid amount for -mintxfee=<amount>: '%s'"), mapArgs["-mintxfee"]));
    }
    if (mapArgs.count("-paytxfee"))
    {
        CAmount nFeePerK = 0;
        if (!ParseMoney(mapArgs["-paytxfee"], nFeePerK))
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s'"), mapArgs["-paytxfee"]));
        if (nFeePerK > nHighTransactionFeeWarning)
            InitWarning(_("Warning: -paytxfee is set very high! This is the transaction fee you will pay if you send a transaction."));
        payTxFee = CFeeRate(nFeePerK, 1000);
        if (payTxFee < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -paytxfee=<amount>: '%s' (must be at least %s)"),
                                       mapArgs["-paytxfee"], ::minRelayTxFee.ToString()));
        }
    }
    if (mapArgs.count("-maxtxfee"))
    {
        CAmount nMaxFee = 0;
        if (!ParseMoney(mapArgs["-maxtxfee"], nMaxFee))
            return InitError(strprintf(_("Invalid amount for -maxtxfee=<amount>: '%s'"), mapArgs["-maptxfee"]));
        if (nMaxFee > nHighTransactionMaxFeeWarning)
            InitWarning(_("Warning: -maxtxfee is set very high! Fees this large could be paid on a single transaction."));
        maxTxFee = nMaxFee;
        if (CFeeRate(maxTxFee, 1000) < ::minRelayTxFee)
        {
            return InitError(strprintf(_("Invalid amount for -maxtxfee=<amount>: '%s' (must be at least the minrelay fee of %s to prevent stuck transactions)"),
                                       mapArgs["-maxtxfee"], ::minRelayTxFee.ToString()));
        }
    }
    nTxConfirmTarget = GetArg("-txconfirmtarget", DEFAULT_TX_CONFIRM_TARGET);
    if (mapArgs.count("-txexpirydelta")) {
        int64_t expiryDelta = atoi64(mapArgs["-txexpirydelta"]);
        uint32_t minExpiryDelta = TX_EXPIRING_SOON_THRESHOLD + 1;
        if (expiryDelta < minExpiryDelta) {
            return InitError(strprintf(_("Invalid value for -txexpirydelta='%u' (must be least %u)"), expiryDelta, minExpiryDelta));
        }
        expiryDeltaArg = expiryDelta;
    }
    bSpendZeroConfChange = GetBoolArg("-spendzeroconfchange", true);
    fSendFreeTransactions = GetBoolArg("-sendfreetransactions", false);
    fTokenGuard = GetBoolArg("-tokenguard", true);

    std::string strWalletFile = GetArg("-wallet", "wallet.dat");
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", true);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

    // Option to startup with mocktime set (used for regression testing):
    SetMockTime(GetArg("-mocktime", 0)); // SetMockTime(0) is a no-op

    if (GetBoolArg("-peerbloomfilters", true))
        nLocalServices |= NODE_BLOOM;

    nMaxTipAge = GetArg("-maxtipage", DEFAULT_MAX_TIP_AGE);

#ifdef ENABLE_MINING
    if (mapArgs.count("-mineraddress")) {
        CTxDestination addr = DecodeDestination(mapArgs["-mineraddress"]);
        if (!IsValidDestination(addr)) {
            return InitError(strprintf(
                _("Invalid address for -mineraddress=<addr>: '%s' (must be a transparent address)"),
                mapArgs["-mineraddress"]));
        }
    }
#endif

    if (mapArgs.count("-mempoolmaxbytes")) {
        int64_t nCap = GetArg("-mempoolmaxbytes", (int64_t)DEFAULT_MEMPOOL_MAX_BYTES);
        if (nCap < (int64_t)MIN_MEMPOOL_MAX_BYTES) {
            return InitError(strprintf(_("-mempoolmaxbytes=%s is too small: the minimum is %u bytes (0 does not mean unlimited)"), mapArgs["-mempoolmaxbytes"], MIN_MEMPOOL_MAX_BYTES));
        }
        nMempoolMaxBytes = (uint64_t)nCap;
    }
    LogPrintf("Mempool total size cap: %u bytes\n", nMempoolMaxBytes);

    // Default value of 0 for mempooltxinputlimit means no limit is applied
    if (mapArgs.count("-mempooltxinputlimit")) {
        int64_t limit = GetArg("-mempooltxinputlimit", 0);
        if (limit < 0) {
            return InitError(_("Mempool limit on transparent inputs to a transaction cannot be negative"));
        } else if (limit > 0) {
            LogPrintf("Mempool configured to reject transactions with greater than %lld transparent inputs\n", limit);
        }
    }

    // The crash and checkpoint-interval hooks exist for qa/rpc-tests/wallet_crash_consistency.sh.
    // A stray line in zclassic.conf must not make a real node exit at a wallet write point.
    if ((mapArgs.count("-testcrashpoint") || mapArgs.count("-testsetchaininterval") || mapArgs.count("-testblockindexinterval")) &&
        Params().NetworkIDString() != "regtest") {
        return InitError("-testcrashpoint, -testsetchaininterval and -testblockindexinterval may only be used on regtest.");
    }

    if (!mapMultiArgs["-nuparams"].empty()) {
        // Allow overriding network upgrade parameters for testing
        if (Params().NetworkIDString() != "regtest") {
            return InitError("Network upgrade parameters may only be overridden on regtest.");
        }
        const vector<string>& deployments = mapMultiArgs["-nuparams"];
        for (auto i : deployments) {
            std::vector<std::string> vDeploymentParams;
            boost::split(vDeploymentParams, i, boost::is_any_of(":"));
            if (vDeploymentParams.size() != 2) {
                return InitError("Network upgrade parameters malformed, expecting hexBranchId:activationHeight");
            }
            int nActivationHeight;
            if (!ParseInt32(vDeploymentParams[1], &nActivationHeight)) {
                return InitError(strprintf("Invalid nActivationHeight (%s)", vDeploymentParams[1]));
            }
            bool found = false;
            // Exclude Sprout from upgrades
            for (auto i = Consensus::BASE_SPROUT + 1; i < Consensus::MAX_NETWORK_UPGRADES; ++i)
            {
                if (vDeploymentParams[0].compare(HexInt(NetworkUpgradeInfo[i].nBranchId)) == 0) {
                    UpdateNetworkUpgradeParameters(Consensus::UpgradeIndex(i), nActivationHeight);
                    found = true;
                    LogPrintf("Setting network upgrade activation parameters for %s to height=%d\n", vDeploymentParams[0], nActivationHeight);
                    break;
                }
            }
            if (!found) {
                return InitError(strprintf("Invalid network upgrade (%s)", vDeploymentParams[0]));
            }
        }
    }

    if (!mapMultiArgs["-eqparams"].empty()) {
        // Allow overriding equihash upgrade parameters for testing
        if (Params().NetworkIDString() != "regtest") {
            return InitError("Network upgrade parameters may only be overridden on regtest.");
        }
        const vector<string>& deployments = mapMultiArgs["-eqparams"];
        for (auto i : deployments) {
            std::vector<std::string> vDeploymentParams;
            boost::split(vDeploymentParams, i, boost::is_any_of(":"));
            if (vDeploymentParams.size() != 3) {
                return InitError("Equihash upgrade parameters malformed, expecting hexBranchId:N:K");
            }
            int n, k;
            // TODO: Restrict to support n,k parameters and cast to unsigned int
            if (!ParseInt32(vDeploymentParams[1], &n)) {
                return InitError(strprintf("Invalid N (%s)", vDeploymentParams[1]));
            }
            if (!ParseInt32(vDeploymentParams[2], &k)) {
                return InitError(strprintf("Invalid K (%s)", vDeploymentParams[2]));
            }
            bool found = false;
            // Exclude Sprout from upgrades
            for (auto i = Consensus::BASE_SPROUT + 1; i < Consensus::MAX_NETWORK_UPGRADES; ++i)
            {
                if (vDeploymentParams[0].compare(HexInt(NetworkUpgradeInfo[i].nBranchId)) == 0) {
                    UpdateEquihashUpgradeParameters(Consensus::UpgradeIndex(i), n, k);
                    found = true;
                    LogPrintf("Setting equihash upgrade activation parameters for %s to n=%d, k=%d\n", vDeploymentParams[0], n, k);
                    break;
                }
            }
            if (!found) {
                return InitError(strprintf("Invalid equihash upgrade (%s)", vDeploymentParams[0]));
            }
        }
    }

    g_startupTimer.mark("setup+flags(1-3)");
    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    // Select the SHA-256 backend (portable C, SHA-NI or ARMv8 SHA) after its
    // known-answer self-test, before any thread is started, and record it.
    LogPrintf("Using the '%s' SHA256 implementation\n", SHA256AutoDetect());

    // Initialize libsodium
    if (init_and_check_sodium() == -1) {
        return false;
    }

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Split the former coarse "ecc+sodium+sanity" mark: this isolates ECC_Start()'s
    // secp256k1 table precompute from InitSanityCheck() (which hashes the ~1.69 GB
    // of Zcash params). Proves which half the ~8.9s actually lives in.
    g_startupTimer.mark("ecc-start");

    // Sanity check
    if (!InitSanityCheck())
        return InitError(_("Initialization sanity check failed. ZClassic is shutting down."));

    g_startupTimer.mark("sanity-tail");
    std::string strDataDir = GetDataDir().string();
#ifdef ENABLE_WALLET
    // Wallet file must be a plain filename without a directory
    if (strWalletFile != boost::filesystem::path(strWalletFile).filename().string())
        return InitError(strprintf(_("Wallet %s resides outside data directory %s"), strWalletFile, strDataDir));
#endif
    // Make sure only a single Bitcoin process is using the data directory.
    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    FILE* file = fopen(pathLockFile.string().c_str(), "a"); // empty lock file; created if it doesn't exist.
    if (file) fclose(file);

    try {
        static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
        if (!lock.try_lock())
            return InitError(strprintf(_("Cannot obtain a lock on data directory %s. ZClassic is probably already running."), strDataDir));
    } catch(const boost::interprocess::interprocess_exception& e) {
        return InitError(strprintf(_("Cannot obtain a lock on data directory %s. ZClassic is probably already running.") + " %s.", strDataDir, e.what()));
    }

#ifndef WIN32
    CreatePidFile(GetPidFile(), getpid());
#endif
    // Never open a mixed database pair after an interrupted GUI repair.
    const auto repairJournal = GetDataDir() / "chain-repair-pending.json";
    if (boost::filesystem::exists(repairJournal) || boost::filesystem::is_symlink(repairJournal))
        return InitError(_("An interrupted blockchain repair needs recovery. Open the ZClassic wallet to restore the previous chain before starting the node. Do not delete the repair journal or blockchain backups."));
    // if (GetBoolArg("-shrinkdebugfile", !fDebug))
    //     ShrinkDebugFile();

    if (fPrintToDebugLog)
        OpenDebugLog();

    LogPrintf("Using OpenSSL version %s\n", SSLeay_version(SSLEAY_VERSION));
#ifdef ENABLE_WALLET
    LogPrintf("Using BerkeleyDB version %s\n", DbEnv::version(0, 0, 0));
#endif
    if (!fLogTimestamps)
        LogPrintf("Startup time: %s\n", DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()));
    LogPrintf("Default data directory %s\n", GetDefaultDataDir().string());
    LogPrintf("Using data directory %s\n", strDataDir);
    LogPrintf("Using config file %s\n", GetConfigFile().string());
    LogPrintf("Using at most %i connections (%i file descriptors available)\n", nMaxConnections, nFD);
    std::ostringstream strErrors;

    LogPrintf("Using %u threads for script verification\n", nScriptCheckThreads);
    if (nScriptCheckThreads) {
        for (int i=0; i<nScriptCheckThreads-1; i++)
            threadGroup.create_thread(&ThreadScriptCheck);
    }

    // Start the lightweight task scheduler thread
    CScheduler::Function serviceLoop = boost::bind(&CScheduler::serviceQueue, &scheduler);
    threadGroup.create_thread(boost::bind(&TraceThread<CScheduler::Function>, "scheduler", serviceLoop));

    // Count uptime
    MarkStartTime();

    if ((chainparams.NetworkIDString() != "regtest") &&
            GetBoolArg("-showmetrics", isatty(STDOUT_FILENO)) &&
            !fPrintToConsole && !GetBoolArg("-daemon", false)) {
        // Start the persistent metrics interface
        ConnectMetricsScreen();
        threadGroup.create_thread(&ThreadShowMetricsScreen);
    }


    g_startupTimer.mark("datadir-lock+threads");
    // Initialize Zclassic circuit parameters
    ZcParamsLoader zcParamsLoader;
    zcParamsLoader.Start(chainparams);
    g_startupTimer.mark("zk-snark params (started)");


    /* Start the RPC server already.  It will be started in "warmup" mode
     * and not really process calls already (but it will signify connections
     * that the server is there and will be ready later).  Warmup mode will
     * be disabled when initialisation is finished.
     */
    if (fServer)
    {
        uiInterface.InitMessage.connect(SetRPCWarmupStatus);
        if (!AppInitServers(threadGroup))
            return InitError(_("Unable to start HTTP server. See debug log for details."));
    }
    g_startupTimer.mark("rpc/http servers");

    int64_t nStart;

    // ********************************************************* Step 5: verify wallet database integrity
#ifdef ENABLE_WALLET
    if (!fDisableWallet) {
        LogPrintf("Using wallet %s\n", strWalletFile);
        uiInterface.InitMessage(_("Verifying wallet..."));

        std::string warningString;
        std::string errorString;

        if (!CWallet::Verify(strWalletFile, warningString, errorString))
            return false;

        if (!warningString.empty())
            InitWarning(warningString);
        if (!errorString.empty())
            return InitError(warningString);

    } // (!fDisableWallet)
#endif // ENABLE_WALLET
    g_startupTimer.mark("wallet db verify");
    // ********************************************************* Step 6: network initialization

    RegisterNodeSignals(GetNodeSignals());

    // sanitize comments per BIP-0014, format user agent and check total size
    std::vector<string> uacomments;
    BOOST_FOREACH(string cmt, mapMultiArgs["-uacomment"])
    {
        if (cmt != SanitizeString(cmt, SAFE_CHARS_UA_COMMENT))
            return InitError(strprintf("User Agent comment (%s) contains unsafe characters.", cmt));
        uacomments.push_back(SanitizeString(cmt, SAFE_CHARS_UA_COMMENT));
    }
    strSubVersion = FormatSubVersion(CLIENT_NAME, CLIENT_VERSION, uacomments);
    if (strSubVersion.size() > MAX_SUBVERSION_LENGTH) {
        return InitError(strprintf("Total length of network version string %i exceeds maximum of %i characters. Reduce the number and/or size of uacomments.",
            strSubVersion.size(), MAX_SUBVERSION_LENGTH));
    }

    if (mapArgs.count("-onlynet")) {
        std::set<enum Network> nets;
        BOOST_FOREACH(const std::string& snet, mapMultiArgs["-onlynet"]) {
            enum Network net = ParseNetwork(snet);
            if (net == NET_UNROUTABLE)
                return InitError(strprintf(_("Unknown network specified in -onlynet: '%s'"), snet));
            nets.insert(net);
        }
        for (int n = 0; n < NET_MAX; n++) {
            enum Network net = (enum Network)n;
            if (!nets.count(net))
                SetLimited(net);
        }
    }

    if (mapArgs.count("-whitelist")) {
        BOOST_FOREACH(const std::string& net, mapMultiArgs["-whitelist"]) {
            CSubNet subnet(net);
            if (!subnet.IsValid())
                return InitError(strprintf(_("Invalid netmask specified in -whitelist: '%s'"), net));
            CNode::AddWhitelistedRange(subnet);
        }
    }

    bool proxyRandomize = GetBoolArg("-proxyrandomize", true);
    // -proxy sets a proxy for all outgoing network traffic
    // -noproxy (or -proxy=0) as well as the empty string can be used to not set a proxy, this is the default
    std::string proxyArg = GetArg("-proxy", "");
    SetLimited(NET_ONION);
    if (proxyArg != "" && proxyArg != "0") {
        proxyType addrProxy = proxyType(CService(proxyArg, 9050), proxyRandomize);
        if (!addrProxy.IsValid())
            return InitError(strprintf(_("Invalid -proxy address: '%s'"), proxyArg));

        SetProxy(NET_IPV4, addrProxy);
        SetProxy(NET_IPV6, addrProxy);
        SetProxy(NET_ONION, addrProxy);
        SetNameProxy(addrProxy);
        SetLimited(NET_ONION, false); // by default, -proxy sets onion as reachable, unless -noonion later
    }

    // -onion can be used to set only a proxy for .onion, or override normal proxy for .onion addresses
    // -noonion (or -onion=0) disables connecting to .onion entirely
    // An empty string is used to not override the onion proxy (in which case it defaults to -proxy set above, or none)
    std::string onionArg = GetArg("-onion", "");
    if (onionArg != "") {
        if (onionArg == "0") { // Handle -noonion/-onion=0
            SetLimited(NET_ONION); // set onions as unreachable
        } else {
            proxyType addrOnion = proxyType(CService(onionArg, 9050), proxyRandomize);
            if (!addrOnion.IsValid())
                return InitError(strprintf(_("Invalid -onion address: '%s'"), onionArg));
            SetProxy(NET_ONION, addrOnion);
            SetLimited(NET_ONION, false);
        }
    }

    // -embeddedtor: launch the Tor linked into this binary. Its state lives in
    // <datadir>/tor (the datadir lock is held since Step 4); its SOCKS and
    // control ports are loopback ports chosen at runtime.
    if (fEmbeddedTor) {
        std::string strTorError;
#if defined(WIN32) && defined(ENABLE_EMBEDDED_TOR)
        const std::string strTorDataDir = EmbeddedTorDataDir(GetDataDir());
#else
        const std::string strTorDataDir = GetDataDir().string();
#endif
        if (!StartEmbeddedTor(strTorDataDir, embeddedTorMode, strTorError))
            return InitError(strprintf(_("Could not start the embedded Tor: %s"), strTorError));
        proxyType addrEmbedded = proxyType(CService("127.0.0.1", EmbeddedTorSocksPort()), proxyRandomize);
        if (!addrEmbedded.IsValid())
            return InitError(_("The embedded Tor did not report a SOCKS port."));
        if (onionArg == "") {
            // An explicit -onion keeps its meaning; otherwise .onion peers
            // are reached through the embedded Tor.
            SetProxy(NET_ONION, addrEmbedded);
            SetLimited(NET_ONION, false);
        }
        if (IsLimited(NET_IPV4) && IsLimited(NET_IPV6) && !HaveNameProxy()) {
            // Onion-only node (-onlynet=onion) without -proxy: host names
            // (DNS seeds, -addnode, -seednode, -connect) must never reach the
            // system resolver. Hand them to Tor instead.
            SetNameProxy(addrEmbedded);
            // Literal IPv4/IPv6 destinations do not use the name proxy:
            // ConnectSocket() dials them directly unless their network has a
            // proxy, and -onlynet does not stop it. Those are -addnode,
            // -connect and -seednode given as addresses, the compiled
            // bootstrap peers init adds as -addnode on every start, and the
            // bootstrap snapshot download. Send them through Tor as well,
            // the same as -proxy does.
            SetProxy(NET_IPV4, addrEmbedded);
            SetProxy(NET_IPV6, addrEmbedded);
            // Addresses with no network (private ranges, TEST-NET, ...) have
            // no proxy and would still be dialled directly: refuse those.
            SetProxyOnly(true);
            LogPrintf("tor: onion-only node, host names and IP destinations go through the embedded Tor\n");
            // Without -bind the P2P port listens on every interface, and a
            // clearnet peer that connects in is sent this node's onion
            // address (version addrMe, addr relay), tying the two together.
            // Tor reaches the port on loopback, so listen only there.
            if (!mapArgs.count("-bind") && !mapArgs.count("-whitebind")) {
                mapArgs["-bind"] = "127.0.0.1";
                mapMultiArgs["-bind"].push_back("127.0.0.1");
                LogPrintf("tor: onion-only node without -bind, listening on 127.0.0.1 only\n");
            }
        }
        // A node that asked for Tor never continues without it: if Tor exits
        // on its own, shut down instead of leaving its loopback ports free
        // for another local process to take over.
        scheduler.scheduleEvery(&EmbeddedTorWatchdog, 5);
    }

    // see Step 2: parameter interactions for more information about these
    fListen = GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", true);

    bool fBound = false;
    bool fOnionTargetBound = false;
    if (fListen) {
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind")) {
            std::set<std::string> setBindArgs;
            BOOST_FOREACH(const std::string& strBindArg, mapMultiArgs["-bind"]) {
                // The same address given twice (on the command line and in the conf
                // file) is bound once: a second bind of a listening address fails.
                if (!setBindArgs.insert(strBindArg).second)
                    continue;
                // <addr>=onion: the listener the onion service points at (see doc/tor.md)
                std::string strBind = strBindArg;
                bool fOnionBind = false;
                if (strBind.size() > 6 && strBind.compare(strBind.size() - 6, 6, "=onion") == 0) {
                    strBind.resize(strBind.size() - 6);
                    fOnionBind = true;
                }
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, fOnionBind ? GetListenPort() + 1 : GetListenPort(), false))
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind));
                if (fOnionBind) {
                    if (!addrBind.IsLocal() && !addrBind.IsRFC1918())
                        LogPrintf("Warning: -bind=%s=onion is not a loopback address; the onion service target should not be reachable from outside\n", strBind);
                    std::string strOnionError;
                    if (!BindListenPort(addrBind, strOnionError, false, true))
                        return InitError(strOnionError);
                    SetOnionServiceTarget(addrBind);
                    fOnionTargetBound = true;
                    fBound = true;
                    LogPrintf("Onion service target: %s\n", addrBind.ToString());
                    continue;
                }
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR));
            }
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-whitebind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, 0, false))
                    return InitError(strprintf(_("Cannot resolve -whitebind address: '%s'"), strBind));
                if (addrBind.GetPort() == 0)
                    return InitError(strprintf(_("Need to specify a port with -whitebind: '%s'"), strBind));
                fBound |= Bind(addrBind, (BF_EXPLICIT | BF_REPORT_ERROR | BF_WHITELIST));
            }
        }
        else {
            struct in_addr inaddr_any;
            inaddr_any.s_addr = INADDR_ANY;
            fBound |= Bind(CService(in6addr_any, GetListenPort()), BF_NONE);
            fBound |= Bind(CService(inaddr_any, GetListenPort()), !fBound ? BF_REPORT_ERROR : BF_NONE);
        }
        if (!fBound)
            return InitError(_("Failed to listen on any port. Use -listen=0 if you want this."));

        // A node that was asked to run an onion service (embedded Tor, or an explicit
        // -torcontrol) gets a second loopback listener dedicated to it, the port after
        // the P2P port, unless -bind=<addr>=onion chose one. ADD_ONION points there, so
        // a connection accepted on it is known to be an onion peer. Fail-soft: without
        // it the service targets the P2P port as before and inbound onion peers are
        // simply not recognised (our onion address is then only sent to peers we
        // reached over Tor). Not done for the legacy auto-detected control port, which
        // may belong to any Tor on the host, nor for a -torcontrol that is not on this
        // machine: that Tor does not share our loopback, so it could not reach port+1
        // (it keeps the P2P port as the target; -bind=<addr>=onion chooses one).
        if (!fOnionTargetBound && GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION) &&
            (fEmbeddedTor || (mapArgs.count("-torcontrol") && TorControlAddressIsLocal(GetArg("-torcontrol", ""))))) {
            CService addrOnionBind(CNetAddr("127.0.0.1"), GetListenPort() + 1);
            std::string strOnionError;
            if (BindListenPort(addrOnionBind, strOnionError, false, true)) {
                SetOnionServiceTarget(addrOnionBind);
                LogPrintf("Onion service target: %s\n", addrOnionBind.ToString());
            } else {
                LogPrintf("Warning: no dedicated onion listener (%s); the onion service targets the P2P port\n", strOnionError);
            }
        }

        // Opt-in (default off): ask the router to forward our own listen port via
        // NAT-PMP/PCP so NAT/firewalled peers become reachable for inbound
        // connections. This is pure net plumbing (zero consensus surface) and can
        // only ever map THIS node's own address — never any other host.
        if (GetBoolArg("-natpmp", DEFAULT_NATPMP))
            StartMapPort(threadGroup, scheduler);
    }

    if (mapArgs.count("-externalip")) {
        BOOST_FOREACH(const std::string& strAddr, mapMultiArgs["-externalip"]) {
            CService addrLocal(strAddr, GetListenPort(), fNameLookup);
            if (!addrLocal.IsValid())
                return InitError(strprintf(_("Cannot resolve -externalip address: '%s'"), strAddr));
            AddLocal(CService(strAddr, GetListenPort(), fNameLookup), LOCAL_MANUAL);
        }
    }

    BOOST_FOREACH(const std::string& strDest, mapMultiArgs["-seednode"])
        AddOneShot(strDest);

    // Sub-mark: pure network-arg setup (UA/proxy/onion/listen-bind/seednode).
    // With -listen=0 the bind block is skipped, so this should be ~0ms on any node;
    // it isolates in-memory arg setup from the bootstrap-snapshot work that follows.
    g_startupTimer.mark(".net-setup");

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs);

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif

    const bool fBootstrapServeAuto = (GetArg("-bootstrapserve", "") == "auto");
    // Set true below for ANY verified-anchor bootstrap import (v1/v2/v3). Consumed at
    // Step 10, where the ActivateBestChain that connects whatever the imported block
    // index contains is wrapped in a CBootstrapForwardConnectGuard so ConnectTip re-runs
    // the contextual header (retarget) + contextual block checks on each above-checkpoint
    // block, rejecting a forged low-difficulty post-anchor fork. Stays false for every
    // normal node and manual serve — Step 10 is byte-identical there — and is a strict
    // no-op for a pure-anchor import (nothing above the checkpoint to connect). It is
    // deliberately NOT keyed on the server-advertised manifest tip; see the security note
    // at the arming site (CRITICAL-1 / HIGH-1 / HIGH-2).
    bool fBootstrapForwardConnect = false;
    if (GetBoolArg("-bootstrapserve", false)) {
        // Manual serve: a fixed prepared source dir, validated up front.
        if (!mapArgs.count("-bootstrapsourcedir")) {
            return InitError(_("-bootstrapserve requires -bootstrapsourcedir=<dir> (or use -bootstrapserve=auto)"));
        }
        const boost::filesystem::path bootstrap_source = boost::filesystem::system_complete(mapArgs["-bootstrapsourcedir"]);
        std::string bootstrap_error;
        if (!BootstrapSnapshotPathsExist(bootstrap_source)) {
            return InitError(strprintf(
                _("-bootstrapsourcedir must contain blocks/, blocks/index/, and chainstate/: %s"),
                bootstrap_source.string()));
        }
        if (!PreflightBootstrapSnapshotService(bootstrap_error)) {
            return InitError(strprintf(
                _("Bootstrap snapshot service preflight failed for %s: %s"),
                bootstrap_source.string(),
                bootstrap_error));
        }
        nLocalServices |= NODE_BOOTSTRAP;
    }
    // MEDIUM-B1: warn when the aggregate serve rate cap is set below the floor where its
    // per-window budget can hold even a single chunk. Below that floor the token-bucket
    // first-chunk-through still serves ~1 chunk/window, so the EFFECTIVE rate exceeds the
    // operator's chosen value — tell them rather than silently over-serving (and, before
    // the B1 fix, silently serving nothing at all).
    {
        int64_t configuredKbps = 0, effectiveFloorKbps = 0;
        if (BootstrapServeRateCapBelowFloor(configuredKbps, effectiveFloorKbps)) {
            LogPrintf("Warning: -bootstrapservemaxtotalkbps=%d is below the effective floor "
                "(~%d Kbit/s); the aggregate serve cap will still pass ~one chunk per window\n",
                (int)configuredKbps, (int)effectiveFloorKbps);
        }
    }
    // Note: for -bootstrapserve=auto we do NOT advertise NODE_BOOTSTRAP here.
    // A fresh auto node has nothing to serve yet, and advertising before we can
    // answer manifests would pollute peer discovery with a dead "server". The
    // bit is set later (after the retained snapshot is wired up AND its manifest
    // is pre-built) in the SetupAutoBootstrapServe activation below.

    if (mapArgs.count("-bootstrapdatadir")) {
        std::string bootstrap_error;
        boost::filesystem::path bootstrap_source = boost::filesystem::system_complete(mapArgs["-bootstrapdatadir"]);
        if (!ImportBootstrapDatadir(bootstrap_source, GetDataDir(), GetBoolArg("-bootstrapforce", false), bootstrap_error)) {
            return InitError(bootstrap_error);
        }
        fBlockIndexFromSnapshot = true;
    }

    // Fetch the chain snapshot from a bootstrap peer. This runs automatically on
    // a fresh datadir using the compiled default peers; -bootstrappeer overrides
    // the peer and -bootstrap=0 disables it. An explicit -bootstrappeer makes a
    // failure fatal; the automatic path is best-effort and falls back to normal
    // peer-to-peer sync if no bootstrap peer is reachable.
    bool bootstrap_snapshot_ran = false;
    // Sub-mark: everything between net-setup and the auto bootstrap-snapshot
    // decision -- ZMQ interface create, the -bootstrapserve preflight, and
    // the optional -bootstrapdatadir manual import. On a -connect=0 -listen=0 node
    // with no -bootstrapserve these are all cheap, so this row should be ~0ms.
    g_startupTimer.mark(".pre-bootstrap-snapshot");
    // If a genesis-only datadir is moved aside to make room for a fast-sync, this
    // names the backup directory so we can restore it if the bootstrap fails.
    boost::filesystem::path genesisBackupDir;
    // True when this bootstrap was triggered by abandoned-stub auto-recovery (a
    // small, real, far-below-anchor chain backed up to fast-sync into). Lets the
    // success handler clear the stub-recovery churn-guard marker; the existing
    // genesisBackupDir restore handles failure with no extra code.
    bool fStubRecovery = false;
    {
        // D1 crash recovery: InstallStagedBootstrapChainData renames blocks/ then
        // chainstate/ non-atomically, AFTER the anchor/trustless pending marker has
        // been written and fsync'd. A kill between the two renames leaves blocks/
        // present but chainstate/ absent — an incomplete install. On the next start
        // that blocks-only datadir is NOT genesis-only (IsGenesisOnlyChainDatadir
        // returns false for a missing/over-size chainstate or a blocks/-only dir),
        // so without this guard BootstrapDatadirEligible would classify it as real
        // chain data and silently skip re-bootstrapping, while the verify step never
        // runs (chainstate/ is gone). Detect the incomplete install by: a pending
        // marker EXISTS but the installed snapshot paths do NOT, and treat it as a
        // FAILED import — remove the partial chain data, clear the marker, and let
        // eligibility re-run below so the node re-bootstraps into a fresh datadir.
        if ((BootstrapAnchorPendingExists(GetDataDir()) ||
             BootstrapTrustlessPendingExists(GetDataDir())) &&
            !BootstrapSnapshotPathsExist(GetDataDir())) {
            LogPrintf("Bootstrap: a pending-import marker is present but the installed "
                      "snapshot is incomplete (blocks/ or chainstate/ missing); treating "
                      "the prior import as failed and re-bootstrapping\n");
            RemoveFailedPeerBootstrapChainData(GetDataDir());
            BootstrapAnchorPendingClear(GetDataDir());
            BootstrapTrustlessPendingClear(GetDataDir());
        }
        const bool explicit_peer = mapArgs.count("-bootstrappeer");
        const bool enabled = GetBoolArg("-bootstrap", true) && !GetBootstrapPeerList().empty();
        const bool conflicts = mapArgs.count("-bootstrapdatadir") ||
                               GetBoolArg("-reindex", false) ||
                               GetBoolArg("-reindex-chainstate", false) ||
                               !mapMultiArgs["-loadblock"].empty();

        if (explicit_peer && conflicts) {
            return InitError(_("-bootstrappeer cannot be used with -bootstrapdatadir, -reindex, -reindex-chainstate, or -loadblock"));
        }

        if (enabled && !conflicts) {
            const CFastSyncAnchorData& anchor = Params().FastSyncAnchor();
            // Option B: trustless mode accepts a peer's self-snapshot at its own
            // tip and verifies it by background re-derivation, so it does NOT
            // require a compiled fast-sync anchor.
            const bool fTrustlessMode = (GetArg("-bootstrapmode", "anchor") == "trustless");
            const bool haveAnchor = (anchor.nHeight >= 0 && !anchor.hashBlock.IsNull());
            // A pruned node cannot re-derive the UTXO set from genesis, so trustless
            // background validation can never run — the provisionally-accepted (and
            // possibly forged) snapshot would be trusted permanently with no
            // backstop. Refuse the combination outright.
            if (fTrustlessMode && fPruneMode) {
                return InitError(_("-bootstrapmode=trustless cannot be used with -prune: a pruned node cannot re-derive the UTXO set to validate the snapshot, so it would never be verified. Use a non-pruned datadir to bootstrap trustlessly, or use -bootstrapmode=anchor."));
            }
            std::string bootstrap_error;
            // Eligibility: fresh / genesis-only (handled by BootstrapDatadirEligible),
            // OR — as a SECOND chance — an abandoned stub (a small, real, far-below-anchor
            // chain a failed-then-stalled node was left holding). The stub path backs up
            // (never deletes) the stub and is bounded by a churn guard so an offline node
            // cannot loop. genesisBackupDir holds the backup either way; fStubRecovery
            // tells the success handler to clear the stub-recovery marker.
            bool fDatadirEligible = false;
            if (!fTrustlessMode && !haveAnchor) {
                SetBootstrapInfoPhase("skipped", "no compiled fast-sync anchor");
                if (explicit_peer)
                    return InitError(_("-bootstrappeer requires a compiled fast-sync anchor (or -bootstrapmode=trustless)"));
            } else if (BootstrapDatadirEligible(GetDataDir(), genesisBackupDir, bootstrap_error)) {
                fDatadirEligible = true;
            } else {
                // Not fresh and not genesis-only. Try abandoned-stub auto-recovery: a
                // node whose first bootstrap failed, fell back to P2P, grabbed a
                // few-thousand-block tip far below the anchor, and would otherwise NEVER
                // re-bootstrap (eligibility is false for any non-genesis chain).
                int stubHeight = -1;
                std::string stub_err;
                const CFastSyncAnchorData& anchorForStub = Params().FastSyncAnchor();
                if (IsAbandonedStubChainDatadir(GetDataDir(), stubHeight, stub_err)) {
                    std::string skipReason;
                    if (!StubRecoveryAllowedNow(GetDataDir(), anchorForStub.nHeight, skipReason)) {
                        SetBootstrapInfoPhase("skipped", skipReason);
                        LogPrintf("Bootstrap: abandoned-stub recovery skipped: %s\n", skipReason);
                        // The attempts are used up for this anchor: no download will resume
                        // here, so a partial snapshot kept for it only takes disk space. A
                        // cooldown is different: the next start may continue it.
                        StubRecoveryState exhausted;
                        if (ReadStubRecoveryMarker(GetDataDir(), exhausted) &&
                            exhausted.anchorHeight == anchorForStub.nHeight &&
                            exhausted.attempts >= kStubRecoveryMaxAttempts)
                            RemoveStaleBootstrapStaging(GetDataDir());
                        if (explicit_peer)
                            return InitError(skipReason);
                        // else fall through to normal sync (NOT eligible).
                    } else {
                        LogPrintf("Bootstrap: detected an abandoned stub chain (tip height %s, anchor %d); backing up and re-bootstrapping\n",
                                  (stubHeight >= 0 ? strprintf("%d", stubHeight) : std::string("unknown")), anchorForStub.nHeight);
                        // Count the attempt BEFORE any backup/download so a crash/offline
                        // loop can't churn (repeated multi-GiB backups / disk-fill).
                        StubRecoveryState st;
                        ReadStubRecoveryMarker(GetDataDir(), st);
                        if (st.anchorHeight != anchorForStub.nHeight) {
                            st.attempts = 0;
                            st.lastAttempt = 0;
                            st.anchorHeight = anchorForStub.nHeight;
                        }
                        st.attempts += 1;
                        st.lastAttempt = GetTime();
                        // FAIL CLOSED: if the attempt cannot be durably counted (read-only
                        // or full datadir), do NOT proceed. Otherwise an offline node would
                        // read attempts=0 every startup and churn backup->fail->restore
                        // unbounded. Leave the stub for normal P2P sync instead.
                        if (!WriteStubRecoveryMarker(GetDataDir(), st)) {
                            SetBootstrapInfoPhase("skipped", "stub-recovery marker not durably writable; leaving for normal P2P sync");
                            LogPrintf("Bootstrap: abandoned-stub recovery skipped: churn-guard marker not durably writable\n");
                            if (explicit_peer)
                                return InitError("cannot persist stub-recovery state (datadir not writable)");
                            // else: fDatadirEligible stays false -> normal P2P sync.
                        } else {
                            LogPrintf("Bootstrap: abandoned-stub recovery attempt %d of %d (cooldown %lld s)\n",
                                      st.attempts, kStubRecoveryMaxAttempts, (long long)kStubRecoveryCooldownSecs);
                            std::string backup_err;
                            if (BackupGenesisOnlyChainData(GetDataDir(), genesisBackupDir, backup_err)) {
                                // genesisBackupDir is now set -> the datadir is fresh -> take
                                // the SAME download path the eligible branch uses. On failure
                                // the existing genesisBackupDir restore puts the stub back; on
                                // success fStubRecovery clears the marker.
                                fStubRecovery = true;
                                fDatadirEligible = true;
                            } else {
                                SetBootstrapInfoPhase("skipped", backup_err);
                                LogPrintf("Bootstrap: abandoned-stub backup failed: %s\n", backup_err);
                                if (explicit_peer)
                                    return InitError(backup_err);
                            }
                        }
                    }
                } else {
                    // Genuinely real chain (or corrupt -> reindex path): existing behavior.
                    SetBootstrapInfoPhase("skipped", bootstrap_error.empty() ? "datadir not eligible" : bootstrap_error);
                    // A snapshot staging directory kept for resume (an earlier download
                    // that was interrupted) is dead weight once the node has a real
                    // chain: no bootstrap will run here again, so give the disk back.
                    RemoveStaleBootstrapStaging(GetDataDir());
                    // Datadir already has real chain data: skip silently unless the
                    // user explicitly asked to bootstrap into it. A datadir holding
                    // only a genesis-height chainstate (a node that initialized its
                    // DBs but never synced — e.g. a prior interrupted bootstrap that
                    // then fell back to peerless P2P sync and hung at 0 blocks) is
                    // backed up by BootstrapDatadirEligible and counts as eligible.
                    if (ShutdownRequested())
                        return false;
                    if (explicit_peer)
                        return InitError(bootstrap_error);
                }
            }
            if (fDatadirEligible) {
                if (fTrustlessMode)
                    InitWarning(_("EXPERIMENTAL: -bootstrapmode=trustless accepts a peer's self-snapshot provisionally and re-derives the UTXO set from genesis in the background, reindexing if it does not validate. WARNING: until validation completes (which can take as long as a full sync), the node operates on an UNVERIFIED UTXO set; do not rely on balances or spend received funds until getblockchaininfo reports bootstrap_validation state \"validated\"."));
                else
                    InitWarning(_("Bootstrap snapshots are trusted input; the snapshot tip is verified against the compiled anchor."));
                // Retry each peer a few times before giving up. A single transient
                // hiccup (a brief connection blip, a serve-side snapshot refresh, a
                // momentary stall on a lossy link) otherwise drops a fresh node
                // SILENTLY into peerless P2P sync and it appears to hang at 0 blocks.
                // Each BootstrapFromPeer attempt is self-contained (it stages into a
                // fresh dir and cleans up on failure), so retrying is safe and cheap.
                const int nBootstrapAttempts = 3;
                const std::vector<std::string> bootstrapPeers = GetBootstrapSnapshotPeerList();
                const int nBootstrapPeers = (int)bootstrapPeers.size();
                int peerIndex = 0;
                BOOST_FOREACH(const std::string& peer, bootstrapPeers) {
                    ++peerIndex;
                    if (ShutdownRequested())
                        break;
                    for (int attempt = 1; attempt <= nBootstrapAttempts && !ShutdownRequested(); ++attempt) {
                        // Keep the UI alive during connect/handshake/failover. The GUI
                        // surfaces this warmup status via getinfo; without it a dead or
                        // stalled peer leaves the wallet frozen on the prior message
                        // (e.g. "Verifying wallet...") for the whole failover window.
                        uiInterface.InitMessage(strprintf(
                            _("Connecting to bootstrap server %d of %d (attempt %d of %d)..."),
                            peerIndex, nBootstrapPeers, attempt, nBootstrapAttempts));
                        // Stamp the structured getbootstrapinfo status with the
                        // peer/attempt/mode this iteration is trying (the download
                        // loops fill in percent/bytes/streams). phase becomes
                        // "active"; mode mirrors the anchor/trustless choice.
                        SetBootstrapInfoProgress(-1, 0, 0, -1.0, 0, peer,
                                                 peerIndex, nBootstrapPeers,
                                                 attempt, nBootstrapAttempts,
                                                 fTrustlessMode ? "trustless" : "anchor", 0);
                        if (BootstrapFromPeer(peer, GetDataDir(), bootstrap_error)) {
                            bootstrap_snapshot_ran = true;
                            break;
                        }
                        LogPrintf("Bootstrap snapshot from %s failed (attempt %d/%d): %s\n",
                                  peer, attempt, nBootstrapAttempts, bootstrap_error);
                        if (attempt < nBootstrapAttempts)
                            MilliSleep(3000); // brief backoff before retrying
                    }
                    if (bootstrap_snapshot_ran)
                        break;
                }
                // If the explicit/compiled peers didn't work and the operator did
                // not pin a specific peer, OPTIONALLY fall back to peers discovered
                // from the network's NODE_BOOTSTRAP advertisements. This is OFF by
                // default (-bootstrapdiscover=0): the discovery path is a bespoke
                // pre-database network subsystem (DNS-seed dialing + handshake +
                // getaddr/addr parsing) that would run against untrusted IPs purely
                // for fast-sync AVAILABILITY when the compiled peer is down — and the
                // benign failure path below (continue with normal P2P sync) already
                // covers that case. Keeping it opt-in keeps a default node off that
                // code path entirely, shrinking its attack surface. (Even when
                // enabled, any imported snapshot is still verified against the
                // compiled anchor + UTXO-set commitment, so a discovered/untrusted
                // peer cannot feed a forged chain.)
                if (!bootstrap_snapshot_ran && !explicit_peer &&
                    GetBoolArg("-bootstrapdiscover", false)) {
                    BOOST_FOREACH(const std::string& peer, DiscoverBootstrapPeers()) {
                        if (ShutdownRequested())
                            break;
                        if (BootstrapFromPeer(peer, GetDataDir(), bootstrap_error)) {
                            bootstrap_snapshot_ran = true;
                            break;
                        }
                        LogPrintf("Bootstrap snapshot from discovered peer %s failed: %s\n", peer, bootstrap_error);
                    }
                }
                if (!bootstrap_snapshot_ran) {
                    // Tell the user we're switching strategies so a fresh node that
                    // couldn't fast-sync doesn't appear frozen during slow normal sync.
                    uiInterface.InitMessage(_("Bootstrap fast-sync unavailable; falling back to normal peer-to-peer sync (this may be slow)..."));
                    // The node self-transitioned to normal P2P sync. Record this as
                    // the (correct, self-healed) terminal state so the GUI surfaces
                    // "fast-sync unavailable, syncing normally" rather than an error.
                    SetBootstrapInfoPhase("normal_sync", bootstrap_error);
                    // The partial snapshot stays for the next start to resume, but it
                    // sits next to the growing chain until then: say where it is.
                    BOOST_FOREACH(const boost::filesystem::path& keptStaging, ListBootstrapStagingDirs(GetDataDir()))
                        LogPrintf("Bootstrap: the partial snapshot in %s is kept so a later start can resume it; "
                                  "it uses up to the full snapshot size and is removed with -bootstrap=0 or once the chain is real\n",
                                  keptStaging.string());
                    // No snapshot was imported this start. If we moved a genesis-only
                    // datadir aside to attempt it, move it back so the datadir is left
                    // exactly as it was found (and no backup dir accumulates). Only a
                    // genesis-only datadir is ever moved, but restoring rather than
                    // deleting guarantees we can never destroy chain data even if that
                    // classification were ever wrong. Done before the explicit-peer
                    // InitError too, so a failed -bootstrappeer also leaves no mess.
                    if (!genesisBackupDir.empty()) {
                        std::string restore_err;
                        if (!RestoreGenesisOnlyChainData(GetDataDir(), genesisBackupDir, restore_err))
                            LogPrintf("Bootstrap: could not restore genesis chain data: %s (backup retained at %s)\n",
                                      restore_err, genesisBackupDir.string());
                        genesisBackupDir.clear();
                    }
                    if (ShutdownRequested())
                        return false;
                    if (explicit_peer)
                        return InitError(bootstrap_error);
                    LogPrintf("Bootstrap snapshot unavailable; continuing with normal peer-to-peer sync: %s\n", bootstrap_error);
                } else if (fStubRecovery) {
                    // Abandoned-stub recovery succeeded: clear the churn-guard marker so a
                    // future, legitimately-different stub (e.g. years later, post-anchor-bump,
                    // after a fresh failed sync) is recoverable again. The stub backup
                    // (genesisBackupDir) is intentionally left on disk, matching the
                    // genesis-only path's keep-on-success behavior.
                    ClearStubRecoveryMarker(GetDataDir());
                    LogPrintf("Bootstrap: abandoned-stub recovery succeeded; cleared stub-recovery marker\n");
                }
            }
        } else {
            // Bootstrap was not attempted at all this start: -bootstrap=0, an empty
            // peer list, or a conflicting flag (-reindex / -reindex-chainstate /
            // -loadblock). Record why so the GUI can distinguish "skipped on
            // purpose" from "never ran" (idle).
            SetBootstrapInfoPhase("skipped",
                conflicts ? "conflicting flag (-reindex/-reindex-chainstate/-loadblock)"
                          : (!GetBoolArg("-bootstrap", true) ? "-bootstrap=0"
                                                             : "no bootstrap peers configured"));
            // A partial snapshot kept for resume by an earlier start is dead weight
            // when the operator turned bootstrap off (or asked for a reindex or a
            // block import): give the disk back instead of keeping it for ever.
            if (conflicts || !GetBoolArg("-bootstrap", true))
                RemoveStaleBootstrapStaging(GetDataDir());
        }
    }

    // A cancelled download must not continue into database initialization.
    // In particular, ActivateBestChain honors shutdown before activating
    // genesis; rewind assumes that initialization produced an active chain.
    if (ShutdownRequested())
        return false;

    // Keep a persistent connection to the bootstrap peer(s) for ongoing peer
    // discovery. ZClassic's DNS seeds are unreliable and the compiled fixed-seed
    // list can be empty, so a fresh OR peer-starved node -- an interrupted
    // bootstrap, -bootstrap=0, a foreign-fork chain copy, or a non-fresh datadir
    // whose peers.dat is empty or stale -- can otherwise end up with zero reachable
    // peers and hang at 0 connections / 0 blocks. The bootstrap peers are ordinary
    // P2P nodes, so
    // pinning them as -addnode is a safe peer-of-last-resort on every start
    // (honors an explicit -bootstrappeer; skipped only when the user pinned peers
    // with -connect). This is what previously only happened when a snapshot ran.
    // TODO: remove the injected -addnode entries once IsInitialBlockDownload()
    // latches false, so the bootstrap peer does not permanently occupy an
    // outbound slot. Doing this cleanly requires a hook to drop entries from
    // the CConnman added-node list without lock-ordering hazards, which does
    // not exist yet.
    if (!mapArgs.count("-connect")) {
        BOOST_FOREACH(const std::string& peer, GetBootstrapPeerList()) {
            std::vector<std::string>& addnodes = mapMultiArgs["-addnode"];
            if (std::find(addnodes.begin(), addnodes.end(), peer) == addnodes.end()) {
                addnodes.push_back(peer);
                LogPrintf("Adding bootstrap peer %s as a persistent sync node\n", peer);
            }
        }
        // Onion-only node on the onion bootstrap peers; the clearnet fallback
        // check is scheduled after StartNode() (Step 11).
        if (!mapArgs.count("-bootstrappeer") && BootstrapOnionOnlyActive())
            LogPrintf("Bootstrap: onion-only node, using the onion bootstrap peers instead of the clearnet addresses\n");
    }

    // This now measures ONLY the bootstrap-snapshot decision + (when the datadir
    // was fresh/genesis-only/stub eligible) the actual BootstrapFromPeer download &
    // install. On a genuinely SYNCED datadir this is the cheap ineligible path (one
    // exists() stat + a size-capped stat walk) and should be ~0ms; a large value
    // here means a real fast-sync ran (a fresh/eligible datadir) -- network+import
    // work, NOT synced-restart startup overhead. This was the misleading "42.7s".
    g_startupTimer.mark("network+bootstrap");
    // ********************************************************* Step 7: load block chain

    fReindex = GetBoolArg("-reindex", false);
    fReindexChainState = GetBoolArg("-reindex-chainstate", false);
    if (fReindexChainState && fReindex) {
        return InitError(_("-reindex-chainstate and -reindex are mutually exclusive "
                           "(-reindex already rebuilds the chainstate)."));
    }

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    boost::filesystem::path blocksDir = GetDataDir() / "blocks";
    if (!boost::filesystem::exists(blocksDir))
    {
        boost::system::error_code blocksEc;
        boost::filesystem::create_directories(blocksDir, blocksEc);
        if (blocksEc)
            return InitError(strprintf(_("Cannot create the blocks directory \"%s\": %s"), blocksDir.string(), blocksEc.message()));
        bool linked = false;
        for (unsigned int i = 1; i < 10000; i++) {
            boost::filesystem::path source = GetDataDir() / strprintf("blk%04u.dat", i);
            if (!boost::filesystem::exists(source)) break;
            boost::filesystem::path dest = blocksDir / strprintf("blk%05u.dat", i-1);
            try {
                boost::filesystem::create_hard_link(source, dest);
                LogPrintf("Hardlinked %s -> %s\n", source.string(), dest.string());
                linked = true;
            } catch (const boost::filesystem::filesystem_error& e) {
                // Note: hardlink creation failing is not a disaster, it just means
                // blocks will get re-downloaded from peers.
                LogPrintf("Error hardlinking blk%04u.dat: %s\n", i, e.what());
                break;
            }
        }
        if (linked)
        {
            fReindex = true;
        }
    }

    // cache size calculations
    int64_t nDbCacheArg = GetArg("-dbcache", nDefaultDbCache);
    // Raise the default cache on 64-bit when the user hasn't set -dbcache: a larger
    // cache means fewer leveldb flushes during sync and a faster, less "frozen-looking"
    // cold block-index load on an already-synced chain. A full reindex / chainstate
    // rebuild replays genesis..tip, so it benefits from an even larger cache. Never
    // override an explicit -dbcache; 64-bit only (avoid OOM on 32-bit); capped modestly.
    if (!mapArgs.count("-dbcache") && sizeof(void*) > 4) {
        int64_t nDefault64 = (fReindex || fReindexChainState) ? 2048 : 1024;
        nDbCacheArg = std::max(nDbCacheArg, std::min<int64_t>(nMaxDbCache, nDefault64));
    }
    int64_t nTotalCache = (nDbCacheArg << 20);
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greated than nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", true))
        nBlockTreeDBCache = (1 << 21); // block tree db cache shouldn't be larger than 2 MiB
    nTotalCache -= nBlockTreeDBCache;
    int64_t nCoinDBCache = std::min(nTotalCache / 2, (nTotalCache / 4) + (1 << 23)); // use 25%-50% of the remainder for disk cache
    nTotalCache -= nCoinDBCache;
    nCoinCacheUsage = nTotalCache; // the rest goes to in-memory cache
    LogPrintf("Cache configuration:\n");
    LogPrintf("* Using %.1fMiB for block index database\n", nBlockTreeDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for chain state database\n", nCoinDBCache * (1.0 / 1024 / 1024));
    LogPrintf("* Using %.1fMiB for in-memory UTXO set\n", nCoinCacheUsage * (1.0 / 1024 / 1024));

    bool clearWitnessCaches = false;

    // An exception from the background parameter load is not a block-database
    // error. It is kept out of the catch below (which reports "Error opening
    // block database" and offers a -reindex) and rethrown after the load loop,
    // where it leaves AppInit2 exactly as the synchronous ZC_LoadParams did.
    std::exception_ptr paramsLoadError;
    bool fLoaded = false;
    // A bootstrap install is verified after the load below and its marker cleared then; until
    // that, the block index is the serving node's (see fBlockIndexFromSnapshot). The markers
    // are written before the install, so a crash before the verification keeps this set.
    if (BootstrapAnchorPendingExists(GetDataDir()) || BootstrapTrustlessPendingExists(GetDataDir()))
        fBlockIndexFromSnapshot = true;
    while (!fLoaded) {
        bool fReset = fReindex || fReindexChainState;
        std::string strLoadError;

        uiInterface.InitMessage(_("Loading block index..."));

        nStart = GetTimeMillis();
        do {
            try {
                UnloadBlockIndex();
                delete pcoinsTip;
                delete pcoinsdbview;
                delete pcoinscatcher;
                delete pblocktree;

                // -reindex-chainstate wipes ONLY the coins/UTXO DB (fReindex stays
                // false, so the block index and blk files are preserved and not
                // re-read). The wiped coins DB reports a null best block, so the
                // chainActive starts empty and the Step-10 ActivateBestChain replays
                // the connected chain from the existing blk files under full
                // ConnectBlock -- rebuilding the UTXO set without a full reindex.
                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex);
                // The reindex flag is the only record that the block index was wiped on purpose: a
                // node killed after the wipe and before the flag is written starts with an empty
                // index next to full block files, and its sync overwrites them. Write it before the
                // chainstate is wiped (the long step), and when an earlier -reindex was cut short
                // (flag found) run it again from the start with a wiped chainstate: the half-built
                // one may be torn and no longer matches the index that is not loaded.
                if (fReindex) {
                    pblocktree->WriteReindexing(true);
                } else {
                    bool fWasReindexing = false;
                    pblocktree->ReadReindexing(fWasReindexing);
                    // The flag can only be written once the wiped block index is open again, and
                    // opening a new LevelDB syncs its files: a -reindex killed in that window left an
                    // empty index with no flag next to full block files. A plain restart then refused
                    // (the chainstate names a block the index lacks), but one with -reindex-chainstate,
                    // or with the chainstate gone, started from genesis and wrote over blk00000.dat.
                    // An index that never recorded a block file while blk00000.dat holds data was lost
                    // (cut short like that, or removed by hand): rebuild it from the block files.
                    int nLastBlockFileRecorded = 0;
                    const boost::filesystem::path pathFirstBlockFile = GetBlockPosFilename(CDiskBlockPos(0, 0), "blk");
                    boost::system::error_code ecFirstBlockFile;
                    const bool fFirstBlockFileHoldsData = boost::filesystem::exists(pathFirstBlockFile, ecFirstBlockFile) &&
                        boost::filesystem::file_size(pathFirstBlockFile, ecFirstBlockFile) > 0 && !ecFirstBlockFile;
                    if (fWasReindexing) {
                        LogPrintf("An earlier -reindex did not finish: starting it again\n");
                        fReindex = true;
                    } else if (!pblocktree->ReadLastBlockFile(nLastBlockFileRecorded) && fFirstBlockFileHoldsData) {
                        LogPrintf("The block index is empty but the block files hold blocks (an interrupted -reindex, or a removed index): reindexing them\n");
                        pblocktree->WriteReindexing(true);
                        fReindex = true;
                    }
                }
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex || fReindexChainState);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);

                if (fReindex) {
                    TestCrashPoint("reindex-after-wipe");
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode)
                        CleanupBlockRevFiles();
                }

                if (!LoadBlockIndex()) {
                    strLoadError = _("Error loading block database");
                    break;
                }
                g_startupTimer.mark(".loadblockindex-db");
                try {
                    zcParamsLoader.Join();
                } catch (...) {
                    paramsLoadError = std::current_exception();
                    break;
                }
                g_startupTimer.mark(".zk-snark params (wait)");

                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex()) {
                    strLoadError = _("Error initializing block database");
                    break;
                }
                // Shutdown may also arrive while genesis is being initialized.
                // Do not rewind or verify a chain whose activation was cancelled.
                if (ShutdownRequested())
                    return false;

                // Check for changed -txindex state. Only treat it as a change
                // when the user explicitly passed -txindex: the default flipped
                // to true (a bootstrap snapshot ships a txindex'd chainstate),
                // so comparing against the default alone would force a spurious
                // full reindex on every existing node that ran with the old
                // default (which persisted txindex=0 and is read back here).
                if (mapArgs.count("-txindex") && fTxIndex != GetBoolArg("-txindex", true)) {
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (fHavePruned && !fPruneMode) {
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                // -reindex-chainstate replays the UTXO set from the on-disk block index
                // and blk files. On a pruned datadir the below-horizon blocks are gone,
                // so the replay could only reach the first pruned block and would silently
                // leave a truncated chainstate. Refuse rather than rebuild a partial UTXO set.
                if (fReindexChainState && fHavePruned) {
                    strLoadError = _("-reindex-chainstate cannot rebuild the UTXO set on a pruned datadir: "
                                     "blocks below the prune horizon are gone. Use -reindex to redownload, "
                                     "or run unpruned.");
                    break;
                }

                if (!fReindex) {
                    uiInterface.InitMessage(_("Rewinding blocks if needed..."));
                    if (!RewindBlockIndex(chainparams, clearWitnessCaches)) {
                        strLoadError = _("Unable to rewind the database to a pre-upgrade state. You will need to redownload the blockchain");
                        break;
                    }
                }
                g_startupTimer.mark(".rewindblockindex");

                uiInterface.InitMessage(_("Verifying blocks..."));
                if (fHavePruned && GetArg("-checkblocks", 288) > MIN_BLOCKS_TO_KEEP) {
                    LogPrintf("Prune: pruned datadir may not have more than %d blocks; -checkblocks=%d may fail\n",
                        MIN_BLOCKS_TO_KEEP, GetArg("-checkblocks", 288));
                }
                if (!CVerifyDB().VerifyDB(pcoinsdbview, GetArg("-checklevel", 3),
                              GetArg("-checkblocks", 288))) {
                    strLoadError = _("Corrupted block database detected");
                    break;
                }
                g_startupTimer.mark(".verifydb");
            } catch (const dbwrapper_error& e) {
                LogPrintf("%s\n", e.what());
                if (e.IsEnvironmental()) {
                    // Permissions, a read-only or full disk, a path that is too long or a held lock:
                    // rebuilding the block database cannot fix these, so do not offer -reindex.
                    return InitError(strprintf(_("Unable to open the block database: %s"), e.what()));
                }
                strLoadError = _("Error opening block database");
                break;
            } catch (const std::exception& e) {
                if (fDebug) LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while(false);
        if (paramsLoadError)
            std::rethrow_exception(paramsLoadError);

        if (!fLoaded) {
            // first suggest a reindex
            if (!fReset) {
                bool fRet = uiInterface.ThreadSafeQuestion(
                    strLoadError + ".\n\n" + _("Do you want to rebuild the block database now?"),
                    strLoadError + ".\nPlease restart with -reindex to recover.",
                    "", CClientUIInterface::MSG_ERROR | CClientUIInterface::BTN_ABORT);
                if (fRet) {
                    fReindex = true;
                    fRequestShutdown = false;
                } else {
                    LogPrintf("Aborted block database rebuild. Exiting.\n");
                    return false;
                }
            } else {
                return InitError(strLoadError);
            }
        }
    }

    // Load any persisted trustless-validation latch now that the chain databases
    // are open (drives RPC status and lets a previous run's background validation
    // resume below).
    LoadBootstrapValidationState();

    // A previous (unpruned) run may have persisted a PROVISIONAL trustless-bootstrap
    // record. If this run is pruned, the background re-derivation can never complete
    // (it parks in PROVISIONAL_PRUNED), so auto-finalization stays PAUSED indefinitely
    // and the node keeps using a NEVER-VERIFIED UTXO set. Refusing a FRESH
    // trustless+prune bootstrap is handled earlier (InitError), but a persisted record
    // can still reach here; warn the operator loudly. No-op for normal/non-provisional
    // nodes (DISABLED) and for unpruned nodes (validation can still complete).
    {
        BootstrapValidationStatus bvStartup = GetBootstrapValidationStatus();
        if (fPruneMode &&
            (bvStartup.state == BVS_PROVISIONAL || bvStartup.state == BVS_PROVISIONAL_PRUNED)) {
            InitWarning(_("WARNING: this node holds a PROVISIONAL trustless-bootstrap snapshot whose UTXO set has NOT been verified, and pruning is enabled, so background validation can never complete and auto-finalization is PAUSED. The chainstate remains unverified. To resolve this, run with an unpruned datadir so background validation can re-derive and confirm the UTXO set, or re-bootstrap. (getblockchaininfo bootstrap_validation reports the current state.)"));
        }
    }

    if (BootstrapTrustlessPendingExists(GetDataDir())) {
        // Option B: a v2 self-snapshot was downloaded and awaits provisional
        // acceptance. Run the cheap gate (integrity + checkpoints + tip PoW); on
        // success start background full validation, on failure discard + reindex.
        // The marker is authoritative regardless of the current -bootstrapmode.
        int bvHeight = -1;
        uint256 bvHash, bvCommit;
        std::string bootstrap_trustless_error;
        if (!ProvisionalAcceptTrustlessSnapshot(GetDataDir(), bvHeight, bvHash, bvCommit, bootstrap_trustless_error)) {
            LogPrintf("%s\n", bootstrap_trustless_error);
            CloseBootstrapChainDatabases();
            RemoveFailedPeerBootstrapChainData(GetDataDir());
            BootstrapTrustlessPendingClear(GetDataDir());
            return InitError("trustless bootstrap snapshot failed provisional checks: " + bootstrap_trustless_error);
        }
        BeginBootstrapValidation(bvHeight, bvHash, bvCommit);
        // Arm the imported-tip finalization hold: this snapshot's tip is above the
        // last compiled checkpoint and was NOT validated live, so auto-finalization
        // must stay paused until the live network corroborates it (otherwise the
        // 10-deep finalization rule could permanently pin this node to the bootstrap
        // server's — possibly minority/forged — fork ~finalizationdelay after start,
        // before it ever converges with the majority). ProvisionalAcceptTrustless-
        // Snapshot already required the tip above the last checkpoint (SEC-TRUST-1),
        // so this is always the above-checkpoint case; guard defensively anyway.
        {
            LOCK(cs_main);
            const CBlockIndex* pcp = Checkpoints::GetLastCheckpoint(Params().Checkpoints());
            if (pcp == NULL || bvHeight > pcp->nHeight) {
                ArmBootstrapTipHold(bvHeight, bvHash);
            }
        }
        BootstrapTrustlessPendingClear(GetDataDir());
        LogPrintf("Bootstrap snapshot provisionally accepted at height %d (%s); background validation will confirm it\n",
            bvHeight, bvHash.ToString());
    } else if (BootstrapAnchorPendingExists(GetDataDir())) {
        // An anchor-mode snapshot was installed — either this run, or a previous
        // run that crashed after installing but before verifying. Verify the
        // imported UTXO-set commitment against the compiled anchor BEFORE trusting
        // it. This is gated on the DURABLE marker (written before the install),
        // NOT the in-memory bootstrap_snapshot_ran flag, so a crash in the
        // install->verify window cannot silently bypass the only anchor-mode
        // forgery check (see BootstrapFromPeer / WriteBootstrapAnchorPending).
        std::string bootstrap_anchor_error;
        if (!VerifyImportedBootstrapAnchor(bootstrap_anchor_error)) {
            LogPrintf("%s\n", bootstrap_anchor_error);
            CloseBootstrapChainDatabases();
            RemoveFailedPeerBootstrapChainData(GetDataDir());
            // The snapshot is gone; clear the marker so the operator can restart
            // into a normal sync instead of re-failing this check forever.
            BootstrapAnchorPendingClear(GetDataDir());
            return InitError(bootstrap_anchor_error);
        }
        // GROWABLE v3: read the bundle tip the marker recorded (the grown
        // anchor+1..serverTip range) BEFORE clearing the marker. This is the server's
        // ADVERTISED tip only — logged for diagnostics, NEVER trusted for arming (see the
        // security note below); the real tip is discovered from the imported index.
        int advertisedTipHeight = -1;
        uint256 advertisedTipHash;
        GetBootstrapAnchorPending(GetDataDir(), advertisedTipHeight, advertisedTipHash);
        // Verified: clear the marker so subsequent restarts skip the (now
        // redundant) re-verification.
        BootstrapAnchorPendingClear(GetDataDir());
        LogPrintf("Bootstrap snapshot verified at height %d (%s); server advertised post-anchor tip height %d (%s)\n",
            chainActive.Height(),
            chainActive.Tip() ? chainActive.Tip()->GetBlockHash().ToString() : std::string("unknown"),
            advertisedTipHeight,
            advertisedTipHash.IsNull() ? std::string("none") : advertisedTipHash.ToString());

        // The verified chainstate is PINNED at the anchor, but a snapshot may ALSO bundle
        // post-anchor blocks (anchor+1..serverTip) whose headers LoadBlockIndexDB loaded
        // into the block tree. Those blocks carry NO commitment, so THIS node must
        // validate them itself before trusting the tip.
        {
            LOCK(cs_main);
            const CBlockIndex* pAnchorTip = chainActive.Tip();

            // SECURITY (CRITICAL-1 / HIGH-1 / HIGH-2): arm the forward-connect retarget /
            // contextual re-check guard UNCONDITIONALLY for ANY verified-anchor import,
            // and arm the finalization hold on the REAL post-anchor tip we discover in the
            // block index — NOT on the server-advertised manifest tip (bundleTipHeight/
            // bundleTipHash). The marker is written verbatim from the wire manifest, whose
            // nBlockTipHeight/hashBlockTip are NOT bound to the shipped block index
            // (ValidateBootstrapSnapshotManifest only sanity-checks them). A malicious
            // server could therefore ship forged low-difficulty post-anchor blocks in
            // blocks/index/ while pointing hashBlockTip at a hash absent from that index
            // (or, on the v1 path, at the anchor itself). The old code keyed arming on
            // that manifest tip resolving in mapBlockIndex and descending from the anchor,
            // so the guard stayed disarmed while Step-10 ActivateBestChain still selected
            // and connected the forged higher-work chain through ConnectTip with no
            // retarget re-check — a silent consensus divergence onto a server-chosen fork.
            //
            // The guard is purely additive: ConnectTip only re-checks blocks STRICTLY
            // ABOVE the last compiled checkpoint (main.cpp), and a pure-anchor import has
            // nothing above the checkpoint to connect, so arming it is a strict no-op for
            // an honest v1/v3 import and only ever REJECTS a forged post-anchor fork.
            fBootstrapForwardConnect = true;

            // Discover the real highest-work descendant of the verified anchor that the
            // imported block index actually contains (independent of the manifest claim),
            // and arm the imported-tip finalization hold on THAT. The height/hash only
            // affect when EvaluateBootstrapTipRelease releases the hold; the hold being
            // engaged at all (g_tipHoldHeight >= 0) is what pauses auto-finalization so a
            // difficulty-correct minority/forged post-anchor fork cannot auto-finalize and
            // permanently pin this node before the live network corroborates the tip.
            if (pAnchorTip != NULL) {
                const CBlockIndex* pBestPostAnchor = NULL;
                for (BlockMap::const_iterator it = mapBlockIndex.begin(); it != mapBlockIndex.end(); ++it) {
                    const CBlockIndex* pidx = it->second;
                    if (pidx == NULL || pidx->nHeight <= pAnchorTip->nHeight)
                        continue; // below/at the anchor — not a post-anchor candidate
                    if (pidx->GetAncestor(pAnchorTip->nHeight) != pAnchorTip)
                        continue; // stray sibling fork that does not descend from the anchor
                    if (pBestPostAnchor == NULL || pidx->nChainWork > pBestPostAnchor->nChainWork)
                        pBestPostAnchor = pidx;
                }
                if (pBestPostAnchor != NULL) {
                    // The anchor is at-or-below the last compiled checkpoint, so any
                    // post-anchor tip is above it — the case ArmBootstrapTipHold is for.
                    // Guard defensively against a future anchor at/above the checkpoint.
                    const CBlockIndex* pcp = Checkpoints::GetLastCheckpoint(Params().Checkpoints());
                    if (pcp == NULL || pBestPostAnchor->nHeight > pcp->nHeight) {
                        ArmBootstrapTipHold(pBestPostAnchor->nHeight, pBestPostAnchor->GetBlockHash());
                    }
                    LogPrintf("Bootstrap snapshot bundles post-anchor blocks up to height %d (%s); will forward-connect and validate them before trusting the tip\n",
                        pBestPostAnchor->nHeight, pBestPostAnchor->GetBlockHash().ToString());
                }
            }
        }
    }

    // Auto-serve: once this node has a snapshot at the current anchor (just
    // fast-synced this run, or retained from a previous run), serve it to other
    // peers so the network becomes a self-sustaining swarm rather than depending
    // on one operator-run node. Runs whether or not we bootstrapped this run, so
    // a restarted node keeps serving its retained copy.
    if (fBootstrapServeAuto) {
        // Wire the serve machinery to the retained copy, then PRE-BUILD the
        // manifest here (during init, on this thread) so the expensive one-time
        // hash of the whole serve source does not happen on the message-handler
        // thread on a live peer's first request (which would stall the node).
        // Only advertise NODE_BOOTSTRAP once both succeed, so we never announce a
        // service we cannot actually answer. This runs before StartNode(), so the
        // mapArgs writes in SetupAutoBootstrapServe are not racing the net threads.
        std::string serve_err;
        if (SetupAutoBootstrapServe(GetDataDir(), serve_err) &&
            PreflightBootstrapSnapshotService(serve_err)) {
            nLocalServices |= NODE_BOOTSTRAP;
            LogPrintf("Auto bootstrap-serve active: serving the retained snapshot to peers\n");
        } else {
            LogPrintf("Auto bootstrap-serve idle (not advertising NODE_BOOTSTRAP): %s\n", serve_err);
            // Option B: when periodic self-snapshotting is enabled, point the serve
            // machinery at the (possibly not-yet-existing) auto-serve dir now, while
            // we are still single-threaded before StartNode(). The scheduled freeze
            // task will populate it and advertise NODE_BOOTSTRAP once synced, without
            // ever having to write mapArgs from a background thread.
            if (GetArg("-bootstrapservefreezeinterval", BOOTSTRAP_SERVE_DEFAULT_FREEZE_INTERVAL) > 0) {
                mapArgs["-bootstrapsourcedir"] = BootstrapAutoServeSourceDir(GetDataDir()).string();
                mapArgs["-bootstrapserve"] = "1";
            }
        }
    }

    // Drift check: by this point -bootstrapsourcedir has its final value (after
    // any SetupAutoBootstrapServe rewrite) and the served files exist on disk.
    // Warn loudly if this node is serving a prepared snapshot whose chainstate
    // tip matches no compiled anchor (operator drift) so peers are not handed a
    // snapshot they will reject on verification. The check is cheap: for an
    // auto-serve / anchor-pinned (v1/v3) dir it reads the ".anchor" sidecar and
    // never opens the pinned chainstate (opening it with LevelDB would mutate the
    // frozen serve files and break chunk serving); only a bare, markerless dir
    // falls back to reading the tip from the chainstate.
    {
        std::string bootstrapServeWarning;
        if (!BootstrapServeSnapshotMatchesCompiledAnchor(bootstrapServeWarning)) {
            InitWarning(_("Bootstrap serve: ") + bootstrapServeWarning);
        }
    }

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);
    g_startupTimer.mark("block index (step7)");

    boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;
    g_startupTimer.mark("fee estimates");


    // ********************************************************* Step 8: load wallet
#ifdef ENABLE_WALLET
    if (fDisableWallet) {
        pwalletMain = NULL;
        LogPrintf("Wallet disabled!\n");
    } else {

        // needed to restore wallet transaction meta data after -zapwallettxes
        std::vector<CWalletTx> vWtx;

        if (GetBoolArg("-zapwallettxes", false)) {
            uiInterface.InitMessage(_("Zapping all transactions from wallet..."));

            pwalletMain = new CWallet(strWalletFile);
            DBErrors nZapWalletRet = pwalletMain->ZapWalletTx(vWtx);
            if (nZapWalletRet != DB_LOAD_OK) {
                uiInterface.InitMessage(_("Error loading wallet.dat: Wallet corrupted"));
                return false;
            }

            delete pwalletMain;
            pwalletMain = NULL;
        }

        uiInterface.InitMessage(_("Loading wallet..."));

        nStart = GetTimeMillis();
        bool fFirstRun = true;
        pwalletMain = new CWallet(strWalletFile);
        DBErrors nLoadWalletRet = pwalletMain->LoadWallet(fFirstRun);
        if (nLoadWalletRet != DB_LOAD_OK)
        {
            if (nLoadWalletRet == DB_CORRUPT)
                strErrors << _("Error loading wallet.dat: Wallet corrupted") << "\n";
            else if (nLoadWalletRet == DB_NONCRITICAL_ERROR)
            {
                string msg(_("Warning: error reading wallet.dat! All keys read correctly, but transaction data"
                             " or address book entries might be missing or incorrect."));
                InitWarning(msg);
            }
            else if (nLoadWalletRet == DB_TOO_NEW)
                strErrors << _("Error loading wallet.dat: Wallet requires newer version of ZClassic") << "\n";
            else if (nLoadWalletRet == DB_NEED_REWRITE)
            {
                strErrors << _("Wallet needed to be rewritten: restart ZClassic to complete") << "\n";
                LogPrintf("%s", strErrors.str());
                return InitError(strErrors.str());
            }
            else
                strErrors << _("Error loading wallet.dat") << "\n";
        }

        if (GetBoolArg("-upgradewallet", fFirstRun))
        {
            int nMaxVersion = GetArg("-upgradewallet", 0);
            if (nMaxVersion == 0) // the -upgradewallet without argument case
            {
                LogPrintf("Performing wallet upgrade to %i\n", FEATURE_LATEST);
                nMaxVersion = CLIENT_VERSION;
                pwalletMain->SetMinVersion(FEATURE_LATEST); // permanently upgrade the wallet immediately
            }
            else
                LogPrintf("Allowing wallet upgrade up to %i\n", nMaxVersion);
            if (nMaxVersion < pwalletMain->GetVersion())
                strErrors << _("Cannot downgrade wallet") << "\n";
            pwalletMain->SetMaxVersion(nMaxVersion);
        }

        if (!pwalletMain->HaveHDSeed())
        {
            // generate a new HD seed
            pwalletMain->GenerateNewSeed();
        }

        if (fFirstRun)
        {
            // Create new keyUser and set as default key
            CPubKey newDefaultKey;
            if (pwalletMain->GetKeyFromPool(newDefaultKey)) {
                pwalletMain->SetDefaultKey(newDefaultKey);
                if (!pwalletMain->SetAddressBook(pwalletMain->vchDefaultKey.GetID(), "", "receive"))
                    strErrors << _("Cannot write default address") << "\n";
            }

            pwalletMain->SetBestChain(chainActive.GetLocator());
        }

        LogPrintf("%s", strErrors.str());
        LogPrintf(" wallet      %15dms\n", GetTimeMillis() - nStart);
        g_startupTimer.mark("load wallet");

        RegisterValidationInterface(pwalletMain);

        CBlockIndex *pindexRescan = chainActive.Tip();
        if (clearWitnessCaches || GetBoolArg("-rescan", false))
        {
            pwalletMain->ClearNoteWitnessCache();
            pindexRescan = chainActive.Genesis();
        }
        else
        {
            CWalletDB walletdb(strWalletFile);
            CBlockLocator locator;
            if (walletdb.ReadBestBlock(locator)) {
                pindexRescan = FindForkInGlobalIndex(chainActive, locator);
                if (pindexRescan) pwalletMain->nCheckpointHeight = pindexRescan->nHeight;
            } else
                pindexRescan = chainActive.Genesis();
        }
        // The note state that was read back (witness caches, nullifiers) is checked against the
        // active chain before it is trusted. A crash, a reindex or a chain that was rolled back
        // behind the wallet can leave it ahead of, behind or on another branch than the chain;
        // a rescan from the locator alone does not see that. This may start the rescan earlier.
        bool fNoteStateRepaired = false;
        if (!clearWitnessCaches && !GetBoolArg("-rescan", false) && chainActive.Tip()) {
            fNoteStateRepaired = pwalletMain->ReconcileNoteState(pindexRescan);
        }
        if (chainActive.Tip() && chainActive.Tip() != pindexRescan)
        {
            uiInterface.InitMessage(_("Rescanning..."));
            LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight);
            nStart = GetTimeMillis();
            pwalletMain->ScanForWalletTransactions(pindexRescan, true);
            LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
            g_startupTimer.mark("rescan");
            TestCrashPoint("init-after-rescan");
            pwalletMain->SetBestChain(chainActive.GetLocator());
            nWalletDBUpdated++;

            // Restore wallet transaction metadata after -zapwallettxes=1
            if (GetBoolArg("-zapwallettxes", false) && GetArg("-zapwallettxes", "1") != "2")
            {
                CWalletDB walletdb(strWalletFile);

                BOOST_FOREACH(const CWalletTx& wtxOld, vWtx)
                {
                    uint256 hash = wtxOld.GetHash();
                    std::map<uint256, CWalletTx>::iterator mi = pwalletMain->mapWallet.find(hash);
                    if (mi != pwalletMain->mapWallet.end())
                    {
                        const CWalletTx* copyFrom = &wtxOld;
                        CWalletTx* copyTo = &mi->second;
                        copyTo->mapValue = copyFrom->mapValue;
                        copyTo->vOrderForm = copyFrom->vOrderForm;
                        copyTo->nTimeReceived = copyFrom->nTimeReceived;
                        copyTo->nTimeSmart = copyFrom->nTimeSmart;
                        copyTo->fFromMe = copyFrom->fFromMe;
                        copyTo->strFromAccount = copyFrom->strFromAccount;
                        copyTo->nOrderPos = copyFrom->nOrderPos;
                        copyTo->WriteToDisk(&walletdb);
                    }
                }
                // nOrderPos was just overwritten above: the wallet's cached transaction-order index is stale.
                {
                    LOCK(pwalletMain->cs_wallet);
                    pwalletMain->InvalidateTxOrderIndex();
                }
            }
        }
        else if (fNoteStateRepaired)
        {
            // Nothing to scan, but the repaired state has to reach wallet.dat in one atomic write.
            pwalletMain->SetBestChain(chainActive.GetLocator());
            nWalletDBUpdated++;
        }
        pwalletMain->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", true));
        fWalletInitComplete = true;
    } // (!fDisableWallet)
#else // ENABLE_WALLET
    LogPrintf("No wallet support compiled in!\n");
#endif // !ENABLE_WALLET

#ifdef ENABLE_MINING
 #ifndef ENABLE_WALLET
    if (GetBoolArg("-minetolocalwallet", false)) {
        return InitError(_("ZClassic was not built with wallet support. Set -minetolocalwallet=0 to use -mineraddress, or rebuild ZClassic with wallet support."));
    }
    if (GetArg("-mineraddress", "").empty() && GetBoolArg("-gen", false)) {
        return InitError(_("ZClassic was not built with wallet support. Set -mineraddress, or rebuild ZClassic with wallet support."));
    }
 #endif // !ENABLE_WALLET

    if (mapArgs.count("-mineraddress")) {
 #ifdef ENABLE_WALLET
        bool minerAddressInLocalWallet = false;
        if (pwalletMain) {
            // Address has already been validated
            CTxDestination addr = DecodeDestination(mapArgs["-mineraddress"]);
            CKeyID keyID = boost::get<CKeyID>(addr);
            minerAddressInLocalWallet = pwalletMain->HaveKey(keyID);
        }
        if (GetBoolArg("-minetolocalwallet", true) && !minerAddressInLocalWallet) {
            return InitError(_("-mineraddress is not in the local wallet. Either use a local address, or set -minetolocalwallet=0"));
        }
 #endif // ENABLE_WALLET

        // This is leveraging the fact that boost::signals2 executes connected
        // handlers in-order. Further up, the wallet is connected to this signal
        // if the wallet is enabled. The wallet's ScriptForMining handler does
        // nothing if -mineraddress is set, and GetScriptForMinerAddress() does
        // nothing if -mineraddress is not set (or set to an invalid address).
        //
        // The upshot is that when ScriptForMining(script) is called:
        // - If -mineraddress is set (whether or not the wallet is enabled), the
        //   CScript argument is set to -mineraddress.
        // - If the wallet is enabled and -mineraddress is not set, the CScript
        //   argument is set to a wallet address.
        // - If the wallet is disabled and -mineraddress is not set, the CScript
        //   argument is not modified; in practice this means it is empty, and
        //   GenerateBitcoins() returns an error.
        GetMainSignals().ScriptForMining.connect(GetScriptForMinerAddress);
    }
#endif // ENABLE_MINING

    // ********************************************************* Step 9: data directory maintenance

    // if pruning, unset the service bit and perform the initial blockstore prune
    // after any wallet rescanning has taken place.
    if (fPruneMode) {
        LogPrintf("Unsetting NODE_NETWORK on prune mode\n");
        nLocalServices &= ~NODE_NETWORK;
        if (!fReindex) {
            uiInterface.InitMessage(_("Pruning blockstore..."));
            PruneAndFlush();
        }
    }

    // ********************************************************* Step 10: import blocks

    if (mapArgs.count("-blocknotify"))
        uiInterface.NotifyBlockTip.connect(BlockNotifyCallback);

    uiInterface.InitMessage(_("Activating best chain..."));
    // scan for better chains in the block chain database, that are not yet connected in the active best chain
    CValidationState state;
    {
        // GROWABLE v3 forward-connect: when a freshly verified snapshot bundled
        // post-anchor blocks (anchor+1..serverTip) that were NOT validated live,
        // wrap this ActivateBestChain in the guard so ConnectTip re-runs the
        // contextual header (retarget) check on each above-checkpoint block, rejecting
        // a forged low-difficulty post-anchor fork the context-free PoW check would
        // otherwise accept. The guard is a strict no-op (and is not even constructed)
        // for every normal node and pure-anchor import, so Step 10 is byte-identical
        // there. Scoped so the guard is released the instant the forward-connect
        // returns, before any live block is accepted.
        boost::scoped_ptr<CBootstrapForwardConnectGuard> forwardConnectGuard;
        if (fBootstrapForwardConnect) {
            forwardConnectGuard.reset(new CBootstrapForwardConnectGuard());
        }
        if (!ActivateBestChain(state))
            strErrors << "Failed to connect best block";
    }
    g_startupTimer.mark("activate best chain");

    // A stop during replay is not permission to start new import/network work.
    // A fatal activation error can also request shutdown: preserve its failure
    // result rather than treating it as a successful user cancellation.
    if (ShutdownRequested())
        return strErrors.str().empty();

    std::vector<boost::filesystem::path> vImportFiles;
    if (mapArgs.count("-loadblock"))
    {
        BOOST_FOREACH(const std::string& strFile, mapMultiArgs["-loadblock"])
            vImportFiles.push_back(strFile);
    }
    threadGroup.create_thread(boost::bind(&ThreadImport, vImportFiles));
    if (chainActive.Tip() == NULL) {
        LogPrintf("Waiting for genesis block to be imported...\n");
        while (!fRequestShutdown && chainActive.Tip() == NULL)
            MilliSleep(10);
    }

    // ********************************************************* Step 11: start node

    if (!CheckDiskSpace())
        return false;

    if (!strErrors.str().empty())
        return InitError(strErrors.str());

    //// debug print
    LogPrintf("mapBlockIndex.size() = %u\n",   mapBlockIndex.size());
    LogPrintf("nBestHeight = %d\n",                   chainActive.Height());
#ifdef ENABLE_WALLET
    LogPrintf("setKeyPool.size() = %u\n",      pwalletMain ? pwalletMain->setKeyPool.size() : 0);
    LogPrintf("mapWallet.size() = %u\n",       pwalletMain ? pwalletMain->mapWallet.size() : 0);
    LogPrintf("mapAddressBook.size() = %u\n",  pwalletMain ? pwalletMain->mapAddressBook.size() : 0);
#endif

    // Optional read-only ZSLP token index (off by default). It only reads blocks.
    if (GetBoolArg("-zslpindex", false)) {
        if (fPruneMode)
            return InitError(_("-zslpindex needs the full block files and is not compatible with -prune."));
        std::string errZslp;
        if (!zslp::StartService(errZslp))
            return InitError(errZslp);
    }

    // Optional read-only ZNAM name index (off by default). It only reads blocks and their undo data.
    if (GetBoolArg("-znamindex", false)) {
        if (fPruneMode)
            return InitError(_("-znamindex needs the full block files and is not compatible with -prune."));
        std::string errZnam;
        if (!znam::StartService(errZnam))
            return InitError(errZnam);
    }

    // Start the thread that notifies listeners of transactions that have been
    // recently added to the mempool.
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "txnotify", &ThreadNotifyRecentlyAdded));

    if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler);
    g_startupTimer.mark("start node");

    // Onion-only node on the onion bootstrap peers: if neither connects (and
    // nothing else does) within the grace period, add the clearnet ones
    // through the proxy, once. Counted from here, not from Step 6: block
    // loading and import can outlast the grace period before any connection
    // is attempted, and ThreadOpenAddedConnections (started by StartNode)
    // replaces vAddedNodes with -addnode when it starts.
    if (!mapArgs.count("-connect") && !mapArgs.count("-bootstrappeer") && BootstrapOnionOnlyActive())
        scheduler.scheduleFromNow(&BootstrapOnionFallbackCheck, BOOTSTRAP_ONION_GRACE_SECONDS);

    // Monitor the chain every minute, and alert if we get blocks much quicker or slower than expected.
    CScheduler::Function f = boost::bind(&PartitionCheck, &IsInitialBlockDownload,
                                         boost::ref(cs_main), boost::cref(pindexBestHeader));
    scheduler.scheduleEvery(f, 60);

    // Option B: periodically freeze a self-snapshot of this node's own tip to
    // serve (EXPERIMENTAL). Only when -bootstrapserve=auto with a positive
    // interval. The task skips while in IBD and skips a re-copy when the serve
    // copy is already near the tip, so the first eligible run self-snapshots once
    // synced and subsequent runs refresh it as the chain advances.
    if (fBootstrapServeAuto) {
        const int64_t nFreezeInterval = GetArg("-bootstrapservefreezeinterval", BOOTSTRAP_SERVE_DEFAULT_FREEZE_INTERVAL);
        if (nFreezeInterval > 0) {
            scheduler.scheduleEvery(boost::bind(&BootstrapServeFreezeCheck), nFreezeInterval);
        }
    }

#ifdef ENABLE_MINING
    // Generate coins in the background
    GenerateBitcoins(GetBoolArg("-gen", false), GetArg("-genproclimit", 1), Params());
#endif

    // ********************************************************* Step 11: finished

    SetRPCWarmupFinished();
    uiInterface.InitMessage(_("Done loading"));
    g_startupTimer.mark("done (step11)");
    g_startupTimer.summary();

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile)));
    }
#endif

    // Option B: start (or resume) background full validation of a provisionally
    // accepted trustless snapshot. Spawns the re-derivation thread and the
    // failure->reindex poll only when a snapshot is pending validation. Started
    // last, after every other fallible init step, so an AppInit2 failure cannot
    // tear down the chain databases out from under a running validation thread
    // (the startup-failure path interrupts but does not join the thread group).
    MaybeStartBootstrapValidation(scheduler);

    return !fRequestShutdown;
}
