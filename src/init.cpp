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
#include "checkpoints.h"
#include "compat/sanity.h"
#include "consensus/upgrades.h"
#include "consensus/validation.h"
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
#include "txdb.h"
#include "torcontrol.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "validationinterface.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#endif
#include <stdint.h>
#include <stdio.h>

#ifndef WIN32
#include <signal.h>
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

#include <libsnark/common/profiling.hpp>

#if ENABLE_ZMQ
#include "zmq/zmqnotificationinterface.h"
#endif

#if ENABLE_PROTON
#include "amqp/amqpnotificationinterface.h"
#endif

#include <fstream>
#include <thread>
#include <chrono>
#include "librustzcash.h"
#include "sha256.h"
#include <curl/curl.h>

using namespace std;

extern void ThreadSendAlert();

ZCJoinSplit* pzcashParams = NULL;

#ifdef ENABLE_WALLET
CWallet* pwalletMain = NULL;
#endif
bool fFeeEstimatesInitialized = false;

#if ENABLE_ZMQ
static CZMQNotificationInterface* pzmqNotificationInterface = NULL;
#endif

#if ENABLE_PROTON
static AMQPNotificationInterface* pAMQPNotificationInterface = NULL;
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
CClientUIInterface uiInterface; // Declared but not defined in ui_interface.h
static unsigned long long int initialBlockchainBytesDownloaded = 0;

// estimate download size
static unsigned long long int totalBlockchainBytesDownload = 8805222238;

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
    threadGroup.interrupt_all();
}

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
    GenerateBitcoins(false, 0, Params());
#endif
    StopNode();
    StopTorControl();
    UnregisterNodeSignals(GetNodeSignals());

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

#if ENABLE_PROTON
    if (pAMQPNotificationInterface) {
        UnregisterValidationInterface(pAMQPNotificationInterface);
        delete pAMQPNotificationInterface;
        pAMQPNotificationInterface = NULL;
    }
#endif

#ifndef WIN32
    try {
        boost::filesystem::remove(GetPidFile());
    } catch (const boost::filesystem::filesystem_error& e) {
        LogPrintf("%s: Unable to remove pidfile: %s\n", __func__, e.what());
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
    strUsage += HelpMessageOpt("-alerts", strprintf(_("Receive and display P2P network alerts (default: %u)"), DEFAULT_ALERTS));
    strUsage += HelpMessageOpt("-alertnotify=<cmd>", _("Execute command when a relevant alert is received or we see a really long fork (%s in cmd is replaced by message)"));
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
    strUsage += HelpMessageOpt("-exportdir=<dir>", _("Specify directory to be used when exporting data"));
    strUsage += HelpMessageOpt("-dbcache=<n>", strprintf(_("Set database cache size in megabytes (%d to %d, default: %d)"), nMinDbCache, nMaxDbCache, nDefaultDbCache));
    strUsage += HelpMessageOpt("-loadblock=<file>", _("Imports blocks from external blk000??.dat file") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-maxorphantx=<n>", strprintf(_("Keep at most <n> unconnectable transactions in memory (default: %u)"), DEFAULT_MAX_ORPHAN_TRANSACTIONS));
    strUsage += HelpMessageOpt("-mempooltxinputlimit=<n>", _("[DEPRECATED FROM OVERWINTER] Set the maximum number of transparent inputs in a transaction that the mempool will accept (default: 0 = no limit applied)"));
    strUsage += HelpMessageOpt("-par=<n>", strprintf(_("Set the number of script verification threads (%u to %d, 0 = auto, <0 = leave that many cores free, default: %d)"),
        -GetNumCores(), MAX_SCRIPTCHECK_THREADS, DEFAULT_SCRIPTCHECK_THREADS));
#ifndef WIN32
    strUsage += HelpMessageOpt("-pid=<file>", strprintf(_("Specify pid file (default: %s)"), "zclassicd.pid"));
#endif
    strUsage += HelpMessageOpt("-prune=<n>", strprintf(_("Reduce storage requirements by pruning (deleting) old blocks. This mode disables wallet support and is incompatible with -txindex. "
            "Warning: Reverting this setting requires re-downloading the entire blockchain. "
            "(default: 0 = disable pruning blocks, >%u = target size in MiB to use for block files)"), MIN_DISK_SPACE_FOR_BLOCK_FILES / 1024 / 1024));
    strUsage += HelpMessageOpt("-reindex", _("Rebuild block chain index from current blk000??.dat files on startup"));
    strUsage += HelpMessageOpt("-nofastsync", _("Disable fast-sync from Arweave, sync from genesis with checkpoint trust (default: 0)"));
#if !defined(WIN32)
    strUsage += HelpMessageOpt("-sysperms", _("Create new files with system default permissions, instead of umask 077 (only effective with disabled wallet functionality)"));
#endif
    strUsage += HelpMessageOpt("-txindex", strprintf(_("Maintain a full transaction index, used by the getrawtransaction rpc call (default: %u)"), 0));

    strUsage += HelpMessageGroup(_("Connection options:"));
    strUsage += HelpMessageOpt("-addnode=<ip>", _("Add a node to connect to and attempt to keep the connection open"));
    strUsage += HelpMessageOpt("-banscore=<n>", strprintf(_("Threshold for disconnecting misbehaving peers (default: %u)"), 100));
    strUsage += HelpMessageOpt("-bantime=<n>", strprintf(_("Number of seconds to keep misbehaving peers from reconnecting (default: %u)"), 86400));
    strUsage += HelpMessageOpt("-bind=<addr>", _("Bind to given address and always listen on it. Use [host]:port notation for IPv6"));
    strUsage += HelpMessageOpt("-connect=<ip>", _("Connect only to the specified node(s)"));
    strUsage += HelpMessageOpt("-discover", _("Discover own IP addresses (default: 1 when listening and no -externalip or -proxy)"));
    strUsage += HelpMessageOpt("-dns", _("Allow DNS lookups for -addnode, -seednode and -connect") + " " + _("(default: 1)"));
    strUsage += HelpMessageOpt("-dnsseed", _("Query for peer addresses via DNS lookup, if low on addresses (default: 1 unless -connect)"));
    strUsage += HelpMessageOpt("-externalip=<ip>", _("Specify your own public address"));
    strUsage += HelpMessageOpt("-forcednsseed", strprintf(_("Always query for peer addresses via DNS lookup (default: %u)"), 0));
    strUsage += HelpMessageOpt("-listen", _("Accept connections from outside (default: 1 if no -proxy or -connect)"));
    strUsage += HelpMessageOpt("-listenonion", strprintf(_("Automatically create Tor hidden service (default: %d)"), DEFAULT_LISTEN_ONION));
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
    strUsage += HelpMessageOpt("-rescan", _("Rescan the block chain for missing wallet transactions") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-salvagewallet", _("Attempt to recover private keys from a corrupt wallet.dat") + " " + _("on startup"));
    strUsage += HelpMessageOpt("-sendfreetransactions", strprintf(_("Send transactions as zero-fee transactions if possible (default: %u)"), 0));
    strUsage += HelpMessageOpt("-spendzeroconfchange", strprintf(_("Spend unconfirmed change when sending transactions (default: %u)"), 1));
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

#if ENABLE_PROTON
    strUsage += HelpMessageGroup(_("AMQP 1.0 notification options:"));
    strUsage += HelpMessageOpt("-amqppubhashblock=<address>", _("Enable publish hash block in <address>"));
    strUsage += HelpMessageOpt("-amqppubhashtx=<address>", _("Enable publish hash transaction in <address>"));
    strUsage += HelpMessageOpt("-amqppubrawblock=<address>", _("Enable publish raw block in <address>"));
    strUsage += HelpMessageOpt("-amqppubrawtx=<address>", _("Enable publish raw transaction in <address>"));
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
        strUsage += HelpMessageOpt("-stopafterblockimport", strprintf("Stop running after importing blocks from disk (default: %u)", 0));
        strUsage += HelpMessageOpt("-nuparams=hexBranchId:activationHeight", "Use given activation height for specified network upgrade (regtest-only)");
        strUsage += HelpMessageOpt("-eqparams=hexBranchId:N:K", "Use given equihash parameters for specified network upgrade"); 
    }
    string debugCategories = "addrman, alert, bench, coindb, db, estimatefee, http, libevent, lock, mempool, net, partitioncheck, pow, proxy, prune, "
                             "rand, reindex, rpc, selectcoins, tor, zmq, zrpc, zrpcunsafe (implies zrpc)"; // Don't translate these
    strUsage += HelpMessageOpt("-debug=<category>", strprintf(_("Output debugging information (default: %u, supplying <category> is optional)"), 0) + ". " +
        _("If <category> is not supplied or if <category> = 1, output all debugging information.") + " " + _("<category> can be:") + " " + debugCategories + ".");
    strUsage += HelpMessageOpt("-experimentalfeatures", _("Enable use of experimental features"));
    strUsage += HelpMessageOpt("-help-debug", _("Show all debugging options (usage: --help -help-debug)"));
    strUsage += HelpMessageOpt("-logips", strprintf(_("Include IP addresses in debug output (default: %u)"), 0));
    strUsage += HelpMessageOpt("-logtimestamps", strprintf(_("Prepend debug output with timestamp (default: %u)"), 1));
    strUsage += HelpMessageOpt("-debuglogfile", _("Write debug output to debug.log file (default: 0, disabled for privacy)"));
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
    strUsage += HelpMessageOpt("-rpcbind=<addr>", _("Bind to given address to listen for JSON-RPC connections. Use [host]:port notation for IPv6. This option can be specified multiple times (default: bind to all interfaces)"));
    strUsage += HelpMessageOpt("-rpcuser=<user>", _("Username for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcpassword=<pw>", _("Password for JSON-RPC connections"));
    strUsage += HelpMessageOpt("-rpcport=<port>", strprintf(_("Listen for JSON-RPC connections on <port> (default: %u or testnet: %u)"), 8023, 18023));
    strUsage += HelpMessageOpt("-rpcallowip=<ip>", _("Allow JSON-RPC connections from specified source. Valid for <ip> are a single IP (e.g. 1.2.3.4), a network/netmask (e.g. 1.2.3.4/255.255.255.0) or a network/CIDR (e.g. 1.2.3.4/24). This option can be specified multiple times"));
    strUsage += HelpMessageOpt("-rpcthreads=<n>", strprintf(_("Set the number of threads to service RPC calls (default: %d)"), DEFAULT_HTTP_THREADS));
    if (showDebug) {
        strUsage += HelpMessageOpt("-rpcworkqueue=<n>", strprintf("Set the depth of the work queue to service RPC calls (default: %d)", DEFAULT_HTTP_WORKQUEUE));
        strUsage += HelpMessageOpt("-rpcservertimeout=<n>", strprintf("Timeout during HTTP requests (default: %d)", DEFAULT_HTTP_SERVER_TIMEOUT));
    }

    // Disabled until we can lock notes and also tune performance of libsnark which by default uses multiple threads
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
    // -reindex
    if (fReindex) {
        CImportingNow imp;
        int nFile = 0;
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
            LoadExternalBlockFile(file);
        } else {
            LogPrintf("Warning: Could not open blocks file %s\n", path.string());
        }
    }

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
    FILE* file = fopen(path.c_str(), "rb");
    if (!file){
        LogPrintf("Cannot open file: %s\n", path);
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("Cannot open file:\n"
              "%s\n"),
                path),
            "", CClientUIInterface::MSG_ERROR);
        StartShutdown();
        return false;
    }
    char buffer[1024];
    size_t size;
    SHA256 buff;
    while (!feof(file)){
        size = fread(buffer, 1, 1024, file);
        buff.update(buffer, size);
    }
    std::string buff_hash = buff.hash();
    LogPrintf("%s: %s\n", path, buff_hash);
    if(buff_hash != hash){
        uiInterface.ThreadSafeMessageBox(strprintf(
            _("hash of %s is not correct:\n"
              "%s\n\n expecting:\n%s\n"),
                path, buff_hash, hash),
            "", CClientUIInterface::MSG_ERROR);
        StartShutdown();
        fclose(file);
        return false;
    }
    fclose(file);
    return true;
}

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

bool Download(std::string url, std::string filename, std::string hash)
{
    bool succeeded = false;
    for (int i = 0; i < 10; i++) {

        boost::filesystem::path filename_path = boost::filesystem::path(filename);

        // if file is already downloaded with correct hash, skip download
        if (boost::filesystem::exists(filename_path)){
            if(check_file_hash(filename, hash)){
                initialBlockchainBytesDownloaded += boost::filesystem::file_size(filename_path);                
                return true;
            }
        }
        
        boost::filesystem::remove_all(filename_path);

        curl_global_init(CURL_GLOBAL_ALL);
    
        CURL *curl_handle;
        const char *pagefilename = filename.c_str();
        FILE *pagefile;
    
    
        /* init the curl session */ 
        curl_handle = curl_easy_init();
      
        /* set URL to get here */ 
        curl_easy_setopt(curl_handle, CURLOPT_URL, url.c_str());
      
        /* Switch on full protocol/debug output while testing */ 
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 0L);

        curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "mozilla/4.0 (compatible; zclassic/1.0)");

        /* disable progress meter, set to 0L to enable and disable debug output */ 
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
      
        /* send all data to this function  */ 
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_data);
      
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
      
        char errorbuf[CURL_ERROR_SIZE] = "";
        curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errorbuf);
    
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
      
        LogPrintf("Downloading %s\n", url.c_str());
        LogPrintf("Curl File Download: %s\n", filename.c_str());
      
      
        /* open the file */ 
        pagefile = fopen(pagefilename, "wb");
        if(pagefile) {
      
          /* write the page body to this file handle */ 
          curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
      
          /* get it! */ 
          if ( curl_easy_perform(curl_handle) != CURLE_OK ) {
            LogPrintf("Error downloading file: %s\n", errorbuf);
          }
      
          /* close the header file */ 
          fclose(pagefile);
        }

        curl_easy_reset(curl_handle);
        /* cleanup curl stuff */ 
        curl_easy_cleanup(curl_handle);
  
        curl_global_cleanup();
        if (check_file_hash(filename, hash)){
            boost::filesystem::path filename_path = boost::filesystem::path(filename);
            initialBlockchainBytesDownloaded += boost::filesystem::file_size(filename_path);


            double c;
            std::string warning_string = "Fast Syncing Initial Database: ";

            c = initialBlockchainBytesDownloaded / (double)(totalBlockchainBytesDownload * 1.0);
            c *= 100;
            InitWarning(warning_string + std::to_string(c) + "\% Complete\n");

            return true;
        }

        InitWarning("error downloading (retrying): " + url );

        // We had a download failure, wait 5 seconds before retrying.
        std::this_thread::sleep_for(std::chrono::milliseconds(5000 + i*5000));
    }
    return false;
}


bool BlockIndexDownload(std::string url, std::string filename, std::string hash)
{
    boost::this_thread::interruption_point();
    boost::filesystem::path data_dir = GetDataDir();
    boost::filesystem::path tmp_blocks_dir = data_dir / "tmp-download-blocks";
    boost::filesystem::path tmp_index_blocks_dir = tmp_blocks_dir / "index";
    boost::filesystem::path tmp_index_file;


    tmp_index_file = tmp_index_blocks_dir / filename;
    if (!Download(url, tmp_index_file.string(), hash)){
        return false;
    }
    return true;

}

bool BlockDownload(std::string url, std::string filename, std::string hash)
{
    boost::this_thread::interruption_point();
    boost::filesystem::path data_dir = GetDataDir();
    boost::filesystem::path tmp_blocks_dir = data_dir / "tmp-download-blocks";
    boost::filesystem::path tmp_blocks_file;

    tmp_blocks_file = tmp_blocks_dir / filename;
    if (!Download(url, tmp_blocks_file.string(), hash)){
        return false;
    }
    return true;
}

bool ChainstateDownload(std::string url, std::string filename, std::string hash)
{
    boost::this_thread::interruption_point();
    boost::filesystem::path data_dir = GetDataDir();
    boost::filesystem::path tmp_chainstate_dir = data_dir / "tmp-download-chainstate";
    boost::filesystem::path tmp_chainstate_file;

    tmp_chainstate_file = tmp_chainstate_dir / filename;
    if (!Download(url, tmp_chainstate_file.string(), hash)){
        return false;
    }
    return true;
}


/** Sanity checks
 *  Ensure that Bitcoin is running in a usable environment with all
 *  necessary library support.
 */
bool InitSanityCheck(void)
{

    boost::filesystem::path sapling_output = ZC_GetParamsDir() / "sapling-output.params";
    boost::filesystem::path sapling_spend = ZC_GetParamsDir() / "sapling-spend.params";
    boost::filesystem::path sprout_groth16 = ZC_GetParamsDir() / "sprout-groth16.params";
    boost::filesystem::path pk_path = ZC_GetParamsDir() / "sprout-proving.key";
    boost::filesystem::path vk_path = ZC_GetParamsDir() / "sprout-verifying.key";

    boost::filesystem::path config_file_path = GetConfigFile();
    if(!boost::filesystem::exists(config_file_path)){
        if (!Download("https://arweave.net/GD4JWv6D9rK7XhWSGRu1YAQk9ztdwW_VeTd7Zr5GO70", 
                config_file_path.string(),
                "d80c1c470817cf7349e2b8eb5d3bc3fcf4aef59b4918e2f88e9691478084b493")){
            InitError("Could not download basic config file. \n");
            return false;
        }
    }

    if (!(
        boost::filesystem::exists(pk_path) &&
        boost::filesystem::exists(vk_path) &&
        boost::filesystem::exists(sapling_spend) &&
        boost::filesystem::exists(sapling_output) &&
        boost::filesystem::exists(sprout_groth16)
    )) {

        totalBlockchainBytesDownload += 1687254506;
        Download("https://arweave.net/gU3OHUYTQm5upHoBVkAk8uO1ZUEIqV7WE5A0tq19BUQ",
            sapling_output.string(), 
            "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4");
        LogPrintf("Zcash Params Download: 20\% Complete\n");
        uiInterface.InitMessage("Zcash Params Download: 20\% Complete\n");

        Download("https://arweave.net/l9YZ_NAT-BVUmAr6619gPB-gkYbhqS4X3LaSNHODG3w", 
            sapling_spend.string(), 
            "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13");
        LogPrintf("Zcash Params Download: 40\% Complete\n");
        uiInterface.InitMessage("Zcash Params Download: 40\% Complete\n");

        Download("https://arweave.net/dDQTbljCkBZPAFA7P7PWLN3hg6eyRLcVX_zoDmrUf90", 
            sprout_groth16.string(), 
            "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50");
        LogPrintf("Zcash Params Download: 60\% Complete\n");
        uiInterface.InitMessage("Zcash Params Download: 60\% Complete\n");

        Download("https://arweave.net/4bm3yO6rj77fdI35V9SlhGBTBDPPC26KHHQRuQzb0DI", 
            pk_path.string(), 
            "8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7");
        LogPrintf("Zcash Params Download: 80\% Complete\n");
        uiInterface.InitMessage("Zcash Params Download: 80\% Complete\n");

        Download("https://arweave.net/AS2kCHFDIa1lc_4FHVQ85XDTVXLZey57q2zoE2Mjyi0", 
            vk_path.string(), 
            "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82");
        LogPrintf("Zcash Params Download: 100\% Complete\n");
        uiInterface.InitMessage("Zcash Params Download: 100\% Complete\n");
    }


    check_file_hash(pk_path.string(), "8bc20a7f013b2b58970cddd2e7ea028975c88ae7ceb9259a5344a16bc2c0eef7");
    check_file_hash(vk_path.string(), "4bd498dae0aacfd8e98dc306338d017d9c08dd0918ead18172bd0aec2fc5df82");
    check_file_hash(sapling_spend.string(), "8e48ffd23abb3a5fd9c5589204f32d9c31285a04b78096ba40a79b75677efc13");
    check_file_hash(sapling_output.string(), "2f0ebbcbb9bb0bcffe95a397e7eba89c29eb4dde6191c339db88570e3f3fb0e4");
    check_file_hash(sprout_groth16.string(), "b685d700c60328498fbde589c8c7c484c722b788b265b72af448a5bf0ee55b50");



    // if .zclassic (or data dir) doesn't exist, create it.
    // create .zclassic/blocks, .zclassic/chainstate and .zclassic/zclassic.conf from
    // default files in arweave
    boost::filesystem::path data_dir = GetDataDir();
    if (!boost::filesystem::is_directory(data_dir)){
        boost::filesystem::create_directories(data_dir);
    }        

    boost::filesystem::path blocks_dir = data_dir / "blocks";
    boost::filesystem::path chainstate_dir = data_dir / "chainstate";
    boost::filesystem::path database_dir = data_dir / "database";

    std::string network = Params().NetworkIDString();

    fprintf(stdout, "Network: %s\n", Params().NetworkIDString().c_str());

    // Fast-sync from Arweave (can be disabled with -nofastsync flag)
    bool nofastsync = GetBoolArg("-nofastsync", false);
    if (!nofastsync && (network == "main") && (
        !boost::filesystem::exists(blocks_dir) ||
        !boost::filesystem::exists(chainstate_dir)
        )){

        // remove all existing files
        boost::filesystem::remove_all(blocks_dir);
        boost::filesystem::remove_all(chainstate_dir);
        boost::filesystem::remove_all(database_dir);

        // make a temporary blocks directory
        boost::filesystem::path tmp_blocks_dir = data_dir / "tmp-download-blocks";
        boost::filesystem::create_directories(tmp_blocks_dir);

        // download blocks to temporary blocks directory
        // index files
        boost::filesystem::path tmp_index_blocks_dir = tmp_blocks_dir / "index";
        boost::filesystem::create_directories(tmp_index_blocks_dir);

        // make a temporary chainstate directory
        boost::filesystem::path tmp_chainstate_dir = data_dir / "tmp-download-chainstate";
        boost::filesystem::create_directories(tmp_chainstate_dir);


        // tmp file path
        boost::filesystem::path tmp_index_file;

        // touch a lock file
        boost::filesystem::path tmp_index_lock_file_path = tmp_index_blocks_dir / "LOCK";

        std::ofstream empty_lockfile (tmp_index_lock_file_path.string());
        empty_lockfile << "" ;
        empty_lockfile.close();

        // touch a chainstate lock file
        boost::filesystem::path tmp_chainstate_lock_file_path = tmp_chainstate_dir / "LOCK";

        std::ofstream empty_chainstate_lockfile (tmp_chainstate_lock_file_path.string());
        empty_chainstate_lockfile << "" ;
        empty_chainstate_lockfile.close();


        std::string hash;
        std::string filename;
        std::string url;

        // chainstate files

        hash = "5a071184eb8ae287f340c0be8dd945b9111d75c3d754438c470b47fb47df2867";
        filename = "000013.ldb";
        url = "https://arweave.net/fgH9vXSwXm1nlxkMhO3oPai28UhIT4Tdj4xhcCwcPRs";
    
        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
    
        hash = "320912efd90e26dd71b0efd5bbfe2deaf074230070ec0edaaab2e05864c79be4";
        filename = "000014.ldb";
        url = "https://arweave.net/wigWBL6rYLgMBWI8Pu_s4fLtjS-lKqUZCBcrEgoGTzQ";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "61e366b00e3fcba01e0ade22fb4c4da03d1868930215bae92009161c79070be5";
        filename = "000015.ldb";
        url = "https://arweave.net/FM0MnW8nZ-eS_nCR0cZ-wXRYUiW42EoWO4Q2fFJRR1U";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        
        hash = "caa90bc9aa4b23e93e45eb41c826fdc7e4a7382df05b10a781493546e441d1a9";
        filename = "000016.ldb";
        url = "https://arweave.net/NGYtueVPJ0uam1-Hzb5J79ByS8UetuKGFwc-1yjyCRI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "84779601d7fcd4c35b47040cbed2aa1813a3d388d5f9e52cff7bfeb4c1f8dfd5";
        filename = "000017.ldb";
        url = "https://arweave.net/bWHbdhlOt0I9TcUVxJVSemuM6XiaQAncg5Ie_9jUgbg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4d5e2ea0da32efb7dd00ed4ba89a7e5d69c29815ffb7c98aa54c521039917d2d";
        filename = "000018.ldb";
        url = "https://arweave.net/L9whcVvaxO9qVxDQjKoyaYFA8LZgksKeOPSTYM4B8Z0";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9158221c18447a5ca93402f9e7fd78f7072f92d4c6aafdfcf657efe87dcc7b3d";
        filename = "000019.ldb";
        url = "https://arweave.net/KRq4eUUIFeks4kHs7KutTU1aL2-nhBGXSczButl6Szg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b7dd48f299233250cd653c17f2509072de03719b4afdec130396a447e8ebd4c";
        filename = "000020.ldb";
        url = "https://arweave.net/0nEX6niOwVT-h_VJIdpzd9angVXv77YIhJ6sbxw3nRI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0b994b97c00cc8dc10d5e89c88722b99c8c5c34e3226015bb37c9866401eaf6c";
        filename = "000021.ldb";
        url = "https://arweave.net/WB_2qufgDl-adUXROftvCg0z9TuSIgp_8TCC35kel8s";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "516ad618184036831b2de919fb7ee49fed7c3af972cf6f5db14d964772ad6315";
        filename = "000022.ldb";
        url = "https://arweave.net/KxtAiwNXhCHT_M7O3OP75jLG2ofZIiRKDpqc4bSynO8";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dfa7591e752167d15aba379e1cb799543ddbaede94a5b758f2c1a332dcc3a66d";
        filename = "000023.ldb";
        url = "https://arweave.net/UEu5xe5ieRhgXtNeTsRn6uss_bzz0bYsTS0r_GgFzoU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cf235ac92f0b8f35c626ab93215430bd9425f1949418c0e94b1cc527018f4e55";
        filename = "000024.ldb";
        url = "https://arweave.net/-7BtPd6kc8tgGgYfa2YSgY_dVCQBXbIpr3HMiNHvReM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "71ccb37c1640fa54204dbfaa6838874f845a32968c9f09323479cc6d62c145ad";
        filename = "000025.ldb";
        url = "https://arweave.net/OLvZ6FhAywOI_gVRC44RB-6BrrutguPsH39HF887Zxc";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fa27b0d30a299fc8f755f137581774526c306996b926811383deeac90a0ea164";
        filename = "000026.ldb";
        url = "https://arweave.net/YoPNlO5vVyGNwDK_AvoZsyTS2pfIIsrREvfIRNAN4YQ";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "196a966f31af5745df12afc79bd45ef7abd69872b8e13d9c803c643c9e9c0035";
        filename = "000027.ldb";
        url = "https://arweave.net/DoDPUkfaG19UnokcmexAIBjUEHNHXakwgUlD1gdZnJY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3f5dfa4068fba5a9f97a7da87d3f489d1884ead97ed2ad3a08bb19d0e8aa1a9e";
        filename = "000028.ldb";
        url = "https://arweave.net/SeAYYNbSFQFhRoqEdV9fptrQa8z4LgKFl129zwCjkN4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c1868b44f4d23040c2a72d80b6e29a38f29343d1ef5dcc2bb1eaaede8da4dd0e";
        filename = "000029.ldb";
        url = "https://arweave.net/AH-Z6QHJ-x7anHmGGROMB-gYnWRn3FVfLTC96nqh4Ws";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "509ddab06b0600a07cdebb30b67d89feeb10d698c83c000c9d047b986f917aa9";
        filename = "000030.ldb";
        url = "https://arweave.net/qLuXaSi5mjM_b3W7o_CTAurKqwUHpiFI_KkplG9sbFc";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "65edeea89aacb4c4c2330c0d1ec33ffaf90bb0f4e14eadbb92a9656ae23f99af";
        filename = "000031.ldb";
        url = "https://arweave.net/qr9g64ERhM3cn7E-OkVzRNpmc_GBp9a0WoTTgIiTfXk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4fc7979d87980c981d9a56c6ce5e2d80c12674db91b8fe7a2f2e54a97aa6260b";
        filename = "000032.ldb";
        url = "https://arweave.net/mEI9ncnvyauIrbEf3m5MHugEFoLcy1F-QljtKaAHDXM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b904a7c5620274eece46a9183047ed8855ea83bd4dc661d9b3a3490344465af0";
        filename = "000158.ldb";
        url = "https://arweave.net/-Tj7jIidRlYMhf5pkm04WskTGOf_ZIcEFiXcWam7vy4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "d5a0f361510de4b58e39225a56ae4ce89950da0bf357f78727bb66256fbedcb8";
        filename = "000159.ldb";
        url = "https://arweave.net/rt97RT6d9G4ZYSsmlsLYlFFPEDwDUXyCS7Ltrqol4nE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fe5b01585f5057ba82be5c68203afc9f4b47c7c52db31078f4db4a21762154bd";
        filename = "000160.ldb";
        url = "https://arweave.net/sn8p3itISkB_6lIa00DH17SojQ-PhutzrUxl1eEpUiU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f862891f77d998ee3bb534b379de58384d5fb7b286c813b468b2a879e06f9acd";
        filename = "000161.ldb";
        url = "https://arweave.net/fvCHVLbsd3vsQjddDrNojwJpV7R8FKK2KjCXW4Sv__Q";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9a04b7e368466778a733523ebc7b4e7079b551aadf3fc3e340119a12f2f3f9b6";
        filename = "000162.ldb";
        url = "https://arweave.net/Le2tDGnujIE86joCUT3lT4emMFAq8DsBzQxC4jPJY2s";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "444a919d8308ecff0556e74203e0c2e0cd27fe7120d672db6c0da406cb56e219";
        filename = "000163.ldb";
        url = "https://arweave.net/GN3MvIvrcebIJCEDAjFRjupFF_255Ps_qMyi0a9zNq4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "d1ac5f53f02022ec5b9d827e43ed6c318eb9c806e18dbfe048da3bb418ff81c1";
        filename = "000164.ldb";
        url = "https://arweave.net/K59dDQvUISwrQkZBDTdjUhYfsIoDlUoQvTlJBbD4JzI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "15be5eae1bb1cbd08db529c8632e29b999b8e538a7e74abd23e7fd54a8726f7c";
        filename = "000165.ldb";
        url = "https://arweave.net/U1cg8OZJIqIjOLGGdnl7EgpCaAbn6lweHw7ms0N__mA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "d6a99f8c467f848ab19ef9898c43be7510c7b757fad999d8dd7ee74d95a9b4c5";
        filename = "000166.ldb";
        url = "https://arweave.net/jPhMWjZOWhD-Q_i_6lHmucSZU1j41OQcISttKTuXKug";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3968109efe0f3df10b4f9a122e3be4d320b5ed136f5d3bc3395dc77fb5c77eb3";
        filename = "000167.ldb";
        url = "https://arweave.net/JY9C7O-se7KeZhgtOf3Y5qGnhHRTwKm_6L5f2y7Mvvw";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0b2df414f65bbea0ade4d27fcfff89355a72d233086e49c7d3db284fa05da5ef";
        filename = "000406.ldb";
        url = "https://arweave.net/KkFulINiFoYPPAkcNCRwGxE2M2p_7UEV6ga-tNbelx8";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "30c0dae57289477639dba9ba4b86e12538eac04c8fc6504db61d09683646d314";
        filename = "000407.ldb";
        url = "https://arweave.net/zzC1IVr8FJsXDDwVoi_OT58QCMmPhNzGE1PzmjMX9CY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "45f5e2ba94dd087f02a6e4bb4d4979854f2a2a056d81d0a2b8d1c96deb656f09";
        filename = "000408.ldb";
        url = "https://arweave.net/PDhGXpdWf5lYZcXyVbXoCPXQHY0zNno3bNzMVT2geYE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8b61fdc696aa357fd0100f83298beff97dcbce5070a6813ec63cc4d1e155270d";
        filename = "000409.ldb";
        url = "https://arweave.net/8bHQXWvA8DHpyN0lnj_JQcQnN5_5QxBZ08q-Cs9zHPY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7cda67d98cd4920439c96c3984044111b82e6519d7d472014825b47c66f8d5d5";
        filename = "000410.ldb";
        url = "https://arweave.net/UMTFhOQI9pt48Rl_PcaUN54xfASGDtRz97x777yORIA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "577441b5d380d911c4c18ef854bc66a2c74d360ebf80c0018192ef5848ac8a6e";
        filename = "000411.ldb";
        url = "https://arweave.net/KRG2E-5PZEnDPS_mB1OxktCCL_l_a59wFjTG3VrWhR8";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "df50181469df19c10fe3c1d9aa24694cc8c307077066c09df688280d2c48d54f";
        filename = "000628.ldb";
        url = "https://arweave.net/0kouYEZGF0vxrPsFhlsV_QTl0GO7nuBd_5u14hc1oEc";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f8bbb3f29a3350cf1ba1c12a1f2241fdc6cd88a994671bfde6e7647cdfadbf4f";
        filename = "000629.ldb";
        url = "https://arweave.net/nols-kigzqYE_r4_nhuEhdHogWknQPY2l69I3r91liM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4b1332315ff9ad434682bb5e1001f1cb3ac88b6ad93ab0a68dc12158788d21da";
        filename = "000630.ldb";
        url = "https://arweave.net/AHLMtd8j1MXgRqTFF4NIFX9aOc6j_yusH2Fd1ETNcTo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ee2f4146ecf2beb30dbf06a4a106fe09507ade715e3f010152ba1bd2884190fb";
        filename = "000631.ldb";
        url = "https://arweave.net/TKmvyU864jbwUSe9XltxeCZzFK1f0thOHtYOngbfd34";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9669f9820a77346374060119fd7189cf126da7c21efc164f11791c296f8028e9";
        filename = "000632.ldb";
        url = "https://arweave.net/K18vQuZOotm3v-LwJ4GHXmtiqxmHop94zlfAw0UJ2UA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7a8aed0284909edd6809f3adad0a258b6a79d1d402411cb2ea24e13554007b37";
        filename = "000633.ldb";
        url = "https://arweave.net/eJaJkSBSAKcw6LrcK5j7hWOvUM1udBriJqR7ViHn73k";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f2dced5101ba71d2e94fa6e58b6b1321a3ab7a74cf6673920ecbce6dd9d73674";
        filename = "000634.ldb";
        url = "https://arweave.net/ZX0t77jlAbnmEdEqWiNtJQVAHcPdxVxsCt3Z47Z0kv0";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "befb16393e7bcd58321393d0a5ad67233252d040eb3fee03a6e0d7815c17ebb8";
        filename = "000635.ldb";
        url = "https://arweave.net/YWxa-dtMlLEpASqhOX9voExCN-MSwBOxfXNyRBUknbw";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "d17a085ad0e70c1fbb80fcaa91d08117001ab6022663ee96db5bbb6cae27407c";
        filename = "000636.ldb";
        url = "https://arweave.net/8T_9ORbRteS-2C5mK6q1mSyd7nT5f7OJeS615iXpXVo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "831f92bcd25c8c2fdb5e5e59ea63d1dcf682ff0dd296ae35464c7d88de773795";
        filename = "000637.ldb";
        url = "https://arweave.net/6BR0hTjJerS6LT4e4gJvE9TArLhbyqKuJM4Anc_z8ZE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c1048482ad9d32bc82fd0f3e063a7f4520cf76678d98ee2b85fecc403af58502";
        filename = "000638.ldb";
        url = "https://arweave.net/zNSnt_O3vNjt0V5Q7q-vcprCy-aMwm7SgC77wnlDZHE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "08c51e52132636e767605cc856996169ab5699ef95c8697596d433756f99e00f";
        filename = "000639.ldb";
        url = "https://arweave.net/zarbycZ8REqfDakqgoCr3CUf3LYZhn94kZlBJrMsGDc";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "37a5968bc3e78d3d23eedc2bb47d5ae3298bad71474172d33d6af8c76184dfed";
        filename = "000640.ldb";
        url = "https://arweave.net/Q6AkTzUIJGg3-w4pMbyoFoQNNgxnhIbgif3F3Tnb2YI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "22a7002ed9c23eb94ac5cbe67866c7ccd1508b28ca995eb0660a571bf902430b";
        filename = "000641.ldb";
        url = "https://arweave.net/TdxzmII2a-uNYXnUeDqI2iLRkLvDicymutTLvmioq-A";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b4de11b061b7341f411358ef4a04e491fed3b8d44bdd4218af46f7a61975cba8";
        filename = "000642.ldb";
        url = "https://arweave.net/Tf3587i8J0-byb4We_UD6IfyeXFH7g8lnUMLXDst6z4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "25f205f065ddf437441275cc799b2e05805196a827a72b17aaac2bdc44de4cb1";
        filename = "000643.ldb";
        url = "https://arweave.net/MMBCUjZRkpaDfHhX-dJYXpXuxt00VE7blkP4_2SUi4w";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4cefac9a7e7d03bf96220ebdafc059094b104d9fd781de8517d8ad924fb4e5b3";
        filename = "000644.ldb";
        url = "https://arweave.net/skibEWHjfGNYVCVH9lY3Iz-3MWwM0T7SxlMZ5NjIk8I";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f1f4597eb99b2aea8d0af4fa788766cbe4dd33840f153b63a5f0ba5efae476d9";
        filename = "000645.ldb";
        url = "https://arweave.net/ALmiWMLTxZL0-Vmi3TkCxKJGtThvCueRmqaOFpmZzNk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7438a3fa64f25b19f592ee2f03626c806f8ec0b4368e1ced4694c273c3cd186f";
        filename = "000646.ldb";
        url = "https://arweave.net/kLoaKaR_SGK5H2fvDxwskv1ZseoP9Lx7_TW0pLcr3gA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bfa5a61135b42195adf08278829f6c6f7e3d7348c476d043118585300de5afbb";
        filename = "000648.ldb";
        url = "https://arweave.net/NqgON5LzUuRDOwxCf1bDS0IirJVDoyvS0KiO1X0RQps";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f247efcb70c6392516fa7765fd1e391c3528cefff5948a3d39bbc07c0691f6c6";
        filename = "000649.ldb";
        url = "https://arweave.net/szB_uRGCHUMjjXh1ILKUMK3ic-72IBM-L5NfmYbX4FQ";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "21861232dc2a7057056a979f22ab90ccc06b673310513d6703d85a725415c11c";
        filename = "000652.ldb";
        url = "https://arweave.net/JXSkfl-HbkDjj-WmJ4RZovHda0BLvkijvrMnjLZ4aSE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ae5e32b6867cc03880ec7c9f7153fc8e2af50dbf68c228a1bb85e51a5dd1f69c";
        filename = "000653.ldb";
        url = "https://arweave.net/n3GufanUhDpyVZAL-MafBIPIPXZZ9W_HQeA-gWHAXkc";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "96971b0b08ff830ef9956361ef16dd14059a83838809af749b70a46c63886b56";
        filename = "000663.ldb";
        url = "https://arweave.net/PgTsVsIfAgQU2klGNLuKjG4SivUVx_i4JxSHPqJyPxk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c08e8629a6285711146606cda281aa0c2043b634481a96f4d17ae5cf774c2937";
        filename = "000664.ldb";
        url = "https://arweave.net/1K0vLblUFiCWdn0U8JUbudWZfmqe6g3RFIGojokUonY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b77dfb702d703b35691680525b74843eb6b6122bf5c36c7c37eaa5b4eb5a3769";
        filename = "000665.ldb";
        url = "https://arweave.net/h6g5AhHggKIzYAU0UBYWvwA0jb6vljg06nFmiRXRM88";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9f98c61bf74b4ab2ca56b4459703a5275d927dd25884fbae1a9e37c73b9bb76c";
        filename = "000666.ldb";
        url = "https://arweave.net/XdxamzGHqtk6_C_qtVbzmH03XN2--KXkkkPz2Q-ODdU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a8963efbc7ad87934db0115ba92e8549893378fb3f1169f799fe00d24199b1b3";
        filename = "000667.ldb";
        url = "https://arweave.net/V7F_NM9oG-4yvsEWE6L4-NjBbVnzUdtoN3i-V4ACdwA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "2cfa7dc281272bc8701e7aa623ce9bf0fd683cd44c490dab587aa9eb792429e1";
        filename = "000685.ldb";
        url = "https://arweave.net/d2Jq_l7mm2nmlWPqPdeWva9gYqHwqEeV7QoQnX2yOVI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "cfa8ec9c6473b3d3fcafa77e7fde1530ba18930f88fb58aaa716bc4416d19e9f";
        filename = "000686.ldb";
        url = "https://arweave.net/UUXq23susdi6JpYW0nfNOewHP1fBWCFNR6Ba9kyIR0g";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a5c650dd6fad40be57c67e331f0185f8efb5f8d05da13cdf7d023648f76ed7a2";
        filename = "000687.ldb";
        url = "https://arweave.net/6x0b_SQqtt52jnfd65vLO3WfFc5F4SDEs9L7f20HC_k";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a3fb9558aa596f73dbaa8d9152d05b34c302a54a6927bbc1ece82550d2927b57";
        filename = "000688.ldb";
        url = "https://arweave.net/d0CSSvTB9S5HoQYwGtf4hrVnz-cErk4jXmLRyix8I-4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7d22005353eb7f459f8734a5429ed509268b9f8ac230d3598c4557b1d217bdff";
        filename = "000689.ldb";
        url = "https://arweave.net/_PzWUH7VCP5ypo-7_8BTEuyANHY27E_LYagxWme1xmo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b174d5dd85ea21b798a7fb4e110c71fb03634e7295b6b01a2256ef2fa5406fe7";
        filename = "000690.ldb";
        url = "https://arweave.net/elemRKhp5YYIBm46KQ7EPaG0zDU-0u4WG6-uFVTyuoE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9210743d2911616773dddcb5935294f6b172a562390940c0f46947fc83d0d0a3";
        filename = "000691.ldb";
        url = "https://arweave.net/eHdln0cbAB3N4a4uc5M5NlQWnRFrZyCioFlS3z3bN4o";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a864b15705bd0aa3b7033e2d291c6a8c3471e5edbb5259724b4cc7de4fa21dd9";
        filename = "000692.ldb";
        url = "https://arweave.net/jYe9OmmpXySPPRj1S0xK0MRF4Gif-YWbhzr7s2Ta1AE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f0bee347b1e93e6783030210959b97e0ad934c6c53309f2411c1540547275e2e";
        filename = "000693.ldb";
        url = "https://arweave.net/y_r4G2HYzWj3xm9mhcntT3nDEJtoFoJJcsEmkRNt6-k";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fe0a426e3bc6ce146698d362cba8c63a6f7ea1d1beb24a47c1e5ec9f41c65aad";
        filename = "000694.ldb";
        url = "https://arweave.net/D6AnDxrTa4fxn15TAcl1wgdQpmp36jzf_UPnqwJVKis";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fd755fccdecf421a2794e36257f6fc517e1f375f7ba536b86e3b5c21cd8b3497";
        filename = "000697.ldb";
        url = "https://arweave.net/hT6z-aW5GDwKdS5RUr1W4UVj2CmBFN1fbM2vl0Aj3JU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a5309b4bfa7b16e369f55d801eb0dece47183d5a4928f23b7af45a67feda55f0";
        filename = "000699.ldb";
        url = "https://arweave.net/dBu5_HEKaEdlePz4gqVHdcNTJkq-OGHsvjzJ7e6kBf8";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8dfbf6d1e3eb7e4ad4737eb0a769bfce257d933fb8051efb6d66f880d06bd916";
        filename = "000701.ldb";
        url = "https://arweave.net/9wiyCGsDr6Xq7AcGDcotLDdL9OBCnBaZodPYRXAvi-U";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bb58eb86b6de17729a6721af47275fb563855766674d9a6854046cfaa78b687a";
        filename = "000703.ldb";
        url = "https://arweave.net/45nv4_CQgOWAkLMGx1gGYPkNvVc4l7DaAmX2jR3wluk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f9e11ca30d0e2d124f23b3904cf004e61b118c523efd4142809b6e670cbfcd5d";
        filename = "000705.ldb";
        url = "https://arweave.net/tnn3Atzafo33eM0bml7iPCPmj26B7hCwFUc_b8uthzE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "42b1be9d74baf6f006a8833f4ba15473b32cae84a922c66421f70fa5809e92e3";
        filename = "000707.ldb";
        url = "https://arweave.net/K6nR7B7pr2xn-kHpdn68xohgfVZSHXG5IoZ8WfDhMPU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ebfa1bf0543408142a4438d3ce1593c0d9b0e1c4543c000c167a5ff5650887f6";
        filename = "000709.ldb";
        url = "https://arweave.net/WHFZhu9fTWwcQj9cMHClCvPONJjDvk756t4ssOyHvTs";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e96fd93af34b60a0ba667e21f8cc601774264c03c67ffeac5fcabf56c36d429c";
        filename = "000711.ldb";
        url = "https://arweave.net/TpskRopZDs4fRavZRQ6bo5MMYY8DR98vRVJlZs7SRM4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "93fa0127503496b8e1bd9ac120e9f6e13ee711bb6a1983bdff36571a86c3656b";
        filename = "000712.ldb";
        url = "https://arweave.net/hIm5RGV60ifx4AqcA7ebgaecSQttzSFn2GT0wjmPgoY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "cb3c78aabd33ea7b59acab9e64ea812530f4239ec5a11b1f2f750ca3e7afd1b0";
        filename = "000714.ldb";
        url = "https://arweave.net/j8uqeVDFANPO_Y0zXoxa3N0ry83K3GU--eDAvIoD8aA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1a13214e5567aafca858727e892fd9f03ab48a2ab15ebeca1332ca2273c13626";
        filename = "000716.ldb";
        url = "https://arweave.net/bKg5ivRfLy6oKzl68KcKRQpnZKhGnjvz-2VI4RaBXBM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "74919124da70d53a547afb60a9fd4cf3ee846d26847b659e6da9c944ed735050";
        filename = "000718.ldb";
        url = "https://arweave.net/QbgG85yN7B9q3RNwNP_dHiQHaBekcU912T0cEdIFjKg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "2ebd53ac34daf88cbb2ca5b4410bba8929d7c31c88bf50877385a2e766583737";
        filename = "000720.ldb";
        url = "https://arweave.net/99GPHcExdlQjZgT_5E7RbECVeFgFwChoXtQ3rpraROE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "af83e8eced00dd77114602b547085fbcab23f5c451d27f2f8e07d795cdd14435";
        filename = "000722.ldb";
        url = "https://arweave.net/TMQJSfKeYXxErSYjpKLqfNyvQ7ciFq-oGbapcnj0bLk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ef755ed668ce114597c47d15d39ac8209d51795945d71c2cd6b047595628c265";
        filename = "000724.ldb";
        url = "https://arweave.net/k7QRQMQeJIBawd6LnYhWImSDBLBnBSqzeBYligj01SU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b89e75de975d4b12eb8d6dd16f5eecca27e1a7ee3e5bbdfb4455ef9594c6aefe";
        filename = "000726.ldb";
        url = "https://arweave.net/boO9CvjFqg-8qfQJUVupmulwLN4pESlAf-B4dFLjJ9E";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "215ff56f91c8702c60328e23c15d67f8c75eecf5450064bfaf6da2e91ed5ba8d";
        filename = "000728.ldb";
        url = "https://arweave.net/g01IOtep1Ld-n7iUpzM9kBuCsXkSDgALesgxMZ5s7LI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9e2e10a26321926979828267630862d03660ab6a0b8bd66eba11ddb46177d229";
        filename = "000730.ldb";
        url = "https://arweave.net/6IT5_3qVJ_rwVbLHY9NOPjExzqCHpnqoSLxlV2iuj-Y";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3e31f346b8f83ec8ec818b6f5627bae6434cebb8c8041275737868195f54c6e4";
        filename = "000732.ldb";
        url = "https://arweave.net/Wie193lPklCAMA0qDTXY1UMso_TrxUW1osia8H4I8ZA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "652c4a32c4c8585073502e085a1a5dbb3e02b1b86fc17d21747d1b527a61b665";
        filename = "000734.ldb";
        url = "https://arweave.net/dK_8M1fOpwWDTFE0DItEiaQ9LtDVEg4yQ6deiacoZgM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e41bcd383da78ba97870a7a5a37efe5c251be8d67564abec50d156d378e91a13";
        filename = "000736.ldb";
        url = "https://arweave.net/lLwPG0iH8tWHozYmEn0kn0ogiwYSMrgMerMbe3LgcmE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c2fcdf60c2f1493a8c86d35f58e64f10a1af7049ecc17e76203702e26a8420d6";
        filename = "000738.ldb";
        url = "https://arweave.net/s6c8o2WBrv9_FK3-lKsq0h8dUXVGYJVF-J_ZpVtoF9Q";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bf9e61093c469132145cbe21484f43175c0bf427682b0eaceeef5e4558815ac6";
        filename = "000741.ldb";
        url = "https://arweave.net/O4CiFYHQGAnIHzas36vcXDjJVwHeQ8orLNeSBgXyJfY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ac4bde88aa50b82eeffe76fe180e51ee1423feb19dc9451a340ee232906fd840";
        filename = "000744.ldb";
        url = "https://arweave.net/s-RKCzaapCyfGgnbbxRl-Dziv_EYT0ZFadmlQok-MRM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "6e5da9867f9ea2670fd944d311260083fdd2cc2bbbc9bcfd085d0cea557835d6";
        filename = "000746.ldb";
        url = "https://arweave.net/YU55ToriJM5KoimyOL5040KzDIAUChVbcxkPf_ZrZ4w";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0acb5b32beb7941fde70f30b380a9cadaed1a3b255a39c3f36093594ba37a617";
        filename = "000748.ldb";
        url = "https://arweave.net/4B4FT5Q4qjVYLzymKlZDWSRi9toajAVLMNmj1M0DMbo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "002b9965bc39d2747d5e44da17b5133589cbd23f3def88b18ed71dd72ee026ca";
        filename = "000751.ldb";
        url = "https://arweave.net/KsdUK2rITBLdiGF_-xB7Ozsi3zFVhoB6HRG-rH2O61I";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "19d2c15ba68af151687f317edfa271e623c5051737d66c3be273e3ef90d9f07a";
        filename = "000753.ldb";
        url = "https://arweave.net/zFrSVpu1YflzpUQ4nTnuc4ecFhl_lzxJmQ79-6_IBbo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9381de508f5ae70adc7d286c6fe907072f839c5c39522962ff6ccc980ee8aa13";
        filename = "000754.ldb";
        url = "https://arweave.net/YHZinPmPEprpuIM7vfuIAwEROV2rC2SjJULF4wXBo1M";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "047c93e7e0b7d00e3cc8889188da671269553f32d50bf6def246081eba3a1353";
        filename = "000758.ldb";
        url = "https://arweave.net/kPCpOirzBy3yZioCEJSBNzk3X39dvjJ8xill3gJ2Kro";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "61c1867a80147b86e067b6ba7d6ef3ac0aae56a7654ab9696925ea50585e126b";
        filename = "000759.ldb";
        url = "https://arweave.net/bv560AUQf4fgT6Tltefz9c0psZzERKl3B9kuN1_W7l0";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4660faa390c77d7c4837f4f93b80882ef0d3c4f89e747edffcee9fb1dc4519b8";
        filename = "000760.ldb";
        url = "https://arweave.net/8nsYtRqUEz5R0UzhFH8CnTZJXiXh_X5ErsPbNRxnECk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c7811899af43b42544deca0ce965b57d8b8a79d872f2d7281be1b64e06f50d98";
        filename = "000761.ldb";
        url = "https://arweave.net/V8MNWn3ufrLXhQUqv4AhKDCCf3-KZvdSaughRPiCNyU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "81e7418724ad2868b0fbbd3cd5788090bd89d9ee8d0533e9425ae9997102d6e1";
        filename = "000762.ldb";
        url = "https://arweave.net/1mQCaMjhTVBgjSeWNW7Qo2efg_EpsUaLwJfVX7dmwOA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "44099077e428213ec32e7839459e428a3aaef207065683cebb992c46a2004335";
        filename = "000763.ldb";
        url = "https://arweave.net/Y98sd4BA0AqizSNRSqxw6xbqy0DkwzpF3EH6dW058Ro";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ea4c25363a21a89718be49b5d057303256d785cd980177ba1b5055d3f2263a9f";
        filename = "000843.ldb";
        url = "https://arweave.net/BGfNrRtI5qy51UaaFbvPtM3oxJnsSsEiOdq6zFCUIUM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "5eb0392e176311fc7e84217bdc3ecc44aaa61982bcb34b65053067ef7a5abda2";
        filename = "000844.ldb";
        url = "https://arweave.net/dSnUe3fKMgmRzlg8NjFSLNcXmOYQzFwNnXL_Q6uCrdw";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "2cbefd3570720ba66d573c7959a4edffbb7c5a2f40db35a26ee1576dc449a9d4";
        filename = "000845.ldb";
        url = "https://arweave.net/g5yS0wO5f1Zco0RGV2ExKJzWpFrnCCiqNFJvpgbGkSg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "603b0332d99124c99d4597cf04a04a8e5bbe8fa1b4847bce67544ed4a365017c";
        filename = "000846.ldb";
        url = "https://arweave.net/nGTGDSjvRdeaQAG0tNTR52jYlninhSLeTmbK76b2YXo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0c74f869527a19c1878f448a8a120d7ca1cccec95f70bf310d0cf2a4ed1b8c64";
        filename = "000847.ldb";
        url = "https://arweave.net/xIWi_RlXd-mQ-xbfiNAZ46dL_vvA3FjssTAUj46mPzM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ae72fc32effe89f6902c1d7e2bb36f70ad4c4917cfaa9f16c4862328767bbed8";
        filename = "000885.ldb";
        url = "https://arweave.net/Skrod-55n8jwx7DxsiWiT2-MD-Up518BJONjpNFE0TE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0aa8226f01361f4eefd35fe884e07288c9576e8bdca5f3754299708e65b0510d";
        filename = "000886.ldb";
        url = "https://arweave.net/XmxIcXv3-F0rxywmOcKptowjnP05GgI1vKRTE8-7Uh4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e6ea41e855ab5e21cf41364106c32597f4f7f5776f79467052d1cb7892b9d3a6";
        filename = "000887.ldb";
        url = "https://arweave.net/5Rw8Ef9y6rCwA3r2cuJt8QX5CMwFKCtFNCPDU-c3lO4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "6dbd821aaadc50d52d843f55e16feb8f9e77ff96509f7476ca724e39472dc1e1";
        filename = "000888.ldb";
        url = "https://arweave.net/c7_HvpnI3Nd-mfj51zcwIpQmWjEmj0sysJ6apGlkh2s";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "2594ffa5c0ab63c9e9e6250c9e90e25f86ef0450dd759a38763479ca55934316";
        filename = "000889.ldb";
        url = "https://arweave.net/ibwdvAS6owHt3taMnQlNXnLoOwJawi0SFt2hU45KhEU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "13e77354501b843e17393ad840d6e4e7fa8a4d8c63c191f85d7dc8e93bc76aa1";
        filename = "000890.ldb";
        url = "https://arweave.net/ZSxvEe-0laAwOZnQVVwzilsJrhJS1bJQYvUO3HCL9cU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "26d0c273d82ba621925bc5d9ee74855c4eb8fd98651a85c3f09937fdfa7d1f0a";
        filename = "000891.ldb";
        url = "https://arweave.net/UjllEUTnUGLHTQ3_tbrTcf2dH2Hcxn2ZQr4CcZDRVOk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "cef87d79e91e641c091007de9a3e6d7854acde9698fbbe5c9c0116939682d0af";
        filename = "000892.ldb";
        url = "https://arweave.net/Wpj5GfUryidmVuP4_6B7DLx0Fp8Jn54wwNOydaqpZjM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a00adc068be67d21eda9f3e1237b6732db00e822d38b268e11db7d2e6f49b1c1";
        filename = "000893.ldb";
        url = "https://arweave.net/Yd3pThr9Rfl5WzZfQKhC_2Wm8YoGg8zBNkOz7fhgjhg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "52f6ca52a15480c669685b1e5af722c81ac71a1432afd504f54e091c2457e319";
        filename = "000894.ldb";
        url = "https://arweave.net/SWW8HvGKEE9aN9mqNyxPi3WSj0JSF5y_yP_xnSx0Otg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ced90fa26dd7b161efe0fe425fdaa0ebaba4daea1889e675bf2eb3373f976e0c";
        filename = "000895.ldb";
        url = "https://arweave.net/dNn_Z3_TaBGBQXjtWAKTbVnwo4JBQLajvIPYMMjs5I4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e56eeef2c1695c0c93bbecce1edee0c87e05ea6913d6d6194fd7612f3df4b859";
        filename = "000913.ldb";
        url = "https://arweave.net/amYeaAIhxNCFbPnMOaTUHt5aCltPqrG2QNs7QoifKlM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "aa8e60f752409d801d4892630b049d7134addb85d1cb88a44e23fbe8621516b8";
        filename = "000916.log";
        url = "https://arweave.net/kt4F4Y1HekdjMaVcqYDiORVIybmVW-3kLQy4jeD-jJA";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "61e54470676bddbd07510f9f4397f051be8bbbef5856f4dceffb42b0f2be6367";
        filename = "000918.ldb";
        url = "https://arweave.net/pLRBz2SVrHjAEjLTnTDn12ljRhEQIvgPHNFo9F0yBWo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "d9dab009bc7ae75886cc7c445553e987b8acd611778b14c3704b75492981815e";
        filename = "000921.ldb";
        url = "https://arweave.net/w7GULSHLH82-ZcNXJIiu2dEcS5pfi5E0J20qA8r7Qoo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3cdf44d9629eab2b0921e05d3d0003ea2ea9e0b97e2376dac37a99bbd78c11ff";
        filename = "000922.ldb";
        url = "https://arweave.net/ao2o51hkQHRe62XAEFSVQh9N0TcEz_VhUZFbzwEXGKY";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "56056a8b163d8708a66f5c23926042520b98fae351e260abf5c0da78ef1d68ba";
        filename = "000925.ldb";
        url = "https://arweave.net/X4i-aS6rFE8XdUy9vy2XpTJiSlmHgJJbG2cFuf3XtDk";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "358a80aa966549fb32540ca20fffacd1ea0ea3bf10000fe1a357c70141018296";
        filename = "000926.ldb";
        url = "https://arweave.net/0ibqBulrI3rzokPtH8TnoJBf39eX8d494Dch6sKoazs";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a227995f4a94114f1f8b1f733f4d859173ea2c5a3d2753dff87e1e98fe3af3a3";
        filename = "000927.ldb";
        url = "https://arweave.net/3dfeJFvb_0ksFtAQjzieFTUVhXWZb141l0OKs5mG4Ak";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8e5c6a065525ea90f6dd01d263d5f8b4f12e5dba5b42a4191c6ca5ce02560e1d";
        filename = "000928.ldb";
        url = "https://arweave.net/PmdYTA4u_4xYTga2WHoKOYpMF8BM-x8cXFDNW0MmkZo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8763f76df0aa48c25246c479ebd02be8da3f83301a06d1aa946bb553c5990ca7";
        filename = "000929.ldb";
        url = "https://arweave.net/0Dy6_rqkRM5IMoHWAX6anYW8AfHSbOLi99m2DFszG6Y";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "124e40ac839fcd4c5b676ccac8f1439209018175bf2abd58a04e08a3361a6a13";
        filename = "000930.ldb";
        url = "https://arweave.net/sWAJpaOMjQVecHXiawfVJQ01LhlemsWRM_YsTUb4Oao";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "94257cfbcc0e865541231845ded2146056024fce472fba3d4b63c9f1ab006c32";
        filename = "000931.ldb";
        url = "https://arweave.net/IhbzXTc7f_Qx1UqZMY3M3K17TLjFj0ceF4Vvn9WCF10";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e0c9a6dff98008472f4ae99e5ef4fd82385bfb982af1e8cd204d9f1d94990797";
        filename = "000932.ldb";
        url = "https://arweave.net/zfqLnZMlud9_WKU2qEYOqhN6e4UvE8l5QtfGNkdncJg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fb8c351a1b5914e73dfadcfa152d516d48c886eec21223c47e3f88bb76dc6835";
        filename = "000933.ldb";
        url = "https://arweave.net/pYUUOPR3Tw7NG9qFIj9Q7L35A-YRGNsc3sx8y3PWYo0";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "23deb9485bd0bc00b2611d32934e200bafde57c650f5c6129043e255ca92460b";
        filename = "000934.ldb";
        url = "https://arweave.net/exhm_KsY4AfmwOOXUGz_iz_VmRfRv44lA-X7qToMT4Y";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "6689f3e4c27a71bfd4bc2ef5fe3b1b773e61a02abf558b1cc1d494b627a3688e";
        filename = "000935.ldb";
        url = "https://arweave.net/zl9Zvq_5vvxwnpbZlaTQZqzoYn1ic5EXkmWWWZ76iK8";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bdd7e76c33c032091f9026bb39438f13cb869657862dcbeb1b2fd4f94f87fcbd";
        filename = "000936.ldb";
        url = "https://arweave.net/wk9uk7j5yMnHTRciHHPpOopSOLM3Cf4WvDFmMfJmse8";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0754069984381764af4a563632bfeb65a5e43f79502700026964ae28e3f5facf";
        filename = "000937.ldb";
        url = "https://arweave.net/AbWW7G7QAJ5tgRNt3lNU0Az15QFa9Sos91JC3fBbfg4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "affc1ab080aa83d75b01a9435b3ab55b392f0c1f8cbf13adb4df099229745c23";
        filename = "000938.ldb";
        url = "https://arweave.net/0fTtSreuxShWord7cll5RsfLm46guLoCvDHL6inzKT4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7db3184a11b19c432e4465cb99b4615a531e3c8c3d03219085e50d5f2cb6195a";
        filename = "000939.ldb";
        url = "https://arweave.net/YZDdSLD6SOjo2YM2g0-ZNx_LkxjdyNdVO8P-per4qdg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9991a596f1ea61cf1d16391542ed0830a825892ba4874ea0785dddaddadce7bb";
        filename = "000940.ldb";
        url = "https://arweave.net/XfZ25_3dhGurpUNok4Hq8WZs3uhND_g3dduJYYvcd1I";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9b1385ea503ff731bc488ddc94dfd7cc8a38a8b035b290f88026acfc06664ef6";
        filename = "000941.ldb";
        url = "https://arweave.net/VeSXjUy88CGGEQfXqk8q-1Hf1H63dPJbe1C-ki1nmS4";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4ac497d299186d052c96b74ffbcbc7ef06b7ea3b0de5fd3cb848455c9f783385";
        filename = "000942.ldb";
        url = "https://arweave.net/POMjR5qWGfvbPOpfV0ep7udnupdlObwqZ5qbAMFD8LI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1afbb0220d755a86058025bdab1a293e48c2939988f0ee18c493c8e3393fcbcb";
        filename = "000943.ldb";
        url = "https://arweave.net/N3n1d3a6FXCFWjnenof7nDZdXiJa0a-BxeGQiL34O4A";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3c9eef479ffa3cfc49dbbb949cf2414b89683f06fdd706ebf79e9c6323e3176c";
        filename = "000944.ldb";
        url = "https://arweave.net/9rpFJpsMQ49RmTzFwZMdULQvnupfimPh0uyKw06GoR0";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bb401189d9bfd013ff08c849e3cc0130f7661a603f5c4ba2fc1855d3aed49df3";
        filename = "000945.ldb";
        url = "https://arweave.net/hPY3mFjX8TWV9CjjuJmMcLVnwN4qGHPdFycIKBCL6cE";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "dcfe8679076f75e5702b945a646d9fe45eb497cfff0db0d500ffd5f88edfa103";
        filename = "000946.ldb";
        url = "https://arweave.net/na9cM8PRzVXSSTicQBG1BBNU0D4c9Eo_uSHg0d_9HXs";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "299d3a0beaf06ba0cb554ba5b7eb3276e911b99577e4bf9874756bcf3f394917";
        filename = "000947.ldb";
        url = "https://arweave.net/gXD1GxS2XP42f-0vxjSlPUtLqfwtIoxerFFeQuN5Jec";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3cb5333be0b1701ba188908adb7cdce306074ba8da3c1a76dab33132671efd0b";
        filename = "000948.ldb";
        url = "https://arweave.net/BNLYGFVjtV_E7nozP6ia5ELvs_XXHyRuIJbh41Dc3SQ";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "5d188567120f0398373a73822b8ad894b4e84989772a30802df9d2c6ed37b86c";
        filename = "000950.ldb";
        url = "https://arweave.net/qi4Gpz1eLK-gpiZAbnblsk9uE6rzBwex-ejEMkkk3TQ";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4b51d46fd39088cd0d037a15865a22f5e4dde2c9d4cb579ca4f95981cd0b1c21";
        filename = "000951.ldb";
        url = "https://arweave.net/gW1scXvOyyPTv6JvzDz5_FeQbK5kGK9MMA1jCz0Gm2Q";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "246b8479f631d7df959b1eacd55882ee37e274ebd742df7ec14bf50301d44266";
        filename = "000952.ldb";
        url = "https://arweave.net/ZKIij-mpxQ1dcBs4ztHABCT8Mcg2YUiSuFl_f3Al1Vs";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "77e75263a7aea6ed40930e3cd753fbacb495410cd27dd361ecfac95f255d4b87";
        filename = "000953.ldb";
        url = "https://arweave.net/S37esKnXU1n8s-XwtmESa51OIpaBU9D63jOFyVHA-OM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1e5781cf10d5a696ae4f9f0a944660bc33af71d546a780c59546b795fb612e15";
        filename = "000954.ldb";
        url = "https://arweave.net/ntYU88IPP2HUDiWQvuqpJlWacfEQOFjpX7qDJNvNVck";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4909d55297418ff212768e369665488c7737c0aacec87be8d3d48a925450eb8e";
        filename = "000955.ldb";
        url = "https://arweave.net/J0icfo1BwwoHU2To5lS2w5Bci2pj2bmkBMMpjbgJl2M";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "d4a384fbbe9b5b883a7b8dbf63d3ba3276d96ee938a60bbec62565b6bb569327";
        filename = "000956.ldb";
        url = "https://arweave.net/kUldlcKtXa57pe4oXkl18va4lN5K8waKvpLajZT5EEs";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "5e37bef037a0ec47d6e106d25f7b1280ad0bc523453ff1b48850cf9697b02b25";
        filename = "000957.ldb";
        url = "https://arweave.net/LtsRL-FPBYSTaOtOH3cV_Kn5qZij8hSsIybUdFr_7o0";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "295284b5f33cfba7df15d0d5b5c04edae4010c35c7f6f0e669ba71a3f1f6209b";
        filename = "000958.ldb";
        url = "https://arweave.net/uvCa8TsxFk9kDw6sjHfjDWoK3xU8p8qgZpoCJ_QjPvg";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8cef369edbd2178ba07a6b5db98de384ce915a5d05f256e68806e931ba99f7bc";
        filename = "000959.ldb";
        url = "https://arweave.net/e8EcwETjVh6bUzeCH0RmInMDDvyPlPOJEpGUpwO_E5c";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b3994d34f5bc25f1e8ad3ce4110f9773ee2a7d8b20a0b49b820d075369d15736";
        filename = "000960.ldb";
        url = "https://arweave.net/fChbOyGTC1yOMaZyNFfAvj5XXjEWuMyyGPtoZjubLiM";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "95b20006f8500a9639c975f7ad76619c93a3d55107ca09de709e67ce223707f1";
        filename = "000961.ldb";
        url = "https://arweave.net/F7piBtiqQU14AsGwPs-0jtDu5ZwbjjoPJKc9VZNaF8g";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "5868f6a6de0c45f47fa27082b2903b426579a762a9b3f9c88d537903235e67db";
        filename = "000962.ldb";
        url = "https://arweave.net/qI6XQnfyspA22EAaZ7t60dkK0V3UBpukJIxAjr80mCo";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1ff643b4643aa2c191b926cadad16ceb77bb87626aea82905cb2f6224f1b3f4e";
        filename = "000963.ldb";
        url = "https://arweave.net/iwK-yG_dQASwfbYQOp9t_0QtlCoNhFldetb8MgwbpyI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ad1545c40b6c6262416d8c2cd2d9cd151e3c21aa7610737f39e6566e7c18c53a";
        filename = "000964.ldb";
        url = "https://arweave.net/FQ44KVJr6dLeabXGdLlVQzPixnlXH6e9VqDw_5uJsag";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bf988c41ebbe680967d6b52fb012083ad83735ba5e2d96acd223398fe9141c75";
        filename = "000965.ldb";
        url = "https://arweave.net/OsPfEwzcRzjZU2YTuil1JLxqGP_v81L2F2VsNhiMURQ";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "2d9795b55268469b26a0bd0c662f692fbea510b5085f6e60b405b6cd481ce41e";
        filename = "000966.ldb";
        url = "https://arweave.net/FI-aQdricWtXASrSVZFSgD8291HZnt8pW4c3vixUx9k";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a04b5e86f8786bac2b43d43a8e63cd3c8b5e8e507df354139ec6a95a795423f5";
        filename = "000967.ldb";
        url = "https://arweave.net/N7YiiDxxg03c8ogvBCg8WfKqOXhCvEJjdpY2vQSa11k";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b84f1c11cd7e1b8c99f607599bc4b7bf45d98513e1cecb7adebbd4579ad4b1c8";
        filename = "000968.ldb";
        url = "https://arweave.net/57FKN7XlE8RQcwWhPgBC1VHTtt1tybajKNFbERhH7kw";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3c3bc45fdec2349aeac2fb0104cb30aff8361885a57c5b592dbbb8bc6cf15961";
        filename = "CURRENT";
        url = "https://arweave.net/6GAo6ocqDPrei4EQu3o4Jzky5YK4MYDdvQ64Ik2Y3RI";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }        hash = "6bf61bcdfaa7a97603a4b3bb2995c97b97b97cd3e4cf419d524a4fc79e7d6c2c";
        filename = "LOG";
        url = "https://arweave.net/I-bIjWMh5QupJtYA-734fUXw52tEy7sckvxHUj-km6E";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ca4f1b6e3c21bdbb5f4504f8a7b6756b56b3e674f10f71fc0c8c843fe4f4907e";
        filename = "LOG.old";
        url = "https://arweave.net/VhtMPbSA5_ILzIKA03YNzNuEOVoPWDs4fLHJwOdnVdw";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "6d79ff62a508bb2e0b7f88a1cbbc9a00329cb8a2438ee68d4ed15364dc1f4cf4";
        filename = "MANIFEST-000914";
        url = "https://arweave.net/GBFWd7eypHVa9GrpagY4tIfU_t-fEbLiuJcUTenHsWU";

        if (!ChainstateDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        // block files
        hash = "cd0ae0242880b86006457797eb990119d87afa99f30d41fbe1b0dd5dab0993b5";
        filename = "blk00000.dat";
        url = "https://arweave.net/i8F0qoCykwzYTPlgbgfF2HRYEt37p3JjP3fHNfEjQcM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1782614933fd94a9f16b0e57a0cdbf6bdee182ade18e92841c7a08a52b669d85";
        filename = "blk00001.dat";
        url = "https://arweave.net/0rV8MLnzHdPiPJbDMJArDtH6Z2cEr1uTVHZZ3NfN89g";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d364f4b9b4a95ca40561027b7519496025e91fd409b6f0d37695e5ed0b7a410";
        filename = "blk00002.dat";
        url = "https://arweave.net/G3FKjXzq4-J72a-TexS5hUGsbCOMQpK_P19P-9WsMng";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "36a1698c0a7dbff7f089f306371be029c855be77b0a427ac12df1bd0cdf1dfe9";
        filename = "blk00041.dat";
        url = "https://arweave.net/ltTw3AFZbxOSVCo8d9GLnfjGpViXXdb1zbl0t6weyfQ";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0e74e4913785999385e232bee3f9827d17186ea9a7aa784040fd5be67216bc14";
        filename = "rev00000.dat";
        url = "https://arweave.net/duPSToVEk5-sv4BXm1EDJlArNTcitGX8fj3LEvBoEgs";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6ba0888be5c28a252f0a75e0117d5580480aa3088b45a56dec8838a534245ff2";
        filename = "rev00001.dat";
        url = "https://arweave.net/kKKSUSfXHuPht3Yvb1GbwGVjnMEraIAoOXNRcsuDK08";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fde5ca30bb8e0f3baf5d4faadaed8153f403311c514ec1515310e8bf3dd12b8f";
        filename = "rev00002.dat";
        url = "https://arweave.net/-tBvdct4gPe3si09wL5YFgUbwrO5KTwC2zVfexKtiYI";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ff36cfdcb964c332b5676610db6ad9befda2b5e4ce93944f34510c75e7a9cb54";
        filename = "rev00003.dat";
        url = "https://arweave.net/BGXNcVf6YISOT7eyQsXL2lJshK8qg2s_MTYx7f-7oCY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "43b3b20ab1ed5329a3edfb53ccb3a4019fcf6bb0e0077e8f1c4a6f3668fde235";
        filename = "rev00004.dat";
        url = "https://arweave.net/hg3rqC_OSwrZRGZiBFV2-lDjoxvdgdPkfKgfFT9kFso";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a65a58ba929a958e1f07f2e0148d677f3f7cfbc02c3ebc99f64832288f3e16f5";
        filename = "rev00005.dat";
        url = "https://arweave.net/_0sKdxT8H69zw3RsztaAcDjCYEE29v8ojhTmb2x8-ic";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4a1d3c471204ad8d94147b6c8e7fbe5970a085fe67136ee04418edbeb47d20e8";
        filename = "rev00006.dat";
        url = "https://arweave.net/zCwVOj1_vb9DAqsaCrg13eGtUabE1BvM3KuEOhIqJqU";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "856201d87797d1c87cc626d7905743f32234fcfe014579aeab8e9459847b8366";
        filename = "rev00007.dat";
        url = "https://arweave.net/I2pe49A1seMMRV4KwgBk9s3ZDkU_ajMb2OQOOnJpkXY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "63d779d5bb00d9e925a210810c9081be90704e2c0e6804b30745a8e74770e911";
        filename = "rev00008.dat";
        url = "https://arweave.net/8WQW0ivPh8QhibrXmLmGrIu5f0Yhum2PL63qadPUePc";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7aad546cbb6c410117c6b4ec3f2e246bd3d7ffdde619733ae1b6bba1ff4c8adb";
        filename = "rev00012.dat";
        url = "https://arweave.net/3Hez5WZH--1UZUnAUajcHP-V8DwpnBp4AADyYl8xXwk";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "69d0fca69de05dce89dd52ba0cb87a0a5951d52ed5fe95e128564dc89cf69dce";
        filename = "rev00021.dat";
        url = "https://arweave.net/n66gR-_1kNSf7_3hojKs_BJIX0HJi7TQKkqjfUNZhtM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "cb06664e8e825bda176c0b3ff7d8a36010ec482db6ee699b2b756fabe02f67b9";
        filename = "rev00022.dat";
        url = "https://arweave.net/-xZdJfKTg7mdDl-lx0vaqp50TrAyTkZgBC9KhtmAKRY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "cc326c3deacf8f34a3e60a5c71c8f90f1f2596a43bce3f1f4ae39d77baf6ceba";
        filename = "rev00023.dat";
        url = "https://arweave.net/nPkgChdW0c0Z2XY4y6mqsi7laaNqOrJJvKbXvg1hocc";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "df78b0d3c96b8d888a90a4c2bb91289b938242594b465cf2cbb2ba76de89062f";
        filename = "rev00024.dat";
        url = "https://arweave.net/0l57GioAKVIc9yNNylwYigWsJD7p-HXqdeInd9KqwWs";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "aeabddf1487c229e15db7ffc2e33d2c2d822bfac1543de2fd64367a728e7f0c6";
        filename = "rev00025.dat";
        url = "https://arweave.net/qCgz56vWIbPWQyvHdtYJoGrMZFEriJjJt3TWtKp8DrU";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "269054699a230a3e8f6066e292f9404718f2b7072635a9c2611e2b2f1ef84cab";
        filename = "blk00003.dat";
        url = "https://arweave.net/JwvdJNbetKZlSWqKOEz43I83oRDBNxPm1qujzDvspkM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8ce39e3f8d2d7a627841cfe5a77b12151ee28027eaa25d5654501a3e400a0fe8";
        filename = "blk00004.dat";
        url = "https://arweave.net/zJvYYIiZ_-Sda_Kgvy6LMXA9bpKGWsTqw7gVWhWL9MY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "777e86ec879101b3f2f93bb7412f1586705ead19ff2f3a1ad67b42971769b522";
        filename = "blk00005.dat";
        url = "https://arweave.net/cNuiO2pzCMFJbXYo83gfbcd6WZGd-bwoJGXHI4TTEEU";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0d09e950f32d6dd52f899e57c8e06d3d4934197bc63a341a69c66ab61eeb3e72";
        filename = "rev00009.dat";
        url = "https://arweave.net/qBf7hO8KnoYgn7zVKVgULDm-yqgdsb9wO0QmUXZ5QX8";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0083659d6aac9c95987405914f1dcb1299e5e8995708f2590f8d0cd62322c8a3";
        filename = "rev00010.dat";
        url = "https://arweave.net/DB3GFseiR3DGDKSah0AkV97RI2OAQv76loMA31S_wOc";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0fbe71d605104e7cec0eeda850e3e96219ffcf2b0068f3d66a4f554ca7fb2a68";
        filename = "rev00011.dat";
        url = "https://arweave.net/DEMRK6ZFaqVTJ6TWVeHitFNcn0o8GFE-oFPS0Fn8dJE";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "329d36b9d4b08082cc699cca3cfa2ad607e69396078acf292fb0aa14851631dc";
        filename = "rev00013.dat";
        url = "https://arweave.net/wsJsKvNqFbwLzdMCi349nmYIIv9yYW3B1LrXQ34E620";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "862794bb9b9b06e666070a94721207ddbec6bc75b053d2030a3fee36d17d341b";
        filename = "rev00014.dat";
        url = "https://arweave.net/xuSbDTemp9GXvvLRIcqn7hQVtmiH1PUcIuhpL9vLXzA";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ae5fdf4316e8e1d8d7ccab72a9128862f49955bd221f269fc7c96e057d03f074";
        filename = "rev00015.dat";
        url = "https://arweave.net/V9pWpnzqqNY3o0X9QtFra4I3ljNw-jXlSj5tL1EIiBo";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "dca88703ac54225528f7ca969e6c7b3017a399ce7c8cf4a9c89e63dd3d1e3069";
        filename = "rev00016.dat";
        url = "https://arweave.net/2vDMavfWr4KUeLjXxU4-M_foVZpZQy33v77_1i3oeT8";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "b70995ba3f8903c37ce5ad2e8b857a70f322725c254fb6b32ca888750c2df7f2";
        filename = "rev00017.dat";
        url = "https://arweave.net/OE5DqWgiZJ5l9nQl3Lx2-HvVjQAH0Ir8R3KFIv8uuYA";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "3ef4e47f13a5a0afeff6be20bd8da18871a2f08639909bc6b023f372e85147fc";
        filename = "rev00018.dat";
        url = "https://arweave.net/Y7rWRQSirDlLHN0vnl2t7r39MGqegv4d5QxcaO_iq64";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a9429f386c9a6fb850dcddef453b6e702c8a00fefee3593b66f62efadc8b59c7";
        filename = "rev00026.dat";
        url = "https://arweave.net/ely5ekKB2AuixvaYQWDN441djJfZ3deubJchLY2rwnE";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "0d116540c2fc56b89640e4a26203f15b1b30541038cd6524e69ee58433f7698c";
        filename = "blk00006.dat";
        url = "https://arweave.net/ClZAgBWrPhESVKYWUfWIrYvWA0OvaD5fX4LMvl4qHwc";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "36be5c7448576ad0da3d47dcf960c1435ad9c412b5b2f6cb0c6a330c29e9bb3e";
        filename = "blk00007.dat";
        url = "https://arweave.net/I8LOG_d5RK5lqRgmJgFy2o9jV63C4Eixv4C2UA6vV1w";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a37219e3364df2d359268738f8ab3f20689bb3e9c2d7d934674caa0870941597";
        filename = "blk00008.dat";
        url = "https://arweave.net/eXoE-UzZz6-hH8mZgSl5NpuNAEI9d9mwx5katsEwcpE";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "771d420a34ab1cc5560ef67e5a3781739ae6aeb0644c8dec2b4c9df2eefbb93e";
        filename = "rev00019.dat";
        url = "https://arweave.net/WN5i4YAKbqDgDh8IPruGS1qCQt-1UF8vsWn5nvLOpk4";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "447f438cbc01a258b705dcc04732834daf7e3d99c1f9dc528b84459a945eb506";
        filename = "rev00020.dat";
        url = "https://arweave.net/dZSyqYZkBg4sysPw-M6XgyuKDLti-swkTvn34Lj5Fz4";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c1e6c2d9085c01bb42d89f8517e782df3bfb3f7f65ae3288ce0badd73b6e83ce";
        filename = "rev00027.dat";
        url = "https://arweave.net/NfQLDDjrLcLtzZmd9D4WbeJOv1mgQzCqsF-128h1Vgg";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "48eaa8f735ab8dd6765ac8e049798bbb78ae66d032b999e1b09da4fb160f89ab";
        filename = "rev00028.dat";
        url = "https://arweave.net/8zAxzMmixH4rlsX28uzsQT3GJsriQyWdJerkPjDXfdo";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8951a0344d8727686be19ed710b98a5dd8187f451004f63b0adbe19b55d8d7f3";
        filename = "rev00029.dat";
        url = "https://arweave.net/RggXoapPHrLDcsM6xU0L0HMUK715u0FABHzzmsSKrSk";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1949eeb7e659de3f4149486be3330ab203a27afa0e53f3e747c1b025c2bcbb19";
        filename = "rev00030.dat";
        url = "https://arweave.net/rgx9uCAVeoYCcFpP0s7TJEstvkPz9X9TcUUKBwcWa-4";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "efb9974c5d1639a043a3fc1a4ad92b82399452e3a299acc6eb3c7dd5ccd15c27";
        filename = "rev00031.dat";
        url = "https://arweave.net/5ZQ2wNy3a6Mr_BMp0EkiC_A0ZpMjzNUR0_lTA7MKcCo";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8e12a02e49268f6b9a4e28294321459b22a096d1412182660ee4614920cacfe9";
        filename = "rev00032.dat";
        url = "https://arweave.net/5TtdfktFSnvqsuXXKu1KOTFF1w2WM4tMII8oMehNItI";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ec8d215ee52edb946abadc82f91a8e9757dfa1d2f5c4729ac2a0391506b91528";
        filename = "rev00033.dat";
        url = "https://arweave.net/89yMobvnt0HnHvKUWThcOA2ufzB4KklWQ68aJCD_5Y4";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "719b452f706dc5b78c219e6fe1450442c1420e1666de3b8b6428fd4d25a52ee6";
        filename = "rev00034.dat";
        url = "https://arweave.net/bQX_7q5hSOWjBFPUcz7oc7kjgU6hX-V8TDbpTFCNTsQ";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ce5cc0cc44492b64222859958ff2845423864ff8f2d8e55dd0c654b2f1dd0c99";
        filename = "blk00009.dat";
        url = "https://arweave.net/QcLT0v1KmaMQLMfc57QnzzP4rDantN9bzRWqXYjdXTM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "79a2b0ac1326411736144bfdb7e574a0dfc0cd1aa3596612d71917db4865ba3c";
        filename = "blk00010.dat";
        url = "https://arweave.net/R4qd_2TVXv8XdoKYupTAqYbf4rInDTOy1IUbJA36U2g";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1362f5906ef1c65f66aa30c49ec94aa5aa30daee84973b65e4db599ee4b39d4f";
        filename = "blk00011.dat";
        url = "https://arweave.net/Z6Yd2BODO316sUa2ApYf8smVbTKHV3cHFZVz58bJ3Nk";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7d748fb52705fdd975de6396c6c49dfc1309f098dacf1a6d5a56eb1f9ac70e79";
        filename = "rev00035.dat";
        url = "https://arweave.net/X6s9niSMeMvCTOecS1pfJM0SAwlTcWi0pY6PYq_S6AA";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9c52f551264037fa6892e8c808b629e26b0e1dd4e562b3d4958dadd99a4228fc";
        filename = "rev00036.dat";
        url = "https://arweave.net/1eW0qPWI2hpkgNqeLJc8n4FSC-SC3pv_2UE0HRXuvQQ";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "9bd58bbdaa216ce83c625e4b8d314eb2f97297aeb25624c3d5edb44060e7810e";
        filename = "rev00037.dat";
        url = "https://arweave.net/8eA7C88Lts89gXi40-DtmcpnvGi97ykHkDzstzmk-Ok";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ab5c44c2c6118cdc3e48d12b5e63027c36477c4cc9e0b51ecd9e44486373f1eb";
        filename = "rev00038.dat";
        url = "https://arweave.net/LqmFIwUpNMdP7RlOJB_n6BQouiWELENcIvs_vDRTi5k";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "540ddbd517db83970c8235d41d89bbdebad7a9956cdd854b6c2ca9dc4d1da8a1";
        filename = "rev00039.dat";
        url = "https://arweave.net/Mpym2ry_Fndo8C_A20-PlkkCX8sEhge82qSgxz2YfDI";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "6d3527fdec7c5fedf3bd173847ea5d8fe6e57bd7655d60516df90441562e9025";
        filename = "rev00040.dat";
        url = "https://arweave.net/u_Q18jDft39Nnt6sPqlkNYx7VGNx3Gnf4nfRhgxomYo";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7addb47ee53b7c67361a98b7a1fe0587674200ebba57cbce856eae66170a1961";
        filename = "rev00041.dat";
        url = "https://arweave.net/HZsLVsb5GKbI-nV8SryldMYXORVWRFIQEVA7dnDqXJM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c97c2cbf11bf252ee9343ec8b6d88b99acd150154f6f6646b518fe2ec9986abb";
        filename = "blk00012.dat";
        url = "https://arweave.net/XRBP-hkCqG--Ronv3ezBezkgKXRF9-GRCwlXnMJlL1A";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a2f150ade23beebae356a56b52d6c7138e02dbc3ebdd1c033e8be238e8a90238";
        filename = "blk00013.dat";
        url = "https://arweave.net/J_O5BE3cSjjUJJJoTuOx0-tR8WaSFYfpzF6h72JM36Y";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "61b7c3ea1835964519743d67d6c1b8efa3ccdb2554ec960963727212f1e743ee";
        filename = "blk00014.dat";
        url = "https://arweave.net/4EqwpDeJnL_hUEV-Oa86cQgqFXC76Abf7mOsdW571YI";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "bcf2ba0d665e7dec33d31d7c8571b0db08ae97fc366d31b0cb8f117b96c9dfcf";
        filename = "blk00015.dat";
        url = "https://arweave.net/II5EuGT7JthFdt4ovwMpgCUUpwt7oeveQ07hs1Sg2Yw";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f9944b59e56be5347159bb3c12038e451ab0055ea13b695946722b509dd61f59";
        filename = "blk00016.dat";
        url = "https://arweave.net/c4mV2VL4HqM45WK3kvN-nBGn6IXSqccY_qfWWtwjTDU";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "ac8da7fb83c7dd43aa76e8e6877d041da797f3fef1c26959cd34a22fa1f479a4";
        filename = "blk00017.dat";
        url = "https://arweave.net/mbaEOg5ycdokkJ1minddrYwP53KF7dfy8vr32HtUTiA";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "06d3a4deab0d292778c268e8569b44d6708a392b1a37da4c697d274c07e54ad0";
        filename = "blk00018.dat";
        url = "https://arweave.net/aV9HvEXAeYq-PymhalJdXtvuqjFAC8bzG37TcRgyWVM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1c3015453fa6041d25ead90668e9b925d2a1b1240827fb4d985e01f2a7fa866b";
        filename = "blk00019.dat";
        url = "https://arweave.net/jBEinBfY3qRx6D7E1LO8HiEUDMjNOG94FOwcK87eHH8";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "528c45c7bb67feb476eb3e8fdc49b509a266fb2c0ce21918beb88e856cbd5bd2";
        filename = "blk00020.dat";
        url = "https://arweave.net/aAhUonEbF0t1CcvDjRoSXx4qNyYQNzFdA6VauWZZJ98";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "1fda2e9e0a790f0021b8b82c7590c3dd6dbb41d4768621218a104656f7d08dd5";
        filename = "blk00021.dat";
        url = "https://arweave.net/dtV6miUUk0HOiJgVURbENtSYdtCgEC2bv9J3fYjCYUA";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "978d7b974cc5d6a9f31ed7d2c29ce89450732edb542d2ee8a5fc0e23330190ce";
        filename = "blk00022.dat";
        url = "https://arweave.net/kbJmmoTho6pQJ13EbzH9k7bZmP2iphLqbNPXLjBfh8E";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "80cb3c1052684fae2373b7219899b554ba487a2b70db52620da6f1c9eb48719c";
        filename = "blk00023.dat";
        url = "https://arweave.net/XToWpF60TgIA0z9A9IUL_l9oWU9nW5QTsGkSGY0HfjM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "56c063d948fc1ca9aa496a016f634bafa748e1986d81145968e3a7b0eb6d6177";
        filename = "blk00024.dat";
        url = "https://arweave.net/4p_0XiQl7MCl_OqQYODWgCChh7GUprlK-tJEUpwcDL8";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "fd71d5cef912eac2f03008270c83e68fcf0f895548e889652edaec10dfd11986";
        filename = "blk00025.dat";
        url = "https://arweave.net/mXt8fY37f7R9egC3L7zUn8AJUkWTI2__HhwZcIZTziw";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4bc6ead22fd8befe8e6dcd2d68996708d9babf6351f387a6859e568aed99531c";
        filename = "blk00026.dat";
        url = "https://arweave.net/njqROhR-WBMPasUfHWkkQIZe11DbpyxbdpuK-2HkJXE";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7688c7f91163d5cb5f6543ae298fe6834a4994b52c110d36de46e7407c8b7a27";
        filename = "blk00027.dat";
        url = "https://arweave.net/ese5bbPu86Ua7_58tyrY8dVIyGyrY-j9J-J01d0kxrU";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "87a60c6f7e57f385ef6cc0cff4809b926016cb1014a4e3864b5f8b5eaa9b551c";
        filename = "blk00028.dat";
        url = "https://arweave.net/33gvv22ECi5-CFfyW7GhiKpBXlQhS4KWMCMfLwQ5iNY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "4b95c5622db194f8eed0d8803803fbdf660ee90d37fe921944d54ce6bb1a02a9";
        filename = "blk00029.dat";
        url = "https://arweave.net/Cb_rjyb7ScFPqix1OqkQ3Pj2ALv8BVRdk0_3a_yRxqY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "585d61b204cc99465727b5b78669169d5fbbd30cadc4e2aa6c1205afff90250c";
        filename = "blk00030.dat";
        url = "https://arweave.net/0krGCq58lGQt0m-CZYuAOQfwhhMj8GHt_GYBzybQFkc";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e53e8dcd67a6a899695c450b5eb0433151fe791220f1a8ccf5da32fde2e2c70b";
        filename = "blk00031.dat";
        url = "https://arweave.net/3vqpKkKLBBOUdTa0I6uahGLsQNjblSPrJbhJ_3BSr50";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "74f841dcffc7040f9638d13ccc9124450434f483342afc5cdb6f54274e0771bc";
        filename = "blk00032.dat";
        url = "https://arweave.net/BXTIPe2jVl08NXcspgD50IQy7jRSkvy_ncJa9gvGaGM";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "200de25046846c1bcbd9223314b7fefc413f878ec9c7a1a22d7569140918532f";
        filename = "blk00033.dat";
        url = "https://arweave.net/B5uL-q45A6Dp96q9J6KHs9uloq0vCYZa73E4t3YBp0k";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "29c8d83078941701575ee9cc0fa7d3b12e6b5247af3a3b65fd6dfd1e6a7b3d7d";
        filename = "blk00034.dat";
        url = "https://arweave.net/VsRGHX7Jqp-Ux0k534F8biA2TWmIcC6aYhA-gzxYdao";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "7b6ed1af388fc94cc790ea8401cf2146e55d8776881e54df00fba04583bd3a18";
        filename = "blk00035.dat";
        url = "https://arweave.net/ftlfDmvi9p-hRuV31bafsuMGpHVUv2MCJ-SGTsJnMQU";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "e51e31da07b2473f00f54593a13b44ffb27dd9bb915ce3f22b99bc3b86c5c3ba";
        filename = "blk00036.dat";
        url = "https://arweave.net/YSssPvhTTSdRyuiRdLoUVMcTD2v-KezKlVY-gKGRhv4";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "8860f533c85a84a24c4ce88091fa812a5fdf56ae1f026f53e084b59ec35e9ef8";
        filename = "blk00037.dat";
        url = "https://arweave.net/461v1MCHScfVTnravU5PJ0al-EvhNJZUXV6idcTe6bo";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "dea30ee9c2e31474b2d7d057787f7fd87e8edbd807c70e55716937e632e04e46";
        filename = "blk00038.dat";
        url = "https://arweave.net/EdlmZYVdVSgnNK4_PMOO28ndMQHbryjqf6asU3LGbPY";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "f80e829c03cdece0a5ae2c566b1245a78fd454d14f48ffa40d730ed94b376f1b";
        filename = "blk00039.dat";
        url = "https://arweave.net/Kjxr3LP04fixVdfagAt0CHx2m0ouEUR4E9jOb2fkF60";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "a3fc4ea2bcf10c9209f2eee890c3c2b4f7a896b5a5ae85ebd9c7a445d534394a";
        filename = "blk00040.dat";
        url = "https://arweave.net/kaSa4OCK7nPCQFRbnVTs8PBE3yuabrZXH7lzFhsSyNI";

        if (!BlockDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        // index block files


        hash = "21642c32aa11329ceb20d144bba688924d24b73b6225cf89b1a419cd72b748b9";
        filename = "006544.ldb";
        url = "https://arweave.net/siXfbnHY_BX6fIRPRDAwJBMME9H9_jo37wWx0ePjuRM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a37bc08d1511dd077f21b1ea5a0bc1f24051789488e7ddc206f2aefe593acd62";
        filename = "007226.ldb";
        url = "https://arweave.net/4_j4N4AxCop-Ju5CRizzsCTUyK-bRH0k4ug7CSK9ywo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bea210b9a7fcfadbf1c0dd44743b846d2506647f420d3b917d308cb1c39ec430";
        filename = "CURRENT";
        url = "https://arweave.net/cqy8B5Dzi4KZS6afvB8AkDyX67Cw6JqwYpbdN85sDXY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a43d62710807c91482f3157171292212750ae23355468d288878ff9ee6637394";
        filename = "007472.ldb";
        url = "https://arweave.net/BQG4QzHFM5WXqoGJIZiATpAikkx6j086K0vnU1J6BW0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0d39afc3c780488a4b9c2d6d091a2a76c4e18578e6d452f46dd54942afc5dc60";
        filename = "007546.ldb";
        url = "https://arweave.net/Z5NkeGRsYhRENPiEZHv0L-_Yqpz29NpRmEbaPqrhHBY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7dfd31833a5388855eabf79e59c1406daa782f73ca5b5fc3cb15e6c94e8faa4d";
        filename = "007547.ldb";
        url = "https://arweave.net/gkXdeaZNJQayF0xFz4obcksVbHSW7TO7yFQo3X4LIZo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3a25c99432398e742f31cc03621d487007c0aa8aca081cb52889a1b649745d87";
        filename = "LOG.old";
        url = "https://arweave.net/IObiRFhOzrkI2egeAJWiGvoxRNVI3PCONbQ1QkuLdk4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fa425825716d80b16c56a244d1618dba00792edd2f428a2495bb15f8fbfb8a76";
        filename = "001264.ldb";
        url = "https://arweave.net/RxsvZ4tJ_KQPRfIDFG2pAaj-TblqVwNy1m44tQX91YA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8caed5ffd902f0021d65e0913fbfdb40eae4ac5464cb6321098584a1854baf2f";
        filename = "005139.ldb";
        url = "https://arweave.net/osoOZtsNcAMTOL8h-4CvbyEWEXyV2oU__WFUTl2Q2uw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a4253387a773f39cd56707eb0227d19858f02a2dd4f61918e2703409b3aa2c87";
        filename = "007603.ldb";
        url = "https://arweave.net/elrm6RCCAka4Y96ANnsRR5y7xQkpN3nyDe4pwgne9og";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7db7dab8b35577f2d947f8a68046b57dde3d8a882abaf99e594cd9835392ad2a";
        filename = "007706.ldb";
        url = "https://arweave.net/tOTDr0YXKgF1O4pCF_4U-HBzRlvw2HRBRpCvw9-Z4LE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9cf57e166c75a96547c8db63c559ef4e498e895452725bc944b7cefb12a92b67";
        filename = "001000.ldb";
        url = "https://arweave.net/-ig41gDVLS4_FAwhQye8iOWtPsVFn_iAFbX8IgwBcaA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a4ed26b7b0ba39d165bf376a82e7b870e64f535417a20aa9c8ab64baff477b01";
        filename = "001003.ldb";
        url = "https://arweave.net/pVGKNRZ_QbiO_Gcb9oqL5Gm-pk7ba9svLlt37vOFMpk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "86dcac09397b6673de9fcc813fd9f5b1f92a32947223d7fb5bf87f6edaa75eed";
        filename = "001004.ldb";
        url = "https://arweave.net/fexCQqjmgDRMm2F9PekcMjfZmvPhs0OQO9JV6PFCnMw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "23d75504c819c7cf515100edab86c52fbe20dac19be53f3024e6af131ec0fe1a";
        filename = "001007.ldb";
        url = "https://arweave.net/StnHlPi5jx-keaQQIazqXz7gTS3_ko8HQwYnqXAjXjo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b5db03c705c6e7a35044814174edfd8464741ce7075b78e5c3b5857075d3eeff";
        filename = "001010.ldb";
        url = "https://arweave.net/oSbstcKFORT9BT1QDtFtOph3kFi2JiN134hffGAB2Gw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bae5c3ba6c9dcc2d506a4e2399bfef580ba71cf63b960aa15b4153930962bf86";
        filename = "001011.ldb";
        url = "https://arweave.net/pc2lM2Fnaiqt1wJAUd-aZ1lFGcvn7kwX35hHxY1EfvU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "72756166fa6845f8331e5aa64faddff2138ac24259498b44bbcc2522bfdba8ec";
        filename = "001014.ldb";
        url = "https://arweave.net/6jTTzj-vH84Au0F-zl8vI4XDYt4R16Td6nr04CLEqSc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3c59ac3683769d237882851199cb3158f3857b571d1e65002d199356af230775";
        filename = "001017.ldb";
        url = "https://arweave.net/KpUEB0oh-qdInvJkGrUvA_QyDsCVrqvEdMJOSdeu-QI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c4492ebfc854b9e6fd30221b4f3b434b0b66938cbd8cb1a618d2d9ef48f6bc5c";
        filename = "001018.ldb";
        url = "https://arweave.net/-FWtTdnBv-OlTPWkuwU6wFVmccbT4S2_o-THN5kk7iE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e493b712106d851859380160dcfd03a48ddc035e791645b2d5fd2ef79093866e";
        filename = "001021.ldb";
        url = "https://arweave.net/qu7SXARgV63F_wkVjouj9bAg6mh4ujCkw3kz0Mij8SQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "034d7585ef4a5ad3c4e6049ffacb93d4ace7232a9e3c4f1945a0cf2c7e148636";
        filename = "001024.ldb";
        url = "https://arweave.net/pNhrAJmf2ZCYMf7d_dvegHGDLCpGEXT7KSm42Lehcms";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ae04c91085e630782586b9a7f9dc9a22521c4c6a696729e18b112886df60ffc6";
        filename = "001025.ldb";
        url = "https://arweave.net/Aom9LCPbq65JBF7iU3nOaBSCl0Pn2MHJ81EMO0vSAY8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8825266adb92ee3f1ce2fd9b17aec932044f6c792bd8a316762bd2936e8e31dd";
        filename = "001028.ldb";
        url = "https://arweave.net/D28NxZH87vCk8MbqQBlqE30T3Or-ja3EPgZ_KRuMA_Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "22be4ea0c3d1b2cf2866fffef73511c0fec7d47d5a2c0e0f5983762ef9ae2b6f";
        filename = "001031.ldb";
        url = "https://arweave.net/CKZ5uX3yIfVOkjMrz0PnjXE5-OsmS7vhYk57-3vAeoE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2e5579e511390910ebadf4d34caacbc547373ed092a0999b0738e7a8a1bd6a54";
        filename = "001032.ldb";
        url = "https://arweave.net/8x7tPijKYCoXmI7Xbyx4P8NXL_KZLdyZZK4Vr4gca0Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ebd6be19df68a0db24aee3a5f1534d1ea43ade80fca64d82715e6d723d61d14e";
        filename = "001035.ldb";
        url = "https://arweave.net/Dts3hX_OeigzmH-RzMV79_ucN48NR9vjqQ123kZpX_Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "061e5f6546507bfc04c6c297056764c1a6cb969efcae1e8847836c8cd8265fa1";
        filename = "001038.ldb";
        url = "https://arweave.net/wu9Q_EOmVZ5RDx_JrywoUDLoFMRu9kTE9kmkmB0M7Dw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "de5c527c7dbea81659489515f5e43b0c934140c135996e44391090f3a737d2ae";
        filename = "001039.ldb";
        url = "https://arweave.net/681TPpT-VElm8F6-Y7IXRSHCuR3iYIv-SJW1czL6uoQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d315e4b85aa59054898beadfe86960be4007581f6aaec48d29313e5913e3812a";
        filename = "001042.ldb";
        url = "https://arweave.net/_q_6jT3jhXxMLN3J4eYMIOlzZBHDVCNt_NxQJ3EpFPs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd8549dded16af6c30b5fedef4c4f3a1cf536bc090ca081a95f3ca1a6cfb69a7";
        filename = "001045.ldb";
        url = "https://arweave.net/vo5dcDUPymOkK4qkvOuzSd-GjTHLzPtNo5oOaSSUPD8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4539e8487e496e29f313b40eec2fa4e46873b0785b3e90e54d12d3588d7794df";
        filename = "001046.ldb";
        url = "https://arweave.net/c2leSptonpySGosHIDO_oznCSJuoY_pMPzvU9lXD4G8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5d26f0f5dd42033dae2bea327c76d4da1742f5f5cf6e1785d64794efb934da8c";
        filename = "007407.ldb";
        url = "https://arweave.net/s6KcfXEPvkyaiX4iMu6ntZg-_rQ93Sl5r8R9mLCjOZo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "faacfc67202d89cb32235398eff75e590615bcc256955528778bde8059996432";
        filename = "007611.ldb";
        url = "https://arweave.net/jxwBQf6WYFAaL6tzG4mta8tjfAepLMSl3jL5hmrdgqY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "544438476a9469b21de553a123f7cbe72dba4d9fe426548f483e2c1475e9b073";
        filename = "001049.ldb";
        url = "https://arweave.net/o_zvDViF7K2OpxJy5EK_p4d3Jf2-ahnwqdDyabGRiVE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dda76a97b9a8b4d0315c6954d58ac0548ce2d732717e8800a2d765110a6a3737";
        filename = "001052.ldb";
        url = "https://arweave.net/zzxurm5a-ZxC11gU8XFLZCOdcJpS-8AfT0MK3ZuhBgo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "883110f4971c5d47a17509105cd55501a503d14009e3764ca66b5d4a82adf3af";
        filename = "001053.ldb";
        url = "https://arweave.net/DBPPw8VhFS5iPFCNeEC7yB8GOtQ0zB49lxpfPiRM9WE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c0c6effdbd3e9faf213604b0cdd61545471c79405b408a7235ae01a05abf4125";
        filename = "001056.ldb";
        url = "https://arweave.net/MuDKsgxouUlHsD9lfBwP37alTtFKBLaBgSprrhzAm8Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b89bff5ed5a1522c30837b3b5e250115b1ba1a877f1319bd8e8bcaeef7ea94de";
        filename = "001057.ldb";
        url = "https://arweave.net/4PooROtVW-wizLSse7aHUBH05Xz_5Qr_JZGIhGiQrv4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "054e0d6159c1587cabe1446fcec76b431b17e464dde9d407105023f0dafb0d59";
        filename = "001059.ldb";
        url = "https://arweave.net/j8s7uCyaeIZU-vzzZl5rHnxVKP31-s74TAa8yB8wRHw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fe0ba17ce292e801bb06d1c67cb9b851b12e9666813748611e5694d4a487fe77";
        filename = "001062.ldb";
        url = "https://arweave.net/k7wM0maJdou_8C2sssSRNUEMRvcrMU7zKJPYTc5dc3U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d4d24d0efbd3a17eb1fca560ea5a6b58c974b9a6c353cfd60157936f759c1f18";
        filename = "001063.ldb";
        url = "https://arweave.net/x6p4hOqfNS2tl62XRGGgkwr-a8csWy7VFcoFkcYrx5g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b71c3474f9b5fad43e9133ba4743d324f27f8e2b9c1a1ca90e45be61229f0d7b";
        filename = "001065.ldb";
        url = "https://arweave.net/SSS7F-9t1soFW6PXMkD9lxlvRz9HCF9CSIrnOS5DkS0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f07c1c4d97c909e55b55049dee29512643a92af9f5638ff0a9d5ffefba770c80";
        filename = "001068.ldb";
        url = "https://arweave.net/OHGDesHQf195Bd5WxynwO-gBrH56jNd8JJSXdEPOKQk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eca24aea49554d042211a1ea0e8e00ca6be376e7be8bb1683cabe7e1613ad699";
        filename = "001069.ldb";
        url = "https://arweave.net/7X2lwX2Bl6AMf76T3ZtWji5fwWgkPHtyH4NQY9OQGlU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d9e366d0cb6fced991bd56cdcbfaa3b8a64dc8b89350b6d277e9240c0aa8eafa";
        filename = "001071.ldb";
        url = "https://arweave.net/vR-O9F1Pd-pbaZaXRW5bsLXSgQjXJrW21dQ_v5eU7Do";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "804b69cac71da5f8b8523cf42baa06a9acff7320e6647455e696b2fb70dcddba";
        filename = "001074.ldb";
        url = "https://arweave.net/DXinXXy89bgDmNC5pC5EF-f_GbVpjBRI76-I8IqvuAk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7b876f0b3eaa02ac79c77da960d6a4952ab234346d6a9dc9293930ae98f8428b";
        filename = "001075.ldb";
        url = "https://arweave.net/3kJtbBZtWPBHBwfHNDhHbB9F34Wkk1KVb6v5eOa8OE0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9c51f53419bba71a2a0548132c52479f32662a253230f82eae1c1c390abe4d18";
        filename = "001077.ldb";
        url = "https://arweave.net/ZP3JZs1BEA3BjAoZ6e7nSfQlT2FMhJsthehkZWI7Mug";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "56adfb908c783d4c0e466606cfd9a514574ab4dc13879be20a5adb38a1e5cb35";
        filename = "001080.ldb";
        url = "https://arweave.net/lcKBP11IKSEcMv4SJMUTD51lxkbhV9H5QflfXfvPKXg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e47a896b5952f9361fe173348f97229b733e6d40361c9d11cab6bc2f2e540fa7";
        filename = "001081.ldb";
        url = "https://arweave.net/ZGhjAdnM5dZr9wQCCsQGL5pRCmuz3z9-6_COD37vZCQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dfa3f12533aaa8af0d7ccb36d2d240d06bdc48acd2ee28c16d3d943f305fc144";
        filename = "001084.ldb";
        url = "https://arweave.net/RdMnzfisTxur4ASKckLxT3iDMifPHLO7354iqQ_QY28";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2982ef588a3150ff6e20b127ea2dcd86c88e3f6aeb311b691b01fc0828538320";
        filename = "001087.ldb";
        url = "https://arweave.net/WVYH2Bp6sM_J-p0RqMzKZah5PlE8oAoEitkCBtayBAM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6cdf939473476198c4ac5d5e4d3c2f047a050f59298b7d48ba86229573ddcb92";
        filename = "001088.ldb";
        url = "https://arweave.net/eFHSw27kxdVrPEDIuNFzGiQz-rCZ_ePEAdIue7qzTGw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d488699b0550202d454db59c5d28eb39e906137c627d1166cc87902235626e18";
        filename = "001091.ldb";
        url = "https://arweave.net/wLJQczB28X09t_IzbfXF5D1YBKTt9SU6IvavEyyPlMI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "587b567b712366e7199179a0bbf3f0757442d24a9271d3ea6d5b37f926567d80";
        filename = "001094.ldb";
        url = "https://arweave.net/9kO7i4iRL78gxDZohL9PxBkxSYv4arxxSQQxC5JuUb8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "55b2ca1bd6b60c68e256d3550e81b234749a18159906d61722a1f632540384c8";
        filename = "001095.ldb";
        url = "https://arweave.net/c315A1sdvU-9PTq7SP2lxgORYQT1cv5F_-Y34FJ9vuA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e7f247f45a3e58c4ad2c555100ef14be4e162880176ae6fc9de6319a06e0c431";
        filename = "001098.ldb";
        url = "https://arweave.net/RVCEnitJOEaPWLxdLCIBoPY0oX1y62-luXAemCaUf2s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b65f2d2fe1139f0b001ec29e60fe814af1185ca91f9eb70d4a65b2c517ab1863";
        filename = "001101.ldb";
        url = "https://arweave.net/bU53998bJm016jWiGM4LqARLCr4mwwgDSHLciAXfaes";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0e1a9c591b50150d90ed28321b617cf4581428713092d4a225a222093e81f373";
        filename = "001102.ldb";
        url = "https://arweave.net/riSdSOFoR8qU1j1QMKSXnhCovlerINNjzRty6ALkqc0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "35903bd6d84a46010e8ec7d7fd2a67f9cbb0bfd1aa996e02ad56affd7ebe0aeb";
        filename = "001105.ldb";
        url = "https://arweave.net/6kk7W1zxNVpANEOWbsdfG4pw__HPPqNSsvDshxOpzpA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "837628d61cb69704fc6cbb014239b23bd05fcfd0e6d189410b5d7ab941115fd7";
        filename = "001106.ldb";
        url = "https://arweave.net/9g4HhiGIf7OxjjxP8JMiu4l_j5eLo-y6tjgU4j59JkU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cdc8945cc4719c9583316e639385b7ad203c41c74249d2db83dbf85bf9be7c44";
        filename = "001108.ldb";
        url = "https://arweave.net/kB23INPV224b-WH-e0tVLvii4Lo6wrbp8tfpDG1XANY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b8bba17051dbb30c67dd7963c9a79a68f47914bd17cf2aebdb67ef33f53ff45f";
        filename = "001111.ldb";
        url = "https://arweave.net/oOPgRj3yZltJrkW3qY0PMeH6y1UWMmpxW9fC2OlXCfo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ed97f88099171e736d28bff0cd9c6e4f5baa5c1368aba65c19720f8993d4eb0";
        filename = "001112.ldb";
        url = "https://arweave.net/ajx6Q6PU2pONSyGNNhbgQZ-hmxWwZALVGxHX_dAVVDE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "98ff38aa45aed88f79240c23c7cc6d63b9f1f8e4b09f55d89ed84e7f0be5b231";
        filename = "001114.ldb";
        url = "https://arweave.net/X4HzyPt1sSxBkFD2rJ0o9Xcf43U9leX1Ax32oQaHiYM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a06746568cf09fac1bcf71cf300b50c7dd7d122689b10191f54ff52f12cbb09d";
        filename = "001117.ldb";
        url = "https://arweave.net/jIyaonaKb87lkqYj_KgYpa7HXIazPqWJuHOhKEsJ5Ig";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "83cf9812afd2023810afa1553ea0af63b63cbdc8f627fe33645af51041ecf860";
        filename = "001118.ldb";
        url = "https://arweave.net/sexGOSwheBH8_9dKiTbIVRejO3AQgET_uShBnT9OsF4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "058dba5df6931d56da6cfd26bacbedd137fe4ba61195e143f0a9043d65d1bf61";
        filename = "001120.ldb";
        url = "https://arweave.net/AJSJwRMEyMufCOp6btSf3IuZJEX3ttx-3CvymOEYSxY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0537465def4e13110339d00498c20d76a57bd0d37edd35155413e2aa1a7effcf";
        filename = "001123.ldb";
        url = "https://arweave.net/yY9dnvlxexdoxYZ34t1nTxgAe8h5-EgnohPN9FL_m00";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d8a2b30e94db03d656e451f515f66da42f3dd08298155a8dd02a69958c5b4844";
        filename = "001124.ldb";
        url = "https://arweave.net/rfS-f4upkWC8SqaszV85ECYqZTdPa177tXC4znKvfDM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fbd932e259a2fc6953004e0a744e48be8e0d9618916d433caf18b3e410ccdaad";
        filename = "001126.ldb";
        url = "https://arweave.net/TMDUJ3S5wGznl1w9zLzRl8pUR_ixgXa2XGEkCxxULyY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "76cbbce4d3db4f8ae863aaf1808c3f4a856fbcbf7c2cc3c2f05afc4d0bbbbe91";
        filename = "001129.ldb";
        url = "https://arweave.net/bCuw0hkXf0kAaKzgXeY0g82a4cpUKLIHT42ByckoWn8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5f09aceaf7289d3dcfa95c904fd74e75af9477033c6196931beb74ef576f1312";
        filename = "001130.ldb";
        url = "https://arweave.net/Ftc4iVJSE8mKJS1EmdB76mlUje7vh-OHFRnHbRswIk4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0509964897169cb0d0aa9562b61fad140a2247de3502a9b7561785dca1ee0944";
        filename = "001132.ldb";
        url = "https://arweave.net/NcdS8sVSxuwqbT9Q9eORRB7qkWqNg1ZRmTYjPYpHBr0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e1c565d76f00bbe4f065dd29774828348f43abd444fc34fb69451024dbb5ebe2";
        filename = "001135.ldb";
        url = "https://arweave.net/HuCcNUUUSyei3oqM0fmqmU1WAICoZkbzdvVex34WLNc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "05e7ed9c36b109e45a5d48f7d22d208279acf2fb6aa231edb851a20695eb0149";
        filename = "001136.ldb";
        url = "https://arweave.net/N2WaG2ATOY4NUrqqEAc9vNznQBZ2pKM2j3wNnpOeKgU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "46e22cfb50c61202334ca019b5aa97f5209be6f7f9f2851de70be591d67d2d07";
        filename = "001138.ldb";
        url = "https://arweave.net/CjRVcJt1emtUVC2Tgmc7qjG1Nk67Cfvp8k-bCm2LoYQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "19a71321c8f006dd5c8d06dc41f266666c73e363fe86351513fdbf03ad59bd82";
        filename = "001139.ldb";
        url = "https://arweave.net/vCuFKJboyHlg-MzupwnkVRva8CLPfxUQPI52NR2si9Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "efbbc0bc5f6a9b3aaf47c5113a86751a47fea4d9abf9494b5cc995240eadfda3";
        filename = "001141.ldb";
        url = "https://arweave.net/NfO158Mmgh2QnhG2a7frq6ZFv8gIpqLolAie9AoLCZg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "46264c584c95eba2ef99ab10728ebfec78ba5a105c71c441752b8b9def91d533";
        filename = "001143.ldb";
        url = "https://arweave.net/E1XRHIT5R5uFAegU1BJbWvDkPamshHoj8WAYOP5ZLiU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ceed3a5d420a4d4ed2cc23bfe59448100328561eab74dda113cba2a3a3699c25";
        filename = "001144.ldb";
        url = "https://arweave.net/-9_SbV2QTMsABWuJMEemQcxXlnclCnPlw2KHDUHc3W0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4b8d98492b9841206c0580e870542db2df5c3d106dc6bf9870eae961c4f8801d";
        filename = "001146.ldb";
        url = "https://arweave.net/PXjniqT8ym05_elIP7ql4H5OecghwYhWNQCWVrkyri0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1d6204af8e56311a366890398aa30cd2745374e44357a3f14890b23809ccecc8";
        filename = "001148.ldb";
        url = "https://arweave.net/44MHY_r2y4GqUzo10_9YdRkAJ9S01yRK5r7Md5SqtOQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3d6837cf544d15398ff0b994d4ac35cd583232160f0836e30c5599eb766a4075";
        filename = "001149.ldb";
        url = "https://arweave.net/qv8JKzrhjcfdocxDOChEMHDwy-3_20I3ygWLIAMSdNg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7462bc233d58025ec218957a00749f1cbcc5a51fbe833e21d9cf7faba9847646";
        filename = "001151.ldb";
        url = "https://arweave.net/f3hAbEGQBhjdGnzMQ6ECDm07mZNDT1dZYG901qEOvCo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f75d229bf6b90268c61f76f941e6ab4c4c98ecd9b03157092b55ebaa4c4852d8";
        filename = "001153.ldb";
        url = "https://arweave.net/EhmW2SDB_0yoP2XWqgTLm6McvUvtH2wH0W0h9FG5XdA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5c1a2d5d12c25af6a8ee5954c4cf9d0646077e2729d3c20baa810d0b005d5fd7";
        filename = "001154.ldb";
        url = "https://arweave.net/k3gO0_KV2g_w1DYkGbv3CFVXFPSL-lsv6LnBDmht0Ng";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "373da01b6fac999550631e21a4d0a0bf1383061818c7d45e52ab46617447006b";
        filename = "001156.ldb";
        url = "https://arweave.net/_eIUccEgvhIkd4LYNlbICoiTN_sepDskixvPm-sAHGU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "21f25212c11c18d6df1d2fa18060358a1836448732037baa5629fe2f022e27c2";
        filename = "001158.ldb";
        url = "https://arweave.net/ZiW6InqBbJOPhCqokN8zAshxFm8eURl006-yqo_j1zo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "831909c457fe3087b313a5a8d9a883368bb23b0d08df02ff47cc9580db197d0f";
        filename = "001159.ldb";
        url = "https://arweave.net/v2nOtCBLxjJHeUa_dVlYfCT9sKYqngTR9PMmBnUlWXg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1cd6eddabc2ca241e8338f52b444216bf436e28263c08c0595fd796110bc52ab";
        filename = "007477.ldb";
        url = "https://arweave.net/-NqSwH4LNIyyooGWuf0OrIi1WN4oesD6pCOiEw6AuwQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5fa2a11139c2896949d2d5f64221e5e044debbb5702925b6c010670552086326";
        filename = "007675.ldb";
        url = "https://arweave.net/6ICa3liHbX3UD6aE7F7H5PpYeGYriUmdKWIyHWNTMDQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8413f11274cebe87e3125a98be6ca47c32c98d6be9ba1d408b86699bb2ade246";
        filename = "001161.ldb";
        url = "https://arweave.net/sxG0zIVa5qhM3pSrlytiCyy7_zMX002Syk5N-XEICCE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e48024ceb2f6395fbf6ba6aa5e61a1424a908882453c2965a46bd571446c96af";
        filename = "001164.ldb";
        url = "https://arweave.net/npatQZ2E6Jtn-ghQYyhIaaBQAz32TI13GqTP51pJD2c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "45dda83bd69c712b44d04ee1a5511bfe789962354972cb85c3e5b07f71ae9ea6";
        filename = "001165.ldb";
        url = "https://arweave.net/yTnf6dgKHFhxWMZWBcbPkbiHnnFQWrnJ_dDSr6x93nw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "80850356e32fddc79bae6afd109d0f8664c86ab3f58f6519e877e0b652a42bcc";
        filename = "001167.ldb";
        url = "https://arweave.net/lcJWcCzhnNehC_qFfX98wQsCiNsH4qJjft-iBNUVatI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5786f866637f3d28387f5a2e7d64278ee7db6010fd99251d7360983cbebd78af";
        filename = "001170.ldb";
        url = "https://arweave.net/askmxvVlbWNfgy_3VYX0y0ljZ67WkpvMB-tf68v5H4U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9d74b85196979a7550e5b73c84c4876c70807142353f0e20cb7a7d54bac0d36a";
        filename = "001171.ldb";
        url = "https://arweave.net/09ZJJJMmFSlP1ss7M3r5jQTYDOMm4bTPMIZAz2-uYXc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0087e8f7f1b81bd91d3961f7e3020415b87fbaaa01cb72354d29ac4b68dc1bc0";
        filename = "001173.ldb";
        url = "https://arweave.net/jgirP6Uk3f_fRxjmd1JzBgXa_OMYfssyIx5-jFNwc3c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "81e2dc4a17d6219fb56df7ca8a6c6d67a457c02644b6bd53100dd249eb184744";
        filename = "001176.ldb";
        url = "https://arweave.net/zi7ghKY08S3n5ysocAgNlYDVdwS79hslu9edSEk7e_0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "35c24ad97c186b997dae68859aa256a52b040482d888bcb33ab491d9d31d55e8";
        filename = "001177.ldb";
        url = "https://arweave.net/f1_7aMeYJTVPJGzfqsosB0ZDRpw94GyQx1RvoK8qJgM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d4310d69c3109dbc0991b5227161574e9b6eea1e54660ea6074235391c7a52c8";
        filename = "001179.ldb";
        url = "https://arweave.net/kXBzZn0JFUfc849GyGDMfs_YzwZAof52F97XA3ux5EM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88dfccb13c42eb218937db80f9fec0ccde4c0cf387554875ff30e981d5d3aa45";
        filename = "001182.ldb";
        url = "https://arweave.net/xGiQibnCAPysIYF_em59b-Ym6KlT3Kz9m6ChM2uOnQs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "857529ef5e0bac956ca15cfba3fe5523a20bc5d6a22c4e2e8fa4ca404cc5ee1e";
        filename = "001183.ldb";
        url = "https://arweave.net/uM7n9C8YYAWRyIjCuiChSmO_PWZnryx1OyTVRsOtBlw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "95456e4ee07d1b46b3a08e3d81b2fb71366a48a2685ca2f80029e344f559ab27";
        filename = "001185.ldb";
        url = "https://arweave.net/U_wUIZ2MF4JApmdwSNHEhTJR53r-qjkJzKHFJVbQZqo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "515c57f170e240088d9bf16016fe7179e59d506d703a805917346df5f53aa84f";
        filename = "001188.ldb";
        url = "https://arweave.net/k4cip7l9MKkf3PkJLMzPtYYLYVkBGweX0wBamiZFTcY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "16c4c1bcd4e3dd2faab93cfe8641de2242fc3c27828ea8c67f275e66fa82bbe1";
        filename = "001189.ldb";
        url = "https://arweave.net/LGJjZZZdl08t2FKYaOBIfc62gvStjh_FbNqqHC_vo5c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd5d8b87c12cba7ce83338949cba9f81db0e15423d5eba4a08af5fac7db39957";
        filename = "001191.ldb";
        url = "https://arweave.net/utFuoxsp3ChK4VOdypHKFobFlgYgeOaLOArVmINBQJc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e5e5f91107cb6a06cdee10421d601c3dee0fd728b97f5ce821794f5423d338cf";
        filename = "001192.ldb";
        url = "https://arweave.net/qL46wrBzcbKNkKReF0-jdA6UhbECjR8XM49xWOWbZTc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6eb3310b9aa4f4e1420910d2cd06fe7834f1cb7ffb5ccaca93b519d6204836d7";
        filename = "001194.ldb";
        url = "https://arweave.net/UM3Qfw98H_plQX097auiMnX68j8VqQuBqhEj1uC4fNE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5899503d61f7fb323fe311a0713239b9bac2bb22ad7ba0718ffe8e4c7cf91736";
        filename = "001196.ldb";
        url = "https://arweave.net/ZhTUZpMWdgL6yCjGaKNwxYu6o6dr7gSWzeD3iELuxLc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cd2e823520c7f8d6972204c35b8fe601a979689e37954d1dbb4d32bd3a0c590d";
        filename = "001197.ldb";
        url = "https://arweave.net/XYJH9C5LT2oCR3hTf0kM_j5rbtseRnKR1sSKu6MyADA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cd73b8d9a73ff68f9f231e44f455fb6d5ec7b2ac9d6fc0b3ed86b500012a38a4";
        filename = "001199.ldb";
        url = "https://arweave.net/_gfxuBseHex9ZpPyu3HbptGX7toP455D_3iW0r1s0EU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7b15e81a9ccefd67c567518ee5a059c09d98984101b739f344335eeff0642b09";
        filename = "001201.ldb";
        url = "https://arweave.net/WcYLW8px7Du0ijkF1l0lKPJrT5h4udqv40pa0zQZaNc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c31d2f290a6a80bdfda62f250590bf94eb23cc7ecaa62f56b5cf477787ab0d4b";
        filename = "001202.ldb";
        url = "https://arweave.net/ccowORt_GvzEcdEUgN4GkXpIxqWaq67LjsoFJm2OMTI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7740883d2b16dad37ab6d5f2a9456f9192550de83f13432d9dc26457f0290ec2";
        filename = "001204.ldb";
        url = "https://arweave.net/7W0ArPrjHdy2WBTdWUohZ5IgatbxxlymN_NXrIVeg40";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cde3b264d15bac39e092ce3d35dab1ed44a1e60f185074a8bc864aaf3481974f";
        filename = "001206.ldb";
        url = "https://arweave.net/uDqk0Z-iakXAcd96zLqi10HlhXQFaownFhF1aA-FK1E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f1484f07de4681fae7d2af3c6c07ff1e4b31e8d4297c97566f55bbd0a2bf89d7";
        filename = "001207.ldb";
        url = "https://arweave.net/ruUURLSPsyVty3Lv93aG2QVyp4RLgOTbW370V0i83VY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "adf02e63552efdd1667a0baa740c6a8839693c4755f2d542ae576916d2a20680";
        filename = "001209.ldb";
        url = "https://arweave.net/cGn1wRfL64T_qoV9kXk_Us32CO81KBzqjuGoe1X8osc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "10a4f8760dddd1ae1c12fa2927c7d44e298719433ecc1e20abcaeb6d83691058";
        filename = "001211.ldb";
        url = "https://arweave.net/HvAdSL6ZokrUetkZS_FIokEUkauPK80u-qS-GPsUIms";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "40408a489f38f1be600df3d78b76ac8fa753767de18c20d28eb41d07172c308e";
        filename = "001212.ldb";
        url = "https://arweave.net/YziUMiuD4YemoMBebs7uNpPyejNj3qxvVPVb4BUdot4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "47b24a84236c77e4821b2fc77801d22a7c85513546e36c3dfdcf4372da468fd0";
        filename = "001214.ldb";
        url = "https://arweave.net/2-X7b60bmdPilko31-Q-wGv77_yU8YSZt_hPJrG-7g0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aa041c0732277cc6d655dc66ebef991596c0ecd0469b77d4c6ecaac6c2ebd369";
        filename = "001216.ldb";
        url = "https://arweave.net/aVQH_XC03EZIvo7qGCTD1e4oemWxi82yv4VQOM3zEdE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a5fb8342a9009468a2f2b20aef02bbbf3ebfc04aadc1442e655315f7cdca4833";
        filename = "001217.ldb";
        url = "https://arweave.net/qkB12HjlTcgPBY323PLeVq7dZbXWi9ODvzyDcF9i6w4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e3013752f59d9cc6eb9e1cdad67345de62bbef87bf8140bf7ad9b9e09dd8b586";
        filename = "001219.ldb";
        url = "https://arweave.net/u55J9sihnUonmV4ukQ_Bnjhwx0-fJjbmQtWpZHJZSAA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "849ac0b8952e033c0ecf8700afd1e71a65fff3c6566dc4151fec064485c5422c";
        filename = "001221.ldb";
        url = "https://arweave.net/TRUFVGCdLf3l1D0TZgAqHvtrPVTjGr12VJ-w0oXzSN8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9bad548869460a2e8ac0672708be296d9106b6936be504baa6f1e7edc3163c10";
        filename = "001222.ldb";
        url = "https://arweave.net/4VDsBCwI7ERA9C_pNMSMkZG4MMO6n5wuZPTji96OWLk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "683e1b43e2edf6232a119ce7b795b9f167b885ee5011e667360061d5b8a30162";
        filename = "001224.ldb";
        url = "https://arweave.net/mmcRniOOjwimLU7gNXCNPtrahMbg0EiSB8E0_6aYkbU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a8785ffb1fe5294f63aa26c16e6eb2b5016842500a80c8c91a03888e2db62eaa";
        filename = "001227.ldb";
        url = "https://arweave.net/Zf_9UsAcUvLe3BdIZD4rLluvhsp-UKzZm0yQuV2FUus";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eb8fffb50bd4fa9b1e814bb362f6471e454d4af6ae8a19e72da54012c72072cf";
        filename = "001228.ldb";
        url = "https://arweave.net/3NJ37eCaQIxkCKRNFwpSTrxGo0PpjLSFWb5FgVhr-q8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e09bd141247ba5eeb07efb9368d539cf57a5dede5fdbe9913c66751d7bd98b67";
        filename = "001231.ldb";
        url = "https://arweave.net/4jNMFFZB5ksCqSffsfda1e5JdlB-4E2qg0YFJzEEZsI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d09620e7e555b2a92d1f2904d47e2552f872288c11425d7e4bbc9e5d00ebec48";
        filename = "001234.ldb";
        url = "https://arweave.net/pP60vnbAjI26MtugLihDsfogYkjj8geL37EjDsLZkAQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e32977778b8a944c8dc894ffdec7994788f2dd928865b3d0b3068b83c8675732";
        filename = "001235.ldb";
        url = "https://arweave.net/CKV-d1cFpFE0B9UyG5wBb-vzkVYKaDXovJ7kSgUPoP4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "492f1bcc591b16ac30bdec59f24cc9903f080abaed2f2d3ad0b492c2511c7526";
        filename = "001238.ldb";
        url = "https://arweave.net/fPdjK1R0CMSskR3oObIP5eA_SNy27sDljKHpjQ1bFHI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3293966edfc22aa20d3a9139126ca533d4443a5e4b772809e9a599412e0a2103";
        filename = "001239.ldb";
        url = "https://arweave.net/2NlrCrJOZHdhxad81rSWT0xU8FuMpMh1mPdKES3dNAg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3d7ec05611d74fbde33193ff5b36f9433f0e2f96afa67c0fe4e03dc8c6e2614f";
        filename = "001241.ldb";
        url = "https://arweave.net/6MIoejqWVT_NGUV5_GqJbR90BIPU57DQlMirgeLPG6I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d9dd8a554b06f3660ccb205e70519cd7ab8e9440dc5d7bd7419a5bb25af83c9";
        filename = "001243.ldb";
        url = "https://arweave.net/WZ0hNqQFQhDjYu9YYx0yuqd9FKWABdpeDJxhTZWQy78";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2ccc19d3dd85cf490d8b21980ee47bd765544bd14c04dbef2911201387b2f4f6";
        filename = "001244.ldb";
        url = "https://arweave.net/mrR16XsxQ_RuBeXxCBs6PSVONgEE89sr9qonPqsy_J0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b2cbce46584ae16ef451a7a483d85988938bf34b824053ff0d75de3d5a38f82b";
        filename = "001246.ldb";
        url = "https://arweave.net/2x0eWj-UwIkcAy6fz8yb4XTfrIj5CUrfUGTAOZMe7z8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2724eba3ec9a732a1f3740c2161c8c952f69915c596ed0b070e84dc35dbe1208";
        filename = "001248.ldb";
        url = "https://arweave.net/ZdznBcmPqMfS_c0DbRBSvgv-p5j9m5U0OY8qv3GuqFo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fac2843cf6484ba9561228146d93d0651caa46eece79f6f70bad261a1477cbd8";
        filename = "001249.ldb";
        url = "https://arweave.net/V5fCLhdU-XG2zFHqNrbt1JdAC0W87Cw8kNoamPkn1D4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "335c3da9d61e5378fb488e49add040c0d41492317c439c17f69ef53fc3dbeea7";
        filename = "001251.ldb";
        url = "https://arweave.net/qAm_eAablxih1TkK2jLdfzWANvChiaEQQyASHqQBCfE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "92c4d60298b5454765fc25add3c10cd6acffcdcdf7bf9c3b03fbe962a2b4d086";
        filename = "001253.ldb";
        url = "https://arweave.net/7hTxBlVvB0Q8vdWcrX2e7FrjiS3IOnPu8bzEi6XpKBc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0294371b63d3728f8198eb38bb99f6964102e8140df0994abb2214d5e69184d4";
        filename = "001254.ldb";
        url = "https://arweave.net/gi9vf8t3fC3ysn5HTV8Q45XGQSIZf-4hnmxRitmVyK4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fdf776336f78f99d3029d654bf3ba6cad6d8c84148ad408d762ed808b054c673";
        filename = "001256.ldb";
        url = "https://arweave.net/o8UKrqnSSPYltVKDlbV7K_oYGI61pveH0hIaCalF39U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "33418af4bfa38fdabf656e20e4ddc19a2339f3177c11379a767df3d15d293183";
        filename = "001258.ldb";
        url = "https://arweave.net/KqPcjHIRlpO0zzoBQR4htbhsEp9Aqu-VFm6r8y3rm9M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "98b208a0b6ff3904043d4506b3cdb930b9aa26a54f8c16eab64d4b4fcb8d9c26";
        filename = "001259.ldb";
        url = "https://arweave.net/eT2zEcNgAHJluefOAEjx_xj4m6oOth6QekVxISz8yeo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8528f9555c059823e6b82376678617bf18fcc5d0441983549d7e75e99bb53b63";
        filename = "001261.ldb";
        url = "https://arweave.net/MiGI6rX-dHTK3aFA5avdbO-7qDk8Mf6YfWqd8TMo2uw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9b81c27499a065d37a6fc3ebcff83d59ba76a946bb9b1cc3c44c63ad9039afae";
        filename = "001262.ldb";
        url = "https://arweave.net/Sh7k46eRjpV91ZXBKsIDad9Uewz6p6ktK0j0C0Ol8Wg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "487717599fdddef48d8c34db039379f407a04217aaa78062fc569ace2138af7b";
        filename = "007608.ldb";
        url = "https://arweave.net/bZKbqy9iE-pqojbDEr8nq5yJbbAaFeZc7s92Hp0Akx8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c77da2a9871356f4a66c99043505728efab48f69a8b4a8876697b18535a00669";
        filename = "001263.ldb";
        url = "https://arweave.net/hN6RSPL8KB6CPFbxXO0kpe0zq0ydXKrYFbzKczBHFgc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "23578ba474bf28f2426551d5dabb4d58a7bf60a946ff3457e252499989f1785e";
        filename = "001265.ldb";
        url = "https://arweave.net/_f5Z1qGNNewvoJvPTRnltwWJnAHeVhbbwktyooc_LEE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "40f302d27b3338bd29ef23fa3f6526553701314fecaa8b297a0ebf4c94ed73ad";
        filename = "001268.ldb";
        url = "https://arweave.net/q5TMJbgAujDGoFT6OpleE9EyYjIy46YsNwjJ3fSv2lU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a522cbad1c5d8ba53f4f5f3522fc4b15a76b1306c20b5eb7e668e4ceeb1f4591";
        filename = "001269.ldb";
        url = "https://arweave.net/MZelJXmU82mi5dzQ11TMkWj21gRILhUYE6PGjeQ6I2U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "74751e0086518794dcb706dba420dc1c98f92e7fa584cbd299c2605664eecfaf";
        filename = "001272.ldb";
        url = "https://arweave.net/MY0K7DEgCZH5l3vjo8Zmc0FTkykbLtvce7NEwnENTy8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b2452bfd057d670f8a6b6c9d558b847b87caa137648027df6e7b1eec7cd41e9";
        filename = "001275.ldb";
        url = "https://arweave.net/NbMG11fcgv4AipX6p0H64GqHhPGtRrmSKoamLhErIIg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "27dab9b8af756d3da79ad6dcaedafd5b3dce77e8ac7e573a3be90aa80016fd58";
        filename = "001276.ldb";
        url = "https://arweave.net/N6WNFerlJ4R0mD96zv1YtaqL7Tqbg_5_OTbPsUaTG08";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5af16dc756b090f6085f153b89d15bee023150b0d82b7adae923090ddb275d6a";
        filename = "001279.ldb";
        url = "https://arweave.net/USnYLEUu2gkIkMpjetxq6KgrCW9aunXJPHArKKyDqBk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "04d567570bf571a7a9f699bc7683fda01af5bd3ecc3ee53ce3409c557b486f47";
        filename = "001282.ldb";
        url = "https://arweave.net/SklAzAS5p0kD7Tp3xKC0rC5UenQNyODetoDayGkjsDQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a6223b35403795a964ecc2c1018338028dcfbf6ec9129d506807cf80f9ed5c2a";
        filename = "001283.ldb";
        url = "https://arweave.net/3t7dgd0BWyBYUlwtNvZiu2lZ_KmloOl7weyNNyytmhU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ce41fe3a26b5c91858dd39697f4b5b4b59e7f04b0aad89f082007e9a1cd073a7";
        filename = "001286.ldb";
        url = "https://arweave.net/m27xRkhsCrNOcGDTmel1JDVAArpacNAMTuH-w_SNsL0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "75f2675b55cf32c6beaf34b71d576148cb711b91f518f274fa7311079f4c08d3";
        filename = "001289.ldb";
        url = "https://arweave.net/qySoYaYrvKUkptYur_PLfaCIGX8VS_orsnWqeBa5r1o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bf6ac2ae10e4db01084866646cbc1d24202360cc5d9010aadf571c082b541f90";
        filename = "001290.ldb";
        url = "https://arweave.net/yucV6FcsxZsiRr55ROm3LNN4HhOOsD8JHo1TglVw3g0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ea06f1d74bb0c22f21d42243341f504f9699be596238f604dd8894b48e8319d2";
        filename = "001293.ldb";
        url = "https://arweave.net/bjCS6tFk_kgm-pdvHi10u80NKmW6b0dX-PUUgOZE7Wk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "93b5c2c3af5c0695e09aacdf61b5c3a36514126a18bf8974a6cf42561b3d3666";
        filename = "001296.ldb";
        url = "https://arweave.net/n79uoIEAgPtzipLLlhB2d5KgdVmZR4iY_UaMOe7LkaU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ed3cc34760e7151535d09acb0199c1c83528d716d5e0775abf38ada9aa081669";
        filename = "001297.ldb";
        url = "https://arweave.net/-NkU4VpYHOjryNGb6l7egzxZiU3BkoKXnVnSnWdKO9o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "439663b11c3040523aad79458123632b0a5ecc2d99b91d6001ae19f7491d7126";
        filename = "001300.ldb";
        url = "https://arweave.net/K_nKTHNBGt8hUszEubu_EFaauJJzCZDWLjANg1Wasjo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4fe63840cee9e310735ba926d8f1ff33702fe098b8b0dd0b005f0ee135275e15";
        filename = "001303.ldb";
        url = "https://arweave.net/xmW8buao2DEQkDaup8RZDXfHhu8KzX4dx3X2JO_HJTI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5ab22b7206cb66ff8423df0ca207b049e190f1537eba71b35e40e853f0ec960b";
        filename = "001304.ldb";
        url = "https://arweave.net/4LQS78yTnRQvAE6g9LkCtIbbhbPDU6o3WB_ij1dR1gc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dbd2c97f99160351f6636a7fc9ee12c32d4772d98edc055c3dd1e42020d56a8a";
        filename = "001307.ldb";
        url = "https://arweave.net/KLPSjAy7NAisNG_iPuXpktjTMjj2R0PdOHEg-t0U0Fs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "719d329534b572b66273027c773662883dbee318549d6fdb454448307cccd6ee";
        filename = "001310.ldb";
        url = "https://arweave.net/394RGYqQm0uKzZ5-USazinurExntYIdSWSE7U89e-ug";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "089590b2fcf5f63f1841a566e64a9cc5cf8696d25765067e1737361537e70fc3";
        filename = "001311.ldb";
        url = "https://arweave.net/gelb3bPHCRuJLcEmtlGOVKysIB-Uel02mvJuDzElQs8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d4b05a7e1611e1adbdf2cc8035af152e7abaec5b310c70b58aea1d5417596ea5";
        filename = "001314.ldb";
        url = "https://arweave.net/_0W1FKm9WIXQcDtSrfKhB0bpW22oZcGikTRr8PGWxFk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b500d48d97f67e8df07a6a1b37a7fb4af667aa0da8ac852d479ed77272d2b389";
        filename = "001315.ldb";
        url = "https://arweave.net/F-ez65Z53duUCY98CXtD8ZWudUo1s8MOBIzX3MrvpoU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "57597b66666d802784f29c2d24e21ff77a79b97db6ce70cb6062c33b6275bd14";
        filename = "001317.ldb";
        url = "https://arweave.net/dusBDnfjI-_86PQYyFfU-dR6L_3bl-Oau61To1udgH0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d687da54f3421a5c3dd9d50745b33b0085e6fe703de3c2aba1e58229a6a9e12";
        filename = "001320.ldb";
        url = "https://arweave.net/0gbzw2nSOju6w0pgy6dM4WwEPvABkNyrGUB5wpKu_ZI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "953eef1c9bc3705403c0a5f6dbf73f8aff1e523db7faad0d49c61fff142b7b59";
        filename = "001321.ldb";
        url = "https://arweave.net/g_lZO5tskH4sro0cAXtFCXAYqJFatm0UA7hoEKIwpEs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c85f5fbf8a2cdf2cd6e43db8ba31013f71cebe5fa0e9e7f9157076f101af0e77";
        filename = "001323.ldb";
        url = "https://arweave.net/WJvceeLnL-znzT6xCTry5bfL_M9s51WHDbLCQfIAQig";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4fc217e907ab3e7b5bd7338b5b7fcc4528a359fe4be1904c8de90c289085a43c";
        filename = "001326.ldb";
        url = "https://arweave.net/Twsl84dRYEt3mxgf476sW4OsAptT3opQbSE7U0Tqnp0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "018595a228d90896bc9f5b44340c3d3a201c40d0a8eefd6442bfb11100bb6e32";
        filename = "001327.ldb";
        url = "https://arweave.net/sdRm5CdknzwxoTA1EMfWAtI1-XoUeKtKiBz-WzDNzmY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4282c473efa65d4465d9e5ced47bfabbc31e5ba1b32ff636f159811f48c51204";
        filename = "001329.ldb";
        url = "https://arweave.net/dEnUPVn1G5_CWJqqq3u29psHm0QEZDZM6uqCR7ezGQo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "24cd69c224cb58f0b9cc57dab0d6f7bf20a2c04087f0fdf7d65a589b7553dd4a";
        filename = "001332.ldb";
        url = "https://arweave.net/CFxadTeBDjXUirHi45R5NDbXgesPG0Acr67USG7QDkI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f3040b1649ec1f422f70283f00a852e41d780354940d5da31a7079e80f40815f";
        filename = "001333.ldb";
        url = "https://arweave.net/gaJzvG3gjb4cc3chjdEAvHCCzrAF63q1rIn9ZxmVmbU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "46bff5571b99cfd04d83281603879f8b4f0046026bcfb80218533f91efdc16c9";
        filename = "001335.ldb";
        url = "https://arweave.net/RAcu2q1DLzFwS2aQcGl39_xTQVQWGAYXGK-OLGXhId0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "50e2c4145fdf8881ac96ab571fa292879191bfe2650bee77992e712a519232ca";
        filename = "001338.ldb";
        url = "https://arweave.net/JwHfk3zQTkD-nh9wNY9ojqs5xoIk1kUUExp2x1CGaAo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c9042469f18a6637d5d928ce2e0db5d42c9053571a0bf33da0a5ea79bbc1fe8e";
        filename = "001339.ldb";
        url = "https://arweave.net/jCHAOk3l-KTa1aSeBJdoEzX5R_6TDoBoZJkvYz3hv5Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dbe23a2f867ba02152dc8f0ea7da91dfa24d5d3280a90d3be781c1d58fbc8f9b";
        filename = "001341.ldb";
        url = "https://arweave.net/XjIe_9qRsRmBn44iM9upXJJz8prFBYQ05RFvP_EUOvc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "63d6734b7c78cf475e7b05c3766c509d517e86254e3d3d616f71c41af6c31ea6";
        filename = "001344.ldb";
        url = "https://arweave.net/0fgAc0xULy_7SjmgZpY2Tt3jfbHJiwtCGfVbWB-7jaA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "13c6db0a9bda9f8fdee7073ac8a9b25985f0a2f2d8eee951768d38e5135f7a53";
        filename = "001345.ldb";
        url = "https://arweave.net/RtLOZL2QYhCKLYpAHX3OyHRBgT6AJvs2y9BB1ypRGeM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "989d8dd0a76ea79798175eb32995e301c443ad351fa41c01da081ee9d2590c0d";
        filename = "001347.ldb";
        url = "https://arweave.net/TGLyvATFAr7pRp81bVvcwjVLictmIyAIMZT3R7iIeA4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cae3dc3b86f4417911c19f4833d390a1ab0dfc86018b0e1169dc7e304a99b8f3";
        filename = "001350.ldb";
        url = "https://arweave.net/g9pmweTmNaqvpN6pPHgTEOoSKqNmzFjZaDzY5-pZmkk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "53ef1c6e8744d8679101a70c4492b4a8546c213017082b59359e3cfee969d68c";
        filename = "001351.ldb";
        url = "https://arweave.net/nRHl_w2tHHepknOBICptMuTaClxtoW1aTCwxIlH13rk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d9fbb37d8f5ef3735ab34c16762700270082cbe580d995be3e515a9ffe9ac94a";
        filename = "001353.ldb";
        url = "https://arweave.net/9TExm5oRhdV4rapr36fkuVE9SMNu9uBERkEfJpOG8RM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e782bcae55c40b607a7e0a982a9284950f5bcbb4cf8de63c14312d328f9ed4f3";
        filename = "001354.ldb";
        url = "https://arweave.net/ffW3-IQUaSOR4BJi18I-qF8o-b9FwbK2aDxW0OZ5iBc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "381506352914dcc19f4a3fd79687c95e51d334a2357d4b0e85a0cbc94480a995";
        filename = "001356.ldb";
        url = "https://arweave.net/kGbHeZA-2s_s1fxZ8zOpO062wa5EULpAbUNTt9Ssv44";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ca359ef52a792badc5944c5acb6def4bd7e69e0f047f069e9d7addd3b350acd3";
        filename = "001358.ldb";
        url = "https://arweave.net/mZswqM77Kqeux0TzRo3z61mELH5bHNLfDrTQseRpoGQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eba6810e2ff9d2c5e54ef8fb900485d7402d554a49db81329d972eddefef5a48";
        filename = "001359.ldb";
        url = "https://arweave.net/-sSotdbPB5cYa79vRf16pT-NOjv8OFqjh8cyoMcPJo8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a969accdb8502a949d32937a69265e92f3eadb7bdd2b246fbf2a8e4e2ae562cc";
        filename = "001361.ldb";
        url = "https://arweave.net/scpvCB2k1-D46OIeJNdtU9w4cGhK5ijtn2S0i0FrLiQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "582b3e86c7a4860ecd59c43001a7924c2c48febb2991bc223814f06b9caf68f6";
        filename = "001364.ldb";
        url = "https://arweave.net/hMkqQ4arjr7TsGHpbYCSTfIONFGQa3RZCbVD9LlcVzQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7aea46086f1fa93e11b18ef3bcacf076ab3430bb26a48778a3863d9360641322";
        filename = "001365.ldb";
        url = "https://arweave.net/VHV-mRQypMOGnqwJmUrSmSZ6HNiQgPPbidoSUTwPQGI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6449d23248ba2e33038c3f1aac5277b1e51bd1a19a6013127f5de58c81b6c27b";
        filename = "001367.ldb";
        url = "https://arweave.net/_ngekrSj4R_YxVpLRnsuu8kX-uinqv2Na_rR-foDUzQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "01a9a425db4a9942b52d9e36d54dd673d8fa1658d62533abd54b653e1362e739";
        filename = "001370.ldb";
        url = "https://arweave.net/0AuvCgW9PjIUqww13pLyKOHkbtX0P9ookgxUkdJb3uM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "21f8cb7153af5a4d30957fc30d87907dc47d2ad9b507c9481d6e08f2a4665a9f";
        filename = "001371.ldb";
        url = "https://arweave.net/hvyA6UIFa1uGTpyeu6GIShJHIylAIUW6N-kI9emvkMQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2ca6af0a1990afb428f4f3b96501c0c827687539b99b7b109ae8c95947a8b16c";
        filename = "001373.ldb";
        url = "https://arweave.net/rjPafeS-h7_kDJwS2Tj7V_3e2V8arufW6gy2WOgCd20";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd451a94a14219266e54f58e1d585ce498587db614c81780b9c9d2966e3a1d6c";
        filename = "001376.ldb";
        url = "https://arweave.net/80BYFtLbHgGOUxGzm85P9g4iSLvNNhbGi2cn_Nu8YXA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd9dc3eed7e455d1d3811debc005513ed5226ff7352cc78e50ddd620253dea7b";
        filename = "001377.ldb";
        url = "https://arweave.net/iqL8XKiMQ92zKYVTgtCFw9BIyGoYjVFEdxq4Njv_nIQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "58d910d020c4ba1bcdaf6d288934f429bcd837bd658d6b0889f7415e5476ff89";
        filename = "001379.ldb";
        url = "https://arweave.net/jF2iUd6mL_sq1f9_XDOnm8GK7QyYvNBiFZuhezJExgM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0d0777d5f75ce4ce47a1384f5d97411e3f217ea4b4826bfd029446456b5cd542";
        filename = "007571.ldb";
        url = "https://arweave.net/HrSLS1nL4wPS7vxVtr2td1Qxjo3hCLSQ4-6gQukI1FQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f57d2840b60c713cfb1e8fa868cfeb85fd8e5553830cd71f22e75d67fd0c89f9";
        filename = "007717.ldb";
        url = "https://arweave.net/bWbzgfk4XjrAmTSufYp5j-RoRNnhV7mt1K3rpHAnhHo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b83938941815c0c87a0b23269deece64011dadf3db80b0ac0d8a1b3b4dee80ea";
        filename = "001382.ldb";
        url = "https://arweave.net/4c1pRccyJM_XVdzgXppz3C7PApqJm1wUONCtP0SxDD0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "165142b789a5b8f216aef987ea461157ca96f9c744273c3fc0ef0ce23a8e7942";
        filename = "001383.ldb";
        url = "https://arweave.net/kpXH9CalSAHmfO5iveBeKImDP8dhiSMk_DPF9c91Ces";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "deba57a7f64acc22c3e98aacbf0471ad6bef4f20b40ed4aca83a5b6498ac0cbc";
        filename = "001385.ldb";
        url = "https://arweave.net/QiM2DjwtTs-p3RNe2ly_PlxGuE_amzO22JllvilOoI0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2c8463c290b7e8e42b438b4f1e0f487d85ed3420917e47c5de6eb339a354bdb4";
        filename = "001388.ldb";
        url = "https://arweave.net/562kHuzJv0gJRuHvB49ikix9mVTbgCo64VNFuPg1fPc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4bcde57e30406a434cd6196dbc31bf2304ebe8860aa5ace515bb46ef3705cb24";
        filename = "001389.ldb";
        url = "https://arweave.net/wbTjMh7UkiuAnNTHIPE6MuuW92oiQWyW4a8Qy__XAOU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2c2d77408391ad5f0a428da5d7d7c028a581f213e6119d67b65ec9574e7927b2";
        filename = "001391.ldb";
        url = "https://arweave.net/W6ygJ2hB-t3cppufQujbu6svZmMra2WrfYVG6eckpcs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d6ca53ee847ca267dcb96420b140de444b3ec6234e5710184ed0f4ece1003b98";
        filename = "001394.ldb";
        url = "https://arweave.net/7csyi3296NH_fxQHkVoH62uL_0YFY7PdZYcGyx9unqY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d438ab77aeb8301caf0c85e44218098116b269e37096550391e10795f3f14fbe";
        filename = "001395.ldb";
        url = "https://arweave.net/tUxdO1N6bCLrL3hNwhn4ZHp3KPPHc4WKOjEfQPEPYGY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "905181f074d4de95c345ac835c829413b7b3e441dfce2a9a60a26ec1c81f0ba7";
        filename = "001397.ldb";
        url = "https://arweave.net/QofAQWvbOgFoH8v8JFo_Anl2IaPI_1tMF2GgNXH1rA8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f860e9f84f3d4ce856ea40026dea585f9734061eb11d11fc6c7462bcfce8bc43";
        filename = "001400.ldb";
        url = "https://arweave.net/-pgNKuse2tKaqzdLFvGtXNqtWRuGSvTXba9nRecsHtk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9b81e032288c92050c848c533ab77cbd8e5c46cda24d68f017bd24c5a8a66837";
        filename = "001401.ldb";
        url = "https://arweave.net/8qMzrrC1birErJQfKlHWvVPuRgqQSPa97tSQ9vW7DbA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ea3adb531b4da3b34a9719178c3c0d6951af3f61030df4b45c47c8f85012431b";
        filename = "001403.ldb";
        url = "https://arweave.net/Phiz-LCcqVzcYlsQU1BtsxPydwgxFeMu_W9jTyA2IBw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aaa247da8fdb5b62136dbc6735a17894c2bbb2c4598b784368a1fe3d03a0be06";
        filename = "001406.ldb";
        url = "https://arweave.net/wySvXA-r3eQKw4tnFtBqWIXCm7xOKVCWaWn5VIZnCkg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1c8ea91b9908720b3cbcb2d48e6e06bd7d7bf5b691dc167ac349a9e25e5948e3";
        filename = "001407.ldb";
        url = "https://arweave.net/y0eMqJpllrd-YGfTukY4S8-NqziWsVgqq1GNciXZHqs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "622bb99e303f8d55d0e15487ad1bc540e64771b102bcfaeede7f7c309d3a6add";
        filename = "001409.ldb";
        url = "https://arweave.net/tIZsZmRlwyFHDEEMf_LqmjLxORe0jsnofbVWVmOrZjk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e57c6803581b63447ecf6050f63b262b3780fbeafe5f54d0c900743e96999702";
        filename = "001412.ldb";
        url = "https://arweave.net/WnOPMKBmmP5Aq12BA1jIB5RxOF8GOVoHdLqsfUia_OA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c63c7cf121ff1fa9a7670ba1b93fd8d325cc96c5683059862a629864b948f100";
        filename = "001413.ldb";
        url = "https://arweave.net/SX6VK7jLN1BGWiz3zgLjdx5LaLbjVYNtGOfplq8OPtg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9593c702a4dcadefc5e0f32b07cdd68a0f3653c6bbe1664e77d7ed18cc67c275";
        filename = "001415.ldb";
        url = "https://arweave.net/UhxjiyGZTKHSwcCUUVhwENGoAYyBV1ITeqox6rfoixs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7bb8831ae0985b9b59b14eee00f8cfc67ffa04bf5217b51d112782ce3f691384";
        filename = "001418.ldb";
        url = "https://arweave.net/3mw2phU_auetXJJSnipM-CFTNKfU7AArX4VpVmpKssU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "75dd614382838674f16fbca08e79c457db5f064dd988171ce3b2fe7840a066c3";
        filename = "001419.ldb";
        url = "https://arweave.net/EpjqdO8hmIgXBv3LdkknE2b-1FRs0klCSekg6I6ldaU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e8a4a6600afa812bd9583d5b61890273cd0076c17c08acfccad59c2eaaca58e9";
        filename = "001421.ldb";
        url = "https://arweave.net/BLnD2g3mgVxwdNX3f4HYK9qXjfgcPEi-hekd1vgOk8Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dbe67bb2ae04b19b17139ebd68b01d2083e805a30ad45f20d5728921f29b79f1";
        filename = "001422.ldb";
        url = "https://arweave.net/1dI5urAgk4pustT1jOzC0Jm8HozZCIYgxq-6WoGcFWA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e1dff9419bff6e323b877a8303faf47e1770bba23252156826810b3232b97610";
        filename = "001424.ldb";
        url = "https://arweave.net/8VY-WJEm7skFsX1Xu6v8VPUEoIAqvm67bZxJjEXT2hY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ec9e1a74186a10c6c33a45e43b0961b385498737bca70542cb2b564b3fb401f1";
        filename = "001426.ldb";
        url = "https://arweave.net/AfiSlbwRY-nLq3uT2m0Cf8aRc0fopbicl3KKk_7Jnvg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0ee51990a05faeca45c950e34a8a927728b61f57ac01a42b90b533f0a56b4526";
        filename = "001427.ldb";
        url = "https://arweave.net/loD__lEgEjTXz9c0yNXfgEIMEXVp7Scp-s39C16bFyM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1a8b1da8fb60015d5011fa9f66f411df1422e6626682ee7b95f2c81cd5da91c7";
        filename = "001429.ldb";
        url = "https://arweave.net/MSZmjR0LNx68oHMrBh6zmqMuFkmWfPJcrN2eHiRdStI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1562ae32810a75bed1d065eac31f8153e2754ab06bf0491e2e2d4dacbf81219d";
        filename = "001431.ldb";
        url = "https://arweave.net/ZJOXazPHKtO3iNkE2XyeDSZG2YR_IfZN-5gPxPg4Ahg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ff107acfd699e90ed8d402837e2eaa561e81fb6217f720b3606cc45abcbbe643";
        filename = "001432.ldb";
        url = "https://arweave.net/C6ZUuU8GEuElHPq--ixewuovkK1FLOUA4e5U4o7UqFs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef707e7ce9ff2bc1337c218889f6c64e5e717518be36be9718551018bb3739fa";
        filename = "001434.ldb";
        url = "https://arweave.net/hKINVQBWodHM3PDeMeT18wx34Qabs7aXGnajtzEZqvc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c65ea0d7f62dc0c31e6e3f4c250e05d7219b933c50db284fc8d2d2730142b20b";
        filename = "001436.ldb";
        url = "https://arweave.net/5PVS-f_V0FoA15F1kBhF1hgB2BL33cIFnPDE5ZVhWIA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6ef56dd53a17fb9e0f5e223722feadd8ef69356ab83d9b022f8c5ca7851072b8";
        filename = "001437.ldb";
        url = "https://arweave.net/HZq_2yvdGDbQETwplFkg3kqm9OsBO4uk65aPHKG3d8I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ab3ed563c045b4fc8bb8d1d88a62ad54d267df143a55f85de97b9a793d8146a9";
        filename = "001439.ldb";
        url = "https://arweave.net/uf0U4cJllcSsSPBLkHwmE_gPqA_RjjO7ZMlw3sm53po";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "952db01d4652129a9365c95deb637e6204f2a5587c87ec6c3b20274887e72f1d";
        filename = "001442.ldb";
        url = "https://arweave.net/YbT5FXgfuft4iP_Ssd-jST_Hd5stqlTvMvndb-3tmXw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fc062d3df9e474ccaf0bef844f676c5bacf1f50f5c2608a2ba381582ae82a304";
        filename = "001443.ldb";
        url = "https://arweave.net/7qImjlnZhRAFkYRlTYrGqsmLaW7nZee8VIMxXen_0iQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "44e59cdef822d28828b7c11f7087ebe05ba138bf68d3b4b59e2452d82e230b51";
        filename = "001445.ldb";
        url = "https://arweave.net/jXRuLh2IdpXbg5RWv06AJWxrv3JkZa5IG4g184S6Ia8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2f656c003d19bbd853deb83c96929674d6653c8a2cbebf90404e28fc2235e26a";
        filename = "001448.ldb";
        url = "https://arweave.net/4FbX_sCa1Q17QCmY24vUY1Fk7RGVQwYcp0-w9ByUnIE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "efcf88616922cbcb1f68674dfc8f2d67a5ccc87b885e5379290c701b8e207123";
        filename = "001449.ldb";
        url = "https://arweave.net/2lN00Wf2138iyGx0PXs9SNV_BCGx64oC5ltoZF8dD8E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "26e2be38c5d2c69858f1b971e1e78e786c90b1fdf9b68f7a98fb9967197b7531";
        filename = "001451.ldb";
        url = "https://arweave.net/kplsupfIMnelhnA8RVmjwfcNy6lUPCEOrhaw38j3XwA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e8c9b042b6306041ef5767cc6d5e20d11ad838f2ece3d6dcb045d4e7d76d676b";
        filename = "001452.ldb";
        url = "https://arweave.net/jlWhJUkgDTwzSJq-DdXqwc_JH4m8OaZHYLe6HXsLYKo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "602fff4473e649107072c92dde6551522b22710b33930f45db6b350f85db78da";
        filename = "004687.ldb";
        url = "https://arweave.net/hz70XWfl8J8I5Q4aNgf1EP8VC4E5JA86Lkf8kZEeRGQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "483e9ae194e4fbc0a3457feaea9c7c5dd2ce8d7f4a17dccf7b6f78532900eb3b";
        filename = "004688.ldb";
        url = "https://arweave.net/WtEtxsGtqVPqjX71ezUyCn9bm1G8vJNYg5oNfnw-dfk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5662e0cf230e485cfb278df7ed04d6862c7f2028985c25b609ec9b02e69f595d";
        filename = "004691.ldb";
        url = "https://arweave.net/J8bLinZO6tSZ2q-m8UG7KqZR0iEK9THTTMg6QBjFPb8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "880a7057cbe49077632b07caea8c38fa09d8d2fa6ee1844d95a97491fceaac0e";
        filename = "004692.ldb";
        url = "https://arweave.net/km7O-yKKqnicsyDxd_0AvkH726xJMktqtd5nDKLg384";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f802c5e359fc44879ee722d42bf0d89ef12fad1e55fe021827702c980095f443";
        filename = "004693.ldb";
        url = "https://arweave.net/6zJd818TUqQekn4fXDK7IV1wfwdaJYJwRkJMAvJMt_U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a3c01ae750ee8bb191e91fb2572d3d274e530e3153dcee3513881c44b062e684";
        filename = "004695.ldb";
        url = "https://arweave.net/yuHLzmbFawqHv4Tu08yaj0R7HBXFTq88avoaWdbfs68";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6e5e4c2adbb8b8d4d66056dfd943e279dff98c874e9a3e1b5a6237ea439ca39c";
        filename = "004696.ldb";
        url = "https://arweave.net/C-KkpBznAFnp9DuNpCEIFqVGiMGlftEzPH6ykfTCbuY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4ec0f7b70134a0d29552a95edeb7f32a1d058fd1ad2b0635825c6dbf18fe1854";
        filename = "004697.ldb";
        url = "https://arweave.net/ec16eoMBFLZv88Hu-3Qpq2quNxCcR_iDPQGxMWVJ0Sw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0c130e7acb79ae0d4f312e7f541248dd4d595c48c355518f499289da97b4edce";
        filename = "004699.ldb";
        url = "https://arweave.net/UvbtxFmiLi9Pwmvo8ev_zn0u-ED8mZuExVHH-djK9ac";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d44a3cf197723bacdce492edd961f1ac2ef40a02064c5c3be67177e041a6067b";
        filename = "004700.ldb";
        url = "https://arweave.net/A46qWx5AsYMjRjQCSe2yBucXMb_DlC_bYjmdvT6r8Qk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c21a95a5095f64197d845b6e81f5d49828d66bf2618d6eb36999956fedfa29b1";
        filename = "004701.ldb";
        url = "https://arweave.net/lcX5XZLVelmWaWzFJqeY7bTs2xeV1of5svCx29oujJU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "afc4c623af2b94a054b0491f3fae0c1e6af4d44bbb84ca0414e55f9a66db27a9";
        filename = "004704.ldb";
        url = "https://arweave.net/GRd2Xe76PFLYajrFFYVXRIDY-pIowF3m61xkylF6EnM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c3cd64eb8bcc58272c0c7ca585acab62c8a0a42531c28aa0284d418d200aebda";
        filename = "004705.ldb";
        url = "https://arweave.net/GZN7iUOO7ItvG0lozwOEbwrJsYEMBTAv9rjzbXqeHQk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a9fe089f411fb49b351e70e14de14ed30b1bbbc50cc5ad633f9e23dbba443dbe";
        filename = "004706.ldb";
        url = "https://arweave.net/BUGdgzMjecy9Atl_ZE871y0HUXsxqTK12phKT7Gsctc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "beb97fbb8cc775010e36df76fdab92f88e62ec1be43140bbb6d69bd543804339";
        filename = "004709.ldb";
        url = "https://arweave.net/oF1-YtL0wy-Q6oscIdQsbd-QfayJ0i1lcKewCAwHzRs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9f1722946653aa649451d270f9035e5ca6856f7e6aae28ffad93f8352f9508f8";
        filename = "004710.ldb";
        url = "https://arweave.net/cCGN8DrFHBP8sQ1GeJnrH0MHJUkZSO3AkYUCby77MUU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4c4557924a8a5bd1d2f6c7e31c18661faf8dea889be0f1245984568a216f1702";
        filename = "004713.ldb";
        url = "https://arweave.net/ZOEFP9kUdMHssKpR8JAZlh_6nrrdY0wlF1m_2n8gX7Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8ed04b6d49492bce3bc70ea1a6b94902d92bcf9425db93e3576b7cac74037ea0";
        filename = "004714.ldb";
        url = "https://arweave.net/AEwwcN53mj-F9_I2KCJcvy7IKNJE_8jtdnk57nnNT68";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "328f72be052ceca50764ae9547d19b10a8a5e9bc7f9f749c142c74b065ea5e81";
        filename = "004715.ldb";
        url = "https://arweave.net/QWq1URTpq368TEEcmuFnXutBKjRAQpoJliyAM3DnRR8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7798fda4bf769a0738fb8ce7fa7f4d46be9dce30ac2003b71613536fe43066a5";
        filename = "007654.ldb";
        url = "https://arweave.net/Dc4jIwQT4z43iQKulAABvY4ND6sAGsVLAcCMAy27Rig";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d42a1e1d47175f8a987e30eebbcd2fd48e00371d55c2cd7d0ee216ed6fade9fa";
        filename = "004718.ldb";
        url = "https://arweave.net/GA6l8YOorBS7esKRg_qPZm9EsKcf2l993oDXCLKSPLI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "996000d81a96d4d7d4369c4f39ae3f403af24ad53298f22fd128be24ce050c86";
        filename = "004719.ldb";
        url = "https://arweave.net/Qc5FJhrzVL2tqJoNvvJb_HQKI2ma4RQ4ltemWw8ZQWs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ac54b978cc9ca6e77ae948d869682317f7fd8833c763ccdcedca6677b784da43";
        filename = "004720.ldb";
        url = "https://arweave.net/GwoGpnKTe0aeB54BKOf5nr4NbEzb1eOqI5XwqbYXJGc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "97789942ca248f44bf511016720013a76f3acfe8d1524b588740839d0e645b72";
        filename = "004723.ldb";
        url = "https://arweave.net/h4Qu2NSY-gzGFyzmHI97_iMvCFDQKOJH4-fDxA_UbDE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "df2906b095fa90621c679f8edefa5f3397affbf55d4a49e06035970d3486a9c2";
        filename = "004724.ldb";
        url = "https://arweave.net/0RVwkdtTUQq3k6EPcDlC4fr0CZqwkcbMJApYsYgSLv0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d8e610a9cb68e00181ad85f0c3b0444be8a3dcae5247d40b97520ffba984e815";
        filename = "004725.ldb";
        url = "https://arweave.net/mlIr0a-QuwFVcmq_krXEZxFOJLMmFWedS9RG3a2P9Yw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "547d507d639675287c6474bd63286920c388beab24809ea6dda55567f10478e6";
        filename = "004728.ldb";
        url = "https://arweave.net/pbmfpGpX-LAyzqCpSt4q5kOhF5IrxiP9YWFVzXETlzg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34f095295914f62ef1c4531a0acbd49d37f1039e8aa8e9d72f66363da741f695";
        filename = "004729.ldb";
        url = "https://arweave.net/hJyi3lEXjg2mNcdyOPLHsR-ssN2Trmlfo_cXCBMPh4w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7cd801c6f6389ddd6c7003461926bfcaa5f9cdf8068d2eb7adfcfa2eafb95c33";
        filename = "004730.ldb";
        url = "https://arweave.net/2rOlouS5U1to9wGCAZS-9_aQf84_V9abkKVF1oIi9cA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "050caca3325c65ddae8f749ae3130e817234252efd539132842e0b346b7ecb55";
        filename = "004732.ldb";
        url = "https://arweave.net/EuXGlfcIRtjC098Wo9KlyjQJx8zDyj4hsrtTXhrg0HA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b603407e2efa3dffa4b1d23d6ccef3e81d0474809a5f3b3e921f4bf402156693";
        filename = "004733.ldb";
        url = "https://arweave.net/rlrIU9xQi8botPjlZdEPYjByOVOUlwZqygCGkAzHJWs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dabbaf0394ee530b7cf2f82bd95583d91461dcee9f52c117236dbec223102a2a";
        filename = "004736.ldb";
        url = "https://arweave.net/l-qvfkjJ4IAuYi4aADK87y2-3LgFufA8fxD2hademEQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a979a1d587ee9fa6dee9f9c3efd8af44ab8eff57d1bc227cfd2f6e02d27bc083";
        filename = "004737.ldb";
        url = "https://arweave.net/2OhS0Q4tvpvCmmFpHbh8zk3iKIPLDPd9ma03XxsCi4U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6f5be52a134bc03ad15308a9e5a1a6c662f766cd0ae618af25158dc71bfe9bba";
        filename = "004738.ldb";
        url = "https://arweave.net/kJ-tEfWGjQu3tjiA8hu5wyigd8C27kV8FWLWCwOJ-Xs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7fac4d8f114354f6a108e728993155c2d55f21d5d485f2a6ea4eaac5755576d1";
        filename = "004741.ldb";
        url = "https://arweave.net/cWZ5msS1Og2gfLmtiYqZLY90rky1rG8Asn5oIN4Uks0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0e39d2d247877541cd7e0376e893e1169a3acd948b178f25f534938efd597b5c";
        filename = "004742.ldb";
        url = "https://arweave.net/NFFtK6jjpbAkmYwDS8KCBQE2Zbuo_8cT-KaDpDxPkAI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef8f293a161cd63ec80d856fde937d7f00f759271d027529bd7d5e6e316919ed";
        filename = "004743.ldb";
        url = "https://arweave.net/rhyQgHvr7ocr9XmP7MJFaXqZrmeTZTcHgpF7H57MGRw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2fe16084b450fe2383ce8e416cef497385ff25985068844eded28f4f815d625d";
        filename = "004745.ldb";
        url = "https://arweave.net/F38eQhQqPGpP8cC9IvFrx_l8XRJ6N4hep_6mZXKh8Lg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "84eb9f5b1a7e56099ff61d3700678f04018e331821c4dac20343111b56066204";
        filename = "004746.ldb";
        url = "https://arweave.net/6w9_JGjuN5vua-ZOV-e7s0czmaaEHts0PcistbNNH3s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "088922b70cffcf382505cb254b7931e9181ea12024f28d97bea73663bd7ac6dd";
        filename = "004747.ldb";
        url = "https://arweave.net/f06iAWDyT4fbPuwlFBQykbp2LZFPDI_V9ThX_npOnHA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f8906e42164a7c150bef2be89f029341bc5cd10d0b2b3a2d25b3f273e521b670";
        filename = "004749.ldb";
        url = "https://arweave.net/Ark8cWnA0nupT_lk4-mUMkCs_PIhL4zVQJRdp3hDDFo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "697cf99ab40c290dbe9d331a3866c2e4aac771dcd1d983d47954618a328df448";
        filename = "004750.ldb";
        url = "https://arweave.net/6HPG75HXFvmdaOSicQJqGdJElbdVxJybrL1J9oD-qb8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "beb21b620abccbc6f6adefce2797f944a5005fc79620bfe8c47dd1b33d68e5fa";
        filename = "004751.ldb";
        url = "https://arweave.net/3fKw8nsL9p0aqqnBxfSptBnuHjcpBtzmP84S6WoRHeA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2505985aafce9673bb883c07e052312297371d23cf63ae250a3c1862d4799055";
        filename = "004753.ldb";
        url = "https://arweave.net/di4LmoPec2TT36j0NZP_kuyuzkhjz3_7j0x_NnGRqeI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cbf3817860d0a690565a0ad9fc445b0cb6c98ac308b63cf199a9133aa447bf37";
        filename = "004754.ldb";
        url = "https://arweave.net/WNOXHSLqbTkOl968dqlZiY2G-cFGUTkoHYiXnl0357E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3462857113a6fa49b807714e15aad9395e3bc210551f6d9ed70889125bafdbcf";
        filename = "004755.ldb";
        url = "https://arweave.net/BHMnrzAY_2v0wxi-p0wirik80M0qdB6njSOHzQLKCBs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ad2fcca0f74e1c5a32dec26bcedacc334c4d0056d5aa70b2fa96de5e8557532a";
        filename = "004757.ldb";
        url = "https://arweave.net/t3Ac3c2JEZVwsCnS0VkovBEqdckE7uvDk8dGWltwReM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f569a4b3412afc75402bddccfc6505daf6fc2bad95911557a4dfffba6b240838";
        filename = "004758.ldb";
        url = "https://arweave.net/LBgml36CTNaTeHnWvOLQKe1nHAUbK-r6Jn5_b7IWFh4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "06c98ad56ef0cac1eb06a4d454ab1ffc8ae911293dc0fc95e077bc9bdb9576a1";
        filename = "004761.ldb";
        url = "https://arweave.net/dnE7Rrqf2LFQVcWIaAmoSvk6yZiEBEhLQiudxz8bM3I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "53ddce97db521cc6d88a575942eb6add3a9ce28b10057f0f19f90e6e8d1cc427";
        filename = "004762.ldb";
        url = "https://arweave.net/qWnnxmhrs9_AArXZWBTM4PgfAqMBuCuQHsaju-bwPqE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dc38354914ad39b11530c9077f5235d709699a38294b1f818fea19e9baea201a";
        filename = "004763.ldb";
        url = "https://arweave.net/DxJs1vkgUd9JrGWgA2M26AhMXcPp7dLsaRLoVLmoYPU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3707183547f09b11dc4364bb53ec255a6e2968950fdf5a864d49e36d476698ae";
        filename = "004766.ldb";
        url = "https://arweave.net/9j7fKcFsOm93WfvAvWvqVGFL5dyOy_0xY_4sICWLsko";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8638b6feac0b17ef543022496fcf0c6137be24fc57f76997d8afa5ce4bb984f2";
        filename = "004767.ldb";
        url = "https://arweave.net/WsAnZSwHsWBaDTtWcXZH2hzwb9tzbmLzTzsi96QBDLc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d34f07ec1d2fa6cfe76b2c39db493bc83ad060eba62cb8c25232c63cecb50af1";
        filename = "004768.ldb";
        url = "https://arweave.net/ddDBKr4zXu5YlSEdoX2rIBNngyW65xP63qkjGv3pNog";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fe504c6588338cae7060e77f47fc88008a8508254621b9d3d4f5cbfb4a2b6c2e";
        filename = "004771.ldb";
        url = "https://arweave.net/2i8yZ6ipsL2uDh_iVjnj9amDaS1PKSWWgi2DgnJXwE0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d72f2e710eb1a701f1a0fc6edcf09b069a74ad1ffe8114a5ec888db9ec3293e6";
        filename = "004772.ldb";
        url = "https://arweave.net/0UoA8xki3OB_xex5Gvc68K-J6kPS-bBMm-Ul4wPQilI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "729830ea578d63a98ee31f9935e45326d5025ffea39487298b2975e4149218d6";
        filename = "004773.ldb";
        url = "https://arweave.net/PlH0tdFrqcco8PxzYGuwVYjHxiUvYlystCA-_lCxR6Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "561097ef3250e4c54b0fba7edc4498dd94dce8363d0ae804bc464d7a1437dd46";
        filename = "004776.ldb";
        url = "https://arweave.net/Ty5CSuIMD5u4dJKflrnPxetRdpNtQ1_yZ9rGe_ca0wg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9358be831f4bf4fe39112bcd0e12a0b6809ff135649e39239eb9bbf4f58d29f8";
        filename = "004777.ldb";
        url = "https://arweave.net/JeVVcxhHrEs5IsO2ItU1DbWq4R8LayyIC-o0UG8u6TY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b117af3a863e175b045f0c5180c1d684bf6b1c019364c2fd710644569cc46d31";
        filename = "004778.ldb";
        url = "https://arweave.net/PyhV9xzW0HPC-wBmGysg9PMGVLsOWyJfYCvkQXEStjo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8ab1ea6c457f4687d3a37001c7d5c1bfb50af79fb46e47dee4e2bfb51d04855d";
        filename = "004780.ldb";
        url = "https://arweave.net/3x8EM1fMao-A_oTtUMLtkd1i1paUB6dN1WMG_E8-TRA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0aa92efbbb179e73d6718cf8435c6ec30532967f1535c5e63fabefbd1a498708";
        filename = "004781.ldb";
        url = "https://arweave.net/KUqOJKIzNyLDl-qwIpWVS1LOF2rnWnwuAJwJzCqTDxc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aef88dafc565ffbd4d9998c2058d35b3dc94cdb5678eb20009b305c1126ba917";
        filename = "004782.ldb";
        url = "https://arweave.net/yzs9kgl9zOL-RQFGlKA3Nx45Sf7uEeraMGqpplkys8o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a5be991bcbee2d8f742b8c9fe7287f71833f59f667c26d752d606f8bc7a3ddb4";
        filename = "004784.ldb";
        url = "https://arweave.net/kaZhfXSiVCCIYgbsCalMi7o3qILr7ISyBEc3KnfHCqA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "49254d47c31dad9cf538aadd4e32962d1527888dc163018fae38e7c26c4685bf";
        filename = "004785.ldb";
        url = "https://arweave.net/72CfRjhPyB9H4ahE1REhdw1PNFNDLdIy1UHSFTqEs1g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a12725915a0413fe449904a890ca7f5f084108c7bd61dd143a889f9feca41ecb";
        filename = "004788.ldb";
        url = "https://arweave.net/bmFkO0RTYF7Aul7fO2AG8LR7m7NU_arov9KrBTGhmAI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "355f9a119e1f45c5b15ff3dfd46ec100eee0effd87ab63ab1b52a16688be05a6";
        filename = "004789.ldb";
        url = "https://arweave.net/_MEplpyQlVAyH3GETCgeFfeUAAIvG9YBizpm3lOU6b8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e214c662f85b4f8efe3ef559740511958ecc8cd2ca0787fde793641307eb36ca";
        filename = "004790.ldb";
        url = "https://arweave.net/M0O4WYZJggFRd0HLfQjdCtrmej4qR1It5UepXNxbNHQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5232121813e713b41636c35c891b9811e0d8bbd0b11b75de57cf5e332ff13842";
        filename = "004793.ldb";
        url = "https://arweave.net/YfuSodW2He3xf_8TDyTMlMUUjeG8mX-rzVDxmM8TNac";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4212cfea03e76ce6eae1145cabed45f6f929a12e102c5fa3d7de4e77d076c77c";
        filename = "004794.ldb";
        url = "https://arweave.net/XRHrvcmX63jRE2LWE0tscRkDgAPzNS49hjtCUOeC0QA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b676dd4333a4c1ef24062331efed2d717cef5131e4bbfc14deb0ac8815b2a4dc";
        filename = "004795.ldb";
        url = "https://arweave.net/NYhKnyPW-ajJYT4CEBAIwUu7k-OBQwjtowbXl1EHTJg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9f5bb3f347a0e20a010cec2e0bdfb1e752c52cecb715ad01664fae14917bd952";
        filename = "004797.ldb";
        url = "https://arweave.net/JfzWGT3VgaE5M3Jx-NPuCIhrsK2rcwr3J15Clivhm14";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f6390431766230a3a44242c87ed7740385c60aee6582e60cb4811994d131e76a";
        filename = "004798.ldb";
        url = "https://arweave.net/RrmHa1Mzwyl_8l2VkWZY_vdtDp5DEtIXoZHeX8ScRbU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3bc3ebfef5b5c3ce68857936e3f3cab647f0a72c15f6022f4f7d31b765e2b171";
        filename = "004799.ldb";
        url = "https://arweave.net/fGhGBD3tX7Og4rXj17dl2Sq1Y7XJDL38Tx1D6nDvEhs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "81d83c240145f39ec7050db31517797ffdcb3e4ac0149c246227a99bf50e04f2";
        filename = "004801.ldb";
        url = "https://arweave.net/1-_05NoUPF17ExJnQLWHquIvkVO2korQJJfy3yTvBVk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2afcf9b83c55be5d35e74a1a998339d6d491d4b254ca4a4d5fff62ed65335530";
        filename = "004802.ldb";
        url = "https://arweave.net/SLgoFXgfviMnWm9dOIeXk4e0mbC62b5q29KJxeL1BrY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5110bde147cbcb498a1a89dd98a594ff503e0088557a6acbf5881f290b9518b8";
        filename = "004803.ldb";
        url = "https://arweave.net/Qw9blSTq3rAMZhPeWTYKr8kWm74kb1P2JUS0XEm4-3Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "83dd49fcca0d90339691f23001136e683c778ca335ac799af77b6f71a9041fb9";
        filename = "007625.ldb";
        url = "https://arweave.net/wz4yOZhRfIC6TkN_Bet-8SykqTz8cAYjVVpfhMkgZqs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "52f4137d8146c5177196494ba7f3cf655525338b01e2ea96673e94c0e200efe9";
        filename = "LOG";
        url = "https://arweave.net/kUJ3kS0btuCcAF3B5BuUJP9-U9SYJF1U2IEWb7G-u9k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0f35908d48f6ee30997abe4015a3cc59b0e5df8303f49515bf084fd1a6ac1bd0";
        filename = "004805.ldb";
        url = "https://arweave.net/hbQYybLQZmvwVjCBUPqvEAkVSx-2S1eT7A4g7wf5CrE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "258718d701aebe266133038ad27849d15b6f1d4e1e92f40dc40e4770cc789bd5";
        filename = "004806.ldb";
        url = "https://arweave.net/QtvabHzk9ZpNmcBsu2hxHEnlPV7T69UfWm4K9OhwNMM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "28d4a4a373f4d7c459b45e25cc6c8da7024d08de6b7a47078ddbb3f18dea517d";
        filename = "004807.ldb";
        url = "https://arweave.net/e1ajrIJTqEY7Gj8o6HvyihwLiJbtZAb5GFDvbbATGL0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "967b7012f169267582d15d97f673635f75164f38056cf9a15c20914b857cc97f";
        filename = "004809.ldb";
        url = "https://arweave.net/8L7XmGc3SPFX0-mNd34SxJBLG9SztwWOpsu0wG9KI2U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "834f0216a84a66671517819e42dfad88c091cc30bafaa9a385a7272a0688ac93";
        filename = "004810.ldb";
        url = "https://arweave.net/WshluraXnXv6BdnS4g5R3eU7exwG18aWVr-PqoOXjcE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b38995c856dbd930c54949d3624d73339d20b865c1b68c9a8d0826620c5068b";
        filename = "004813.ldb";
        url = "https://arweave.net/45wHiyMBhJOgogtDGNJ4ae3cvyJDRh8rLpxyUCQ2_PM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "24e7eac0d9e141959742c9f0f1149d804bd806f44992f409a1b6e2e0029fb424";
        filename = "004814.ldb";
        url = "https://arweave.net/DhmiMv5fWiOlyRZpyPF7abte3PMEj5VMCYZoli90s9U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e417681fa388e8227801cc35ed8497141aa074c154ff277422fa69cc79019318";
        filename = "004815.ldb";
        url = "https://arweave.net/cVlAzLHJ0L9gpWtklEPOCDzF67_dnyQ_67-jwuPBAhA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5302a9e6ba2fb4ba0f844ef57f09f41459495d92406073204c26a2d4b42c1394";
        filename = "004818.ldb";
        url = "https://arweave.net/3SnHs3dUZcXgu7ivZTzv7XlnwyDYcTrkBD-LsKOUBtA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f449c967b005b5281841feed2ca70929fb12207839de3a363f117b00ff4d1b29";
        filename = "004819.ldb";
        url = "https://arweave.net/pSPkspBPlPHaitnC9TX8s20XE0VHdXNY2Sew0TcIG8w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f2ec2f41fa2eca97cb88f4548631df623050ce212e434df4b2478cc9f2891acc";
        filename = "004820.ldb";
        url = "https://arweave.net/JBYeeSSvTQQvELfBl19TWTg5XNFGDBsvUrgsZhgx4ko";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e38d333048a238cc066c9f5ef399044705dcab7c2258bc48eca367d2f259b45d";
        filename = "004823.ldb";
        url = "https://arweave.net/MnkR7Ivm-5CzShADm58MIUpiiSIQ0yEdzkSR1dhi12s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4c8c28c703c348a7eee8b8288d495a28d6b0a0a09efbb9a267073600bf8c1091";
        filename = "004824.ldb";
        url = "https://arweave.net/xGc53UyohKzj992h9YH8olKWFryDdNkbu8CzPsd78qI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f03ad527478bd1f794d571423fdd0859feaab5f7f648caf5c2eb615f90ef37d3";
        filename = "004825.ldb";
        url = "https://arweave.net/Yjd0XVWNlvIjJ6LxOFVuW_uWHrazUVVRTuTytPGDQKU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3387881fd87238be5dfe07538480ffd41d316c1ba1ecae7ad912baec8d63d6cf";
        filename = "004827.ldb";
        url = "https://arweave.net/iwPlqunB9Imv22KHBZ2S5kBqPt6fnVxDgIoySTM6I-E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "57fb19e5c1969542c567196a94ab5f4bec83a64bba946a3f4748fc1774873816";
        filename = "004828.ldb";
        url = "https://arweave.net/XlWPSG_FB5WtR5TKhQaN8znvwwdt_6OkwkE_Q9ef7ws";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e87eea033e0cb7ec3f44a9a94b15014a551cc7c54b8f18662e82c122bf8d6130";
        filename = "004829.ldb";
        url = "https://arweave.net/V4I114Bdy9fFjarDR_CHrAIKv0Ulc1gr1Juyt_xh8Fc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bda2669b7c4e0028b00619b55fe9ab8155d5d28b6b258be3bf3d056cb09cf845";
        filename = "004831.ldb";
        url = "https://arweave.net/DnJBKc6qvhd6Hl6bHUcBstNqLQO182XwZAJL2_HR2Wg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5cc3e1806abc0dbf95008ce512880f12e1796a4e9d59b8a352ef07b1ccbdb2be";
        filename = "004832.ldb";
        url = "https://arweave.net/WapUzxk4SKV3Y5L36lLMpZN34X5koTjZ2Ag47MpocWY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "45b73c929ccf96624726cb3d2a42b82543ca5521cbd0a3a8265d0b1b7411896a";
        filename = "004833.ldb";
        url = "https://arweave.net/0YwEiAriDnoxsyDCACab9u1iGy_405wDOc6zhuOvGPI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ca11e61e8426491373481ee269dc5067207d76555528d92818ffc11f145bb71b";
        filename = "004835.ldb";
        url = "https://arweave.net/xx59BJa-LVFWNDz5GobJ9X0Ujd09huhjNR1PlkYnbzo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1669e716c16423ec27b678d16259a573fda2fb7052a65107163816cca7e21a48";
        filename = "004836.ldb";
        url = "https://arweave.net/ZIpHSyN_inELjUMNedwCR8AWUvB3bCqjSRauJQzDwuc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "37cb4ebc8d6d02ac349d59f3ab7eb7726ae97142eb83dbd8d2b2903c16b74169";
        filename = "004839.ldb";
        url = "https://arweave.net/-UC2KvnZrCv0dfbytFBmeZUZrijudrCW5KSQzyAssTk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8002e53a0df511646a8e055470521415f9eda92362844f987158c9f22f514237";
        filename = "004840.ldb";
        url = "https://arweave.net/4aMc5OCmDIxT_ayba7NTJ6ceCxRM6fQKOtzbubTQLkg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c86455220ea9d720e11305cf39c8b753ea5908f1d14a21904b3321f2e8b005a0";
        filename = "004841.ldb";
        url = "https://arweave.net/o7yicQx9bFn-gvcfKWAfHY7X6nzN0aYlkXGVd91F7SM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "29194acfb3a2ccbc38886c4caaaac5a18551df0d0d5d57d67eeb56c72c21a197";
        filename = "004843.ldb";
        url = "https://arweave.net/a35gGSAqjsz3fQ9REBxs1ie-6MEXbPK6tLkeg2lSci4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5f464fc03ca706ec30f18ffeee697e8c0b9e7d75ec8ae158f882958e13bfbf30";
        filename = "004844.ldb";
        url = "https://arweave.net/iBVzVhlQPblrKJfCzxBcy0HHUR1-JGjQE7T3DaBfahE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8f805e6d49dda54f74538825bee47379a31b7944b90815ed27df0ef365e94da5";
        filename = "004845.ldb";
        url = "https://arweave.net/iqJhZh2gD6758VJ-tNAExW5HaR9rOSXQcfvDoNp8oUQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9a7609358f6a2995472219d6706575925ac67995ef950eed6bcbe54c5d223ae7";
        filename = "004847.ldb";
        url = "https://arweave.net/7wVn_yO35BVsQ7XU0m3E08HgwfgKozzOhnhlhRHyTEc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6aae63cedcccaf5c3864f19cf8eededee111baceb1b0b3b914ee104372f0b83e";
        filename = "004848.ldb";
        url = "https://arweave.net/hxz4hZMrJhiRskmwwfq419rGX_5Q_5mE9m_beOB4ZYw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7a10778d93a5f0943d1184693c75068b946dd55e3a233260ffcbf8ed1dc4a715";
        filename = "004849.ldb";
        url = "https://arweave.net/-1d8USPex-GAt1DcDprEy3o_eeh2jI2nHd-NuV7Z-xk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "79717cc836c9dd1ee3d77d89fa85822aef016d0b849bf8cf70b26f72e4e3af40";
        filename = "004851.ldb";
        url = "https://arweave.net/1H2R8-rrxK2qF6Dz2d8a_hl_bnUoOV72wRWmnTQdPdY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7aaaf9551cf731cafc9ffa593f7f2ad434fa3ee59ebe4f1bcc215112f9c28df0";
        filename = "004852.ldb";
        url = "https://arweave.net/sr-SAR3wY3IK-fd3_uKLyEPoxx-H8veTQ3Fsr4zZHUQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "324784de68f55cb016b42ca1d021bfd601a20b0da0e996bd0f55fcb0075e064d";
        filename = "004853.ldb";
        url = "https://arweave.net/1uy2w_5fEDn8spXtR0lZsdsZCh_sTFyxAXAfQ0PSQy8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "248a35d4baeebe8c11f6076fa602d040282b50faa4d375324c23124d66904c40";
        filename = "004855.ldb";
        url = "https://arweave.net/378zTgXwSkfa-FMeXB7mCaTWzjcDQpNQvC6CqIUdfzU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1e58488663c9f1f35ccbd184a658f013af0828fc5ee5bdce2e378af7f04090a1";
        filename = "004856.ldb";
        url = "https://arweave.net/bBPVAdSlDg5n1FaEnsg0bcRleECnnnoO19jex_8dov4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aa3d6aec7857c9e41bfe107efef3b4134971d166f65be70e2fe15c6dd3c0d4ec";
        filename = "004857.ldb";
        url = "https://arweave.net/x133Oak6gAfeSB7NMr249WrQcfeqoubPAwete2c2kcE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f7cf1a68b0829f63e3d2f695b223741fd1f67adcfb9d697019a13d265a038364";
        filename = "004859.ldb";
        url = "https://arweave.net/uOoxa5OF_dO4skfF8-1Ba_OrcatELqa712TWNkbXkTQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "677976ef27c665543ea2992b96d105b8dd6c14c702427a7c01bc09308368445b";
        filename = "004860.ldb";
        url = "https://arweave.net/UFxQT47LTWy0R8KcTJSITEX5DyZ3qHGCsQsK2qJSY4Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34041a319f123226947024ab0761c68097c184fe2553d8b5e8960712dcb1f34a";
        filename = "004863.ldb";
        url = "https://arweave.net/YmnUDB9BXjhU6tm8gTyBop8VRINGL0tFQYObsIduUnI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c7a564ece50cc988dfcaf67e4d9123ec4982ccc8d8b7eaea2e439807855ede98";
        filename = "004864.ldb";
        url = "https://arweave.net/0P-O81U057VC41Im9CO0PU4IHB4dQo1o7VgGS8Ukzpk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aca74efcf3117ad57c9348d3b94cdb45ac2daf434968b86ed41a70e26786bdd0";
        filename = "004865.ldb";
        url = "https://arweave.net/BJ_nQhsu1EAwtE40ZZHV3zXvRyHxqfNT4J4Ya7kwUQ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "576b72b8709b74f2525bc52778d1d2b7fb6df3470abb5c280200c8c2fd8ffb86";
        filename = "004868.ldb";
        url = "https://arweave.net/5xSAcYDSj5pxIqr1tyt0fi6sDQSiwv6HIv2dPoPtPZw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f08f4eda1a4373872313b3e35d64be3a4e840297eb192d2afa6c04ebd1b8a4c5";
        filename = "004869.ldb";
        url = "https://arweave.net/-LyHX59rO1NoCkq2gpyiZOymCO79DAGs2L8KmxldXgg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "76613b5f0f42ca254ee3b1575611109b793ea8f5c9b2a1e4fffc4b4bcd42be0e";
        filename = "004870.ldb";
        url = "https://arweave.net/lbOvA4moEmTVCgPe9V8cfmIBNyWOOY5TQuGqJi2GcD8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d90538b8747dec267031e0e24bbc12488674cfd5fc49725229d45866269732dc";
        filename = "004873.ldb";
        url = "https://arweave.net/h8yl1KJaWyTziJK7i-sCRLc4s5zWtxe6oX4P2wHRbUA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0d23e8c30eedeaaa7a1d64ed1a47e2e9b46fa7e9ae5bc8f14f432d08d294ec1f";
        filename = "004874.ldb";
        url = "https://arweave.net/NkRp_xisyvkELqcwkLpKw5H-gtzcPvr1-5_EayEaJes";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "683dbf5ded92a8e8792d07490009de52ca5e128022bbb10d6896a994beaba168";
        filename = "004875.ldb";
        url = "https://arweave.net/xbg88pOwS2wia93WNkO7Nv89Nf3Py8bAzQMzaZ8tWU8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "99bbd2dbbdb316ecfbffb1f16fd9a2e0adbed878707810b11c4b2fd3aceb59e0";
        filename = "004877.ldb";
        url = "https://arweave.net/MnDrW_MnvMPaC1uQ5F6LpsybJvWVR6_G65lSsG3RTFw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9312f0e24bbe17fe17edbcdb13ef67ea395905957735b4e5159350bcc5644064";
        filename = "004878.ldb";
        url = "https://arweave.net/wksJ4Shcq5dhr0qyaDt97QLBNruGhUC9RqTTVLc6hRk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a811611d05bd83be83bda5a1d4337c0f548cb5ac7951f2cc09a01137481c8fb1";
        filename = "004879.ldb";
        url = "https://arweave.net/7h34CmTDDqRQLbN3vP51yqfMRSItUFc9_tjeKkoSHa8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dcd223040daf91561e9143cbe5abf34a846d0a6c78845335b04400d9b45fa0a3";
        filename = "004881.ldb";
        url = "https://arweave.net/rCSK92OOXK8eQvxgEYpPLxooOZ75xKcerDvTbISjF3A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0837295b276668cae7fdcabc0008de7862dbc42947ff088f8dbf38c47e513d5e";
        filename = "004882.ldb";
        url = "https://arweave.net/ptBC8jGcmA_gSiKK6KBrtmTtop-DS0xW3aabfgwMvQg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "25252100044653318ce8406e6b1c7e824625c2d463be7989e7ec7d1312fae042";
        filename = "004885.ldb";
        url = "https://arweave.net/6w2djmMjiIkPlNJhC97G5V9P-hcGuTJqU5MsWqRYnn0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4b34c1c1301af2d73483b18d67696bbbe4e07cfba4d00e58110e719883e27c5e";
        filename = "004886.ldb";
        url = "https://arweave.net/WOJvlqRzjXU4Cx8G_WspehvyiwDwPl2CyfVZ4ZfwkPs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f0574cdc9e6885cb419248595f1f561efe8268f095f31e6b447aca7c00168d63";
        filename = "004887.ldb";
        url = "https://arweave.net/Xb-TzvLAYUkhvTsGu4_BaVIZN-PNsjn9P9Q5HZcwsCw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "19618922972ff2f3282169112bb0e27f7bd219ed2774305414a7643c5eb1075d";
        filename = "004889.ldb";
        url = "https://arweave.net/2p2XR3ahuXCL3QXxnXdsOzv_XrTKytHw9RqQO540pjE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b9940b34df6eb58a8379b54a157b4f7952a7caac54f1f40e851bd25685bcacb";
        filename = "007628.ldb";
        url = "https://arweave.net/FWJKd5IogZduOzeOHBzyMuugZjJGiN6_o6k0f5IS9l0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0688a0c85de4425fdde69e1e688f259b8c5452ddd1882b450922dd39df0aa5b7";
        filename = "007693.ldb";
        url = "https://arweave.net/hL8bmYGJYNZI-vf6gKRem2MOjRWV7FtWaoDMtKwkBmI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f9b9a1906ac7ff45d7443cfe6a9aa7a90a4429aeafc8480b60cb95da42510852";
        filename = "004890.ldb";
        url = "https://arweave.net/QX4O5pfG2U_uZDwENnId8jCh2Q5U6eEk2_yTeaVCu1w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eb7ee734001de161cccf208f8c8488bcaff735328b53e0dc62920efe012654e0";
        filename = "004891.ldb";
        url = "https://arweave.net/sKCrxkxk5iOmTI2FJvrAjJFhKk6yNzhKgJEqy8dHScU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5f15b124ca93449a10c7ad1701cb9e597a629cc5cbdf0ff843214e3a6cbab5e7";
        filename = "004893.ldb";
        url = "https://arweave.net/m4fGVi4UteCu4_KMuQshbjlCJiXJMV9v0FW2hgtj2UA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6071920d7c18ff5810c96b0717b35506df00d8b3a48796b9ca523ac0724b93fe";
        filename = "004894.ldb";
        url = "https://arweave.net/PdHWNEQaCxDbBO514Yq9B9wEsWxtuUbiQUT1voNQlTc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "65e83ccc7b8838106a15f9872fa2d51601ddebecc919b1545be7354caffba4ce";
        filename = "004895.ldb";
        url = "https://arweave.net/CJk5sLUJLJ7I2wPilaQuYAlo01LlHgJNdLcyTkyI9C8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "497e63b739506ebc82fcc1777f224e929d30816c091781fad355f3e7850f9777";
        filename = "004897.ldb";
        url = "https://arweave.net/jozQzo4FsXaMhl09jHlVTWtoS0TuXkmcZzIlAm5kVH4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3be1d739bfc17cab30286593de9988607ecf9492a443fac1ea99fc3734756458";
        filename = "004898.ldb";
        url = "https://arweave.net/MRxyGEP5k4lkDFQ0PMKvGxFQluvlrqGaAHMHAkoSFYA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "61c82188b8ce395712d7c23e08816ab1958177b84d28694b90555bd0c198a1c2";
        filename = "004899.ldb";
        url = "https://arweave.net/m4H8UTHeu0WtGGupuZiT_Q6FKjnm3tPNxf0RnA8BHbI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f03eb279abb37bc9e98a2f24cc45b56636d6f58513c3f9cdee1ca9cfd1b0203b";
        filename = "004901.ldb";
        url = "https://arweave.net/-xOpnvYx6Yb5x78cB1qHg0v8MQy1oEDTarei4idRGvQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "194c3570cf08e0916b2372128762992203889a8fc81d71a5a5cf503af311a681";
        filename = "004902.ldb";
        url = "https://arweave.net/JR8y2x77_LRNSnUfGBmQTr1cuOnACA6aGleUZQa26TA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1324998994e47a7886f50277f97640ea69a35d9b7c5d6c86c9f3b2e49dbd074a";
        filename = "004904.ldb";
        url = "https://arweave.net/hDndC1vr6MWu8yPhPsIeHEKsyAf8O00nmsC3qY5-3N0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "13a36485343099b315b08953083e9723e569b3b902799cd0b463fe84fd333a67";
        filename = "004905.ldb";
        url = "https://arweave.net/jbJydqj3s5yU2zitXqbbWn-rAcPWNejbBT68us8iSsg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b79af903f8d1094f0c13385097b65d9d318d3da4bc5253dddd9991209cb03963";
        filename = "004906.ldb";
        url = "https://arweave.net/xOL-_RqAC2074R6TdvtuioFiN4WjAxAGMy4_uVvG5Rg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34dad649b848a84195bab3bd8eccc82847b86c966a7aad40603a83298a117739";
        filename = "004908.ldb";
        url = "https://arweave.net/3dJXnxRV6-_mrjL4uuV8fORaUTX0rwC7KzdwhXuF6fg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1de53e5e1788019a1dd1ff0f6cacdef62c495f5a9fd1c495ba869f5b0118044d";
        filename = "004909.ldb";
        url = "https://arweave.net/PA211585jSWj3CoRaVTyyHRGnIYUc09P50zEIFVAO8M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3f05ee6f80f4ec250b2a9a5f547af1d5205eef7cf60ff010a1a50418af98ae1a";
        filename = "004910.ldb";
        url = "https://arweave.net/AWrpLB2PP--539ma_7FCMAg-SghooWHU3ZHyyVgX7CQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "750cf17266af439cd501d6c6569f43a98e028d4c46c2269aae9f57afec52c8e4";
        filename = "004913.ldb";
        url = "https://arweave.net/vHZMwGLvTLt1gqfqMR_FEBw_6dB7mMS08qnPVYa6QH8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "368282fbdaabc1f55881667b4e8174957472199c6bc19b80aec68cfe2917a940";
        filename = "004914.ldb";
        url = "https://arweave.net/AhZH1WJPK7_lnvX90ms00fa95plnitMwGVh9BwCtdr0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2c5a79fdc4d959199ad1fe2bdc05bb22c9da08a3463bf600e39c05562157d25c";
        filename = "004915.ldb";
        url = "https://arweave.net/mZIwYg_25skcX9S-YHFeHh7uaAe67myjtMN3Ny7mJEU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d8f94cbf4dbbd356f5c5b780b1f9e6bc2a425614d9c1a479ff88c675e211af97";
        filename = "004918.ldb";
        url = "https://arweave.net/tZ3_KcJKxK5jp94q2w6oULVUyVTsXmJu3SPH6vlAMfM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "08c4217a8717ae095383f06d0db9c7952861b3f425afc9703231c6f3028e6a93";
        filename = "004919.ldb";
        url = "https://arweave.net/FyOz4W8HGNZdfhHC8j2y2kpyZTTIc7CrHxGmV93Urbk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "84b4d558162f704009ea845b28144df54e34fb99b6c5e147f58b52e80b39439e";
        filename = "004920.ldb";
        url = "https://arweave.net/VEelzU78sKrA6UeDXZ4Wf7PQL2S0UTcW-Et0Ih6NGdY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8c7f47fc0cee36009c40cc887bd5dd3152285cdd284ce427483adac14dacbdcf";
        filename = "004922.ldb";
        url = "https://arweave.net/ViM5d2LQw50T67fyoRVSqWy0jQDB5yLxiUdw8ubvEBk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "97665f19ee5b3060301fa70ca3a8f2777f9e8725d99adc117556b84d1bc9231f";
        filename = "004923.ldb";
        url = "https://arweave.net/iNOxKIEcUFKkjXf9gB--5GnKHpe0C0TEQBW9qDszIec";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9e4bc391e770708575c019af9603d4d0e3919d800fcfcea370f7a0b6e6d1fd93";
        filename = "004926.ldb";
        url = "https://arweave.net/qx8C_lzUZ0YcpdfdB3KcxqH1UXYeb0DqcYc3EU8L5NI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a01e88270ac95458952d1cf63f0965aded7e4277b97f003817993b09a47f0f4b";
        filename = "004927.ldb";
        url = "https://arweave.net/dEnAbHWMYv5gbtzusTrls1iv22DW1kC7UKtEPPzDji4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "03f7588b41276c0a48fbb5f4a60c2f71cd74a5ef2ec8c44f8255c989e4dbf2dc";
        filename = "004928.ldb";
        url = "https://arweave.net/4M6eh_Tlby7aBgwhkEbFOgcq6rrczPLRxlJD-Goy4aU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ed55fc33b7edf0925c96dace39b924e874ecf9544c78cdb160dc903afbaee6ef";
        filename = "004931.ldb";
        url = "https://arweave.net/mjidi6mM14n_-BWA4Ns5hjSpRsHU0JLtSyIuydhg7tQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "17f05636eba174b4444d4e424fb246c50d07bd207ea23aa8845853df9d868980";
        filename = "004932.ldb";
        url = "https://arweave.net/-wmKFYgYg0Od7OAE5AJo5uV0U8lRsTA1v1kElX69C8o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b34de8bab109e6e3a16cd7ba722140ecb8888f126a99cef7a1c63fd2cb9b2ffc";
        filename = "004933.ldb";
        url = "https://arweave.net/MLa3KnyT4C59GbNz7azra02_UAIVKxEc2izFgQEcs9M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd0a63964ebc129d9d2208dc42205f20e0d3f5de819c976e2b1ab555e56e4bb1";
        filename = "004936.ldb";
        url = "https://arweave.net/Vvf1JQBzJZ2eYR_n6JW-yZRr5QuH7mmFNBlgb1MS6O4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b9a90f8430a6a90bde0a0d221397e446c7beedd3417f77c8dc124fc90eda4451";
        filename = "004937.ldb";
        url = "https://arweave.net/b8Ake7dPr_zoimZHRFO3YqQ1mJTissvaQj9ne19uIRY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "acae16cc7e5162af528074e501693527a7563f879b5b1bcd3ae5e7a8cbb1de28";
        filename = "004938.ldb";
        url = "https://arweave.net/h4t6QoJzniPWsHfE91LD-FOxpJuSwImjYJg__AWX0Ng";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9a96c49637f4c9969fbb2a98e3513f04f0a80a17a618866841466b8217ebe0ad";
        filename = "004940.ldb";
        url = "https://arweave.net/gF8vKdohb4y4fc2AN9Fi3Ct07np2OZGfHEZ0QmxB_xA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d7f9e4ee3a4dce3ab63131df9f0b02df2d6aee1cc2db357ea7e530b633f19907";
        filename = "004941.ldb";
        url = "https://arweave.net/h76MdbZUN0cDbo-626-5ynrfsVn3puR6eV_Yj60JqKY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "46787425c63287da06edaf2cdbd025478d98a91d654af0bab5c6edbe50d2e3b6";
        filename = "004942.ldb";
        url = "https://arweave.net/BOJyg3omImLv4GX7SKAVWdMPlSsbt9TbBtREI-i1nEM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5cedd3d72f77bdeec725f1fb6420629ce756a4cb22166a6921f605f2ba0aa60c";
        filename = "004944.ldb";
        url = "https://arweave.net/JhNpOLh-FHCKd5B94op1KfppqclYw1beAt199nmtJPA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a484f6307caddac5a8a39490d0f3864fe02df7f63f8abc4922b853ef7e53cd8a";
        filename = "004945.ldb";
        url = "https://arweave.net/_2bQOO5YJ2bvcMQeJsooRopx0wCDOO5rY-20GzVDQO0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "531e88db71b311bb6e5b6dc0b51e702dd5847f2fade17cd41a2c1ece2e0dc1ce";
        filename = "004946.ldb";
        url = "https://arweave.net/gmWSMI32yR24wDREVOJpgZueTOgr2nKrTZQ5SONuOFk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d4c90ec10e6a5b539cbab37623b50892b861aa012c11137486c5f0cd10ba3d2";
        filename = "004948.ldb";
        url = "https://arweave.net/sdWXieGJ9y4FMi4T6gu9qA79a-jTkT29X-9L5qIK-3s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3927a182f2753d6eb1e45dcf07fc7933ca71255c7606201add3ce22ba6d547dc";
        filename = "005043.ldb";
        url = "https://arweave.net/XCnzR_d8dBqWvJg2PUm9bqsqhl58j2KON2tYt9-qr98";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7454c258a33d16eef58bc92c3a4a448e523a8c5be1cd8fadfce8aad52b557b5d";
        filename = "005044.ldb";
        url = "https://arweave.net/vIIf4NNxqYxMVfICsvdLaNtGnnIu6Q8etTxuC3j1VJI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f8f558f1a75f3aa9164785696b1a2dba105032b93d029f90d3891ede8da9a764";
        filename = "005045.ldb";
        url = "https://arweave.net/zMXfsSdFTEoClzAULY5dY4XJsvFYmZ-JjrV8Rnsy1Lk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d82a86819885713a90d06c427a82ab751b6dddda2293dd7391db18e0dd96ad77";
        filename = "005048.ldb";
        url = "https://arweave.net/ZAk3KP0gyXqIEm1ean5C0vwY9KPoTwNetYpGbD3WO-E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c8749e78109e0579429e3e3e4fcd369d996462be8bf8bc34c08b232494172736";
        filename = "005049.ldb";
        url = "https://arweave.net/Gy-lqQEIOS6UCxY9zhHSyn4J7Xd21XIAwP8FEXYbe2k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "007fd40af47d83682ea9e01397374c7a4c4d164cc6068ee5f9e746280eab3183";
        filename = "005050.ldb";
        url = "https://arweave.net/8Z8wAA30FOeHVOy_Aj3adk6uI9T1Zlspz91DSIVbYBo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a3ce4ec3e0f3428dc620d81481c993b8e70d4724f9824688e214ae5b6f5f3380";
        filename = "005053.ldb";
        url = "https://arweave.net/TaXnSpuhoqVels2yqI4zF02cUm-1bq3ag11CWhkfpkg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ac17e14a40eb857a73f5c4f64891d22eb21d55d12cb754b8a89cfe0e665201a";
        filename = "005054.ldb";
        url = "https://arweave.net/_vqSNDvVDN1R1JqPB1GlDcBuOqRsujkY6420UcHCmYI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "85f5e4b3373cd8ba68569e83a84addb6aa6a4cb9d5461fa85d372b1b98f67995";
        filename = "005055.ldb";
        url = "https://arweave.net/u39Xd4Cqh-OoRzK3kDqNwAih0_PFGBnw6e55DQd1QrA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d7ce10c0b7b775f04012f1dcbe24d0b1b4ee21eeb334138e0dff5c01ac9793c2";
        filename = "005057.ldb";
        url = "https://arweave.net/4XO0_vJfps3VLfiWV1hZFXHDqaY9y5gd0tSxJrHRlNA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cef92b6db914ffefafb2b9a95c5025150e4590c672111a654e78cfc032f1ef65";
        filename = "005058.ldb";
        url = "https://arweave.net/qFqGnNA7JDEIJOqgOKRUr_X81vYcI4AXjlQSMMTZdpI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "828bf5fa1a64cf9171f956ae9786d2b2fd025b4320344ada11b703628dd6fed5";
        filename = "005059.ldb";
        url = "https://arweave.net/qEb_u3lkz92ZjaDOIBqkp-zTrUU8fZ4BfQQVZV3Eris";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "69ebfa13c939e965443a5f6be48cce90f989e3f7cfca3a3fe3a8c578c238392a";
        filename = "005061.ldb";
        url = "https://arweave.net/qN97BYsIWev4mI-sDvSWNgML6A3ZH5EAfkkj5s4gkt0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ff71bf04c913e15a0df240767a3ed2af249c5d45934e4c618d70ddebb7563c64";
        filename = "005062.ldb";
        url = "https://arweave.net/OmfUuhssvbqRDPaFlWrkN8CVpT904JZCONPOg-7wUIM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b0734672cc51a20624a57d1467a9efbb4e82c0f9da817ab504154cb8840d2e78";
        filename = "005065.ldb";
        url = "https://arweave.net/pM9QM8WZbsHzoc_rRReIVUWxaFHj7RRZI2Befknj1ow";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bb143f96a41248233c63c4a116c8f5dd37c26327dcd790ae57e960d9feb97fac";
        filename = "005066.ldb";
        url = "https://arweave.net/hfZQ8NBgMjM71ZJ9lr3vb9MKa6g4BdrFetz1zAlhq3c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e7093ffd517778ff022b2a9d20efcaf6406b68abeac73ca803706fdd24660385";
        filename = "005067.ldb";
        url = "https://arweave.net/aSCu3sSFJerFyHYN4moPAArIaxmclrYJVXJ7SSjH5po";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e72b4bb86b73f647b982c201fdac04771f0165a61a90f8b6a3f6f3b03362dd10";
        filename = "007633.ldb";
        url = "https://arweave.net/iHZ1aDN6bxxrp7wQIk1UBAXsT10yDizPlfPLplz_xDg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4f1a5076726595c7708ced367f96f1ff9784e58a7569fa56c64de971cd9d457b";
        filename = "007704.ldb";
        url = "https://arweave.net/IGOlrxnBy5dugblFAzC3W-_jFaXonxa4BOzZiQPOBDg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "673decf24b106b615ce08e00b02d0c728f3223c50108822c9272084717fc64ea";
        filename = "005069.ldb";
        url = "https://arweave.net/XqOsKFmkYwWytn9GTD1Jhsmhjixc_F-VPlp2EWpcq1A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e9f7d3ae91d5921e5957e6f8594a454af8fdd71acbf005b4c76b75689024c6bd";
        filename = "005070.ldb";
        url = "https://arweave.net/b1cJsmmukF17viKWmr-D7U2Q221VgSJOzwvIFRfgzw0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e100a7603ecc5f10982ad979d6278edc76ea6f959394dda2dd5b850c365bd09a";
        filename = "005071.ldb";
        url = "https://arweave.net/yQ_DVxtzbnsGTKzh_p9_ViLkuLbOQBow1q_ma8hcTGQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c20c70f6f773d2c42528abd431955b2ef405029872987c444a650726e6529449";
        filename = "005073.ldb";
        url = "https://arweave.net/_GIC1Dmg10aNzk2vgVUAjYs2rtdxAizNbcY7aWzq-7o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b0ddea56fc44f9975ff69ebb653b9fa65376113bda0ccb1419892cb4dadff0ea";
        filename = "005074.ldb";
        url = "https://arweave.net/OQ-2zUsIWUgXFMY7VIABxZvL7ink_FvW6pghmlQjGrM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e7b59f650b172ad8c9f50057fcbd3950420fe11d26aeb3533abab85b2622a91f";
        filename = "005075.ldb";
        url = "https://arweave.net/IiWIu6NSbj1S565A6eNfo4K4FhOhvcQtX0oSbiQVcLg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8bfa3a1506f81d26f504104c8c6bd3b4104cb6bc6166a17c92247382b5dd577d";
        filename = "005077.ldb";
        url = "https://arweave.net/iaHnyec-poS15qNO7v2VmTDV6Ale3L0Ivox6LMJSHqA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "af119d646aeec80072b9e40522a757c6babee0d85f94203db77348020efd2ad6";
        filename = "005078.ldb";
        url = "https://arweave.net/aEcz3eGykL4qpTV6LiFMW-hM0YzfQby7c19YLPHoJss";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4b2cfc41388cb79c1bd5863c20c5c28fba8f56fc5b8dddd6eca333a73ab491cb";
        filename = "005079.ldb";
        url = "https://arweave.net/HWHBrpRx8_V_-6ApOZWMLxpJgLbJiaeS2SC6o4Ix9mM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ec32094b0ce1ff51759e4383940aaa4c48524efd88cabbb2094ec4a64eb1891c";
        filename = "005081.ldb";
        url = "https://arweave.net/9RWy4V_DYfRKQWpWMxp_dkR523otVBx-8miyBokQggQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8ce2d7a1290115a6113d43eb0c7b7bc31478877b4a94e24b1b6e8bc48cebd21c";
        filename = "005082.ldb";
        url = "https://arweave.net/VhQ3NkgJzDDDMV3O9BMsudXgZHQrUwk2vEwx8-7RxD8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a700030990b9fad8da63350cf3836393075ccc4491f3d7a2cded5424a7d98705";
        filename = "005083.ldb";
        url = "https://arweave.net/HgO4138a-EtgQvFaYF5nFC9JCM5klGj9bPOxYxKwZGI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6271e0aed4d28d76d44232cf63d1459a0f4a71a61df1f1b2be0f7498bd7cea5e";
        filename = "005085.ldb";
        url = "https://arweave.net/fkJ6Jn7Do73hbedkylxP1qSZmDmi1l1oxWGr1Er7_Uk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e2f3f9090c18d510cf3d0841c8b6252ff9c754edf8265487eb4576c20f3e7f94";
        filename = "005086.ldb";
        url = "https://arweave.net/Ah06ZBMLo3KaZwrKEZRDfjmhNRGS2eQl1SkOMP4QTl8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "80d0377ab8dedd356e5632325a507325e690eea1b649428385858f8e0963139f";
        filename = "005087.ldb";
        url = "https://arweave.net/7PsswJjBJwpPihh1L_V1TqZxenEnDaXXDgoV7K9CjVE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0b38669f22368086da53e121fdae3a5eef89f250c4335149a543cf6be1c9de5a";
        filename = "005089.ldb";
        url = "https://arweave.net/o7j86ZpTrqhMSI7-SV1GifpUxCXyAVfjuPoSlKA5vPg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6c7c703f20626aad640d035b3dec83db4dde92c23fa88bfe811af645d3bed06e";
        filename = "005090.ldb";
        url = "https://arweave.net/qpes_C2e0VDzrJx3-3VC6OWHEhPPhI6CoLS3CCqX4kA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b26142e401cf1b168fc640320ef903257bc297286bda145ba6a0fb75955ecea1";
        filename = "005093.ldb";
        url = "https://arweave.net/2E2AWnI0qsfGtjg59WS86SZkIuV4YUK9iHYocUaxI_8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ff4e01e3a7e80fd3d2cc16b3d2e9792764c77408271c134937561c7367afdbdb";
        filename = "005094.ldb";
        url = "https://arweave.net/QMOS-9qKdGLkTb6LyYtNW-jugfDQ9KsicpViUb7n4hs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c68452fe94c7fa6cc5a625a0ec5805c9b5ab70ddaebf1f75e33e14726b0e89ee";
        filename = "005095.ldb";
        url = "https://arweave.net/bA43cYcUgpxLmKYT8B8o8QLJBQqrdAsuNPSKucJNtAY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9ae47fe2bde035fe51d69093e78bf3a16816b63fa683505aac39cf39b19e77ce";
        filename = "005098.ldb";
        url = "https://arweave.net/H_nDcZehKTPHgvb4yMN0sR_bXTRiYTB-xwr6Ypkrd-Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a62933fb251e45540f5711492a838a4a8062d0f201b20bf279f9b85509c5c711";
        filename = "005099.ldb";
        url = "https://arweave.net/HxX_LgNtkUHexpWgkEOwn4ALbdTvlE7sFQzQuFnoWBQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "09d22b978083883ae6454084d3c9fc6f51ae10fa5ee5498f5812a88c80a3b99f";
        filename = "005100.ldb";
        url = "https://arweave.net/SLH1Jc2wUx1-joFXE-EQWz5D7vzWcEsJLCKpCZ6Hcho";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b1d381d9f1e2d3ff9b872b6621eb9eebd25909e2a7fd5285482edcf3d1d7d326";
        filename = "005102.ldb";
        url = "https://arweave.net/2pdt-GlVK3_4MVmH1BKDJE_3MZW6ez5D5Oaq888rswA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "adde1aa23d68d4dde4f9ac702331f8eed703904e479cfc009e0883f88e6d50cb";
        filename = "005103.ldb";
        url = "https://arweave.net/MNKy3n18rU2e1UVCAjV4_qa4nkLyQN94o7eXEINLCMg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b7286a9a8aea16ebf13255eae6354ef570555c46242cac00e644073f01cb17b2";
        filename = "005104.ldb";
        url = "https://arweave.net/z37x5vk9AOUpBw9indCsRNq2G4PXU3UMQBIcD9y2GDw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d7db706f79421b7cba449d4464a67b530b19f2bbadb7f3379c2fc1b02cbe3d19";
        filename = "005106.ldb";
        url = "https://arweave.net/1Td8B6VbFBbvqIW6q26Cw6-5AjQi2Ed7viI-VaLm-PE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2c1d99590cd680ac9bc7dd60611827354de30a7407570c89b8376d3dbfb25f6b";
        filename = "005107.ldb";
        url = "https://arweave.net/t2VxDOURCJw2XetFQk2Xhtz-d3oxJ_C9XYtaYq5bE_0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d083e1f3fa2574eb41a14b693328640c2f6b2ea3b1ad93f286774b8bf02aeb99";
        filename = "005108.ldb";
        url = "https://arweave.net/DaDzVvpoaYa8LH6C2Vjhpn55cEtwVYxWPZpuruaCJYI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1437180b994d1f5f4691d650d46206ba7df7d1fd169eae0934d5cd06471bf339";
        filename = "005110.ldb";
        url = "https://arweave.net/KFAlDHBvVlTozpsxVpIOLMXU2zdNvjSyUAo0doq_RgE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cf42dbbe9e949ecbf420878dffa174af9e1ecd8418a6eba81a42cf8c656c6561";
        filename = "005111.ldb";
        url = "https://arweave.net/s2Gjdq1qRG-41hdWxIBniy0olP9nK65eUICXxaYwl1I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ede9625f4de9808bc1590ffe22d4db5d3840d9fb860dbffa62e5fd588a65588";
        filename = "005114.ldb";
        url = "https://arweave.net/wPfcK2v4So9SxLmOVxBO4ZlX4Kv0jN-lOYIeKNFdadI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a3e003e605cd696ddf1ea7a06e65fb96f80321c9e9cb8d071db4f5725e3592db";
        filename = "005115.ldb";
        url = "https://arweave.net/YCLoOZ2u8VIpeRQSVnxkSHKIFhsj1crw9iIvT8tGviw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8b82654524765f6b2f74747067866454a8e5b6f7d0374ba6b6b35836e1a68467";
        filename = "005116.ldb";
        url = "https://arweave.net/8rIheZaUy8Ms4DleP7T-DL_sqvdV2W2ECdXN6r2Bgf0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cd401e6ca83f4c96f96db70c523c4614ac220d03d5ddf7c6a1161704b64e10af";
        filename = "005119.ldb";
        url = "https://arweave.net/MkM9OvORrkUx9I4_qAy0vknLWFk0XFWg1RfwbeWbGAA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e4812c4c16ba333436f49a4225456015e47e6ba6895ea244879287f13a80ef37";
        filename = "005120.ldb";
        url = "https://arweave.net/SLBcgGQlLci1GXJJAneJBNEmaLfznE4Y8OkhoCSd1cE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ce7fdc685c8989d739d3c0d4436e962222e6d4dc6b4c293513af1778ffac5891";
        filename = "005121.ldb";
        url = "https://arweave.net/snwPAl8-YyXubtLd1Kb3w4Ojr6O1MPuK8-IwTtmmwKA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b3bd23365f5e2d103d43aef8d3d5001ce62558d5d2270f6d7b4b26a44f9149bf";
        filename = "005124.ldb";
        url = "https://arweave.net/mAR6gjwqVyjvjhdKr1QwvWp4-aQ8YWoDQKFDaL3PJ3M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f1eceba70647ab7265655311f1c577f89accd8fd931bd64545a1586948bc8857";
        filename = "005125.ldb";
        url = "https://arweave.net/60qeUjvginjibYBBJtM0n7QuO8aJgLoynNdD9Tg1Wjs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "751df66f33d0b2b740f7e8512db3c54ae9552c07c7ec7890ac81c7fdeba28f6c";
        filename = "005126.ldb";
        url = "https://arweave.net/1DJlQROAbeDR_NYZf7ZHb9ySeT9T-vKZgFgt5XBNtq4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1e13ccceaf9eaa25a1c6ce581b891f870644bfa3b6ed0527204f23e87b46b508";
        filename = "005129.ldb";
        url = "https://arweave.net/Z2AE-6Zs-JmzCWHpkp_4Q0bO5bPTz3ADD2aiAUI1M6o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a4f62071791dec64548b481368f79476791dd0fb7b029adb34d5b2f8b8ca23c3";
        filename = "005130.ldb";
        url = "https://arweave.net/P_NIaIwB14OCg4uPvo22gBb5oQY0ZARKkX1hRe-LN9s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9d42343e2c83e8a2a0d8f9811854b38cb6a920c42094ce5066c02caf4833f5e2";
        filename = "005131.ldb";
        url = "https://arweave.net/i6ckWO9SR2f1AxsOy3hiEMv062D8I9XFZb5cQjTA6YE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "07e5c6299f935c243b60f89e01db2977cd5d0a38779062561d9516abe8f545dd";
        filename = "005133.ldb";
        url = "https://arweave.net/E-fqg4ZeoQx7_CdyxCxqxaoBKfQpf_7FR-KvMe1qkuE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1007a7c3cee1a92d56ff8d23b5a22825d7dca243221d18c1aefc4386da104c90";
        filename = "005134.ldb";
        url = "https://arweave.net/QtGaQUAs--oVlq6ma3ui_GtB-MKk5IFH7aye9xKrQ5E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c429b763f9f9ea80b16b55354b5aed100b8d4894be7ea3b365b07becc01ec926";
        filename = "005135.ldb";
        url = "https://arweave.net/jOhQ5gAQwjn_ev9yVYxjgDYRTITMoAOa2dAeyQ_wVLg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cf67783bf97a55be85fc336d7e3e9fd1044f133b3fc567f3e5cd98f75ab69ee6";
        filename = "005137.ldb";
        url = "https://arweave.net/5a0JJmedCmgnJeSFqEHgk5DpY4gyj5etpEXxIcuRfHY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3c008203ffbf0caba0f5df52a2e28b5532cf0504643e1867887847f620261736";
        filename = "005138.ldb";
        url = "https://arweave.net/njkcvIl05zJ2Wumm4p_NwHU2LPTJdfiGqzcrlXWvQTs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1db82fa5f2d96a57b55bfe21e5e3712ea2e1c7dd56e6a622980ee6cf450ee997";
        filename = "005140.ldb";
        url = "https://arweave.net/FANb5JqIjtdEtA0RNQ8NoK9cgDrKfvyeW-KG4UkrIEg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8f375fdf5ef2bb11799a4aefcc6ae46ace94b341fa012981d0b3de3140db37e4";
        filename = "005141.ldb";
        url = "https://arweave.net/XQeP451CdA3ldmQ6PR0nQDUCCwqMtDvfCmSAeyPthXM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "30c1f828e2e67c22bb5c1d9b8480c83c1b2429fc0126c3c64c06b5f0d5658737";
        filename = "005144.ldb";
        url = "https://arweave.net/CxOf598gu6aylsSliMSrCCO8KTN3dCvx1E0ReILnb-o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "172168a9f1be27221fd5dec2c585bf7b1fd32491d3be330fc86ab2b6ac7e9210";
        filename = "005145.ldb";
        url = "https://arweave.net/n9JOitEKwOTLX-8mY2AXg99Dg9yjmYJECtcGA5Du26E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "70da5723f528b5bf54eeed953258e4dc3c6f64cbfca4dc75083cc90cb81b9b69";
        filename = "005146.ldb";
        url = "https://arweave.net/YIsqneZraoR1q-RdilqCEnXdqzV8GAHryyka7mV0OGM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e13871aedfaa6d8f679498620d8379455d6b462d91eb7d3e934dc91b27d3bc0b";
        filename = "005149.ldb";
        url = "https://arweave.net/W_5CTUqUJFj5ms9GA51GpA8_yXVp4mBHmOrPPli6XB0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "de34f6c2c66faebc71906344eeb01352a59db308d46bc990d1efb104c10ec564";
        filename = "005150.ldb";
        url = "https://arweave.net/FhhGls6W6Mb3dceKnLPSOQZNBQB70atFOy39Ncdqc7Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6890481d80b14d8c0fb6c073fe648b5da7d6db569f7d9f8976df04ec76a17723";
        filename = "005151.ldb";
        url = "https://arweave.net/hQ0N6CN6diaPHGiSFAiItaqUmnvY9ZOXuvX6jQzv29w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e94fea3f9e2d9c9ee842fd4c092fa61127cb7dd7825bcaf2873817ff0366fd70";
        filename = "005153.ldb";
        url = "https://arweave.net/jJe0xwu38la4ouBY8XbJkScOxNQ6vR6QzAgzFhleWzc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4ae7738dbf36cfa98e2ce9971764a5ff07ccc55b8032c7d1953d6b2fff19d95b";
        filename = "007638.ldb";
        url = "https://arweave.net/w8ZDTr4oBHWpe0p4MlJck3USIkt7HfW1CTkeQ7feDiY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a3207c87925fef75cb71fa39883496e02faf5b928277c0a833d29d76c6846a7d";
        filename = "005154.ldb";
        url = "https://arweave.net/IFwjO459_IjTEYj_7XOrRK1KyUFfhXGThV0GMTRujBU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "918f52cf9681d4b5b2211e3c35fee4ea14a9124b03dcd0247984dc3766f839c9";
        filename = "005155.ldb";
        url = "https://arweave.net/wxDJOk4BF4KFNBaKxC0p5PjsOFYdgsOHQO0kYDSHnNI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ab9cbb2c3eb9f15195b34b6cfaad4728a1db87d6775f8dd86747a9bffd1cbb2";
        filename = "005157.ldb";
        url = "https://arweave.net/33Kjk9ACukOQQx1GcVkZytItdFbS_k9Kdr5MgU3iO5U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "30ba14801aa6e860293788cf063b2ded07855b4ed96b1a3f58ba683695a7d72e";
        filename = "005158.ldb";
        url = "https://arweave.net/RdnrVKxyMq60DEhQkswKcCq5V7xE0ETHD7eXf0QupUo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ac80e08951d4a4bd962a34dcfaffd5425dda20d621d3d5635f15310d3f062010";
        filename = "005159.ldb";
        url = "https://arweave.net/_M91NImSSAxEILsix6mNSm1nPNKeCDYZmZV8OfSEE5w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "882bbac7c5914c30def93e4c46e2fc2c29428dcf2f748345a241469ffbb67f60";
        filename = "005161.ldb";
        url = "https://arweave.net/8bq579kerVBxWADAyJ9so6yM5idW3V7JEE5BJK0z6mQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "54161fe3393c8b79f4e98779e77b05bdfe83ca2bb34ae45e8f22054d9cf1930c";
        filename = "005162.ldb";
        url = "https://arweave.net/xUyc1fGjn0Q67yX3DeNerpP7a829zSPY2nxzF60955s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b959b211299d3a51d66a72650c8bde836f74316ce7feb6edbc39262e86f03bc5";
        filename = "005165.ldb";
        url = "https://arweave.net/l63tYxTDoNRZUqBDO343VeqTRU_-bKKuPVGNMPDo9-4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c020f066158bd0ca3b42b203168268e52842fc079c0a5c2af11f32fd4ff05117";
        filename = "005166.ldb";
        url = "https://arweave.net/swWI_XpMwfTIDVFQZ8oLCHz9BkwHe7533G3CTbP2QOQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "90fdffed7254830ca9073728bf11ac1dcfc44a145d8c42979ca95121a935cbca";
        filename = "005167.ldb";
        url = "https://arweave.net/oTbSuN1AB0rZqamNIQ4LsfG46CoYqKNB-o0rcAN0c0E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "caadb3991e318e2c168102e670b36f02a67b857b6053243e4206be21fac49b93";
        filename = "005169.ldb";
        url = "https://arweave.net/A-yb-1cqEyoF6f_GeY0ZBOIjXT69h6KsSp8uQpc6HfU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "30cef5047cfed2b639412f48dabe5f5ca38a7b4f4c2609989ec93e894caeb830";
        filename = "005170.ldb";
        url = "https://arweave.net/AVhOoTSqgqAVXfGOea9fAmDbr7Qs5kkjMLU9Y8nG8y4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e405178d0fa936ad59231244eb9997b2c7960f692c957b34916a3fe52bfbd12c";
        filename = "005171.ldb";
        url = "https://arweave.net/iZmkWV3ZfR_9L3vY2dMP5-Qt9IhCYK9KEO3Bek3sWBQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d158a3afdcc16982d9e9458ff0b3ec3a356038928d99e66722ecdea8a65e3e31";
        filename = "005173.ldb";
        url = "https://arweave.net/Z6E5UClf-ijFdrgdQ8H5m4DPennmjVIjytWmjDbYKvY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "09586203bc6ee38c1cb868bf27ad22cf2ded4c459404c313161e3c0d051f694c";
        filename = "005174.ldb";
        url = "https://arweave.net/ur6WevvHdzM4ld-2qqW7z4DLpthyZ5wrNd7OSp8n18s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34d43a4e9f35f427cf76aa8bae6f2626b7860d021f249bf3c942af3ec53bfa02";
        filename = "005175.ldb";
        url = "https://arweave.net/l58WMLbljaNV_sHOOGOSnGlhPtUdotdH0DQQbNdlZFA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7d9493b6ab51815c2f331fd4b44bb6ec3cf0bdb92bd2bf7062d40d458a437a73";
        filename = "005178.ldb";
        url = "https://arweave.net/QGHfkQwUrBl2Zh9q0FZoeBZ5x7Y_TzkTy7Rk3J7K_FI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c5ee4728742c958bcbd6f9437f40a7387f0701ff01da28bf8f4e8ff322e0f0b7";
        filename = "005179.ldb";
        url = "https://arweave.net/ne-Hm4dAvIgnVrK58dA_kt9MzZtEY5E8-sivCHAU-CE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "380ac777e6292aa97bf224633118f21aaecdc515741d4ee66fa981bf8acbd5cd";
        filename = "005180.ldb";
        url = "https://arweave.net/hJ-x5fYTF8rIa6thoCVGXI9OXT-4FMtNv9pDeUZpXe8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "892cf76b12cf589c5612b91bf322c76d15f731f8bfa0a4a4e81c57bdaea4b44c";
        filename = "005183.ldb";
        url = "https://arweave.net/P04rIOR5imPQKPvQZoyZNcNcg3CFNIl1fmzkPFHqib8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "44ec1f9b742b3b33210eeca08ccd21cd7fcba9c45138bd8e17756008a8415408";
        filename = "005184.ldb";
        url = "https://arweave.net/cEyDeKhY49FoWp5CBWoOio7RKsvtargs0yCZsRa0His";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7d92699eca37602b1c2d748844f127045873bdfe27a647345c682cb7558d74d6";
        filename = "005185.ldb";
        url = "https://arweave.net/ztr0ByCjTzbYCtb5mz9Zwwo2gplgpX2Um83P20qWvqw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fcb44f8325f890180fb52c23f1ae8ccdf7b2bcccd2d1219ac87cad96559aed39";
        filename = "005187.ldb";
        url = "https://arweave.net/PgeTbfXWrQBhVD0YQDPUeXMA2dEERjV200-nTVD27ps";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5d960f1d6b292b26e0b1b94f9be650798a13de8e841b9c6bd6598271693cdb16";
        filename = "005188.ldb";
        url = "https://arweave.net/fz6lwkclT22h8d7EfWFoCssNQ1ykz-Q2rNGGoNMcfKQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3c50db5f62bdd877a4905bbb0d23c114995238a573fec3403ab5354aaeef7d83";
        filename = "005191.ldb";
        url = "https://arweave.net/MCNE2zxEI1jxON1rd1b-eIPs_saXsdkFPSSdrDnnq2M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "186886fb89a92a92dc335e7d5d53c2277fb5538dae68d1115469a031e3526f35";
        filename = "005192.ldb";
        url = "https://arweave.net/qbLAYUHSsGbC6yoNKeY7YN7QbEF3HGjzqJlOd8R2KiE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "246face4fe8aea404d1d1b2d205b18080994041e93036d70e0f537c9317c8bb2";
        filename = "005193.ldb";
        url = "https://arweave.net/iQj8q0pZL05ib4mga5ypNEsk3nNVHr-xhcr5O2UKfOA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "afb1f4a389e175104ce5eda442af308a3ec3bc7296c1b57bac8ab3146bd0f688";
        filename = "005196.ldb";
        url = "https://arweave.net/8uw6sNwKjWCMvAdbNuw_2-gmuCAZjIxcMM7ge9In-Ws";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a0fab143a0aa1726459c0062da15047cccb66449dfe21306f641580f5d281d21";
        filename = "005197.ldb";
        url = "https://arweave.net/j2u-d0LcabS1LbZOK5CV5iurI-5FCG-5JlV7hs0bjQg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b87c1fa90e43a5776bb5e97ecce8268bfdcb945f71c5078ee8301f261263b8dd";
        filename = "005363.ldb";
        url = "https://arweave.net/r_vVuTQ0K7ywNtT2Ju_jEC1QX7rPOGEyAQUR2Eu5qq8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "38e058409c3e921943f0c32596cb94d26abb5ba829226c38da21b2c91151038f";
        filename = "005364.ldb";
        url = "https://arweave.net/eLMmUBga0kljQTxJ9kNNqS5wB5Pn2bOB1AJuXiwmXko";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ec2a6f9c05b344c65f454995104a774911ececb06756bb44748cd67fb0808b42";
        filename = "005365.ldb";
        url = "https://arweave.net/UP9MBQsfPXE7l7sRJRtCJ9KW6aV3OatZbvyy9r1cLhI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a0c7072a22aa49ffe2e79f25b0e5c200b27aaa4ffc9f8917ebbfbe6c51ab5dae";
        filename = "005366.ldb";
        url = "https://arweave.net/fri-jmltCpVkO5NqMRHkIaJqLDGowWJ8JEEjjNSxW1U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "586430c20e4cb63cbc3b80c98211f707fd7cce67a4e10c99ecd5c6b5b0363ffd";
        filename = "005367.ldb";
        url = "https://arweave.net/9DgTMxwC6rgPLPmQj-CBh5-8x1gmb-r4ntDeGk9kru0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2caacc1bbe976e4508f31686f64751088813e7d69e517c28e4ecba1de557a96a";
        filename = "005368.ldb";
        url = "https://arweave.net/WCjSWkBPMdc7vIu9YkqkttL8xJ5HfiPFCcgSfkp0i7c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f14bad8abe323e61b1fc20e7f0efb4ce5b167379803ecf06c5e71965235bbbeb";
        filename = "005369.ldb";
        url = "https://arweave.net/z3rm5aLdjckq_WOGUh8OAEw_a41juZDkLZQ_FybTUdQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e31e71a82a127927c84c3a126581ea367840afb0a86faaa3bd38fc4752dde52b";
        filename = "005370.ldb";
        url = "https://arweave.net/pQoaueYqmOK1vtYqA3ecBSykAzmfaXaY1NkUIimBCbk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2e4174734ee8f3de440769bf94c800a58c8d1252bace8726d7727fbabde64758";
        filename = "005391.ldb";
        url = "https://arweave.net/AS2h0q4rFdNsY8_jRXGE4vsHfNngomJgF1QcwP-ahJQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8452a076641ce8731783d601600685045c744b50a7888329ab82c27a63639268";
        filename = "005392.ldb";
        url = "https://arweave.net/tcj7064iszpYmH8yhlcyLqqG_zDeD2KA1qQPXed2f9w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7b40d807ecbdc898250090ea8274aff62774669d0be5f855cfab38ec8e161f6a";
        filename = "005393.ldb";
        url = "https://arweave.net/GrQnIaLk5JA3UBuEXpR4vOYm11uCpT6OTy3__OPiK1g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "07f1b743b8b5208c715a4f4b207433221a4c754f814e344c473bf0e97aa22640";
        filename = "005394.ldb";
        url = "https://arweave.net/zAk7j7qx2v9Rl7FZ8HE-lGR-Ck9ttWQ85L74abHWDK4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7787b4e26dea4081fccae9a12fb1a90d43aa7295307df9f9675083d997d20f05";
        filename = "005395.ldb";
        url = "https://arweave.net/71U0shCDY_91ipiQaugtGOUs1Kmm2OUx-0lrGYP8ofE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9d7cf442618c9b9db0782404b5f9acf7783d3a7a26edb5cdf206eff1899e2e6b";
        filename = "005396.ldb";
        url = "https://arweave.net/IEXEbBh5TxHyna6iRIt6Xpm0KyYMzR3A2N-W7ZqMqTs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "644132bc0d318566effe1671f37057a434d24048d5c2c048fe01f0c43a04170b";
        filename = "005397.ldb";
        url = "https://arweave.net/kWNknADWS8XHYAY3VRDLNi4nA8TD1VxwuAl3LT5cwPI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cb71e4d45055be1b845e45d5b5983242f40890675b30677e8c61c7b9e3508fbd";
        filename = "005398.ldb";
        url = "https://arweave.net/lPXRqoHY0DBWda7-yWTiNyZnj96qcE7aPjZPDkD3C9k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "593bb4362c3a774d20c99ab24ceff14b34de33265a5b1e5ba1e296fc4069c2a8";
        filename = "005399.ldb";
        url = "https://arweave.net/9_xNlzqvuuBfNk_GKwYjOOIJ7RdEnsRexL4c0u5-Aro";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d353b0f6eaac7a93f3b2927eedd8d8e7e990c149c0f4a5d1b39905c4047b02ff";
        filename = "005715.ldb";
        url = "https://arweave.net/4WoLJvjeBVjZioBipiCspUhyAW8SrhtItzEYRui7h-s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "94fcc26f139a84146b475b5a1ceb295a91c45ee67f10ffa96bd765ceb94ae159";
        filename = "005716.ldb";
        url = "https://arweave.net/tS-M0VwDKPUjOjNu5nK1Ys2GnPe1kKn75EhiusZO6IQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f22ed9003dd5bd6ae29c34a50a8090eb99906c3db4fb0a01c2be2c210523c0e5";
        filename = "005717.ldb";
        url = "https://arweave.net/-caOA2wvC0X2CRfhk_XhXlsQLVEFKF3GTIpyW9hA_s4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5ec03ba1e45e6bafedb6a9a79a1f186923055519fae2db06843e743123906080";
        filename = "005719.ldb";
        url = "https://arweave.net/tY3odp358hkwgLCzj0sMCRbSLOM8Y0QRWXwNhVMilpo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "45589b97a49134acb8d1983002432f30e1a9ee45efa75a0661ef9c325b4293f7";
        filename = "005720.ldb";
        url = "https://arweave.net/ANJSVmrskIR3Kz3LbWo9BR3Cl3VHNeVCP3GKXvcQ1nI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ba5fa33362f10bd483e21f5a2a441585fcf1c21de36f85be4bc11c2bbb0771dc";
        filename = "005721.ldb";
        url = "https://arweave.net/EtEjRi_Ft5oZrkZQxTMtnLx2ZVik9rkYtMoHMR4MAj8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "526eefd207ef9b120b2f2868c7ef488b12e0a5f0ec46abc471c88951dfef57c7";
        filename = "005723.ldb";
        url = "https://arweave.net/k9rbrGAyETPhBPQPTzaxSLM0vwPKlBGhh__SbTZgGeo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c1352930e8a65b884a85db8bc74b92cace9c8a8b0561ebc96640bda7080cc6ea";
        filename = "005724.ldb";
        url = "https://arweave.net/tH4fy9NFGjzfWMlhixha4iOP2tpfL_CVskLDPvkvj90";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e0369b24087fcf1d4254ce49f30e78e91a28ebcb8ef982aa22ff9d4314946f86";
        filename = "005725.ldb";
        url = "https://arweave.net/pm2Nvb9brol2fuzyxuq4B5qmHW9Djlc5EyOzYaImKA0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "711ede8435eb6c0a2a8ce975f0550230f67713332583cd7081d7cb0a35eff451";
        filename = "005727.ldb";
        url = "https://arweave.net/nfng9AM8kYDqpUEGs3iZ4prAQBAjj-JcD3g28rcHpGQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9036a1a820be279070a322fce9d4f308111a9b236831ea983ffc7d0beef4d297";
        filename = "005728.ldb";
        url = "https://arweave.net/xPpkcsJEPnPiLo5Iccgat6ib1PbNLlrHJ_KmmmDhYrA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "43bb606a92bf1f000eda5f07f2afe7ce32f45da4b1248f2c25dd52828de89d31";
        filename = "007641.ldb";
        url = "https://arweave.net/Is4UUADrQzknbAxWwvoPr03g012bjpHoDxeh-YixsFU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cf2ce948c8f0661971d31ffba2a298a109d3c1839cd749dbbd2a8d25b1370639";
        filename = "MANIFEST-007521";
        url = "https://arweave.net/W-yIl6SjLUSehOZMSz2AP0za4GORzhoIR7-OEjYnowg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e512de1abc878838a098b06b8b857481a94666a20d14a2b81bb74e4bd181d9d3";
        filename = "005729.ldb";
        url = "https://arweave.net/Z-_hiuUAhXVGzPtuhfYwbC9OPIa5C0oV754KsXb7ER8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c102196625ba4ae179c60ea42d80d228b524a6aa05484eff5101149d63b589f2";
        filename = "005732.ldb";
        url = "https://arweave.net/XLvleGpj2Fik7Lgi9YL8A6AWqZVaN2NKIJuFkXadveE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "771182993c532051ce98200ee096fccc49c72cdaeecf200eae334012aed78dee";
        filename = "005733.ldb";
        url = "https://arweave.net/2jd4xHOw1EhVsFTqilAkx7Lh2GAPp6yoxbSeBP-ZxGQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2a8faa10d1b3105c57ecc6bee62055ef23ed88f1702086f8bcc2f8f34c355bde";
        filename = "005734.ldb";
        url = "https://arweave.net/UVIwMDYqPGW7eU9mRGvNYrXuIYGyjkWaSZZdffLFLEA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9e2d68c9db2001fc2621c905c51bcfbba834f4b0affe8eabc408b32d129d37e9";
        filename = "005735.ldb";
        url = "https://arweave.net/4PetEpeIp3HOGL6eW88YSnNyATllJLy-BMegsBLXnHM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "663d5bba7e4863a86ff7223731c6bbe199c065bb858058b3984cd0ccecd24d0a";
        filename = "006232.ldb";
        url = "https://arweave.net/BS13BfQLXsnMgPGZ2l75oOE6OAMLmnFOGOibzlaEZlU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f6a921aaef9fa8d167210a194421b3d05ec58e29f1931d1553a2b3567a5e2eae";
        filename = "006235.ldb";
        url = "https://arweave.net/WETnCdKDvopmGk1VlInW5o-P5Y7PST4cmC6o57ZYjHk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "423070452cf34e946eb0ee03425e1bf48ad01923459e0958db3e8891c1d388c8";
        filename = "006236.ldb";
        url = "https://arweave.net/2s6oj8E46PhOtdXV_daaiwNLwx0slVROam4DbG_luHY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8ec2e81b9919f5e1b4e7e2c8cbf4dc17580d65658f6467b8657f9b8f08622da9";
        filename = "006237.ldb";
        url = "https://arweave.net/CKb_oMKpGtMg0lmA4ZzF47CGXJgUv3KWNtDpJUJ_yS4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3e06e3745753890aff0876aa6cdb8aa31e60d0ba7c75bcf00c63c5fa8df515f0";
        filename = "006239.ldb";
        url = "https://arweave.net/fiv2YmrJSc0ySf_hh4SW7u8gW6Rar2FgmR3QD6AQhxc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "86630191aa3dd46008848d1996253770be47d484773a40356a2e4a4d243b1b94";
        filename = "006240.ldb";
        url = "https://arweave.net/AlwM2yvcMAVbox3lH9ESELSNWEEhVjza6uUX27TyHko";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6f5290d5ebde1235e11c377817f2a87d6914e39e977b3d7c02b1055ebe61cb22";
        filename = "006241.ldb";
        url = "https://arweave.net/wYarVnm314dvhFgjU-p8IcikmSYf1k4ezhr1UpVHcPI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "14c23f0dca279cd27dc718b25aaa97990a8dff8244b632966209bbe48995b985";
        filename = "006242.ldb";
        url = "https://arweave.net/dgaW6yRnZ-XskqtK8QlOPZ1yBTr019lK0PyQh1ffhqA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8265b5a910017aa8ccaafedeb8019ffc159629f35960347ec11504c01c0190ea";
        filename = "006244.ldb";
        url = "https://arweave.net/J78ZJv46W8_A0-N-JLQf7faTeO11HQJnCy66B2FjXG4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5bf0b992e37acbc579bc4f9829ad62323b39ae5b37d182610008a0f6d65a63d3";
        filename = "006245.ldb";
        url = "https://arweave.net/vRKpa50OEilVhYcoTqiMkDrqB4jkRpsO8q_hmVJxJeU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "44719597ac52bdc4951967669b7b89ddd8d0804109cabe7d3190e82eb3e3f1ad";
        filename = "006246.ldb";
        url = "https://arweave.net/tkM4gMNXNI5jzFkK6AySgYCaN2YeSCDtm89AItU8M8A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d2eb2e255c4b745d8b3b967be4352628cbda913a31f0f29975037ca6b7157a13";
        filename = "006248.ldb";
        url = "https://arweave.net/PA0kcqm_lRufHCi6t0YVD_Nuclfl0zqcE5R_JyPpLW4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5848ff1d254a6583bedb06cd6884de5f41b14cf4ce29516b037a99dbbc7e4b36";
        filename = "006249.ldb";
        url = "https://arweave.net/RiNIHPZZY8QM9VzXqpCHoJUQxTkMUnJzOSK7VaoRIAg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "04b3e702918cb7bc361941390665e39ee4332dd61c87717134f19edce8e0fafe";
        filename = "006250.ldb";
        url = "https://arweave.net/ao_FWpgOY_YUda1kIDSv2oAkr8dbsB6UR9vj0wkXc2g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "41f87e0808996ed2b9c204e577a96d553e377e3274ac279610d39a66fb6f6f2d";
        filename = "006252.ldb";
        url = "https://arweave.net/BXngD7VnCAr4mmp6SaP26I62zfvdujyM85_cBd-VuT8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dbb8090e8f7d0bed2dbe9fd808ab60b34e2d6f52b2bef7bb89a33ed6c33d1963";
        filename = "006253.ldb";
        url = "https://arweave.net/0NYn5V91LT-4y71jedWiG4tf7UYR6xw09_fwXdCVJXE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8c06b70cbd9c4a6363e6a7500fc1ceb20d0262ed45b611db73dd92676d15a538";
        filename = "006254.ldb";
        url = "https://arweave.net/NKvE1mRHeqkzGsbg3we0TvZ6mkXVW58lZok8TEhRrMA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd17abb84e65fc3b88ad339b0a63474ef57747ddf804a7f4deafb475954f495b";
        filename = "006257.ldb";
        url = "https://arweave.net/YSlk1fn_nHfC4EUKkK6qaqoCUcaftwY7y20ZCOmAUo4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2afe9ec3acebb5c9b00849a986514eb5b7ce06f433a1ca181c0cebd3b0658823";
        filename = "006258.ldb";
        url = "https://arweave.net/iX81zi9A8940b1Vivf47nPeT5EoMwjBKNyT6rDQSZtc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c665a4db27878cedbac86854177127977a3f492570f1e06cbf452dacbfe7b6b6";
        filename = "006259.ldb";
        url = "https://arweave.net/OV2j2knZrjUbgrflK82xPncluCInS0LZanH9CAduX4g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c5307cf1af3af971227ab4833935973f77327c1c19a10bc177521dcaf7db0cbd";
        filename = "006260.ldb";
        url = "https://arweave.net/wxPf3wqLJqG9QofmE9gVwbwqILdssPUGJUQPt2ZVXEc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aecc00d0c717e13ece4367aab410b3ae6b4fff03a29b1948e8fd79cbefde22f2";
        filename = "006262.ldb";
        url = "https://arweave.net/I-Kk005FCBtIEjkioLJIyhm4cXIHIEYF5MYOtbM6dSU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0aee9b784783acbe78783e5a6dcadcf9af0905668715c3a6f7806c132d73c362";
        filename = "006263.ldb";
        url = "https://arweave.net/_2Ka-OVKzbBQxSJm7E5XKQ_GKck43Waos3rzfiCnVN4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e16eda54a2abf87fef29d5fa6e60c96aeb8cba2614e07de3fcae02b1a1f4688a";
        filename = "006264.ldb";
        url = "https://arweave.net/fC6SZ7NfTuG9Wg5FqKG02mL_I3byCqIbkVryPRkeTW0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a123d9c4920fe4b5413e31d2285eda67662d6a8f1d6ea7948a11d4d633e4a72b";
        filename = "006266.ldb";
        url = "https://arweave.net/SHuH15D7UQiQ3x6O1h8j71MLmoXu4kFouvd00tig0Sc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4401a029b60cc680c1f4c1a7f9fbb0832ec338da3334642031f83578ab894a9e";
        filename = "006267.ldb";
        url = "https://arweave.net/XPT6TmViLyC8_z4LCz2ZLxotwT3PbsAuVC32neVV3Do";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "03876a096258aea0e39ee080f7686fa7df3acebe266df2a3914c93220478470a";
        filename = "006268.ldb";
        url = "https://arweave.net/0-P1soduX4x2tTAGQbPW-6W__ofgcQHhp6NolNDwdUI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ac54068d108a6e0d9c38c892e86b43ad2fe66a362cb3bda76aa757946bfa3f7e";
        filename = "006270.ldb";
        url = "https://arweave.net/7eGsxLDSTQuTqz37g-rffneOavFMLcfu4EQ2Bszlseo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e3562c960faeecdfb4692f48576ca2e3ce33a026b46b8fed977439560dc34081";
        filename = "006271.ldb";
        url = "https://arweave.net/7N6QUmNT6yl_IYgz_k5RmwH6dobv6yrA9kYUa_EKSrM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bf7b03f7025910ebe4ccac745c6f059d9377db6078d1c5306e8753c45c8a375e";
        filename = "006272.ldb";
        url = "https://arweave.net/9rTpHkCKDJVxlo2vID8Zx-YxobNCFHuss-q5kdhEaQw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fe65884a8894b14ea9dcfce12c32618d745f7e81e4cfd0435e19af2ae8d3e5fa";
        filename = "006273.ldb";
        url = "https://arweave.net/AfmCLMQ14BXdahYwz-tiSbz6IOdDph62tErVyERIVBg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a4459dd849a7eb389315470e531143638c808f26e9cd203f11e137c6bd06b2c8";
        filename = "006275.ldb";
        url = "https://arweave.net/eu3ukZbxsDxW2QQ7GiLX6w898JbP5aPipHhLVWuOWS8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a7a261c4c423bc5772bc29f60e56bfa519130d4ce05cf055d9bc929ea8e3cde7";
        filename = "006276.ldb";
        url = "https://arweave.net/YXAwAReaptRdYAFQV-MqktUc7ADJynWomPpNwz1GBZQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "769ef869422dc035c5f41042210f4890e8730e97dc50661ce45baf7416bcd67c";
        filename = "006277.ldb";
        url = "https://arweave.net/kn-VmHW6e6IczMoEg-Yh5HpNLeIJ87qQO7B3YPSvre4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "df47aa2bb711115b45d008e013dd26fe320471daa746123d2f65023c76466886";
        filename = "006280.ldb";
        url = "https://arweave.net/RHs2r47xOPJL4OAvf78I6iMlQj_lmAWpJgZ620s2tXw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8ce341a631c10683255962b111d362464f9bbdd0fb11ce187d169f5f5f481ada";
        filename = "006281.ldb";
        url = "https://arweave.net/KWWV2KDzhhS-PGNeuu4GPJYF61m2ctcnSrOrv6wSGqY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "085c20a8f12ea553d3da0449aff1be2c74e6af661cc0c3626a6534eb222a48c2";
        filename = "006282.ldb";
        url = "https://arweave.net/OB4MgXdsskgOO6y1SYKhl6fEKB7Em1Hz8KC0AzEr8b0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ed1bffb27d154623a5527372a156a2b20981505f928272ec9bb0e72fe0647d0";
        filename = "006285.ldb";
        url = "https://arweave.net/NlTX0elKobhY0J-vR__faoUf4j2ra9zjpOsnFdsaxNw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "43e66d08b2026cbe989865876f3aedda7fed2974b24d215ba39b1da1e139514c";
        filename = "006286.ldb";
        url = "https://arweave.net/GGh9jHj06ej6mmgOC0iWsq22uT-JYruh3J1x4-e4Qh0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "95b48bddf5be4ac94b7f6a272e0e2bf389e4df5435bdca4dfaa195c05c764620";
        filename = "006287.ldb";
        url = "https://arweave.net/8Jtl8MNA5gmSchuxszmkGA7-c5lkJ6Dd_rNlJNsvH_Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aef3532f6225580223d3af82759e0b65cdb78a8530cab73a1f3d9fd99953038c";
        filename = "006288.ldb";
        url = "https://arweave.net/r_6u195k92lcMxsCHa9UPRbDUaXYZpAmvJ_J4FdUZJU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c203afe02af66d064d957e3db9ef8ba87d75d9b53d475b3a3fc84b3e1fea0284";
        filename = "006289.ldb";
        url = "https://arweave.net/J0S5-YaYxqKJ1W6htX_zdQxYpyBK9szx7asO3KqhGgo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cdf1b65c8efac8e86c1718a8e77d177d262619b5219e7c117f1258bb549d95b0";
        filename = "006290.ldb";
        url = "https://arweave.net/nGJfoHIQvd94-PN_TXQrgt8AtfULHyId_tSNZBzCW9g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "072db4a173d987c5f29d536768bcea33c3d992f5f6d3431131ed0156bc21df14";
        filename = "006293.ldb";
        url = "https://arweave.net/mHBr98a8QtQrfxfZ_HRfgtSlt2jn6Iqdr3VARxxD5Vs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "625396bd485f033f52ff5c02f126dd060a5d882f6d159ec02afcfc33f3517cbb";
        filename = "006294.ldb";
        url = "https://arweave.net/jKPTibXdLkqnFyocZUKi9OE9T2ZlO_zJLXgwNkoLcxQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a96906247bdea16e454407acf8b0896a6294f710b2395cc26855d1d19c106b7f";
        filename = "006295.ldb";
        url = "https://arweave.net/44i2dI4_zpiunNsJT4nGxPlHMCk1e3fNVWgLqIeMMaM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34fb78aaa2b2eae8cf0fd449419918889629048dfe61e6c867d7b69507a0c1a2";
        filename = "006298.ldb";
        url = "https://arweave.net/CQyd-ifLbf8K85F8guOnxBNH1NfIVrJv89eOxBBmJdE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5c99e382bd9bb1a9f53fbb818b5c2184d35e2b85457d6ac7d1f2ecfe642d7d1a";
        filename = "006299.ldb";
        url = "https://arweave.net/xYYexvHp3GLzFf--lT-Danokcn0qRPIHuofPZE-Srvw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d67b86cd888d75166c5821d22e02928cf7fdac929714756014fc20aca357828";
        filename = "006300.ldb";
        url = "https://arweave.net/w6qlEyGR_vBS7_4JD_bbQZuNN4z2nROmDiPoj2LeW-c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b95be307fa33e49ba30c7e9e2ff580cccedca11838c6b3e3e8167738bb7de12";
        filename = "006303.ldb";
        url = "https://arweave.net/zPPXFrrljvhGxQjs7MRxC01Ipm-X6p6lcliSL-cz5VU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "40063fb0365fc6e2f856097ccfaaee9bf4c7934d253f2669240411d87a49eadb";
        filename = "006304.ldb";
        url = "https://arweave.net/RaIruhQi5pZtbwYDPcw6QODYp2scMq51_F_aMjBMCpU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "692dd602929cadc028464d2d2d328e197199940e079577d45e82a53b6deae902";
        filename = "006305.ldb";
        url = "https://arweave.net/5jJvp0y-1Zdcu_1-DdvbjD5YTrw35KjNmuPYbreOjR0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8fe253f77c37399fbc94908cbdf8901f969d44b9c4ff8082c463ecd9f9c1627f";
        filename = "006306.ldb";
        url = "https://arweave.net/MXAalVosmOr1ZcOdm2sCGXE0NbNLKPWV_PmZ5JnuTfE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "846dcb2628bf3b077fbed17ae1d742bc0bb2d5847a69a512723ace46d604f527";
        filename = "006308.ldb";
        url = "https://arweave.net/q6FLadpIOKMWD2tlXwFHKptwPpyzjUrHhpgt3lkbX34";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "96e1f1356d69ede4469ac35dc87a4769b46a075cf8c102c61b083f705303ffaf";
        filename = "006309.ldb";
        url = "https://arweave.net/BjEydctfmVs9jZO0A2ICkW0YNcPdovzc-twXcSq-yIA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d540bed4bc05361adc608ed125ca79e2dfe2d5c6d9895931332880813d537dd";
        filename = "006310.ldb";
        url = "https://arweave.net/qfdqyM9hr6XGCRLxKpbYp8KcmDlbpoBzCPqdWxPmcns";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "496cf7fb76f7b11065ca5d92a5b87109e9c9484b6ac171ffe0e841665f340d40";
        filename = "006313.ldb";
        url = "https://arweave.net/9Xl9LwAZ1MBeXVeG-LRUMroB6f90gFoIY6_79wI8EJ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0d58bf7caed907f65888c3abb55f2f38c26270e4cd69eefa6eec85648196f305";
        filename = "006314.ldb";
        url = "https://arweave.net/-8O4UY8lk0EmMns4eBv0XtQUbzpHRlJJZgoLSX4axow";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c319aa802a602ae9eee6503f8b58f1f5239ed439131cb01a606280711a206581";
        filename = "006315.ldb";
        url = "https://arweave.net/aFCCD1tmxfBZ7PXrPhM-u70yY2w70xXRCzC5lotIz1A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "222a59d3301f0ab258c82d0f8e7449e97a790378339015b6092b05fdda78405e";
        filename = "006318.ldb";
        url = "https://arweave.net/RjK9blmuZCy9GQdlEcPngUibi2l5p02b1o4632QdEXE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f567ed420376e041c71f8007705ca5a80ba9093eac2c0684cadde0453fa46e86";
        filename = "006319.ldb";
        url = "https://arweave.net/fnm6NSPpGBJNV7HSI-i3I9wLA2iwru5fgxdIACZgtGk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dfd17190f0154e2c523d598e6dcfd439f46708670c375be54058e98bc6a8a135";
        filename = "006320.ldb";
        url = "https://arweave.net/suwehgHPfE2EPNWaGcWMXFRL6VcpwnvSc--TZI91wSI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8d7b7b3c38ce599cac288a75c1ab2d4dc12d48bb329d08e63b6e20ed425798dc";
        filename = "006321.ldb";
        url = "https://arweave.net/K05Q1962CdWX6MLZ9OMR9UDp8gf0Ep3fBvuaWR3b4Lw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f5fab922252bd393012e011df7eb36b865f67072405ddc3e28c951acb2cf83d0";
        filename = "006324.ldb";
        url = "https://arweave.net/OxntTmsMeAhYsIIYbyynbQ6JNhwoBUf9oW3LtRH7k50";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "933d0fb782c1f099d069dfd9cf64fe7e9ad1ef85c5a6e97ff2b2745a8300d1e0";
        filename = "006325.ldb";
        url = "https://arweave.net/iJgVXokPQG0UuXSenmS-CDj-fJdo7fDogSINqASowSc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "05dee7c301857f31d9e05422af705047c540d1d39c5ae84255a093f6a3af852f";
        filename = "006326.ldb";
        url = "https://arweave.net/K_NPUXcs8evHVh8B5pu-ddYoJuFUKv3gWTwAHmW5TJ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88e318ca6eb91030ba8b9adf78e615e579b6abd44e90a6154a31bac3de2108b8";
        filename = "006327.ldb";
        url = "https://arweave.net/hXos_E3aRFap0mtJWL1i6YzEkNst_aBY8oGpYyQxR1Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0d7ec046713b2484de05496618aca0ecd17caeaac855eb980ce0a7226202bf63";
        filename = "006328.ldb";
        url = "https://arweave.net/pEmooo6sHIN5182VK9h2NDwHNB_Fe2jl-ZfvLW-bj4o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a77eff1e906b9957442ac81425d7f2b68995283e5320381403099e1b5d62f1b9";
        filename = "006488.ldb";
        url = "https://arweave.net/mpUXWogq-RHiU_mWGPY_ndU3w3MKd2jCb-6KzXXHFmg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "17aa4cbba7187d67f971f2ec1ee674923248ba9a85599f02bedacba635dce95d";
        filename = "006489.ldb";
        url = "https://arweave.net/hFZ_FZZyy6bQzxd1t0FKqEAsioDZrjnvFH14AO2aLaE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dc31844b897b1f0b20bd8a8070a311a8dc0c004ae043d49767de7e3f4bce84c3";
        filename = "006490.ldb";
        url = "https://arweave.net/1HkhQ3Gefi10GbU8yCVsnvY-U8Z77UASGNOBy3s2QfU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e5a8ada24b2ee3d47012639257fcd3e9da3ded061c5a1365b03a0a846953a486";
        filename = "006493.ldb";
        url = "https://arweave.net/LL9nrw9IVW1wxOdVwQmWacOaknHC7nXqcFpXsUg90r8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88ad1ca3af74636f63e0eb7e3d272e22b0e475c3e1b92635713bfaeaabf7b3d1";
        filename = "006494.ldb";
        url = "https://arweave.net/mfmxgvFnH7IbZ7u1BT0uixotL-6T_GWy2RNxfFCfuxY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "213d3c41bf180034772df1aaf09c50d8bae5b2fd962ac05425734442f8af659d";
        filename = "006522.ldb";
        url = "https://arweave.net/VYPvr58O8PKd95rMFzaRKWE7Y2E4DjvsjKazGYZ-xBE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "145c2be7d54b1a2d30847c366149afaa6066c01d51c61f9ca2ccb9f013542cbf";
        filename = "006525.ldb";
        url = "https://arweave.net/K1Wvs1OCeqxP1JIo_nIULL95sics60SmVvIzidGpPkQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "98fb4ab5866f2a129112b6be4ae9d56522321d08a65f78a8ee37fff85bf4bac2";
        filename = "006528.ldb";
        url = "https://arweave.net/q36ztQreGWZSEW19YNcyDZSzQEUI-GBN9q4X2XX38es";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "64e53470df3508a0499680bce83b5805ae642455350c7c2d120015de3cca29e4";
        filename = "006529.ldb";
        url = "https://arweave.net/OfW98ffoMboNwKqVK1aqlaVrMKi_lgSqbRfwePpFeLk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "73e34f8c9ddd70d9fa4b5a5c176c7df2304c64cde3b7218d54742c62abac905c";
        filename = "006530.ldb";
        url = "https://arweave.net/2BMZVdzKrtL0uN1z6s9MtZwcm7sETH4LhZeIGckckE8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b091897a8337a050477beea05d66431daff1fe43d4b836ac0c557f967a7e965b";
        filename = "006532.ldb";
        url = "https://arweave.net/R203gEP7jfN67Mq2NbmO7QwYxbhM6NjM6tvzFtgGV3A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "803d3ed506044782e6ebfbad587e293c96ceba52c9b880adac116e6c2fb71914";
        filename = "006533.ldb";
        url = "https://arweave.net/_oS6zk2zdiNjVztPNpyiHr1BjzrntRAdlbT98Pc-TRg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "54b1dba464491b0519e30ff7ea928719fe531d609abb8f9a0d08b227c5667f43";
        filename = "006534.ldb";
        url = "https://arweave.net/UlGDArfzrMIQRqnaNrUcVNRfFFtSg0Ml-Ejxr-VCHLU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b38118cb17d468fb631193868878f5dfdc17b3286fa3b24fcdd97aca08526a8c";
        filename = "006536.ldb";
        url = "https://arweave.net/XICYYBp9aw8NY_G27KzqeHIkPGE9zZ_fcSNxrhnjY5Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fdaa74837edda6cc026c911df997cecd937797caedce3a33f8282371c5f91755";
        filename = "006537.ldb";
        url = "https://arweave.net/JrawwFjXSUeLZz7Uzev8LEiFNfdiZ6SyCOY5ER2e0KI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c1bf3fa9301344d1bf55553f2c1fb1aca02daf0b0a6bb8bf1ee598abfa21ddd6";
        filename = "006538.ldb";
        url = "https://arweave.net/ANWexwtx1tPrkXucHRyUYJbJs1bvssZn9_4uGDWsdoo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6f7b61c6893b00bee1d949b0902d0cb0d4b452742ff1d4269f5937c880755bcb";
        filename = "006540.ldb";
        url = "https://arweave.net/eUa5LQKaUFOTQGUVvYNcqkq524AEfl6acocfFsorKh0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "13eda3e4e8440dee74abaad8772874910b8f8635a74a1cb9bf48790a50f655c3";
        filename = "006541.ldb";
        url = "https://arweave.net/RBx3RqrBsvKE0J3pUXM8Nudw8ZKUaQxmF4F7qsLm8ks";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9c0e8acee5cf6706986985f7ec4eda1f8adca73063bbbaf130ca43b16b585cac";
        filename = "006542.ldb";
        url = "https://arweave.net/zVDO58W4ICsKR-Gi45z72u60EmPnBoGsqyvbjKv3kKw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8dddbad11ad2a6e40915b15fa587b0c77c701437cec7d8b715d6a08783a0ea20";
        filename = "006543.ldb";
        url = "https://arweave.net/Wi75Vx6_bDeOzvgTAnx4MD72CXNxQxlhjWrMwOv7R9I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5eb31d319bcc9692d8a00fc5149e56fb7f8e460c963e74f133a43f457cac754f";
        filename = "006546.ldb";
        url = "https://arweave.net/Md0aNwouqyJnclGkkDyd8kzQhmuvDTTbchYAnCrhuU4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "64e115cc5e3adda7ae39d5179b8c3842eb25466ca2254d64ac238d430e3a3e59";
        filename = "006547.ldb";
        url = "https://arweave.net/K6RtM1iT7MwbpvzsFhCnc1CDPWYRi5FVspcLXao1NNo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c6688271ea9f310134e7fb2d0ef9577807f2d6d7ccf991b436ed3232aa87e834";
        filename = "006548.ldb";
        url = "https://arweave.net/iIs75_QeQhWVYoOQYaG3B-IvbcecfRHBnLgWBMhs528";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fec3903615b97e787ed2946d7b602ec6e59f72f64a3f2178c709eb9b8f679ddf";
        filename = "006549.ldb";
        url = "https://arweave.net/H5Ee7ieUm-cGifUq2m2cUVtZkTVGiPRE3ocssuS3Xqc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4996e7556dcd1c33b0276e724821651782e50f5a41f02fff3d01e2a498fbe897";
        filename = "006550.ldb";
        url = "https://arweave.net/V_c70BhgXwGVNN5qwCl0qY2_ysMcYLWXZWFDxoBABVE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "44f16bd78cf9e0d2482783a8f4a57367beca44c1f574895feff230e575ba5081";
        filename = "006551.ldb";
        url = "https://arweave.net/XIMFgZ0p_mn_Nh6DqOzMOQaGk4nnPsSXy5sPq18WpbE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a0e8dc17968bb6cca26266d93996569a82ef89db6dab6fdbbb391e464779b29a";
        filename = "006552.ldb";
        url = "https://arweave.net/BW1aGgKSxlt8c470EvY_Bp4IjYr5Sk6qYJ62edUxVbg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5b20755db3aa570c48ddae46f041534869748d5cbc6ca5ff0275ea3ab6ddd652";
        filename = "006553.ldb";
        url = "https://arweave.net/JHSWiER_2mrx0hRv8XVDGXgE1QCZOkiJ_J5vIcsqJtU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3cc79749adc99008924ed4584e00e18fa15e95f264bd21a4215e91bf5fd14d6c";
        filename = "006556.ldb";
        url = "https://arweave.net/t1CWQCdIe4KXWHkXEpMS25W4sE-3mv_XSFINLNnvxYQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b06918b685edd68816f7d88acd4c0c5bf8bdf820cf928f6cee79bbc690e55f14";
        filename = "006557.ldb";
        url = "https://arweave.net/MORVEb63lYZ1o6TYCnqY2pSQMAUOStVRJ6-8J_x8SjE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "55c3ef36d4d068c6614f07a75416675309ba2f33768c453c56ab6aeaf981fb8e";
        filename = "006558.ldb";
        url = "https://arweave.net/xfJYWAy_mBjlUJ0pMiPiBIpz8NQhb4xkpgBcDYZWra0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ee5204cfaab659bcc4e4975886bde0b7c5a9a5edb1aff877139d20c4a20840e4";
        filename = "006559.ldb";
        url = "https://arweave.net/IAxlb1eBkrkYiBuYo7wj-nRGyh4Rwe0p1tcxwuFYdIU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9911963be1672bfc45924b1482ba0070ca875d28cefbb2deb1a56f38dbbaa312";
        filename = "006560.ldb";
        url = "https://arweave.net/OCyGPpQADmP-GcGgz-ooeCCCx-Qj79DGKyr-qN0HmEQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8e6666905087e884d23b866ebeb5116b993f1f166715f989acf3bd7dfc9e6e10";
        filename = "006561.ldb";
        url = "https://arweave.net/lxWED_YNfomVG6MzTwR_LQJJ1Fs6xrmiwRHdULHCSrE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "42fb84c93b62d54f4a6621b02d22c44825f34ffe131d9d29fd55c5354507b354";
        filename = "006562.ldb";
        url = "https://arweave.net/Sh0fPI1888xSQETRZZwven9m-hMMxVmMQkf2L731VRM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a5cc86121e3c12b5d4b08b743052396dae1079248ca61b0ed36443fa8cd02817";
        filename = "006565.ldb";
        url = "https://arweave.net/5SnZhMwbC5_LEbXQVD6hS0RryAbrmDo-cRJ7CM1FPFk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "50d3815024bcd8cea2b214a7ef24ebfd5394b2d970bda69167296f0866cc7d87";
        filename = "006566.ldb";
        url = "https://arweave.net/ilVM2qdPxCBmLZ8P52afpnZ4aKB9a5WcxIE_kpP4F34";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "41f25c836ee73803aad15293d6bc9cb3189212ae2a22812e145e4099b3feb417";
        filename = "006567.ldb";
        url = "https://arweave.net/JInAK_THEv6pSvwEAkv7afk2spPiX3IVABKxU8-B3Gg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "87c25ea9e31b7e26acd5d58a40927dd1fe4ef2926ac8dec6590b8ccaa3a44385";
        filename = "006568.ldb";
        url = "https://arweave.net/hmL7JOyau2baah5jZ-mlHlJKJV-mtdMi2lXbToV4nDA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bccac05f97b3a1a7616710323e591802b036a0a1b1b1ada8b7efaf1e9a57022f";
        filename = "006569.ldb";
        url = "https://arweave.net/6-jE25GQJ9gGtG-W1TuHwfxOv4OK0mmzy4L1San6EW4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "50b0f3c618f8e853d621f08c6ec4c2dd7ace5b3220fa6ce55e0d010a126c4d8f";
        filename = "006570.ldb";
        url = "https://arweave.net/TT1YgYUyFk70o5Erov7Crz9TY6XMe0JcysLR3wwBf5k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0e88e14150700af9b583dc76f34d64535946de93a918aa391634d9308e074641";
        filename = "006571.ldb";
        url = "https://arweave.net/2bvA-HJrcwWHYU_vo8mz-jM4y87zlfwGlgOWAifi9Y4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "877b8d9244d1bda627a362bbfe75c9349a415b314557189054d819a9775f5ff3";
        filename = "006574.ldb";
        url = "https://arweave.net/hS3Ha49WOaDhCwwqMhEushwd87bISRi1s7hndFgCYIY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b0d4d97bc7b0ff79abc661dae517c233689104fba4df0b0806ed6afefd3fa0cb";
        filename = "006575.ldb";
        url = "https://arweave.net/RZLkOQLwI-lMFf3MIrMtyDwXYVmK7M7qzRluuRJOAsQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5bac79101ce0e1e6913232ee252ea6438427644aa5690be13d09d33ecd93d72d";
        filename = "006576.ldb";
        url = "https://arweave.net/hNfop4lcbUBQWu_Ai0kO1UES7T_Vo3sKZY8y_wIJV7s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2ec89cdf5b78fcbae27f73727564eb426d8b4dc7fbb615129f2dece35d38dd97";
        filename = "006577.ldb";
        url = "https://arweave.net/qU-tNxmCEAZbMQLxgYnbFWPyCzWQ9v2BlMn34foXb-Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6a15996f6408ee936245110edcc23b045c31c6a388e31f1a6faf58ac23dc66b5";
        filename = "006578.ldb";
        url = "https://arweave.net/rG-MKz8LYqglFAegSYXJl9bbmR3MqqQ3KEss4hf1-6M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8115df311fec6e8888fae7d702fbfeca3dc756d0661e83f562e38fb78b336cf9";
        filename = "006579.ldb";
        url = "https://arweave.net/rKCt7DFfCpzjd-lMUhoUnyls9Dy9hKkHo_Kd3h5VkVU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "75570e392338f3d8d62888e9c98c19f3a06352cd8436b7141e4ef7e3d51cbf15";
        filename = "007232.ldb";
        url = "https://arweave.net/091Y3H93pNW0ERf9AkBBWa7BCBenGSCYNa-_NdgWmtk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "122106bdc1db26137e9a34b21b0269b3cbb859045b707a164cfa8747c41e26ac";
        filename = "007596.ldb";
        url = "https://arweave.net/KuiUDNCc8885SzoBgPiJYOei3vG74-4_AYaRZe1BHDU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1e0124987791c953d58fca3866e77c6609545953d995ac66da61902f75839393";
        filename = "006580.ldb";
        url = "https://arweave.net/W6KwIOheqXjyi3EBqqouJCfbkeCWx1XE2g21mmYQTfU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e2f1ef6c11a1658e21c24ec7620285cb3865c3c076e3ece1992ba91c04a2cf38";
        filename = "006581.ldb";
        url = "https://arweave.net/g4xUyBbJFI82z_JZ-sRIM09Hi01zjuAbR9a4-7lgCW0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ddf08b37e5dda1a91ee471ae05d8a6a1eb125d90b9b816511a65974c2fa17600";
        filename = "006584.ldb";
        url = "https://arweave.net/3DN2VPe06kYL-hndorYw9TUSAjO29sAqX_Md9gF3GuM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "feb7eef4a6aeda971488c9abafeae88d3e6fbe277c36da9ab4e671a07478d228";
        filename = "006585.ldb";
        url = "https://arweave.net/8ofqP1fkSMXIUQN0Qaef1zO8CS1BnZcUiiq438MKlUQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d6e836bd7b99569910c95cee19f0fb21782f3e8f7755c88e65b53f7527fab94";
        filename = "006586.ldb";
        url = "https://arweave.net/40JUjY51P7GDGxKRn0C2-VoICnxLlRHRbDZyts4MkKg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3290715dd01021c054a92a0371382d122df42dc7ece2556a25b2e5f60d6da01d";
        filename = "006587.ldb";
        url = "https://arweave.net/5w6hOEVvLbd9itLJJpxGgDZF-6zduGrXR7vFBB_Zlgs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9987f89acc4dd2ec838a953d0f4a6a5c85746d48f65ef1e5b410d68e136cf2ef";
        filename = "006588.ldb";
        url = "https://arweave.net/px4s_sxkEWuc0Cw5AmideAPHM2_icsORckUHGV3L_eo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cfd72e083e1e9f3d526263e94306ddab51429977ee654a92840de383918d8795";
        filename = "006589.ldb";
        url = "https://arweave.net/gbWqyGH__wWcjItNMCSEMC4dC1K2uN96Rkty-6-s42k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "61dc357fc04042cc8a7f7810dfeee0d06faea85ddc07980dc5f9ea2c643e16bc";
        filename = "006590.ldb";
        url = "https://arweave.net/g37btjfelEXGEHmUOfF2QLQ_GKik9VpNvY51UhWjppE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3af2a5b10f204a9699d2cc584d86a4a681e4bc9738e070bce69afb4af54ff98a";
        filename = "006591.ldb";
        url = "https://arweave.net/xohia4IwxAzVvm9yD3SvD4AKMLxpRba0qV0rkVj_Gck";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "81bed36c8a4d67c5326afe2c3af4fd3c8447fa614e714686ea97446074ed6206";
        filename = "006594.ldb";
        url = "https://arweave.net/1KtX_U0Ox2UV9kKuXl5H2JXJhLPmqHCMT0BEcFegqa4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a17857f8e803ebe0df1d6f7400e60a5dc3d8af318ae0bc6e032ea3b468cfb45c";
        filename = "006595.ldb";
        url = "https://arweave.net/Aq0xhHFxW2XspgNv-PoxLOtmGD5ulztdXJVTPva50TE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0b9ffeca4ed14f720087e03fa082f2526d53ee1dfa63cd18925ee8fbfe84b0b6";
        filename = "006596.ldb";
        url = "https://arweave.net/KPebfeUIUYUTZWmsFjbElJLk2XDYFHpJaDtZM0qORyE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b131f384301f4b677f72f2ee6ab600a2909c940e11f60e72addaeae6a2322cb";
        filename = "006597.ldb";
        url = "https://arweave.net/owdvde4CHEiE0qtLUgJuB6tu25vuEj_8A3mYs6mMuoY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "541d28a00a5164e5b7782fdfef4d567651d34065ec087cc24c6844aebb64cd68";
        filename = "006598.ldb";
        url = "https://arweave.net/-hXUS1qfDyOJ6-b_EN_MRJ5JzccSCUfTUj2zkVEB0mU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7aed41f607dfc165fdf9eb2bc10a61f74e7edda234cde8107f455730dc00280f";
        filename = "006599.ldb";
        url = "https://arweave.net/wIZUmmGh0heI0wxzKSflubHossXK6mD-R3i3PmP9ph8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88b7cee018df37a2307612296a06bd45fffb6b87775f6fe6fc86834bc7917494";
        filename = "006600.ldb";
        url = "https://arweave.net/noZWSRCmL9UXeANnVJkoFkRezJrvExrwiSy_GpGxci4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bdc0b6aee062d7fbf5c3299c2fd6d654130b6f589690f15611fdc6ab3f3bb1c0";
        filename = "006603.ldb";
        url = "https://arweave.net/iFs9pSrgCJ5de1wRNHkBFPQY9BFQMhJlpf-Q5HBY5TA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8d8144123348255687be5ea4a82cad5f6b78321edfe473c2261a9be0b8e244a9";
        filename = "006640.ldb";
        url = "https://arweave.net/YAi6c8Ll9guOi6-_aUsYMpaAvO6c4jTeQhZKXWj63Z4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d5f7a14e2b44163c4fa0f48a0dca7cb90b358f4ff4a03cb238d47a0e924ec9e1";
        filename = "006641.ldb";
        url = "https://arweave.net/dYVKBx-8ZwtPx5o5nsypj0w1FPcV9iU0p-LwHXaaFQo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "863b3bcecf6711146d687dd883c8582327fa1c92242dba6b8eb164d7a273622f";
        filename = "006642.ldb";
        url = "https://arweave.net/NnAElZ5NBJXEFL6Lx7rH_ng-3cm9ZucaeTraxGRkUsQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ad4d3b53de0982866174ed2860c4c1306607c070e9e24655da2c282edb5661d";
        filename = "006645.ldb";
        url = "https://arweave.net/5Q-kT-RL3AwD4qlPH4NkIsbuyD8Dyq9n8rRJgA0wVQI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8f4d1ce615f83b205b45fafb4828394d69b2ced23fed5b6159e3ea9a50115014";
        filename = "006646.ldb";
        url = "https://arweave.net/CiKrheyn32KeYJ_qEoNfOD-j8NCOxuvr_v6jnfLqzuo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a83543e1700b094638b43668cbb2a4fda50c7a72ab7f3fe2485eb48a96c20ff9";
        filename = "006647.ldb";
        url = "https://arweave.net/BjEL2qy9yMveEkKTraF6OCdNJl5nMB4wVw7L91Bkd7c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8d86cc66e307053582ff0457e2784f569d42d32ce335247537c2ca31305a790f";
        filename = "006650.ldb";
        url = "https://arweave.net/2FHfI75sjvu_YPFquo3xVj5byl0FvRM-wIgoi8wU8Gk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5a603c16440630e62cb209da857903b788ecbc92c1fba99f8cdaf45296188f72";
        filename = "006651.ldb";
        url = "https://arweave.net/ypRmpvzhaaM7gj0Jfx_mIp4mlrjRnybH3ZHWjJYRFjg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c9eb1903453bc3f3fa3fb3d0d46b464664b22a95bfcd7fea7f57036d21224ece";
        filename = "006652.ldb";
        url = "https://arweave.net/RJv2OvGjCB3RwA7FB5tnT1gNb2hoxzVg94qQtNS4OOk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "91888b5f4d2451cc1bdb1ea8e9dc21aefe9f5e0ed0268900ebac7adba263b7de";
        filename = "006653.ldb";
        url = "https://arweave.net/yBbAt8D2SbWbN_mgqVPrN4GZ3DN_lyywbK37FGJK2U4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bf7442b797911868d56e8ea5bbb7945e077bbbbc52a7ee962b285211591466fb";
        filename = "006656.ldb";
        url = "https://arweave.net/Yr93s3ApSD5_5Js7dhlcV0WfQjuRuS3yt1m_-DEek-c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "85b75f8038d33281d7654ce81c113d0fab47585a8b0fb2be5b1788b2d054564d";
        filename = "006657.ldb";
        url = "https://arweave.net/Jime-IvYg9ySEKXefnKvCRDRJz3_lFNlddQGzPlqiPk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2694b05547c909e778fa96f685f9c0d720eb437e5103e55ca976df54bd127587";
        filename = "006658.ldb";
        url = "https://arweave.net/s5RodH1-bqS-wWouHg4agJgtgKJGYs2Zqz0jBy9pa9U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "036da612eecfe1864339fa84384ba97dd0bbe8ef6fd94285c56e7e1ddf534f2f";
        filename = "006661.ldb";
        url = "https://arweave.net/V4QSDIj_7Vjucwh2OJ86UpN4hC8RVsW8Ob8lCCrGCJQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c5ff1cfd1460b0771c7f64245a767a024de218b3986520b66c73f048f4f946fe";
        filename = "006662.ldb";
        url = "https://arweave.net/BpEM68ErMfUJ1DSa8NR-uFAxq7Q5l_xRJ5A0gNYJSvk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ab16b485cb4a1000bfbd66e0147d3b6b13183412a2e004bfc4e92a490ca55e74";
        filename = "006663.ldb";
        url = "https://arweave.net/RGy9mNw2k1ffMalm-Xercpz-vKo-xaFRt4SewW2iFEk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e23236fdc128ec82df4903ba1716ff023b762ebde69d6e6a01ed895eae69bfdb";
        filename = "006666.ldb";
        url = "https://arweave.net/ttqVE21cDvQHQaH4tDDvEVTv2han2cP9GJzjlEPpPAc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "455f9ca8a06dd921ccb566ad3e3640f59389a2685390b7f747d77ca205211629";
        filename = "006667.ldb";
        url = "https://arweave.net/nBZ6xUxnGQ6LpRuYxvN9t1pEyiWap77rlmbF8_I2Gpo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cd83136bba12aa1c5d5c8ee8adf1f2246a5edd3415481422e8b54adc5440cee8";
        filename = "006668.ldb";
        url = "https://arweave.net/swYnhkNbSL4Hm8pValVRCG6qb0DdTDwsu514n4KHerU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b831e9948381897a29c27cc35a74d81d46968fb2e8213eb86ba4d82c67081969";
        filename = "006669.ldb";
        url = "https://arweave.net/gnk9bUXqIGc9-N9Qii1zVdaueJA6I8_NlylGSlRiTpg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1d9f233c4f29639366debb9908642fc2db29c460361778b3879f0feb73b2f1c1";
        filename = "006671.ldb";
        url = "https://arweave.net/C-Z3qz3Mx54zAZbgiVw7kl5wVaE1COfGgJPBbJWCl9U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0a0b9a19c7b037113c0b7f758765390c25cbd0b50b4adfe61a8569939a562b5b";
        filename = "006672.ldb";
        url = "https://arweave.net/5jWHpATSYLNo09ouQ3_tqHwpECWJ4UcQE1QhIzdT7W8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "091fde26599e94e02b45e0c267a4ecb8a1facb51bda3030ee68c71b86a214336";
        filename = "006673.ldb";
        url = "https://arweave.net/fFSTDMTUJPlZWpE3lBbecsQgg0tUtRl9pqsq-RsUtx8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fb8bf261902120ced44ca5eda391945b1a9a35efa0803db750668026b768d317";
        filename = "006676.ldb";
        url = "https://arweave.net/H9bZJNi3VnvPis5jjziRsNeDV8B-zrRbzE1hVHh4bts";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "93044daba45e1334693d2b837ff969f8f2d1cd7dfc1064d85f5624423fa2828f";
        filename = "006677.ldb";
        url = "https://arweave.net/s5uJHSTmpB-Uh2ADPAccySYEp1WxKHj4fkLAhDiftYc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3641feea32099cec50be525b3e2bf4423031c43be1ce2556c6d22ad4baf3614b";
        filename = "006680.ldb";
        url = "https://arweave.net/cGujMEGXWkpeQFOiTEtotzdP-QxMgRfQRa1W6Oj4T_M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "945f2cfe83fdbe1ebb620ad55fdb47df7ec68905eebef28f6e30945acf3c4adf";
        filename = "006681.ldb";
        url = "https://arweave.net/oDTbdgMmOQeK12-VuhZf7sjKTaeP4TD2G_IsQs0jCvc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "44b6241c77a6356b562d399d8d9d6ba3a6d270a9e51e8de8120b145a25c99541";
        filename = "006682.ldb";
        url = "https://arweave.net/oZTFIvm3bYWndoNrASD-T9vZ20UrhYZjKCPzG1XXrSw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c78d1528ba8c49c08d79fc85f66475884d50182718b78b6bcc12aec0ede1a1b0";
        filename = "006683.ldb";
        url = "https://arweave.net/rqPpKt1Uc80ehFwYeX4Bj4jW82MM-F8xR2DIWcARD3A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ad9abfff5b6d021596979c9a244920e5f5d2a19fbc59d78310a5692b60009b97";
        filename = "006685.ldb";
        url = "https://arweave.net/thx6RE5DSghCCJtLRc6rf9114fZW85CGYQv-O7dlYgg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ea0c6efd3685ccf3021b6241c29aee9d0f1ba7e772fdd2d3c47b57ce66622646";
        filename = "006686.ldb";
        url = "https://arweave.net/N3nLCaAXWT-VOgQgnGD9zRpY9-PCSGr-TNinMkOo7U4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e65853a7f80436ed8f23418db5303434a0d88cbb01535f51dea724ec48042886";
        filename = "006687.ldb";
        url = "https://arweave.net/MINOzeMTYUJJN5nK2GktPuW1X-RmitIyv-lwnscdZr0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cf60f688c75c6dbafa53c65b144408a3e532d438d91cf34131f9fa49c8d26d62";
        filename = "006690.ldb";
        url = "https://arweave.net/fqyd4lBdxeAOHQuctMoK_IIpVt8RV1itaJhbrksWTXw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5cdf79a7c3efc780ba498acf35262547a086d31f49f8ce1914aed173de713b1d";
        filename = "006691.ldb";
        url = "https://arweave.net/OnOJWRySf5GIjf0WjtpxKrzND8yD7txUwuZ9C2STmiU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ed0376bba3d56bed8ffbc2af4efe8aba43a7e36d4530193c3490e395b18afdf6";
        filename = "006692.ldb";
        url = "https://arweave.net/fR2Wdw8tS9CL0Ph_O4paKviHdPqivRPZje3e6Yo2Uhg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3eb5bd40f4b15d7834c48dd2e31a36b4d44dd3217b852ff54e536406c5a7472d";
        filename = "006695.ldb";
        url = "https://arweave.net/JXZzuKTak5NX46sxwYvfuQ_A4zldhIFRf84dzm8DGlc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b6b16016c47b4ae00f3480fab23f6c69d33018e5223b7f5529fc57bb1a699b04";
        filename = "006696.ldb";
        url = "https://arweave.net/F-gNGnbHiJjztlNmzzqVMTMQAf2YOE8h6VKGkgCIKZc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e0bb44701ada2c2b11e8da6b18faac9e51a302084f4d2090fa4b84e277f6aed2";
        filename = "006697.ldb";
        url = "https://arweave.net/4zAlOEhmjnZq2pEingLpE-gB3or3PayCup2NVyeh2so";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2e4e137ba54818740fd66ed50171bae76f9995db00dec543733f58fba47ce6ae";
        filename = "006698.ldb";
        url = "https://arweave.net/hUqeerABNNMPainGuU1hzVB_ieAn1wEFBOLPzyIxYlA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eef4d5b6388bc050518dc1f07671894d75f074f6ead85ddd5875638dfcc34a82";
        filename = "006700.ldb";
        url = "https://arweave.net/TgiPX4XqxTZXVsYYrfNcGjYaBaVayS5n78phC75MAJ4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0d244b120c0942dfd8b4e44cb291ffc5e89d8d661ffec1f827b8cc60153a06de";
        filename = "006701.ldb";
        url = "https://arweave.net/F2uylam9bL_1Rav2EPIRu8oH5-I0vTBJBeH-9z9jtBA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "944d020bb07c8a8c78f19bb1670ec6de2c6fa698c8763ff37bb4785098226fe7";
        filename = "006702.ldb";
        url = "https://arweave.net/zeijIiN0sGoMQAYVTvQEfQFJXtzGbgiaEPgrmaELK0w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "210f480e5a753459e5c6c7dd180abbb1b8e312c3e0d2b795a29d26ba0e0e4910";
        filename = "006705.ldb";
        url = "https://arweave.net/686G9vRpddhy_cQgBNpQJm72dSP6EpQfWpRyCh_o93I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ba8c1d5c33f10b51c600929622268babf667496bc120a252663afc99df5ed5f4";
        filename = "006706.ldb";
        url = "https://arweave.net/Pl96qTKvu2I55p12zgC-1Ookx8L_u_FC7LTlUa9EwV8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a6c43841c5998a46faf0b3ad44fc2f95c88e2fdb021ef8f3a1ef704cafc7014e";
        filename = "006707.ldb";
        url = "https://arweave.net/c9A0kklwbygHJBBtR8gts9krqtO-AZEbiikFe7Yge1g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "29d550f26936a5eadc1a0c959b37417be701d9c2a0a1146c1bf1d90e36220594";
        filename = "006710.ldb";
        url = "https://arweave.net/XEbEvFcyxzAQAAgLQCCc6bMjvChwYohFFhbzsDB9lQk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "10437c55abdaca1cec7a921f40d488368fe96aa729e86ea2573f292b1fc98794";
        filename = "006711.ldb";
        url = "https://arweave.net/6Zlba_fjak_9CiAFEeK5rT8as9VjE6kdAZaCRMqO3vg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1978dc70284c20611c707c0a292df8269c87cde4e309a534daa4502c51460555";
        filename = "006712.ldb";
        url = "https://arweave.net/y6dNyUbS_hgTPnKbaLYLpQ8wUcbWdD2pH2KVmjsaNnU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e5f3f24a0807ebc8d9818978ba8ad2967ceb8029de934768473fcf2d85ac89fb";
        filename = "006715.ldb";
        url = "https://arweave.net/0FVwUdtdL6XpbqsH8OPmEg2d3nkTcwkX_49F22oubXY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "39ae7d5f85daa7249258c77c465698075c18acdba9397499907306084f6e8ec3";
        filename = "006716.ldb";
        url = "https://arweave.net/SwMBtleJ4ok-H1tjuK79fSNhKs3Upr8FunVUD_4N0K4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d35779d92c5c8deef4f3be8ee6548bb4b48908c8b80e3e7d06c1f9653fb4e5a";
        filename = "006717.ldb";
        url = "https://arweave.net/mAMJmgz5Cjg8CiD1IZ2UfwQT0hawuNcBTkZwSjWnMUE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "357b0e1788e63d8df64ad432ab382c7d34f230492f6b4dcde20f144c1c8e5ca0";
        filename = "006718.ldb";
        url = "https://arweave.net/LmcGHpyreznBTp1MdxPxI-cQAmgVsjAeTYxExvHgwhA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "40cfae6c9cf9a24b112202093d3a09f898d636c7ff60a2e14a32dd49dd716475";
        filename = "006721.ldb";
        url = "https://arweave.net/zd7hUi34x6bjuOBKL9yAaBYhQ068QQl0R2OHuYjSEok";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "49e58da9f87b4511792f18e5edf0e06b3eb71f3f0a63f79e30c284d0da2af6aa";
        filename = "006722.ldb";
        url = "https://arweave.net/ENkdOW7Qct4MM0fSetPRFQsuRzh4G2HeiJN7j6HzOtY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "53f7cb91524d6e5e2c7c0fe89bb8dd28a16d0ef2d111f63354a62168eb3da65b";
        filename = "006723.ldb";
        url = "https://arweave.net/5_zQwuMC7W-dCXkgZjI_JZTaYQKLadjSL-ohD2CtNAE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f78597989d912385cd711c9764e7e8067dffdbd904df8d40c42ccf5dda1aa43a";
        filename = "006726.ldb";
        url = "https://arweave.net/5jiSaC9xpfZJKq2bOD48SxvKDWwecMMwiNMFwjIHWMI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7a4affb7bedd097eb7dcdb0cca026f03f4806f20e6b79688ab236110fc4569a9";
        filename = "006727.ldb";
        url = "https://arweave.net/F4BNoWUV-_f5bnZuyN4nO6E9l3pFekhoq1HP-Y0catE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "79bc9d4eebc96a074003787cf3418cfc24d6dc0cd7b593a9f02cbc8d93eb0998";
        filename = "006728.ldb";
        url = "https://arweave.net/B16jK--sf4mb25fxt_ILpCzff3WAJuw5spgmcrXW9sg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8c6c2c3d426937b91bfcdcacf248bae5e5b01cb82dc8d1d62ccefed9fb18b956";
        filename = "006731.ldb";
        url = "https://arweave.net/Pfh_wujTmbu8NjossqbmCB5xdzZlherPCL4JkPfn6JQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f87e5a4ba7f20d0118fe679489dc2d5cc731783e5eb1565a463da94e64bdd477";
        filename = "006733.ldb";
        url = "https://arweave.net/OdLsS28XjAnjPJjtwxDiKB6DQY_IM0rHE6UgQWW4_1k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0961602a3a6a1e060bcfda06b7364e7e48394bc1e7d5a043db43a7ff26cbe7ae";
        filename = "006734.ldb";
        url = "https://arweave.net/CVaWKS-aIBC9jzJd32_ub-wJEIYq7cunviptHeVXNh4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b3129bac2f2831d197f44dd304f2881426db0f42122c19ccc99630422032e5e0";
        filename = "006735.ldb";
        url = "https://arweave.net/N2z7B6zuYb50LW4KSoFSjkaHk86VtdlvH9IKz1T-IzA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "49a5124394185025e63bd097810da5bcfbf8dcc42d9a034962eab2589741fc22";
        filename = "006737.ldb";
        url = "https://arweave.net/L2zKRdpnYlA1__CI7Eic_F7UL_V54jdJHVff7q7xrNQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b52717ba0a89ae5b1126f6e862b108fde2ce2e01c8974af4c8c11c530eebd538";
        filename = "006738.ldb";
        url = "https://arweave.net/GrXw6ZEFYyOS7245wKMZp-UZ-6qQPq2D0z3_C11bCLU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "757b7eb3c6372103e54fb3eff910f854e27d1ab74519355ebed592152c8f2440";
        filename = "006739.ldb";
        url = "https://arweave.net/TSHEPi0gEWvmzP_-GG3AHnwavCPG7FxX1b1jggjmlsY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cd107ec1ca879f20f3f1f25523b651b71debbcf0009697d5e78847a88aded701";
        filename = "006742.ldb";
        url = "https://arweave.net/mKp8cjX-fwKE0dnwsVVPiVrOfjzer42PaLlyeHbNaSY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88cbf19c5dba0ff4b204f8fb70dc66f978e55e74b7bff39a7b5f9d6f062dcd1e";
        filename = "006743.ldb";
        url = "https://arweave.net/XZXbztfgLELlPyOh-AQpGElgsdDHOphH7y2vDcx4oQ8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8dbffdb20015456ca68b5a6fa778a9b423794230208e3c94adca1a4cf08a865b";
        filename = "006744.ldb";
        url = "https://arweave.net/DpC8j26nERLkyaIrT0baK2ZPaQUqCwNEW-FAws12Rns";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f64efce0b5510720ca35ee6ae7ffb9d95f5558d2e6d291ca93969fcf0f283b62";
        filename = "006747.ldb";
        url = "https://arweave.net/hZ3s5W0xzff3WIwJlpPiKIJxfCY28ISWkE2cealrG0c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2864a96dbb3eb896a165fa689d0fe6e66930d59ae3205925804c3f7dffd2e571";
        filename = "006748.ldb";
        url = "https://arweave.net/SztmcQj3xPngmKn_Psde3tF7ijvlLDZGQoEkJoQSPgw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7094ff867e2f511d4f58509f12260961e8d685a1b9b722e3f371674b24c845d8";
        filename = "006751.ldb";
        url = "https://arweave.net/a5Fe2b9FCzJTaNYNbWNYr6yOII5GexTTZM1GejsN8FA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "336802e351eb8b30b289de074075793f0f8ead139155495eb446177ad00401e7";
        filename = "006752.ldb";
        url = "https://arweave.net/GDILvPJVeA_gfILTJ1tmJcnaV-xnCnvZ5U3qMvPxZsQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d8197d150f0217184b9e5fb5da6259c3f8e6718be132ace513a5796b29cd0c4e";
        filename = "006753.ldb";
        url = "https://arweave.net/ELBh1cqQaLBMAmgdo9ju77Er9Lhzr2WydUU7NL3HBjg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34313870a48b543594e1f03ecd316069dfc8e7f13c76b0911d5abd85b45aac35";
        filename = "006755.ldb";
        url = "https://arweave.net/dvi68XRNoa6HjjVKXZYeHyTk5VoA5_-w-EyB3QEjEB0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5017f8a8112cd13e345c8b749de5fa55b2e2a7d070d93abe0e851521550158ab";
        filename = "006756.ldb";
        url = "https://arweave.net/tSx55_-0TIp9UVEutQ495NWySqNMHIx_NmdI2y15aLw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c9b1cde95f1916f4d40169fda36f3347495e57bd1e7d76f426f8dbe676cc604b";
        filename = "006757.ldb";
        url = "https://arweave.net/0JEVA-JggGpf5y0t_HTUXMmGMMSjP5B69rbGsksQP4M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c76bc7748efe5f11a081ec37193c63dee4b07a2f12ff40554822bfe382756fdf";
        filename = "006760.ldb";
        url = "https://arweave.net/GUPURtjUQHhuOpLX94tPeNrXY1SpNukUq_Zirhnenpk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ae12d0ec18ac7b3b3e79c517b9d757821aacbc44b5caa3a6225f4b55545cbf2c";
        filename = "006761.ldb";
        url = "https://arweave.net/py-NMCwmyAv7JcPH4LAbLLdIj1-Uws46fMsNQ9S1KjM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "df6ec749feba445f7f2ab550b50a045e70a94444c7be72fee544f95ff3cbd240";
        filename = "006762.ldb";
        url = "https://arweave.net/-J7qxHC7lqUvz6QGNru_db0QE_uV-heNm5pHAPgnO5Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "85ce648ccea4294e396f3b8b73fad1e05fdeb24bc3938e370214b216d283ec71";
        filename = "006765.ldb";
        url = "https://arweave.net/C6tcA68Emg_nkznlmIKwLtVDzbRLR7ZuzKLYRhXnDHw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "148ba260b620a18c50bff34cf1c2ccece2bc594b459e022cc2919556649cdf2f";
        filename = "006766.ldb";
        url = "https://arweave.net/v0r5vlhDJ7y-qpbR2pBYRomV5rS_VOgVXeptjyR4Qgg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a64758630a93acc5d4cdb2c8f442f24a2742bf3e042dd93a6633280edd7cd6e8";
        filename = "006767.ldb";
        url = "https://arweave.net/WKPpYojZzfdB4CcIkahZKFm8P7oWfaeaI4ofMnMnpuc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f8ebbca5d254fd168abc3a8e183ed057723bddec93b70f6ad50de1cdf87671f4";
        filename = "006769.ldb";
        url = "https://arweave.net/oPQcRurwGUnJ17GQP2_op0ga9_YEv4WRynmg5z2aUAE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "481d383e1925037fe185f338b5c94685f432c3924d828594df9af82796a6a49f";
        filename = "006770.ldb";
        url = "https://arweave.net/xdcEFvZRhx53v7Tvp3WGvK4uZvEcrQ96_YvVZvJjqlM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "63da146aab12e90de0accea7cab2ca3b2e070c44c2cc351461ff60d69eef87dd";
        filename = "006879.ldb";
        url = "https://arweave.net/6bXYp3teOSK9gibkkClazVFgi1dy4Lg2CgzAe2sjg8c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88f348e7960315be4a45b54a3be43205cdcaab443d359853ea86bedfd33912db";
        filename = "006880.ldb";
        url = "https://arweave.net/8iQznvFKOgirSVCi5pQT0IYQIGY3-dpwiXJBO2az7q0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0c23a3a2824ed3a9bd93e654bb574722b34cafd5dacf7b20d96d50f7cb98f3b9";
        filename = "006881.ldb";
        url = "https://arweave.net/AJM-5iBN8bLo5QSF22nXxmirC2Q7uqmKybgxs3AlVbk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd79dc7562434a81b770ab4fbac5c0b90bda2dbfb329bf5bf02561202150ddf6";
        filename = "006882.ldb";
        url = "https://arweave.net/-LjNyfdjelPXFgeSBQNMyEzVnEi8wlF_IEv9KABUzTs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2a95e65001d5e2b4f024ae9f1e1a4ccc8ef547acbd71b979ffa56961b85b7be9";
        filename = "006885.ldb";
        url = "https://arweave.net/gcqg6dNfxD6etqqxoHUE2iDl_DUI4U-tyJXwOd4sNAk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f75f6c1016d8ec57e73e547feca099b622531f9035c6d4f06526d803079d10b4";
        filename = "006886.ldb";
        url = "https://arweave.net/c6s1pWSBjkdwQ6V5HnbPh1XYRcZ-M-hXvsh-IDOSg20";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "58620344742d68e197c6ff779861e4237aa769a0d3ebab04d38a5fc927fb0b7c";
        filename = "006887.ldb";
        url = "https://arweave.net/qC3RJJBLUvBDyyrnz98QgT8usehMPk8IYLqInJkT14s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e0423313ea38f100fb251bcc92063a16c06c36c1f4e6160b988f6b3928d59eca";
        filename = "006888.ldb";
        url = "https://arweave.net/igQoJEZ8YZFLbQIu6QVFdVGbAOjr5dUIvcQl4IHThJk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a765d8ccd9df29ae8cd90282a2a217afd3722f0a0664effd69f55728b6c4c971";
        filename = "006891.ldb";
        url = "https://arweave.net/j8FAKOexb_WdgpwJEeJkeF-IGIj8gyyD0O5vHrcYVw0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d56704440964daea4b81c90565fac251a9211b6c102aebff105fddb6358d09d6";
        filename = "006892.ldb";
        url = "https://arweave.net/gUc1aXIpMYNhyUzMgXkBKdHcqmwULGH0H6SbZXkA5sU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a4e7b90e53f5e06e04146e6a3e39863c2b3264f74424956487dedd40b6dd309e";
        filename = "006893.ldb";
        url = "https://arweave.net/4sHn20esHF51RV2mClYlfKJ0bT_T9H3I9FGaohY5ndA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7cdcfc02a8d539997583f0e1d819eff95e266543b52ab0cc2f2975ac2e3a2986";
        filename = "006894.ldb";
        url = "https://arweave.net/o19j-Xi4R5S1KeC3YcPruPkBpAcir7HVC8iFmZ4endM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ed4957ac8c309d75b711d5b6323532a32836910f1bbc8b369a316afba155b5c6";
        filename = "006897.ldb";
        url = "https://arweave.net/7ir9a1SngfhZVLz3eiHKpztpp0ubGsKHgfCNlWzihXs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8d5d275987518ba734caa8013d2d84edb3fa27b7d2fbd3051f1d25b65c04c496";
        filename = "006898.ldb";
        url = "https://arweave.net/jRGHDkCC450ian7ijbQbWftYOkdg8jtyCpy8devvK0g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3be70a391cf75148312a5b94d3f0243c5b6932a2206fd384a695c62455b02703";
        filename = "006899.ldb";
        url = "https://arweave.net/blTXRW0GrISO5oO-mnyOWcOVzYfZulaqeHIBufqj54Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e5649dc40e721a4c7ef7a8f0e452fa18d9610b28dc39d4c2f1460e0a7f1d98dd";
        filename = "006900.ldb";
        url = "https://arweave.net/5N5mrrpC3y3Qgel9ZxMroqHbBcDk5jRS2BF6XlbrDbI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3a2c077d5c81bc712575265bbfd9c7f8b7a761d7fc883c1662ad1d67cb247067";
        filename = "006901.ldb";
        url = "https://arweave.net/vc_h_6LE7W2kqh0MxXB7SijyBUUV782oj5HAM6Db7KY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4fba8eb0d91c8477b29b2d3b234b1f2e3e4263d725c7290819c8eeb8093265dd";
        filename = "006904.ldb";
        url = "https://arweave.net/SI0YEGCB0B9NH4gXT9ewXwcRuIrOjsHQf6zaq-II5xQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d866e2e376341af260f171e9fb9712bd238fcf1257bff0604ff271f899af9ec2";
        filename = "006905.ldb";
        url = "https://arweave.net/Ql94y8anxDzKgsfE-3V92B22814s8aURJDDuhxo8ASk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "05c4edd554b0125c9c3a95a5e235e8182d0b6bbf3ee4ad359650af08342ada00";
        filename = "006906.ldb";
        url = "https://arweave.net/H5sdwTKnhhEw97H0co2PGI01gipFnO_AbIJCs4FKleg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9e086e546ebff7a21c37fea2e7fb396cb0440d184493ced7ec19742d4f0da814";
        filename = "006907.ldb";
        url = "https://arweave.net/KbQSfglJyePrvpb6rhontw5c1ox7ST9RM7YPdzs7uoU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2f12a8714d25af5ccf7e832bfba3e6460da7a7d991279ec79cb5ec434c318295";
        filename = "006910.ldb";
        url = "https://arweave.net/4ac9EZz_A-Wgh7Svj9oKTWu8F0IroKK-a6PFV-R4D_Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "69cf7eb9bb220e38bd9a7c4e99f05da430ff6c2f2c63e0603524b000c5a4a89e";
        filename = "006911.ldb";
        url = "https://arweave.net/lUHYcZgFxsl2H-Bij1b0rkGitkQOWgKyZsXxeUTe0ts";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef35b1c79a7c88de4eebb3bc230c76faad1ebc7f3b4ad6983942080560575af6";
        filename = "006912.ldb";
        url = "https://arweave.net/EsHqmyueYYvo2H_EXHRf2J9tZbjRWKE5Skc6FJXu0-4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f5fdff3f5133e0ed182d3c5cfae1345d312e5b8faa625b38005430bd3d5bbdbc";
        filename = "006913.ldb";
        url = "https://arweave.net/8mMQEnPkG7ehMZ7h43Ip16FGTykzgB9SwWYjP7KAEvQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c08336824d3baf329f01eba499f13978d963e6b5156068beaf595bc7327bf894";
        filename = "006914.ldb";
        url = "https://arweave.net/B9X0Wd38SujJqK5zqn6GI0lw49_SZ3Q6XEy97YmTerU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3dae289618b012daa7c2ee63948086896c77ee290ee293a02ef54514a68713de";
        filename = "006916.ldb";
        url = "https://arweave.net/4M6c3cP1CRI_ZLWAY1uzcmKUrwCeyfIAJEGu-apAXug";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "91254da323f856dc8d59dc43dbf1d54984e662868b0dc39d365f6f36a8dbbd94";
        filename = "006917.ldb";
        url = "https://arweave.net/JM71KFwAqN90NlkXkLdIL3Kut5MRwhAfLAzmIoCf64g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1e0a14d399cd8b142d373a222d9a1dc18fcf2a581530bb451f0eec26fd47c853";
        filename = "006918.ldb";
        url = "https://arweave.net/e_4ozF_4yjFOeQcKfx0AUkCdwV6kyHYTrjicFljllP0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4e0516226d45a0862bda8917ef111328cbc5a7577da60f71e3031618dfaec543";
        filename = "006919.ldb";
        url = "https://arweave.net/rXjrWWSNFAhTaZaVuopJ2lRo3LLU_S0cKQnncK1gXtA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef7ed89b234431080f92bd54bf5874db5ead095bcc2c12a369ebc27336aa40cf";
        filename = "006922.ldb";
        url = "https://arweave.net/GAcK8_W4rqqnxsXEfhnxY-AxV6-zDc_NShAd9GTc4GY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "599cc3dc3afcb08c58fe238bf8261bf9e3303bbfa0380b17514e64e1f890c7ea";
        filename = "006923.ldb";
        url = "https://arweave.net/gNLGsZi_8racFBhKaX3XU5i_Zk_aIAfjSRk_kvddJho";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "55813206a8da27513c806e4f7cdbebd191b4aa6149723d5994ed47dfff17e69a";
        filename = "006924.ldb";
        url = "https://arweave.net/BVkqOicAFft0LkqRCfer6LbjYGzVvjH8GKn6VffqTWQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a6cbaa9e65684c66c57d0427e525945ce5e944825d0caee047b00a01ac77486d";
        filename = "006925.ldb";
        url = "https://arweave.net/JN40bm_QVG0oUvApOwNx0IKlLDHd-lJf_q47R5kX150";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0c02d6ece70cede90d002559cf5e0084b9972b8b765d2ff1c8f9ee9f959ce60a";
        filename = "006928.ldb";
        url = "https://arweave.net/OOWIuNZ2Rnsc0HKz7k0FQV26ZpagjNMXD2ljRPdJ5og";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0c5d8753887f14c94b3d03b209f6435aa729f89096c1fdf7e4406e47d5985c47";
        filename = "006929.ldb";
        url = "https://arweave.net/4UdkFaMIjLKCVrpxcoxpFKuHwonJzwGtzSs9J4_fGw8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e525b23a9a7c8a2bcbcde61f13de26e1fdce186f08ced458f1ed81f9e670867d";
        filename = "006930.ldb";
        url = "https://arweave.net/XaK5XamhwRNWHiC5C9toqci0p2u85grAYR_0Y1D43fQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4098bfdbac8812853c3e27ccb86c1a72e7d97e816b6f5efcd804366b131244e9";
        filename = "006931.ldb";
        url = "https://arweave.net/nfjZluo1R6OMl8X4id5m18Cn-y20sMfTM6QwEAR_PzI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "11f4dd764a01fe84b44ea183415091d14ba652cd8afe643870fcfdd0a9da95e7";
        filename = "006932.ldb";
        url = "https://arweave.net/uDXxdVsq09AqlX0amYUXKgJqPPL0D5Q-lTIG0Iy6Ij0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "51fcade4bbc1289b959ba8f744f9a70bb7c980c1f23665547b0ab27fb8e98db9";
        filename = "006934.ldb";
        url = "https://arweave.net/YY5hzbfjGO8htupXiwSmhmY1ULlSZLB_bkFm3R4CyaU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "dc15b963c1eec9436104d6a00c9b03487d37318da52b72cd1eed5b35f253877f";
        filename = "006935.ldb";
        url = "https://arweave.net/PABzRt-I0Ys8J-HY-T0_6O0pTizi7vgeArsaih3fWA8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f2f8511346e8e5d5d4dec6964dc1f6fb08a3777c49c8cee0d63436e0c2a8c240";
        filename = "006936.ldb";
        url = "https://arweave.net/Gp6-nuZ67dYw0h6Tqfg1cffnMdGXElFgS9iPil0YmOo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7b87e95a0174ac3e92cc15cd6a803d41c4a6b900d78502fb5c8de0204996859e";
        filename = "006937.ldb";
        url = "https://arweave.net/QOYhmoipUe0fOfLTpeQEcQmh2NISK2DLNY2xA2TXJ5g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d1804bf4a751dbad47810dda69c7f944a3cb78b26d0881519043b02a955a1436";
        filename = "006939.ldb";
        url = "https://arweave.net/jgTYNfZFC0pct_cvB98cw38n5ECIF13Nc07_Yib6SgY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e243a8eee142b2a6a595e37503a92fe84ac7572545370cc2771a7e48ae3fcd63";
        filename = "006940.ldb";
        url = "https://arweave.net/ljh4hgcGJCwAHqAJubC94pxDVRMwH-P42cXu68YJLD8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fdb6702ffb430691394e7aaeaab00f980b0743850ab7aeeaced386c4c1186970";
        filename = "006941.ldb";
        url = "https://arweave.net/6gvR9rxApmoqh-_MRkDI2vNOQDWonyVSeSZpjUncBls";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b6eda8a7edd863435b07a549a2195fd327d2b5859f65e5f05192bafef31505d2";
        filename = "006942.ldb";
        url = "https://arweave.net/EZI0ORXDWVCbCi4sLSLLRHIOL-PfsvPEfntI5zjDRQI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "13b338fbb1fa0d646e6fa53bd78e7ddd292230931b6fc54c562cbb8886edfa08";
        filename = "006945.ldb";
        url = "https://arweave.net/WZRif5sXxu0J5hVpSCQ2i91YiOrXshvb13aO00S2VFg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ae4f001a58d332caed2e102ae77058b3aff32dd6e4ecb6e1dd67574d6271a26c";
        filename = "006946.ldb";
        url = "https://arweave.net/anxRdzpiiQ7Ork4TbtFbD99cM9Zh42oRyCTBdQe533E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6c1700d6decc74362895d9be77a3b28580092beb6e45f9fd6d6297504f798516";
        filename = "006947.ldb";
        url = "https://arweave.net/ianASuy6IB6U5RfLkiOh39-aHxCClRYWZ1gBFxkja1E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0e39787e6db4fab50f8c2723577d0f865d12afba56d385a21a516b340052aee9";
        filename = "006948.ldb";
        url = "https://arweave.net/Xc7AANfQ6OnMKCbupmUVHSYMIo9aUPGW7oDGHvra36c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c43e9744bf73a62a08779b9f974d4cd35f908310f8912448b13a9df7e2a50137";
        filename = "006951.ldb";
        url = "https://arweave.net/OLakhxRpZ1jIqlY5HWmQklNBotfPDHZuXRbXiau5qmk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fa90655d05d81c318fd5f6af7cfb29c28de19931bb2be2d87f9784426d5789f6";
        filename = "006952.ldb";
        url = "https://arweave.net/Wg8TMTRWuZGEjZy5b0bjB5FZO7OIscwT1A16eYQFrMw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bf718f2c2e70f2b2ff36ef783bd99fd521ba6969c2038fafa1ce599322d191b2";
        filename = "006953.ldb";
        url = "https://arweave.net/7I4-3By7aGBCxWgnmi1vk9_oSH0IOL3kfZic5LKQJsw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d8eaf3d53128a407d3a5e74c609b9dd822fe97ce1505334cafba121473f991a7";
        filename = "006954.ldb";
        url = "https://arweave.net/wY3eUEncRCZc7iMDlnVtnf6aOawMonMsLkQEnOwmmJ4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0401fdd2034a68f39080a271c6fb2b1eb5b1d44e89209a3bbb57e59fad4064ac";
        filename = "006955.ldb";
        url = "https://arweave.net/oPQG_SLsyyZd5t180seCErLIAI_BgyKKYVLOpotI_u0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9e78555cf38ddc44113c0c6965ff8660fa72e921f7fe692fde417ec67949d298";
        filename = "006957.ldb";
        url = "https://arweave.net/e1VwubTW10fO6PIXrj5ZsHxV_a1CWhuy46Al2cGUQiI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0dbe336f0802fdb0dbe12fe82349201cfb4b86aff30617ede0af90b3129c4bd1";
        filename = "006958.ldb";
        url = "https://arweave.net/c_00rTHEZsleFV5750iM3rVWRE6-U0oeWlaMOexRgSg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "032faf7349a5c3415ebbdf548c1ce111ded517cf90d6460ec646bb89d381af14";
        filename = "006959.ldb";
        url = "https://arweave.net/7m-YgSSApjS7s1uBMeutjLwSViBH0SBRveZjyARdOpE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "202c314b655d522a65bdd4cd0583fc48df9dfc559ad9cb7fddf95c0b7384e592";
        filename = "006960.ldb";
        url = "https://arweave.net/aoH6u9aKyF6t3TbzCLpPKKgiy8yJlYbYWschfdbwtaA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5f36b6c8f9a3a7ee29d5acc840b8c55d2406bf09704e74bade3334976fe8b146";
        filename = "006963.ldb";
        url = "https://arweave.net/Q2BIZ6C6IFx4SKwq330RiCqEnM2eWbXSzpnNY5xjlYU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "98e65bb6e1c19eb3b0bc452a8b0705932265b28672fb6f8dd8c06f1f1c166ccd";
        filename = "006964.ldb";
        url = "https://arweave.net/6epkc7-eEVRDgvs97ACkN6f97EA0-svRrte-w2sJeec";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e9119a3f18b5b07951450f498164926d93c6314810f188e1a5de3059911fcddd";
        filename = "006965.ldb";
        url = "https://arweave.net/WvZKDN0O_UVA1oyHtksSYRNm16m35D6QahBSpWYskfw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fcf16ec98b3d7f815696ef189b493f19db7f4595c5407d04299bd557e959eb31";
        filename = "006966.ldb";
        url = "https://arweave.net/5dySQWDNnpaqqABIfDra6IpwccS5mbfquXYLtqbAhVY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "38222876dcd30b033ebf6a3e1f760ee0b03d6cd04d532947f1492a49310893ed";
        filename = "006969.ldb";
        url = "https://arweave.net/gfjycicYXZd3wovTM0zKLTowJ-94orvbhnoDFVBvkqE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1900fbc1af4c7793195288cc16925c001ab498b1149314e1a908f32689e0dc55";
        filename = "006970.ldb";
        url = "https://arweave.net/GQ9OAMzaRzcI5CcN2vZy5s7nFLEJQkP9fbpVT_URyQ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f3c2347642e0832660a9e1bf274d98323dac0d9f5c3ce2f3961abc9e46aec984";
        filename = "006971.ldb";
        url = "https://arweave.net/J_3DoqPqEfO83g7kzuDM8amQoSqYNI_hlZUnYIJ-5dg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a878a5289ddad1a07ad3cbb2cec2b09a8893dcdc5cc28990e4ca6cec8be96af2";
        filename = "006972.ldb";
        url = "https://arweave.net/efHdyI82cQS-gnCMqYcr9IVXZODB9dRmC0Y7141pBO0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b11ba39d8f8aaa6da78ef7646cf4b002addf53582e213410e9e6440bf53dfc17";
        filename = "006973.ldb";
        url = "https://arweave.net/FHSZJPlm8X85RcPZxib1tHFeiaB0WJYdiwAW_PP8ZKA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2ed45017d937838b1dea3dcd97f873924a5880097aab753260014a824378d0ad";
        filename = "006975.ldb";
        url = "https://arweave.net/1OLAhzAsDZS6LW5DIdT-d1UY5CCNMIJuPl2KwSP9R2k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4a6850cafa17453978577f2b4f056f79bed0ccf851c59e057ab775c7f58d3896";
        filename = "006976.ldb";
        url = "https://arweave.net/uDoh1FalAoOz6xXO1k01KNp9eCo65icH_cuq4Irkpmo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e81b2eec0b3eef84fadb2f3fefa67fb9fbe6f84154d0184fbe45dca61896d62c";
        filename = "006977.ldb";
        url = "https://arweave.net/i2yaPhepx-_d_zD59iZE92WKtZJyHwcFj0mcYFilGGM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7a743f6c33bf761ff039da0d8084bad5896ea62d03b1b644fb944ee0fcd000db";
        filename = "006978.ldb";
        url = "https://arweave.net/ngYZew3iLyVzdQ_db_PBeuXUydr4P4mkgkBe9N2ASYw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e8b0b65f667ca7bef5e0bce5f4cac6e7e536eee303a4a054c7f2aecbdbab5cdb";
        filename = "006980.ldb";
        url = "https://arweave.net/2kdTcZysRcc4CLFMLHs24jpuXieo0zZrRMniK9KZ8sM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "82908424053410b55c5596662ac0db550a4c3a0e79f4a446a6705df454d65e92";
        filename = "006981.ldb";
        url = "https://arweave.net/OScOGVkptuqMOJfk3wk3y_JNnSQ8URfi8Ll4bM-eq4o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "85379f7d4d9303e80cf238d923424f94b046f9ebe69098e169e71725b5d44746";
        filename = "006982.ldb";
        url = "https://arweave.net/Osel6YgWf2hohjREnHcqKTnWaJbKCJBy7-PRDI3GIIA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1c4b91d239a24524b6801b737331fcd06f93f37e9deaa042ac1b780a4275d264";
        filename = "006983.ldb";
        url = "https://arweave.net/PkxPi4KjnFywiToZdLJiiC5Wx-r6Fq02680DYAuTQMU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ffde324204821f0f675d2720dd92d59b093122f232206db0e7d82086ff61094e";
        filename = "006986.ldb";
        url = "https://arweave.net/1l8266aln2itT51M0aTFouArw_u4kqoI4jfmK-xN_fA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "44320f4a5d374836278b52677c8eabee595b832715b5c1255abdb4534b94998e";
        filename = "006987.ldb";
        url = "https://arweave.net/FJ5si8Ivrnd816x3aLvVjVx4QK11HP6WB07dM44VgmQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b28b6c42db6403fb9d4001937d50cd3eea743ecf666fbda6b055a042c2cf25de";
        filename = "006988.ldb";
        url = "https://arweave.net/007pX2w9X8PduUhNpNd85o6ydjIKu8dVE-1l0AMpQKQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "95300eebe92e86f80207c54db28a91bb5118f0551f88c74adcb9a88a5a3e9470";
        filename = "006989.ldb";
        url = "https://arweave.net/huts7fw4JBPcLqSaFXi-L-KyIkm9ZaB3cGKglpouyAo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "515c3a24811b1215b99f7032e4ec5ba0441ceb915228c04a935400a46f651132";
        filename = "006990.ldb";
        url = "https://arweave.net/RExinYzX10t6_9mozu3gU7qA8GxIcwXzE7QH0BZTzBc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1ebd67a7996cb0631909848b3907a6479860e063709e770d27f3b066b78152bf";
        filename = "006992.ldb";
        url = "https://arweave.net/1p1lIdp4vUjkO33yk9q3pkLdrzU5S29NXFvHim0ftZQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c821ce7ee842a503813adecfc30f67ee4141fd3dd312e8a74af6305850745850";
        filename = "006993.ldb";
        url = "https://arweave.net/jEB1miyyOv99xf_G9h2osiUUJKImC1CJMC2fpVeIuDw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4657e1a3e90d358219e310a79100b28294126492929acea8719eff8717d581c2";
        filename = "006994.ldb";
        url = "https://arweave.net/x1DELTASFqTWvS-7Z-olynlUYXpRf9BJPgPRIaHF0Es";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "02322c19377cc0e92e2f335d505aa7de30d52367af51507d96975ccb8ae8b151";
        filename = "006995.ldb";
        url = "https://arweave.net/yFHpMNxME7HbH9OSbd30qNeAweTHsgurbakH4nmdIDo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6abe0c2c66c51a4bf58cd6a2bceaa7fd59c053d287f768edce891064a761bd0d";
        filename = "006997.ldb";
        url = "https://arweave.net/EDeg5SxLza02oAV0WhklijwhyPlsT9Zo6u2AOZn5jwI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b65322341d5d6ea0d666b379cf5b8c5b2042fb2848035ef69576bfe27e295970";
        filename = "006998.ldb";
        url = "https://arweave.net/tTQvF6meNulB-03YErwfDZezk8p_B4XU71uUKjNuKW0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "95505810e5fbe3983690c8e6afe6f3fc613e6c3766402db924dd0867b499e849";
        filename = "006999.ldb";
        url = "https://arweave.net/2lnh8Goyo9oxS7PNblQRVkXMkcVLFiouuJoghXyb8lA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5dedcaf88562a5e5bab4a0523c37093fdd18d333ea406762c7e2e0a6f94f0dd2";
        filename = "007000.ldb";
        url = "https://arweave.net/xpqAj7SYLMDppDyaRrgefPLh9BAS5OLhn8rqwkVo-_c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ffbb0927be82a996fc1f82dc999f4d17a95d742fb0d9849aa22339375e9e0e7";
        filename = "007003.ldb";
        url = "https://arweave.net/JsOmgS7rac_CVjwpp_dGVayVISlVRAFqxjeWJdtDAsw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1a0940b5e6e0499e769bf5c3759c8446a666689573d9ec596a26294754c7bdf4";
        filename = "007004.ldb";
        url = "https://arweave.net/eQeUP_RpelQfO-7UNd_XrJnvRUq6Y85_-vcw0DHLi-0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "38c7b2997771560d44ae9d822c3c7d3f5bb63e1153b5f950462cd9b73fd7e2ab";
        filename = "007005.ldb";
        url = "https://arweave.net/qsSkwTQhT5RFXDyJ25hX6zJY_sgpZL28RVAJLN3vVxw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bf066dfc4f92d5b73e7ebf32448c30e53e40c15a9754ab00f9603a11eec9a79d";
        filename = "007006.ldb";
        url = "https://arweave.net/KrlDvQtOXkIbUlUH98NYpMnJIAZO_FFzECQjNHxwcnY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0fd1e142616bf0500792d1e93c32726bec1b62dd93714391e2982bfca23916f0";
        filename = "007007.ldb";
        url = "https://arweave.net/Uh_TgO5iTxMnJGJto3HkpVkOA6o7meM03K5HFnp4j9k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7e591ac80f704286e4adb3178535d3d58712da6ae5f802d2d43b44e404670a25";
        filename = "007009.ldb";
        url = "https://arweave.net/GJ4tJBEuzW9id9CHMylPewKfvzxJoDCRa1bPI68d6G4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9ae8b05055d5eb7bddbfcb8f00abe9f52969fe3a586a849f937d9a8e698319be";
        filename = "007010.ldb";
        url = "https://arweave.net/kmDl8Rxnl2ZyhM04vajz9L9E5OT5kYyZHBxH8SWKnQs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5a4fa30b0c860ae49a4fbb7406e137124f09de0ccd80a872c266fa34431097df";
        filename = "007011.ldb";
        url = "https://arweave.net/Idpl_gK98wVvMwW0ZacmVkiu1FpNzvMsaKAJh0ZsZN4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6e2a9207756a823893fcd82cf378573eb38304bd0314905f58b38d69127f94cf";
        filename = "007012.ldb";
        url = "https://arweave.net/MUSL1st0dIu7tqGTRGWuI5Q1RLz-cBcJXPriXmgmKKM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "901c35671d3ddf0b3ab06e9d35ad22c05953a85ba85885dc85b3a69ba3f61ee9";
        filename = "007014.ldb";
        url = "https://arweave.net/BPzPQyzYUfcjXGHdVAnujPnfaYHoK62zDlLN2piAEuM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9cfa1634078f9386285934e25d7b9b30789e384b57d8780cbc2cff3962ff53b1";
        filename = "007015.ldb";
        url = "https://arweave.net/qRaF_3UEminHvw7ZiXeUDYu41iXJ9ZSCWxatHZP8KEY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ad9fcccc1234c2799b33be2a749ab5715361c340e77a019d8626f4fc4fbe15fb";
        filename = "007016.ldb";
        url = "https://arweave.net/Z62Kx0hmHaLpdiFEM6eBkiNSO2_BWmq7vQKVOW8TPJ8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3e315871271a2a4368232dc04f7be587ce07c665135bac141326c436a08b9903";
        filename = "007017.ldb";
        url = "https://arweave.net/p60yxmVThGlF215Gfg-W0ff56X1UiTfsuJTZMJOj6nY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d5a8cb6da8bdb1af2776f6fd8d6027e8b7e34b6fe7febff2a911ec7a46890ab";
        filename = "007020.ldb";
        url = "https://arweave.net/kWrc5v-2D15qCXBRK7AJeon0KmwX62p8h1NInXlLWak";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c56421377f89942a616f379986cc85ee9b5f472978a57150f63c1c1503ffdb4c";
        filename = "007021.ldb";
        url = "https://arweave.net/u_vrCPkpxHbm-pXu73RjSWIDuOLsJCgBlJ61MTTcrSE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "84e3c66831de9d89722ff207c2dd114297665e14a5626a1ca65c82f3f66def54";
        filename = "007022.ldb";
        url = "https://arweave.net/1CfJ9ZB77atFgY5EBtRSQSbNriHdef5dNJ3vruWfepg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "35628022d6b6374628b97d336219d53432c76756878138527f3418466234641e";
        filename = "007023.ldb";
        url = "https://arweave.net/EfRMDvscRlqzTDeZ2_ynw-ImOcHpQf71g0enSL9izi8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d0bb4fd53fcf1c13604a6f0135d4f7866e86e6f9de28039f333f205d1b8f8327";
        filename = "007024.ldb";
        url = "https://arweave.net/sXg8Ef-J0vUBw3K8gU192L9t8IavIjSNoJehNzE7iHw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bf2c61fcb329577fbec6e0c53594b7e203476dc4205b70b52b691772f422855b";
        filename = "007026.ldb";
        url = "https://arweave.net/eXgsStjm0Qb6ziXfRPBfwUYjXTncu9nPzTqn6kFTUGA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f33de74cda08e3c4dc0f3f2691fb1871242cfdb3890eddcd688e9293b193bac2";
        filename = "007027.ldb";
        url = "https://arweave.net/LZCYN_f1OTk-9qy1bic53r5fM7Go_O1L_5nJM3USLIU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1f1655b17c619a2770ca40907313e9791ee86bb616ff6cae8ab28d5aabbef1d2";
        filename = "007028.ldb";
        url = "https://arweave.net/e0K9GYWP6sGI-1LFSLr-mSBo804YBYgN2hTNonYArY4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "89cfb0ff1f2262861d5d8847202ff5efd9838c7756cfbb2108f3cb9f7164a23a";
        filename = "007029.ldb";
        url = "https://arweave.net/J8JGcyNZjsU3gE1WYT1gJSKgkq-VEL7NVzpwCFLBST4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "82460ec6c0f9c845acbf4fc0f1fe709b8f8339429c2da9e4cf15d1f2dbd1be54";
        filename = "007031.ldb";
        url = "https://arweave.net/MxUJ68IatWcwvS8KWwshMh338v2E_2ouNKQCoqtIdSQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3a7284bdc7b0ce0e1cfc8ee1d480565670bb2948500d811ae62f14e5b0e6a22e";
        filename = "007032.ldb";
        url = "https://arweave.net/GqF6uMR0nhYb_m_ecymqwXj4vOlKETZamABGpqIQ_pY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9add41a8d47c13c86c055de451eafe3335bb1258430ea443c768623ecc203a42";
        filename = "007033.ldb";
        url = "https://arweave.net/i-U1B_SB00QhyZDvakNpKzbB4rtrPkjfo3KdkHOYv4Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8e7a739e49fc7cf3058b792a3615bf3574632a553cc8c4f698fb6d4db0746317";
        filename = "007034.ldb";
        url = "https://arweave.net/jVPZ3W62wtBgQj6DbmbO9vgvwgTszpgnJd8muELXrlA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bb6dcbfdef64b3ffe358c18f886d4798b343cbf4b32b9e194b636cbaa99c5a20";
        filename = "007036.ldb";
        url = "https://arweave.net/7wQJszZd6r-x1-Yi8c1T6kwmnX8RqAiloe_hqTgIB8I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88e9671e3b5f7abe0df145cca4fdd58d909b81c11a84d2fa1c39c297d96d407f";
        filename = "007037.ldb";
        url = "https://arweave.net/F1PihZSMK8ClNmIRBiLyWGI2fEMIXdNxXh8j9paIigA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f5a2a722b95caa9ed42a27db5ec15e6e507de4e1c40977f34cd012b3678dc09a";
        filename = "007038.ldb";
        url = "https://arweave.net/8HGLe6JpK6VgjEbC3AqvsTMB63F73Oz-kLmrXe1MUv4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6f77a4266c2ff57e24ba705a1122d143228d501661f64b4937402b643cf2ad48";
        filename = "007039.ldb";
        url = "https://arweave.net/FdfdsW6dOZ0OxIxVTqjSiPhfPRvuPSs-2LHiyiaedmE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "98c5baa5102019c94e37af01cc2d434e54bd0b65cc943ff0bd4f2df2e80138d1";
        filename = "007041.ldb";
        url = "https://arweave.net/F9OpjLapEYvNdBUmsJrxkP1MdJ4X0IUOhBDcaoT4mLg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "81000077017e2354c31c212bfb8df34f1e8c8fa5d3349bd3b5c20524b2446113";
        filename = "007042.ldb";
        url = "https://arweave.net/MOxQQ_Q6mpuqs6NwFD76Lz4_h0xk8tTfJXhFjlOnkC0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1be5de66be280251e1db259c85cc204b642011b40c7a84730c3ebcc8ac16c189";
        filename = "007043.ldb";
        url = "https://arweave.net/z-aP6vRbKx84z0I5OwNVsaMaO5mz8kVwt-v1H_IlnVk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "27da0b9266eefd7ec7984fe46756911b7415b89851a77d48f2dcbc94d2acea74";
        filename = "007044.ldb";
        url = "https://arweave.net/pOUT5RQWf-VnZN584pbOPChYiouWDq7E9gD5RBGJw40";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "579f5eaffab50dfa20ea7fa47f2fba40f0fe67470bf4c978d3f2df26ac84b280";
        filename = "007045.ldb";
        url = "https://arweave.net/8P3R9pgp-Z3OEXfgTzKWiFIpMD-dF5kaEClwtNQViww";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bea556457c9e11388d34a01e8960bbc85377d78be9e91746346127f05e4fc637";
        filename = "007047.ldb";
        url = "https://arweave.net/6yjq2xW2FO8l4KybJnFNG6Nl1QPhWRIotQwGffSM-nA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6f5d0636a8a21d7175b45fc1d4c5135d9ee89239800cb8558d72fe50bd97e553";
        filename = "007048.ldb";
        url = "https://arweave.net/tP5Z5B3udxI0C74TewTmyUxYO3DQizFgI-myzQs47Ug";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "51a76c67d27a2c6301f5790f6374cc08f7c6d2393020f3cc4cfd259e44f71641";
        filename = "007049.ldb";
        url = "https://arweave.net/GRVeMn4NeW1oQfLg4ky7XR4fjy0dYGz91LwqlbQOlWU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e22428c25e854a6f764f1924c4e9a85739c48c5df4a000c388e58a9828df67c7";
        filename = "007050.ldb";
        url = "https://arweave.net/Sfv_Pbbt5toMc7ESPIE8gCHzHL94kHv2eq1-DIwY9iM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b90e0a451055d70a6513577a7f0cd99c762900a2052bf6662451d8f66cf70a33";
        filename = "007052.ldb";
        url = "https://arweave.net/i_Z9y2s4yRZ4jeIAPs5gAUuvG_mEZJxdZL6AaAG4olE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8e78f5ccf5d620824cde4d2d11bc7571deeb8b21652a4ff4c318a3693e21ed76";
        filename = "007053.ldb";
        url = "https://arweave.net/6eALZWP28mZBzNHce8N-GuHyVflRzLhnEzEKlWXLgWg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ad56f253e3d89d6e46711da0122d64a6b6c0f07570d656e250c6afe9a3115ce8";
        filename = "007054.ldb";
        url = "https://arweave.net/bVjr-pCUVD5x6GLYhZE448j-hNAWp3lvZNQ1N82Bdpg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8db1c48810eb5886d00918933e44a6cb1ac09a2a4af60e578b3a80a44ee15352";
        filename = "007055.ldb";
        url = "https://arweave.net/M0STDqOga3_mDDc6vmvckcgNyQqzyOUGFxaFkD--JaM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "df71c019fbfa8e907ebbc3c1f9e6bf4e2f63e0b54064e04ae52c18ba9c3e00c0";
        filename = "007056.ldb";
        url = "https://arweave.net/1h_0_Tk0Xn9AhvZfz4lPZ8K1r7cITu-NT65jhX4tREA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1d93ccae1edf35f26c5907132e3e89bd3aa8571206733ca9534c5d2c1ede7299";
        filename = "007057.ldb";
        url = "https://arweave.net/Ey5uj8KwqpRl0Dg90Ds_b6O2MM9YTN7d5E4lFfZ2alQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "65ac31118dd7bb56bd8dc29bd29b3061ab22bbfc0b4f7ee9a3a786a30e20da83";
        filename = "007059.ldb";
        url = "https://arweave.net/83njY5k_G7GJ31Ol-uwNWT078iQ3iHZwf5hXwvaWU8E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "972b629733f1c30b04363dec42bd2749ce28a7998a81ee64b466d0441d716eac";
        filename = "007060.ldb";
        url = "https://arweave.net/BN-dcMi2rv2k1OM87wR75SyFwijBq1T8JnwdFGIymwU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2a595e846461b39406ca201e87a03ca694f06780d01f4a67892cd9d8243b6c94";
        filename = "007061.ldb";
        url = "https://arweave.net/uI-S_2DlfSySPfCy014GNN2A1-VgjgpCx2v1fNnwbKU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b41f41b728424c87556f7301dc0425d34cdbbde52279d8e805da6a71449854ba";
        filename = "007062.ldb";
        url = "https://arweave.net/90PMUO-BBzqKpFbYFbnpZVTZZddFBUIJHF0ISRYgCiA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "51cddaaf3d246b44d5813d389596e54617f72678bdac10e88ff3854073d8d2dd";
        filename = "007063.ldb";
        url = "https://arweave.net/YY0Y4lCKNcsyBNazIEYTFqMjwt64NrlGpZQho6ZEM-w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "861ddf15d7cd5167458dba171ff60282f645b1cb5286dcf3ccc156aedf986721";
        filename = "007065.ldb";
        url = "https://arweave.net/JdESg_DYbsq10txMFP_UkCmbn9FHNXAiVs4u_IXcazY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "533e48b151e09f923c5b2581f25df43bdcf8bfc4648d78cd0d5ff6a9b3dd1f85";
        filename = "007066.ldb";
        url = "https://arweave.net/5-wCuhVOcwOSg0Aj-Wd1JMIkkvNhT9A3e33blsLh3IY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c13f975623b54ae2321a0f9107af11e951c336aaab7bd7e6a16481e74057b3b9";
        filename = "007067.ldb";
        url = "https://arweave.net/v5_j2p1nWTbIUi407m4Zdips1oJHAEXgY-UjAB1tEsk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8f11071931acb2aa441cdaa0fa070b347f38bae56d4f653ef9bbc12c11de94fc";
        filename = "007068.ldb";
        url = "https://arweave.net/WegjXyiaCme4tZmmtJAhg1l0z2GsV2QYUM_KbHnEAf0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5b61ad733f3fbcac02959860419386e74a1ccc417668271d15f2c6219edb0cdf";
        filename = "007409.ldb";
        url = "https://arweave.net/PKHMS3dNd6zzY6T3O1SvX4JStGEbTW9LjxZWdBG2lfo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4777fa4c5f04c727d935a4fa6a54c151b30ca9be9777beeff5aab76d34f9efff";
        filename = "007070.ldb";
        url = "https://arweave.net/4ZWnSyDmmxQrHhSD0iJYrgUW8cfoATuP4Vq1TfTmXW8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d74340684338051ba2357d3d63b97af3e14f6fd18804df999209f56a6c9f03b0";
        filename = "007071.ldb";
        url = "https://arweave.net/gF4DPHQgJE8KT3X-hqy7CZoVZGaYWTREL3NqYqU8968";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f39fbdc2f282e0b52337bcd1a6acabd02636ea2a28ec7655aa3e67805beb9c8a";
        filename = "007072.ldb";
        url = "https://arweave.net/1hBjp0baonObbQiYWCRs-QZufdWpigvy8pubxNV1LeU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3ccd3bbcc24124549b5af248f30a6c7870d05fcc3758f1846729ea31057361fa";
        filename = "007073.ldb";
        url = "https://arweave.net/ifWPKi0UhTmbXTz7vw18hGLLAB-31mOFWG3ODmTvICs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c66f3f6f32837d7aa891fd4c964596fee12210a1a7dd110625073b5eab5423c9";
        filename = "007075.ldb";
        url = "https://arweave.net/QljHkF35r8LRI-G_Tv21K9a8d1nQ6daD3Vu0ocs2enM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8b6f411e3c72560964505dbd81a6892311f517b65beb2b27033ddec5dcb1ce5a";
        filename = "007219.ldb";
        url = "https://arweave.net/pSCt2tRw2_6KWEOEbxawXWr8jLVYQOBfC75IyaIIR8Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b8fb12cb567800a4fdfe8c5dca5b143c136964b1519e7317ad3e4dd743984859";
        filename = "007220.ldb";
        url = "https://arweave.net/RPRY0eUpJk3svtUoHJpcJY2xpy793FDTODE2Wd0EGH0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "77d5b0ccf627c22741448ddd9e91fbadf620dd14d35c5bdf87cc16cd6a6a9a34";
        filename = "007221.ldb";
        url = "https://arweave.net/Uq4HWOy9dlmO4LAH6nx1mmxiWv41Bn2VfZV46WyjNxc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "755f57e7fa5932cfb97f9ee00e4acecbf2e50fbf29cfd6eec53a8beb46de872b";
        filename = "007222.ldb";
        url = "https://arweave.net/nnfuN1LbW-Y5Ftxn-njhpNgDbBPXEXorM4sd6N7aGgg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cb52a9e28f92beac4232e7c641d255cf18cbafbaa82065dcc46c256169733a5a";
        filename = "007223.ldb";
        url = "https://arweave.net/bjEesUaMKsKiNzkdUUiR8-gmP6W68T4pmASLfTBTxrk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2b54eafabca6165e5cb9fb9d83eb5cd1a8fee0916cd5266c47a5a062daa381f5";
        filename = "007224.ldb";
        url = "https://arweave.net/hfXmOFu1Um88iHYfBiSw56bQKaPtlTMM2eeufGGJUXY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8fcc9f17b219ffd641111bd5b535a1d7c9da1d9a8f7a6b8e7a2e2f3407f1f423";
        filename = "007225.ldb";
        url = "https://arweave.net/K6ogC_Zfd5pyl0HhbUTHSTUPrr8MljuMDFLb_INmSnk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3fd40f135f2c8769e2d2648743c78071e4c23c0b093d1b1502041a3073dc23bd";
        filename = "007229.ldb";
        url = "https://arweave.net/zY_yGmXeqN-04oUZ8s_PmuMSi9Cc8uRgpPkxVd5CTXU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "137add4d1806b4024c204c40a58b111e1c993a7703f7efcd5aa492665da1f9b0";
        filename = "007230.ldb";
        url = "https://arweave.net/dRL8jIcm4DEITkGDhofFOluoILwTD5_zW_Wi2g-Zgzo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b237c0d14059a1493f92f2d6adc000d244fe063d484450e3cf2e64d60ff93628";
        filename = "007231.ldb";
        url = "https://arweave.net/ltoDk5ZRO-XGwXfgC3kyexOhRW3iNTlF5AAli7EFLck";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef0f64ce0a5056efaeda8047b808ceb111c3b905320135a27d6742d9c107d361";
        filename = "007233.ldb";
        url = "https://arweave.net/PqediuIEU6MUD-bV_3injp6U6W802MUvbVeO6iEmW68";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ee02871232d35eef7d60e9a6472c6c816fc429d60d373d040dc874a39954f7b7";
        filename = "007234.ldb";
        url = "https://arweave.net/lGS-KkxGfrbBBPZDWScGUVnk6nRLvf-c1-wSDdIWXd8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cf071b8db488832472270e85288428eaed27a9e41fdfb99ffc83601f7a6d1f0f";
        filename = "007235.ldb";
        url = "https://arweave.net/LKuGvxevMkietUR6CjkWljhh05jMRy9qZj7qywKkrCQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "815bd168f4823902f79f80b867b11e27c6b1304e935922b151715370a251ed46";
        filename = "007241.ldb";
        url = "https://arweave.net/W6j6QGf5ZqnpyHXZLMEuCJn5QEChqpk9Lg1Z3OUkaq4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a8b08f998a40534c214c5b6c4f879134bbe9353ea39583a742259a39d93ee136";
        filename = "007242.ldb";
        url = "https://arweave.net/5izoNFWa4rAO0rnm0A_358O600CAEgvEx-cnQRSgwH0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4d125c5d4bf0c6cf55254be9fb8bc1bd250269f448b82a0dc46a2e4e56abbba9";
        filename = "007243.ldb";
        url = "https://arweave.net/robkM8jHxPBufI7TDFiay3TMJJsNZuTWiomPjWvm2O4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fc36708d1f6c2776bbe3647dd1b35d1985bfdc34c926496c02f96d2f8331c157";
        filename = "007244.ldb";
        url = "https://arweave.net/LKS-EjYuNMt_GHSiErqqXGEfvzuoUWBqTW83CzkPe-k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "765c8898836a0b655f17d9233667c37bdfcb55904a9714800764da91242243b3";
        filename = "007246.ldb";
        url = "https://arweave.net/v1rD4pfYqBfW4dU7QN5-oA8h2pilRCMUiSrijZRfLd8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d80a118acf42b16d56a45602639e1ab01bfd6e022a195cd26d93c8d4a4a76fe";
        filename = "007247.ldb";
        url = "https://arweave.net/4bVxikvnWWy-2JzKfDi5f2sgzY5gcwNTVBQx9RvoNWM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "da2af3e1a5dfea69fd677eb407af5b43343f17516575cee7afe270bda895d8c6";
        filename = "007248.ldb";
        url = "https://arweave.net/DtIBEpundSGhCjoy5UswfZvTmcjq8CuVpJtt20GYeVk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a38066dc237d6e4ba387911a26624313ad71a23bea307f0df1765b417d906322";
        filename = "007251.ldb";
        url = "https://arweave.net/UMqqsdB36AyqCXQD9b2iPCrXZINWHehSa_PApuAb3p4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "057ead51dae3bf388bd04483664b40c65d0159fed18001f7859973904012b632";
        filename = "007252.ldb";
        url = "https://arweave.net/ddIJR6_7fGEI1oFRaf7xn-TFg2WmcdHnUCU7ItV_thQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a7a6f6d59ab8ed5f6fd67778130fd06f0e338598170d205dcbd2c8f11e44e6ed";
        filename = "007255.ldb";
        url = "https://arweave.net/jHmnMyAJHm75oIwGLo7cU71rfKjg9Kh5_po9ExJ_El4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "512d1f9bea29180f43f905fd1d259700146735b34ebd4f1a01d994b12e66484b";
        filename = "007295.ldb";
        url = "https://arweave.net/OMRCTyVEXm1mqOIi6ia_TZhLIjy6pc8kbMmb6ROmbBs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6fdbf0136c4b3ebff03b0c2acc39298063e460e20d75aeccd78987ce1bcdbe1e";
        filename = "007296.ldb";
        url = "https://arweave.net/h0qlnWG4HYVMZ7KIPCkpPhBCaCqI6XI5ItDj9s5QjTU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b6c5342f5b38442630933630b66d26a2f1c926b61f9c410035c42ec975833fa5";
        filename = "007298.ldb";
        url = "https://arweave.net/JD0hhRJHQJ44QkHhdAKXyNjdJaXugRzEHCEWaNpgO6E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d491a2703ee56224f6b9c2e365713df233e17ee4c9d1eb7d66a0019841fedfe0";
        filename = "007299.ldb";
        url = "https://arweave.net/jd8IcDR0RU6xIB9wGabDYeBax4qDHvmqiWnNPg9SpZE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2f1a565a23cc4c3cb1607a526f4bc9669fc616b2b658f8bf8fded2a7e953c985";
        filename = "007300.ldb";
        url = "https://arweave.net/HPEg4tGIumXu17dW_AlZuEduCX-muYDIFheuTgB-vTQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a3f4c4346963edd47a5742c4777cc771ce04036f312dde3446e68ce0c59643cc";
        filename = "007304.ldb";
        url = "https://arweave.net/JnFBumHnGRzSj4DidooW9I9bOTX3zQS7QIopWOFQLxg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d10771fad70cc7f661d601a0d02b17dcde91e57898f23a9683540a6e80c01b8";
        filename = "007305.ldb";
        url = "https://arweave.net/csw_wS9OBiuYXwjccw75JfBCbuU9lwTCGniRgqd9zlg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6844fdd962a7e5a8510a1c592c86a3e078e9ef9de6222cc7ca8fa81e26a3db94";
        filename = "007408.ldb";
        url = "https://arweave.net/bzhjYKEy-InWc4kHYxwAxCgpKH7yJGRn8_vPG1zev_A";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "19d62f784beecc0bf088a50ba5acb3e491dc2bcdfc3d9ff5f501764ef190210b";
        filename = "007468.ldb";
        url = "https://arweave.net/5sAPYB_ixRLGwl06fRsM0l2F2rQzbJblZaNFCu3L-z0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5521fc71a1c86116c3db4bf73639c4647ccdf486f4042efbce3c2ea21f5a07fa";
        filename = "007469.ldb";
        url = "https://arweave.net/w25xCMgNHS8gZMdfAj536I-pxYwAi9YbUHmOZkOl3yg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c93a465f33b07aa2c660359a6fc3123e6f2f2f38a49daad9a591f63c3d5efbff";
        filename = "007470.ldb";
        url = "https://arweave.net/sW2GRfbNW9Qqv1uFv97fFnnwGEuUn3ZP_Upa-P8xedU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aaf2daee6ad92d13f072dab5940e0b62d0fef12704deff55740a660beba25c07";
        filename = "007471.ldb";
        url = "https://arweave.net/rFy-LMpfP5OP87uhbol2lQzqw_cdwb27U2BJmgtcZcU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4ed54eaa491302c719aa2acd4b6917d8d755c6b917c19a87fecdf3405b0d7ef5";
        filename = "007473.ldb";
        url = "https://arweave.net/3jsBpDmssoZDtXYmfRrofyZi8lI1UgrMm0L8LG6a3LA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bbbd3e4b5db68cffa6c0164aae15bc727b758579fd2186d833c4d867ce0f5aec";
        filename = "007474.ldb";
        url = "https://arweave.net/0ZhI_bVA3VsCWppBMVYJxmcfVnkwG_PTAfL8ekA9A2U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4711aaba35b0deae2bb965b6e57124c9d730af44331182e0d6038b3399cd24c8";
        filename = "007475.ldb";
        url = "https://arweave.net/onP4p0ItB62Fii3j2tuqTzwz2C9xtfKQNH_12iOu8lo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d0f4ed4c4dc953225587569f9406ee60d6b558417d70fbf338ff1a66b2311669";
        filename = "007476.ldb";
        url = "https://arweave.net/eTtsmBBvSr3amuVCCZ83h5C_pzmQyfi6gSFEtb3tEEA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0fb317c832b58a6125c871caf39083090a3d9d4ca9e530981388248e5ae26bd4";
        filename = "007478.ldb";
        url = "https://arweave.net/PQS4kXJSoWoIDIE8sQTJfQrk6956J2TkeS_4Wwr6Ae0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "273cf3a72261e4523b534afe5a6f61839b52abc2fff188ad8d6c8bc979549b67";
        filename = "007479.ldb";
        url = "https://arweave.net/yTfXF0SPhlz2IaawYV_0nLot2_PMx7JMpyvDXIuiIIw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "02ed3986e35cf9004066dba01e162160a9ae12d10f8907eb03bbd11593f12a6b";
        filename = "007523.log";
        url = "https://arweave.net/OfaWN7vK0l6KcfKlRKcNMczH582YjdcgFm_hMozAGnY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0313affc75ce0c54720e0b8e1ca82be56422cc6614b06080aec46ea160b66599";
        filename = "007531.ldb";
        url = "https://arweave.net/bCRkLB5GtE31ats5k1N8I13dZyKawO4uGa4fJyBK_3Q";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1051dc77ec9984a4d56f64e91b3b08bff6bde65e02ad4a4de3fdfccac1df8e06";
        filename = "007532.ldb";
        url = "https://arweave.net/L1ty3LmNcQ1Z0Hc_WhNFVTn8K3iJbULhDlkuKsjL_Ng";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cccce8cfb68be8ead3541fec1412f9606e57042cfb044fe5274a1c0c53cc238a";
        filename = "007533.ldb";
        url = "https://arweave.net/kXibBEmkNzoBRIXYZe2v332GdbSLVK2nO0dL1x9cR_0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f913373707b06c2b2afed7aa50e55b3dd3fdca374da11456062a5ec9606d2db8";
        filename = "007534.ldb";
        url = "https://arweave.net/4fTKkUDJo2m2AxnD0xebWSm3FZp5TExDE8ErNzjDClg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "afb7f51232ea023fb97dbfaabc5d488bd577508ae526b98481fe020e69b5b26f";
        filename = "007535.ldb";
        url = "https://arweave.net/d0qUqyEtvcmeofppYaOaTHe5wXUklKD3tthGyEKfAMw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "994826be997f09bfc9ee88b2f31dd78a7f7605746829f95320bc9c3283b4a3f1";
        filename = "007536.ldb";
        url = "https://arweave.net/db-BxC_pvQ9QUkz8d3YcRCAbFFwK1SLE6s8GhPHogvU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1384929164a1104999f0bbc89566caf867db7ff29413ac455070c700ac70545c";
        filename = "007537.ldb";
        url = "https://arweave.net/gMfcNRIqarBAXStnoSt8yNyA7vxHHNA1yWEjgoT3vaw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e38dbf3902df108f7d62848deb92d9229440d17b3faa97f9db6963499b65bfca";
        filename = "007538.ldb";
        url = "https://arweave.net/vIoW4cqhc--6avHgE33JrbieEJAuJ7PhKylegFOTJww";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d6ea182914703c041436ad8c3549810049eb3e7496c95c90bfaf6c5e96119077";
        filename = "007539.ldb";
        url = "https://arweave.net/59WeZ3Tc2kCV5or2GHJwya6QctxIN5PkQdUJqAgr-yI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "81f1d74b5c54ed5272af0f8c6f5f347fee5aacdb2341ce0cc9dbe9774935efff";
        filename = "007540.ldb";
        url = "https://arweave.net/xhOdc4mcO5d1zBy2koqLXZwn79kGBdQ2_wba_wkTzh4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8806f5a261596a2e3708a1173ad9949f360e07f1d3a6afbd3f1590d2564df879";
        filename = "007541.ldb";
        url = "https://arweave.net/LoVQIZUAHASc81XwMi_V_5z9div3F6h22D1D3pvQU4w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "83481957bc3672fab1b1d5bc225662497134e43640aa4a5b55c731bb7e78f5c8";
        filename = "007542.ldb";
        url = "https://arweave.net/T3vOltmHHEwybv3XMzQX67ilP2x7RoRYGhfJe8fqaXI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "502b5c33fb5e95cbc758859f22ab1455a0485490532311388f4e83e25cf6d648";
        filename = "007543.ldb";
        url = "https://arweave.net/l1XZZ522qRY2sQjHaNj-EyiSNeHppuhy7eFdwS9-l7M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "300448bae2af865bc3de22d8aafec90c45c0cfb5d27bbae7210a1b948c805ab8";
        filename = "007544.ldb";
        url = "https://arweave.net/R3n8lZ8UoVtm09sEp3mW6gfgZdqx6ftnBhOr4oHqGUQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eac4b5f6bd5e1fac362dc9e0634f873ad0f2762d21ed3e256bd3f478f49f82e7";
        filename = "007545.ldb";
        url = "https://arweave.net/64g-9AmPCsMQ7ihsnlRcZOV0dMHX4_s5ZoHNCAu833c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "71b3c72f729326c5eef9c760cdd433b3080a16e3cedb3de73db81f510bf5bbca";
        filename = "007551.ldb";
        url = "https://arweave.net/9OsQMimbMKKwGFGJckjceIZxWyJm79L7kdd410XTZ0Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "30c355873dc22da56aae641ccf34bdb8f4ae77366866bedd1aa211677220d68c";
        filename = "007552.ldb";
        url = "https://arweave.net/S7rXulWKD9pZ3DG5fADXIMeOE0SISWneO6kdEUokLJU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a50c26afa605922e741a8576ed77283fb77ff5a3ea286797c40b9a6835dbcbc5";
        filename = "007553.ldb";
        url = "https://arweave.net/W9Q4NeqCGI0aEWeAew77KP8VxxX7t6MrcXLiOKERSlo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "17119bc7580185d19f6e49732612df2b1368415f0f3df2faa933733807d6159c";
        filename = "007554.ldb";
        url = "https://arweave.net/BZK5mHr-lX8GIu-y4zmqVXIpX1Q2d0AfFAgVdeVlzHc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e571b350244003e4bba184dcb3e1b464faea9fa7595ab6ddbca118f19a5cb169";
        filename = "007555.ldb";
        url = "https://arweave.net/oq7_ab20vBLTW4Iavo4o-0XppJ9G8ChgfXR1fOAokQE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6697babaeb623824df3d585e84a4c5f19fd47367b80d3cbf6773b7477957c2b2";
        filename = "007556.ldb";
        url = "https://arweave.net/y8WQF97Ky6z7ZfzrjtUKfoVHPoO5v1YKd8bzkEvIZ80";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d598df57bb4507e1e03cfdb20cb01e45de570195a32ec93a1b2262e849b30ef6";
        filename = "007557.ldb";
        url = "https://arweave.net/F_3RgnAYumEmk_dufOk5HMfjvIHkMf8KTE9sc1zSMK0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fc49cbe1a2d70480f13b4677af9e1325db633efb693fd325eb2e8460e21597d7";
        filename = "007558.ldb";
        url = "https://arweave.net/ZcVDbRvk_0aUDvw4Mjbyve5acXunWzgKIregIKYAuQA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1f11d865fca92d4088dd10c6c1b03e99a4c376d2cc42909a7b9620d6f6331220";
        filename = "007559.ldb";
        url = "https://arweave.net/LPj00HlzaRs73fYUga1EGWNmU-1Vp74thVLMbUhloKk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a0cb0b725b6e3a62dbbbf9a197b5f312daa47b6bc34b51dd9645fb4c1ab3878b";
        filename = "007560.ldb";
        url = "https://arweave.net/XLFDyJKV1-H5v8DC7t9a1W3anonyKLwpAA81sclJ7hM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0189182a30e7ceed14516807e50ce4fb617a7a6db9de7acc492b6a6d88a9ea49";
        filename = "007561.ldb";
        url = "https://arweave.net/fFnsPAGUVCjQ07FCwwtHl4WxDlws7gpzbX8DZZ_qHUw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fa2f44c29119175a8c4eae8ff625ff2ec64399c4391b54c67ddd6a04095231f3";
        filename = "007562.ldb";
        url = "https://arweave.net/gfkunCVYaHJ7aAUYb4o5DHdo4tyNZTxkK908SBkFBqY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f216f7502e3363f80e8834d74301daa6853c2d80024b501fb3840767889ebf7f";
        filename = "007563.ldb";
        url = "https://arweave.net/G1mxd9SnVpcXMushbM1DDrUN5GDOjpgP9aUVMsIHeds";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e78f2b434b97ba3d7e124df7286a0b142dc663be5cb4a288685b16b97d827dcd";
        filename = "007564.ldb";
        url = "https://arweave.net/ZRu7AVl84ffrPO5EjfI6r9cCl9HC6pYeCwcLMbehzj8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8748f891b8bdd9a565e03c318e3b7ba0e53dae1c179f2571c42a0fe7739cc13a";
        filename = "007565.ldb";
        url = "https://arweave.net/x1d5iQ6aiNvyWkTASFfC322VTZMD0yRybtjao1XUoTk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5ae63591d06829c69ea7284164679c8fd19d7af63f5b1d44c312f7d985cebd22";
        filename = "007566.ldb";
        url = "https://arweave.net/7LgTYlpY_6ivY95gndw6czzWzSycP8O9P66oabEd30g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f50691f15b6d8c915cf98dd18de5c8c41a866fe2e18ee7d771199f8fcbe2e632";
        filename = "007567.ldb";
        url = "https://arweave.net/K52wJFpFIexuTIzCmexx1tsTE2jyLu4BQbud0VR2JmA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f25b6a604e52194c151ae88a621d06361bdb4d0ea20ee9466247d88a78846738";
        filename = "007568.ldb";
        url = "https://arweave.net/H6iZQavT1HXQpAEvbesUd9fICw7SmGnqgHvwRNRzY0E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "589a81da41b96e4ffa7a33191c1f2ba07102e5ed20ef950d7bc9c8122b28d49c";
        filename = "007569.ldb";
        url = "https://arweave.net/Rm_XIxFNntCx3ElpiM6F-a2HzQpe1x77D0WZCh1jn4k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "829fc86672ce98bbdbec359bf0fcbc461fb96192f28b681b59a5fd6d72782995";
        filename = "007570.ldb";
        url = "https://arweave.net/6xIF7qRPmHDAl1YeXB46aiFwfuKUWCWqcFNC_rHUK2k";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d3891ae39ef8cb8f022c9c1d48efcdf1eabb842f1f8fb4dd713babbb32e81c9";
        filename = "007572.ldb";
        url = "https://arweave.net/PeAzdDqggkPH69YSrQ3WFodqHgTDHGsa5hi15J8R9c4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fb6a7598f6cb88afaaf6043fd27da6093c1a9b6076fa5dbf0d2ed5fcf4a2a9dc";
        filename = "007573.ldb";
        url = "https://arweave.net/6PTej7PiLIBI5MD31rbYxKNI9rvprmqFdMoNEELmzDA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1ddbe5465c332fefddf36d29f47bf6e7a25a90bd33dc3ce900a84328684365db";
        filename = "007574.ldb";
        url = "https://arweave.net/ZZD0paZ3-U5vq8cQe4rxAknfAGh4ytWBPqpcnv7xKXc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd624259f0c13fbadc7a77e95a4446a399ffa41d45d820230941e43642cf3cfc";
        filename = "007575.ldb";
        url = "https://arweave.net/JVG-11tZKDZGsbBjQN24bpg0Blh49ZyfmG4KKrKU5p8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "62bcacf53998def9e06d78569da069217ad82c06ce915290b3c82e794ab12f58";
        filename = "007576.ldb";
        url = "https://arweave.net/7Ee5SLHBMoihU55y-3pyGA-7O11KToc3alKng6y9pGA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "db0fc79b684df0963d3622af1e3cd6d5db7fcdc76e05b4d5efb1ab8cfe32368b";
        filename = "007577.ldb";
        url = "https://arweave.net/fo7hBRVlU65VN86hfpwB9E_GUoQ8QGJHoV_035t0sqs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "23948ef52028a33720a3494fc0344f4412b3ce040ac1c9915f8eea50eb3893b8";
        filename = "007578.ldb";
        url = "https://arweave.net/zJCIERG0wMKYEO4xz6JK220S8KPevwZng7bsyIerlR0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "43c260373bf841c278af25e7058292b6a3e633e5403d7734b0a784819b79f678";
        filename = "007579.ldb";
        url = "https://arweave.net/PXo05UcqOtA_gC9NJwTvCkDRlpVVV3x0t6AVmjGR_Vs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fa4ae80abed987a659de6ac429d168e4af394c40cc80de074aa447a295351657";
        filename = "007580.ldb";
        url = "https://arweave.net/NVDdCwi3QZtzJHjfjtpwkA6R3s6OYprh1oxtkZaI0rw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "524d3e98d4c2aea433acaebb918e680f8a7fcf3a7ee5dd138f36c1a755516634";
        filename = "007581.ldb";
        url = "https://arweave.net/fXQyAXfnzOFcdZh156cLhB8k8GaQ1RSO-muusKt6Tww";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "261d5baf02c149edb2f09ff9c0e2c95a61f407621bef79eaed1e04de1cf12402";
        filename = "007582.ldb";
        url = "https://arweave.net/6rWEtULqW6A-keIAEMzjmGklLIWC3XMfksoNbDQxLUo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4b50f5f86662e0500510c545188a4e866b0098f4ffb2b8a6a11a9ab27c819e56";
        filename = "007583.ldb";
        url = "https://arweave.net/M-EDTUSm7SULXcIgtCy-R-M7HQXpcS9ScDQGKGhhjUo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4ce8dce85f2e9a1690b8d17fbf0e37bf61bbfdee2e7c2d05542cbd8e6d9acba9";
        filename = "007584.ldb";
        url = "https://arweave.net/5QkuGjwG5UbZpfJNhnk3H0rQrD0LpdFH-wfjybQBj_8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e5a3a1fffe0dbcc2ba81379fc7184bab5ec88c44faa8b86deb7fac83949bf6c1";
        filename = "007585.ldb";
        url = "https://arweave.net/xrU4lLUwoKpzjty1TBMJ0XQKfbCZdxuBrk_SP0ya2Ww";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "394e0b7d3ad35de99564efbf6bd81a73e9701d550a6bd817d7bb1c3637780628";
        filename = "007586.ldb";
        url = "https://arweave.net/vJEScaoz6YKuzZKoSBiDr0cytM_N1g7buWzGp2bCOUI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4f2a25f5b898058227117d14afeba74005f31576feb7b68c98fcda8a7455d798";
        filename = "007587.ldb";
        url = "https://arweave.net/FR9AUPYW41ozxmHD74f57OFNADVvjvNdXYBXKFeF6QQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a6d12beb3f1b82e102078fa1f80284c34246ca217edf0936451dc6b6b3bce3ee";
        filename = "007588.ldb";
        url = "https://arweave.net/Utx6obnZsc5sy0_nvuFDz4yQIGyqZtFwdEqyjSXeffo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e9d2b528ea4aaa0c3a09dc02714912dbd244e5ab0dd91dd58389c3a92d5978ba";
        filename = "007589.ldb";
        url = "https://arweave.net/W-YXO8UN_R9oPkLBoybz391XMoB3C4bhfLdbkD16SFY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "34d018e771c29a17624ed5bbeb1366061802d6c78de66abbdab2c58057719f30";
        filename = "007590.ldb";
        url = "https://arweave.net/ED_jjH9hfkcfgNRN3EutosqaJqFJrI6HZ8GBcJNAGIU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b29d01f3df6fba9085c5c5f1371e20dbe9637c7e2d688f7fa131bda4a25067a4";
        filename = "007591.ldb";
        url = "https://arweave.net/J_VqDNGUIUtINaE4AL9-Rob5fiS-XOIcmj8jJ5dqip4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3d5f1842836c05e21f8b1e6bd320fdb0b834a64ad2bb22227e3f23f25e275519";
        filename = "007592.ldb";
        url = "https://arweave.net/v3V1fqRdABE_ptyZvusSywijhO0YzYwpEvsHzDXt2QE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2afc78817e75261773fc108da7e0eeb01c93432d978031ffd01787d2ad49b098";
        filename = "007593.ldb";
        url = "https://arweave.net/Se5nGmgkUYZ4Fmc5utNQZt29s3C0XSop_9aUY9G8h6M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "36371378419490f5513f91595e8614c9b7499e14ce4e369a276501a1d4169bd5";
        filename = "007594.ldb";
        url = "https://arweave.net/a2T_Q0BC92UrhH0aX_bJchIsG7Zya4zAgP1jha8eQRQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef970be4bb2cb918f93e8d981c98eb2d9de4b4346e3f194eda4d488ab9f9743b";
        filename = "007595.ldb";
        url = "https://arweave.net/k60UVewmM0HjrEo8Y8RU788Xb1ONvDv_Tz9XgAM6pjw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b4e78fa14f6e69b7d31bbca5edc10ada39ddc8c0340f174e8aa9c884eae86276";
        filename = "007597.ldb";
        url = "https://arweave.net/Zwz114vCn_A1EUkGZsQv5lbr8ZEd8PvovP3jjs8DMLo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9d580487ef761c445b3f4eaadc49103ac14f8abe0b789ee4c88ff6ffbd6330cd";
        filename = "007598.ldb";
        url = "https://arweave.net/7UOiRY-5kPS9zHYwBWncp48hh-waC6B73gXr9xm1Wh8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1c03217bdf911cbd98ed38e83e10c7fd014a5b7dbc0c88fa129c3deadc81ecbc";
        filename = "007599.ldb";
        url = "https://arweave.net/5xWGa_q29eMmJD1E1g_cT-2nOs3lfWa-gqgBhGQHA2E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "65f34bf10e6bf3aaebe462a792183bb03fc4c63813c98380c69455f0aaf35864";
        filename = "007600.ldb";
        url = "https://arweave.net/uulpDfN3GTxCr8fybhTTQfI7PchtxgP4YIXWocIX2PU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "42e52d357acb5b960a703aad6169d656daf01c8bedab6a1f5c9e6b40d4d901cc";
        filename = "007601.ldb";
        url = "https://arweave.net/8hN3gn9ujg0FtQhiOgaQznHlLjjVdEWi6fcUM6D5WzM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "35f0672f4a611e8cc0b995caeb32a3fc97082eb103d03bb9ecf402e260d4100d";
        filename = "007602.ldb";
        url = "https://arweave.net/4-yEIJoWtuk-6cFySW6xzvMUjDpKLORUAOW1hITMgC8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a159daccec201b847a181a1dc626b5e6e5f302dc1c6ac6fa790630b75eaa9e5e";
        filename = "007604.ldb";
        url = "https://arweave.net/WwTi91yNIpYXC-7Hpm3TO0tb75KUewo3r7nWWaP2pm4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "416cd3a6ce062be388f3a1918ff00f83189f24f4bcbf2c9934e0d8923610bba7";
        filename = "007605.ldb";
        url = "https://arweave.net/VY-6aCvvfV-a3rvoBIsEahfDRUirZcSCvlbhkM77Rb8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "94412cd98d4af39ff2653e0abf0afa8ed4f3c1c4b2a8a9def34e9ee6ceea2d2f";
        filename = "007606.ldb";
        url = "https://arweave.net/HYvt7EQFEN5XUEOHA0O0rzBnv6tgdX_HsKYbP7D-Gf8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d486f84d80ffe9e1e3759f05556894818431732ac66c7766cf7cec77513ecefe";
        filename = "007607.ldb";
        url = "https://arweave.net/53l4ZioP7mn9nX3PyMqS4zSD6fsj7jgH2lGsAd-iH0o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bb385fded18043a4df403937ceff9a45047e7591a6012db72947fe688a85b582";
        filename = "007609.ldb";
        url = "https://arweave.net/AFnrg2L3bWzCmGVnudu07B-sfLwQAbnyskWbbqrZZhk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "20019a6a68338f24e1cd70e3456c5751cf1fe5e83775995813a479f7b68a10ef";
        filename = "007610.ldb";
        url = "https://arweave.net/NP3l5cGvjKgTm9pyaTKUL1Ebuxj4-oPKIFOCQXBu6rY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "970f016838739bd04b9b3ac7e2b78a7c40eefc4c2fcde0e6d1e8b07a9b159444";
        filename = "007615.ldb";
        url = "https://arweave.net/qj9a9lcWyR1KAB0ePHFlHrIsksZcRSE4-pTEvBwYYec";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2c90fb5886d76914b60804bfd5379fdc4b3b5acce044f677b90bb57b1f86cba0";
        filename = "007616.ldb";
        url = "https://arweave.net/0LrwEFTjzDFNr1hdN2_t7opIudyTh66zNZ67FmToFSk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "92a7e770f13789f3959fbab1772619a5e525d229fd9b9f8b171a4baa4b151b9f";
        filename = "007617.ldb";
        url = "https://arweave.net/kUT1I8Z2Szs7tEK9zSRMxaOiG3ZlGM1v92ADBROaaus";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "31846621625496fb56751e544e51b05162313c0ab1238e501caaa313a20e41b1";
        filename = "007618.ldb";
        url = "https://arweave.net/Qh8FdLcXHqro3av7t571QKFWnRLZRPXYnCewM3JKN6c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "905ef564d395c47d1095c0a1b4e22c3969c8ac5714fdd3a9e591afc36eeee1b9";
        filename = "007619.ldb";
        url = "https://arweave.net/6ejoSqgkHOUjIndv2sP1O_OAchP7iPPkao9zSdu3QeQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4f405abbde0e9a4ba2f9ed634c892ef123e4350deec998350c4230160145c29e";
        filename = "007620.ldb";
        url = "https://arweave.net/cS0s4T7W9engeuYvWiDKIynO9OakLI21T93swluuOZY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5c2dbcc41b51cb8f6a21f11feb0d973e82f138ea5460e9054976f2dae191e04e";
        filename = "007621.ldb";
        url = "https://arweave.net/ok8W_sbCJTu500PfTGwqRhRFLZMD5xvxjZSv91Y-2wo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d22445eea4c6a78bc4fccbcc236f5b9b645943493dbbde15645316fe07583ed9";
        filename = "007622.ldb";
        url = "https://arweave.net/qjtZ_gCCepW2aGMGzcOk9gUpePuyLNKh2HSdo5XKMu0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e4ee2846e7c8392e66b2973e63bb9ff4b2c97b8407b868a7a6dabeb33b2f2704";
        filename = "007623.ldb";
        url = "https://arweave.net/2C5yjqLJNoKD-yXUiYXnlQjScx2JHpNp3fMOjsIVTTg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ea853f299a0d73050ccf78017c2a0011318ffe1db00480ed2ccec88d0ea1af63";
        filename = "007624.ldb";
        url = "https://arweave.net/R6mPvAYtd6OQcw_wO5Uhpbyfh1CRR92lrvIvvycCeBE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "aa1452bd33287dcb1cc2d3f588f6eb2b4e2c9bc4bea88dca236049155de6b0d8";
        filename = "007626.ldb";
        url = "https://arweave.net/5gh7jPz9_REF0eKJC40P7Q1gk98MdQJCmhtAqOVfGXY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a10ac1f4a8aa3e7c7162699379210d04bc7c637c4fbc8643c7c149c46ba40715";
        filename = "007627.ldb";
        url = "https://arweave.net/_mKH-fL3x5gzBljPqYYdhuNW4VKdqxFrDcuid2r7bWE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a34a6b7d9e922dcb2a41645fa845ece371dde3853211329de6c02886f36c89bb";
        filename = "007629.ldb";
        url = "https://arweave.net/G4hyVpa-Fuis1BztVyjA9HTY0YEawzubWyv5K02AXH0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "30740e44f77f0c3d5492af10021d4f7eb74fe77af73de2a5e311546cb84703a2";
        filename = "007630.ldb";
        url = "https://arweave.net/dDlrAFjORD5RqLaNdMTrzA0__wVgXNXgAK2PNeKVtrQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "22cb5622ae947cad93970486a5cae0b4badb0d112f1d6cef4c14a897150d62a9";
        filename = "007631.ldb";
        url = "https://arweave.net/PWVe3V3qRDnYBJUZoZLemYfltz3RGK5sGQjLzyHjNY8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "915acabe61887a40044ccbc37035ee1d448c4027fdeb38caf1ee7186c6be7863";
        filename = "007632.ldb";
        url = "https://arweave.net/a5S9vHGa36S1fEc61Cd3tBgopXjtSLOWgqRPhs9gXZ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a7354c1faecbb7cd02bfeb2c2b50e7110c23c9158c17dceb83a5ccf881690a3e";
        filename = "007634.ldb";
        url = "https://arweave.net/aN2amt5mPADeN6WYB39fDchUeQkel7ustz3IP9xPs5Y";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2e569ac048839318ed096957f94bc98464bc15e97f63ab06dcf26f1b59ab055d";
        filename = "007635.ldb";
        url = "https://arweave.net/Muw7siIIh-SwdMWQqRDdJ4renzd3o2FN8JumGfskwDY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5a9737bed22b50f389fab1ca911e86770745add3f9b339bbb3162f92387d39c3";
        filename = "007636.ldb";
        url = "https://arweave.net/2_Z-UQ9u2Y-JHiHAPfNvjsjdTSsIa_nbQ_s70Dy78ds";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f21b3327add9b2bb1009593b7d235d91d96a10209adc9680b8538201d5f46117";
        filename = "007637.ldb";
        url = "https://arweave.net/X9pk3kkwhEEDZngRWIWd0OtcqFWk0iq4ZMDK39sFvq0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d46ee1b7c5c5edf61a4bfe52f2cf99a493edd9a537424ea614b1c6d6e6c1f307";
        filename = "007639.ldb";
        url = "https://arweave.net/o872e1utB7nmnwYdCDtLh1sXLQN6kmyWeiHZATDZcMQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ef0d8d0404401c95e452022b8c656d83a41ebf85a0859b2a283959f14b4d60b0";
        filename = "007640.ldb";
        url = "https://arweave.net/GwZinM1GvIpT9E1l6GjhQ3T7SM8iuV93UDT4M5vSVzs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9f6046858eb01d0523f191fb9585e0d12ec654a9e431f90f0f8a0987f823aea7";
        filename = "007642.ldb";
        url = "https://arweave.net/qARzngK3_QDVVxXyec-ISXjaKlziGwfL2YVZYyd8MFc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "69fca1ac16008cdcb9f6fc9a864411b692ae0c5b8024e4cbda722358b6451246";
        filename = "007643.ldb";
        url = "https://arweave.net/UsQ3QuEq-kVvOHG-UTrQultvEw5UiqA-2xnh73mRykE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "003da9b56878f4d706d3f73866fc93a84809784a4ce7de90c4c280b9f7aab72c";
        filename = "007644.ldb";
        url = "https://arweave.net/v9iQWfp-F8EfqSgIwF1cq3cr7zT5q0mij4Xx6T4CgBw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b60da3961ace1d0d46827aa9f293dc14b33201f2f07033acd6df0af3c01502aa";
        filename = "007645.ldb";
        url = "https://arweave.net/hZJPeGAC0x29iDM_4upT6oNlWll7O3nroZKolVt8NW4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8b50329652fb52e9a9e8358c1f6fff73f79c3c19d9f5ea6febf137fdead6e4fc";
        filename = "007646.ldb";
        url = "https://arweave.net/EYe_uMsUIgBBy7-tBa5VjOrweqxtXBDgC2FtJEa1nKI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "85f794c281d006daba52bd3119edaff083da043ce6bdf9dfcff66e96e71a225b";
        filename = "007647.ldb";
        url = "https://arweave.net/Au4PKj1IwO7B6O1EXhldxaYO4A9IsOLFKMPfyyeCOAk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f6bfa04a8cdf6beb238fbc92c05e746ae943c4d3e854584546bb99b940c55796";
        filename = "007648.ldb";
        url = "https://arweave.net/Hh46pIfry03ITxHTY_9VcJfdlQ0pzj25EubBlVca5kE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0577c4d067466ae631100d64eedad9c92e2efacdd564a4754bbbcba2a43b5201";
        filename = "007649.ldb";
        url = "https://arweave.net/JlGhtVtm5goKXtojZWm0LYbZFsVNCK_bZ24TGF5ouxs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "88ed02d0faca2404b1f632d030800fae03df4a35d278bb6ed10c3e65ac3cf67b";
        filename = "007650.ldb";
        url = "https://arweave.net/V4NH95W5GARWG0SMvItM8bjrz_xagtKr37uMt9oAPiM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6b006edd6eb117dac8ee2cec00194161e816c8ffeb6b848669f8d6d8bb68f777";
        filename = "007651.ldb";
        url = "https://arweave.net/RY34D9-3Q5ygEQRVLcNF3mtA0pqWw-sgdL5XXTZzxb0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5351af19754edc4ed10051580dd3d6f6dde2e358a3af525a422276d7221d87a8";
        filename = "007652.ldb";
        url = "https://arweave.net/UCxebJOX1SwzCBnMbNJnwdkJPXjl37g-gWILGxJebdA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5aa6d00b62a85ee0db89af1d67a523630fb047b60933c2a540c3811979c79dc7";
        filename = "007653.ldb";
        url = "https://arweave.net/Yr5BUiTFDcl9X3dyc05vbpLlslQnXbM9ehhRdmQ47nY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "75cb2a56ff563482c7c1a3bdf9917ac1870f44db66922c6327f284280eb0f266";
        filename = "007655.ldb";
        url = "https://arweave.net/Z1OHZLC5OJvWPg1yMj7ezIRszrq2VgoHTmSNrZ50MlI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5576fe5c93e3c6c6940eaa3c5044bdfcd27748b7437764f092c4e003bbe7bcf0";
        filename = "007656.ldb";
        url = "https://arweave.net/bGt2mTmdim3edas2KJWavyNkFJ1f0LkinIkC_1zYZH8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "948f744838566b23951bd78676037991fa3f54c5df7ffba3851b22db39472ea3";
        filename = "007657.ldb";
        url = "https://arweave.net/j0hr2kD2i1FSsqRMbXCrrmyKB1kCCO4P3xjAXWTeGxo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "794c32084a510b382dee6f298853d840320926b6164f5d31c9073f30164f0df3";
        filename = "007658.ldb";
        url = "https://arweave.net/RxDFjziWpmxLksY5Q718mdIjd4Zafuf3qQ70L1-1Re0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "191a74d03bc141c3794153987a8be608be232a013d16ca542bf26720d22c9e71";
        filename = "007659.ldb";
        url = "https://arweave.net/pfx3Pvka4EZPAROeGJG2fREIqzR1a_43vU4U-6rTQEk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c88a3b12aabcdc74b7b655b3173068c47029ce64e9e8fe027e9878cbbf4a8e9c";
        filename = "007660.ldb";
        url = "https://arweave.net/wU_KkeNivqkHfrKghZHRfKee6NgtwpR4vUutqyo3MtI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "721fa2a3aa5cd683350bd20e13cd7687f40e8220f28c94f9a5d3e15d7633362a";
        filename = "007661.ldb";
        url = "https://arweave.net/hMqTfEogTIQb7MpcJoDWlfuWd-kzwI_8hYr8VHZcMSI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ccaceceae7cf06ee1615d8845c4ac4dbc74ec1a3a13eb95c845b5fffe3b2c8ff";
        filename = "007662.ldb";
        url = "https://arweave.net/DfP60Tbc0fM8LTjzCP9A5kYEv-3A_ydV5uxNEAvo1tA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f68e1eadfcfe60b3e2649a3345e7a4868179f9f99363a7f8fbb62e7ccab52779";
        filename = "007663.ldb";
        url = "https://arweave.net/9LSRNMgntwR1mtuWIiJAXtobe1egO0pjiwE4J2SITcI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f74b931c7d4cb64ce10486eec9d1d27e1550a4a56ce2fc0a55d014614c4ba2bc";
        filename = "007664.ldb";
        url = "https://arweave.net/Oxf4f7nVF-Scsw3v_HWKlo33Z7KzCZhR-MXLloH8tVY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e139f44e1eb76e874b745aae162520835f1f27e6b8b1658dd6358fc128dcf8d2";
        filename = "007665.ldb";
        url = "https://arweave.net/xBGJYnc19qHyj9azsKTJ0p9FvDjRtLD38iYK90ud31U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5c651a5aa0f779f2a146e4c92cfe675d0ba60270a74994ecf885041a867926c1";
        filename = "007666.ldb";
        url = "https://arweave.net/wP7VrrqFwI-Al4fUoY4MSPzcP84IAVjTjuo2Z7KQYJg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d67039599613d78c0674ce88ab2576f7995a4e4613de4bc5dfda4ae8bb5466e1";
        filename = "007667.ldb";
        url = "https://arweave.net/mh2-B12TenmM3NgamToRSUwd34BIODYbiTo7UFjn4Xs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d15c4a5e520ae57ea311d7e00d09eb5db92596ec5f7b3ae1ff8a2be837cc6a11";
        filename = "007668.ldb";
        url = "https://arweave.net/h_BSrHoTWGCQx1YUDAc-F16k9DaJ3NdKH13ceYV6CCg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "55a16f87c1699ff3f78586124bac17f42377a136c9ec340e4b2c74cc10a5c0be";
        filename = "007669.ldb";
        url = "https://arweave.net/53fBJrAp_ADfw4gKitBkxiVjoc5H5zHFMFLHXvrC8pg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b2138ca1b020d89abb58049542fbe8817341ca53fcadd5c289bf94af3ba9b985";
        filename = "007670.ldb";
        url = "https://arweave.net/zoLyTb2G0Y4pbP1ucXCL0Pdc0afWBGQXawy4qT6jKxI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c974c5ffca2ef8cde742bcfc592fd0a2a7c5c2734f5a52ce0ecd654b925836d7";
        filename = "007671.ldb";
        url = "https://arweave.net/7zzO-b3xMshdABXub6h3ei2sw50Yu8yWztrkzT7Ebio";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1b9ca7a9eeb8ca7f4cf41b78a393eb69952d72e77fb86237cc783fd4118aad83";
        filename = "007672.ldb";
        url = "https://arweave.net/2P74o_QdqfWuwe4yBLhJVF9bHI9_yELgrgVLX7a3fIQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0c5d9a01b12037e742f9ae43519666ea54c22be3e7fc230de41e7aacaf853853";
        filename = "007673.ldb";
        url = "https://arweave.net/h2Z1MJGXA_O_QyLIIbPWX6HKV82BGO9ujTgmbZfQz1M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0f69fe14568b831dd3453e871159ad304e1a1d59d270cc84248b8b548661fc07";
        filename = "007674.ldb";
        url = "https://arweave.net/aC4Bj6fXLn49o6HC7fdm4fqM6CTY1IwXiWRKaniT4f8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "78c29c2f1f3baf7dac3528f1bdddaefeb504b0c1666bd2e255a2de198467483b";
        filename = "007678.ldb";
        url = "https://arweave.net/Ie5zTHQdfXpOiiJA9eF_R6u5sM13zet5R87anOK-aTU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "61899fc3aec8146af79205638ffdcc5bbad88cbe45dd020b36ce7d767847a487";
        filename = "007679.ldb";
        url = "https://arweave.net/YlnKpJstoQDHCURidlJcVHEilH9agODsUu824lwdMOo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f516e2df472b19a86b7109f604817a7d47820cfb7516ec39f76ce6d753342685";
        filename = "007680.ldb";
        url = "https://arweave.net/zuz3USumYU7Fi7fS_kAx8KL-HavYuq61muobia1Gr-I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f1ac515ca28741bafdc566819ba1e9d76b07801d8018cc9c2dcdc23c1f048d90";
        filename = "007681.ldb";
        url = "https://arweave.net/1DwAnnD3cMv9lZ_Bx-SR-mJeGc1k6NHhXsXSX62cxvY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d5f78f405eae1724203896e5a6c1642f13c97ae9dd3bb97514c1e6ccb9a13444";
        filename = "007682.ldb";
        url = "https://arweave.net/iinkXnbwDx2r8ja09Hx4So7mywvjB2OqAGIDOO9Dkrw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "abf323e0bda81e82a7ad973eb8b87016731a064daee676c16c98c3117490fba8";
        filename = "007683.ldb";
        url = "https://arweave.net/_dayCaT6iI6Sph7_GJBP59LxJKxo5Tr0Ak7IvuyxwlI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1c38546bfcfb8c06118df36a9051e67383332931b38b8527256b22abb376c66a";
        filename = "007684.ldb";
        url = "https://arweave.net/5bTn75mWDg1Nusg4gjErM4VvY2Q6okxfoLEGV1g3LqQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "155fbed8aba4914137145cc610305aa500dffbc59a8059a84bc3f16d2c448683";
        filename = "007685.ldb";
        url = "https://arweave.net/ioPDh7P9Tr4JvrT6Mwao6ITKXvms_OMcWTSY3zDzVlY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e130ed5ed958df21197533f585175e55e4e9a82dd3bd616f282fce56bc827c12";
        filename = "007686.ldb";
        url = "https://arweave.net/L2l1c4S4nbg96m8JJ3nvdWEBBNxcDOA7I_Zg072k2UA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9368e3ed44e4752d0519dcd6e0c08f83fbd9d421a195d44bd2777799bebccef8";
        filename = "007687.ldb";
        url = "https://arweave.net/nFiyvCARcqw_dWwG1fjzB1KyqUd5BhmX5x2g_jT9PxE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5d3756bfb16d1262c50c5c89958ca643f21716c1d3c4ca763fc8daceb61e66c3";
        filename = "007688.ldb";
        url = "https://arweave.net/FN1CjqlJaQkEP6K2Tgv68LwkGz9HCD5DsHRDkkxram0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "23dce58d7742d00a13f5618cb54a10d6621e3a7203e41688449dc39287d47c93";
        filename = "007689.ldb";
        url = "https://arweave.net/Vqtu2aH_zU4rSZ_kUH-EbJipNIQDhRKVlPhXeD2oyxg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b30b983855538f72068f290f09c02383868a5c50fe49a4832591f2414b400c12";
        filename = "007690.ldb";
        url = "https://arweave.net/FmD0xV0OJu_qMuz_-lHfd8cKjHZG4NhHKS2m7PpcdDI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0648b5aed5d2c54b72a1446d2b0a22ecc4eb0cc94af7f7851d6192ae90cdfd72";
        filename = "007691.ldb";
        url = "https://arweave.net/Cyas72BqPp1z85b1EEUoedfP6C2rAhRCq1jgsAu6RDs";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4f45352c8ce2b53b3ee3e7ef40567cc76a510defcaad1998b13ca0e061c48e28";
        filename = "007692.ldb";
        url = "https://arweave.net/tAYtZJynPYZgnHegF6OgRKU7wg9iXgMXlwRjoD81Yec";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e457d79f2a98f58798d7ee456b6456031d1d005fcb47b937efa8b62768781c81";
        filename = "007695.ldb";
        url = "https://arweave.net/SBxP-MnACbd2gYyETjYkQD5BnJ4rzVRlrguc2QTpW_U";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2d81995b53d00337644eeff4332cd0edd746442646763f31f20306f875e85b0b";
        filename = "007696.ldb";
        url = "https://arweave.net/QkDlSi7thn4KTHL1x4mMWS1UnvJT0HjsDiEVckoQseA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c4aca1bb9728d93fccc616fa89e721af823a3fe76bb4dea648ec9619d9a6efc6";
        filename = "007697.ldb";
        url = "https://arweave.net/HL35MrkDLc_xm9R5z5nI5357g3Os82hNvSavXy3ehR8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c26534c35c3adc3458aa9b1842756e53bfca0f58bbd10fd47d787564204c88cc";
        filename = "007698.ldb";
        url = "https://arweave.net/bCM2-S502uNzYHQOb4ns99cmpdoROq2iLTueCssks4w";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5a8bdde43e6343649da302f493b10f44eb1edd16a5ec891ecdae1c75f31b7df5";
        filename = "007699.ldb";
        url = "https://arweave.net/wDhun9gqfNA2vt30OloewJz22LL3_0tQohd6vv8w4f4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "efa5f88dec753623a3b467bfe475213e4450e285c7a89c65e03a264e98825b80";
        filename = "007700.ldb";
        url = "https://arweave.net/i_yKkc04G1GfAkpVKE0XB3LLD1lBTL_rz7nuRv7CF8g";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3e9af708db5125982887113990c63efdac9884e019995a1462b9dbf70e6f9b28";
        filename = "007701.ldb";
        url = "https://arweave.net/Mysfp0S2iKRzGj66jfP3Vq-HN4xJfXy43HbRcvqmLtI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "71e3f25d67bcdbb6c54d99e6f7ecbc2e261403c8eb90577cf5d054ef23d07f79";
        filename = "007702.ldb";
        url = "https://arweave.net/pIKZobCrfiTD6t77TC7iqwGC5hpMikb41JzzUeuCdmQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "276d6594e283f10e4d0035d19aecb1df03943db2d87d41f98f72070a405e790d";
        filename = "007703.ldb";
        url = "https://arweave.net/pwVMvbzqkfz33S6Tlyq_Csfhf-3ol-v-aYwccCGxqEM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1f7059f7e9cf99a5cce1e5c4bdf914d6f5ca0664425d31e63ff69750e80213f8";
        filename = "007705.ldb";
        url = "https://arweave.net/UOafmp2vY7u7acUpGBcfi0MwLaMDMyeOCUDKVnijEDM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d04713e5b3c368dc3c888041e2a41ad337eb13853dc893c4d295e917ece636bf";
        filename = "007707.ldb";
        url = "https://arweave.net/i28Ekg15HaTujsxPBFxqvRdDamAfUf-Jl3qewwytlL8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5bea7a5ad71207824f8e1d2a537a75ff2fe84219fe18e8f33ebde75987be7075";
        filename = "007708.ldb";
        url = "https://arweave.net/-k6NAdufze0D-6iHMO14TWwNgZ70qnBCS17OrfoXT-M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fcb150db1a6809c01bdccd582329d82769ee840ebe983e968dea1135da349b13";
        filename = "007709.ldb";
        url = "https://arweave.net/O-EbTjhQJ_6i9FEGQB5l1Ob1sTyZHGDvukLfRrOTv4c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "247f29070e554f1b3b776d1a0ea875d5c391351b076621e803ec91f4ecb0e0ff";
        filename = "007710.ldb";
        url = "https://arweave.net/qSjhBzDufi-Fui8evLAwVgBSU5dJTG8UeGYohpmHIEQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ebde99ae9760e7949a2e3bbff616ba9e143cb334eec8dd75d37b59a02e2b91a1";
        filename = "007711.ldb";
        url = "https://arweave.net/TM1IaJkO9SUVppa8LRf_8xD7Ayk5l_C9uQI9YWkZ-F8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "165a956109b6547989b72da125062c274df641efa302b218d78c187aaf07adbe";
        filename = "007712.ldb";
        url = "https://arweave.net/atQZuPqX_G9TbZiLBYQZDKBuhnBewfMfqDGdImWOlHg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a4ab8a2882189d6c773720998ddbe284951ac247a2bfde3ba6673e561468949a";
        filename = "007713.ldb";
        url = "https://arweave.net/RRfkVT3acDIzS1WBWrII_8cXzn6hclPtTAi1kEilr14";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a72f596400121e003ba1b74d87db91b233150141c31790219b0b4d4c41ad9075";
        filename = "007714.ldb";
        url = "https://arweave.net/gvvMHrQ5R_-qwMVwbMvrhfE_YThnQrbyfUkdBIcR1OY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "60a0d6d9dc997d1366c0f7277079ccef7423b763936f01fea85ff5158af09b0d";
        filename = "007715.ldb";
        url = "https://arweave.net/_lMg_B8Tboa3HaNB3bEfDCELgHlyGAdwS4Qs4BK6HKQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9da2d15513e41844d0ebe2107222883238a900b79868436aef0d8aecda81afad";
        filename = "007716.ldb";
        url = "https://arweave.net/lAOzRlrfKbv0DT9XaGDPkvJqJK510uPclaIkv0sFIwM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "902cd689b6656fe847597039147ca9d7772ad9b58c7a16a1013380bb45fbe203";
        filename = "007718.ldb";
        url = "https://arweave.net/jgu21EnofuyNBuz9iSVld64wB3k8VQMbksYlMvO4qLg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5503e89caf64bf7140b259cd9c5d52ef987721443ba8d1c3844ffb83905218d1";
        filename = "007719.ldb";
        url = "https://arweave.net/cJuCv71hvnw4KNdoVIZxQCmN27H6Mci0zsXMnwLFod0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fad218acdcd887efaf1f993ecf8fba28cd99abe5179b066e7721a6377e60d4df";
        filename = "007720.ldb";
        url = "https://arweave.net/HRTUFypFReYn9CAKJOc5CPwza1TL7fI3Sv0Gma47Agg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ddcfbd0706e5622818343bf615fa0feae137340c457c65d82a8dbf315cd46375";
        filename = "007721.ldb";
        url = "https://arweave.net/_gRzFuUBmb2w1XX6thEXIgwF8y8lcsdqI7nrM8gwCH8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6bda43db2454b1a80aeb02b94d3b929c5c08bbcf28bb6c551d56425f7cd562b0";
        filename = "007722.ldb";
        url = "https://arweave.net/eoeQTH-QtEneRlZ94wWzXTYdSQaJAPA-eN2ZpM_H_Ss";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6d8f9c5573047cf072b2b7f5d5466c14bb9aba19caf819c1fe0ca94f1cf1478c";
        filename = "007723.ldb";
        url = "https://arweave.net/hHBDIXltXHwrMMnYonDWiSxJUM-_YL9g34IXoYveXGE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "b9c370e72d6b7c035a7826af2e21a403f1ae5bb82b8d91b916aee90951b8f989";
        filename = "007724.ldb";
        url = "https://arweave.net/TVcro3e0d7G66YUFcke3IEW-KvpZOZGvVa59ZrtOxSk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a440bc1ce729bcbd1bd7e531713b82e38699e9a270262c66b2501a6842e1c285";
        filename = "007725.ldb";
        url = "https://arweave.net/rAiGomp_t1_glOMh2NCDLEQ7AWsg98C4u4mIB7UE7B4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6a56513064c0e5cfa5f723f84fd2cb5053ccd8a15aa8791a8d463ee22f3483c0";
        filename = "007735.ldb";
        url = "https://arweave.net/-POm2GwoQswW_Iu6JSNs6yigHNQPMamaymhFrxI6750";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c901835462f125a37734c86a1d5a53ceaaad4e92ab2f50e291ec3bdbe5ee09ed";
        filename = "007736.ldb";
        url = "https://arweave.net/_XtkMSSVAlSyg3Q4baYtLqwJwUU6XqOmLxX552LOFmQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "adb29ec8447f00afd714ac5f20982edb84ec3ba870e6ec4bbeae0d018cf93531";
        filename = "007737.ldb";
        url = "https://arweave.net/fafAFjZzJX0nMP45q_L6uJWdaJkROvCtjIBbgOqdQv0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4fc25925072af14fe97417f3785a82179e38955db9eac268e96049d40c877541";
        filename = "007738.ldb";
        url = "https://arweave.net/R9Jcx2q_WFBj5zBs_Y9q41MIMPteMWoi72lO1VQGCSE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5781236ed758e4c0a12b8ae9d0ae7572b9c5bec05fed3290baf6aedb52963423";
        filename = "007739.ldb";
        url = "https://arweave.net/Xoswh5hrSS0OPGqpV_96hacRMTdiPYFKCA8Ggh_HMd4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "93084065e599a38ed0f244e882b54f28c323514fb862c218f6167dd9ad6f806c";
        filename = "007740.ldb";
        url = "https://arweave.net/syW7u8KVsi2OAJbH3r8C7eobQdKLDYg1lkIpccvjOpI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "efe89d7b916aa29c5a49c809b4e1a5467fe2bc59d26cf8eba0e9b1ab1617c1be";
        filename = "007741.ldb";
        url = "https://arweave.net/u8bJHmdSV0bW_xoG4wek-J4rYND_BxA9K4hjsqh5kt0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3076572e943e5cdf3917eccbe13a85ee5e32ae3404a175f93a598e85a76694ce";
        filename = "007742.ldb";
        url = "https://arweave.net/ML-hmHjTN5afe6C8vImuno4eeax3getqBlS_y8k-pL0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cbfa81b45db155e037de4d290c132ec81effeb365926844dbb7e1a637f7c8519";
        filename = "007743.ldb";
        url = "https://arweave.net/JzjTC5W8qiYo803imqG_ybKvgrv7-ropkPTETpBj6CQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "df7b1b79104f727946a7a185794de121963169cc0eaf991af1c9b41c3b490191";
        filename = "007744.ldb";
        url = "https://arweave.net/zqKYK91cvRQBj8nx-00dexvWRmxCNu1VPG6BfGoKVpk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "566e9140f29d8b1fe6843710bc5b4a2b8a4c376a190e90f6a2f91470f40408d1";
        filename = "007745.ldb";
        url = "https://arweave.net/fILHIsVsUqROkAeH1Dh08o2S9cSZ2_tOKOJA9487dzM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6070dce1798b6ca68ff0600ffa4e5b6d18b1fb55f11a787480dc44e2f0ba2318";
        filename = "007746.ldb";
        url = "https://arweave.net/lI-rN5fstal_JwznwAMELtytGp7LwMhmhinodmS6xhM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "377d7978261afea01ec81fa72a2a3f3df8e58ada5039b02e670dab15968f8341";
        filename = "007747.ldb";
        url = "https://arweave.net/3AAz0oTYn1JXV4V4deQsOdrRCpRz-6xFkvyPv4r0nJU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e226e2da654cc762cbdb81654bec7ab4567ef2d45a83d3b6b74f72f27ef755ec";
        filename = "007748.ldb";
        url = "https://arweave.net/84kXtgFpBJWNYZ7Lp0DKSqPnL152MLxdn8tHoNKCi9I";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e3671ef1e0254b6b3a5d1a83b9316f3a91e6e36e116de0d2e71e39a4d4e13754";
        filename = "007749.ldb";
        url = "https://arweave.net/HmtQ-3eE1Mfl1kfBJIqfY_kAucpCaqqB9oddt83rgvg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6bfbb3939e7d1248556c44d3d12bf9aeb6451e2cc3f3420809375ad8f3e0f7cf";
        filename = "007750.ldb";
        url = "https://arweave.net/PIHrjo8USIhRmpE1OwBKsQz7ksiL8HIHOH7yc3yKbBw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "46bc312a96fb0d3734f2e1ca8488ce6fb80040908f40de34192e80c6bf5afaaa";
        filename = "007751.ldb";
        url = "https://arweave.net/LT5ixe8QkgOp70Un-um9tYdXozNbXdDUFbn9YBNPYao";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "68e6882a1d39f50ee5d78b6e5707bd45f8ca5ed9c4d2532ac5f238705f966dcd";
        filename = "007752.ldb";
        url = "https://arweave.net/U-eoOK6OI0iifHpYcITnMdGe0i7ppX5FndGAAV6nqHk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "742d39994084322d56ead4fddb8d3abb50aad94ac9916e54bfc41bf462c5aaa0";
        filename = "007753.ldb";
        url = "https://arweave.net/LclkQmw-14iMHKErXB1drk1ccdeJeot0ud39fs6O9wc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "ec82e413ccb06655f67ebcea2a0c982ce8bc241b3448a1f71ae05146e8851e11";
        filename = "007754.ldb";
        url = "https://arweave.net/BK5yvd1FUPhxlinWam6-LQYL7I6mfOZPLePqQdasYAw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "633561242af087f0c6228f4308d29ab5055269def6e10b690ee87132ed85add1";
        filename = "007755.ldb";
        url = "https://arweave.net/kpKbjfqhNSU4Ueb8DRE4xBMxbRdQBkOwchStr2S08Ss";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "f6471c847550f17047a6f66928d2ef3137bb9f2f67a42383fbd6bdd2be5a33a4";
        filename = "007756.ldb";
        url = "https://arweave.net/i9HNTgGYtFHjthCR0XaW6TxDGVHGhWjtfCBuWMW9Qx4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "acf81cfcf9adf7d32fe60736f5195871f0521fff8d267ff45ac927d7615357dd";
        filename = "007757.ldb";
        url = "https://arweave.net/KdZK00hRNuAw4BOGypIG9tKkVhJHhPfeeSVEOaqH7Zc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3f2f4d20ad5e558fbf14e58452254596a2d94ad9d20d6729931122c959b2a83a";
        filename = "007758.ldb";
        url = "https://arweave.net/urmoqELqlaXFDv8O9s0C-BdODgnGN7Aaz5p2wUWHSmo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "63ffd607af8a5e88eb206d85dde5d89b0ab53f6395193969755133703ccd6fcd";
        filename = "007759.ldb";
        url = "https://arweave.net/XBEA3tDFqrXVNhrG3IDWgWKi4YPWbbhv3rNpC2pLgc4";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "38ad3bf98d14af9be4ebdf66c9ee9b2eacfd23b72ebe019d3b0c4fc6661736ff";
        filename = "007760.ldb";
        url = "https://arweave.net/S25a6C_HFEXg4ph5n7SPcul75uAXXBkt7mBtmGm239E";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "392589c5bd07eea10dd61d085ad2b797f5193a0d6c7de9e3828200109f665f39";
        filename = "007761.ldb";
        url = "https://arweave.net/glFLpDwSKqL9kVQj82ld9rch8fX8j0AcEu1Vhepy8wo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9dba433c96758800a134f0b54931326fa33bbd49768397a02ec114b56567fbd1";
        filename = "007762.ldb";
        url = "https://arweave.net/gDmgu_fraNExJriWPd4O4mCra6Kb7SZliWOjmYwPjVg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "629432b1d8fa23e6cfc01e28ee0bd7119573b578b2b12299aa96ca8d80b8e600";
        filename = "007763.ldb";
        url = "https://arweave.net/F-3gv63CP2wEYyQ5GvC2QD2SGYui0usHaeEvkjRX4Do";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7ed105a06482338fb40d062b20838b0e8a4cee3f54092d51f032f8b651696083";
        filename = "007764.ldb";
        url = "https://arweave.net/t6ty96Zhk6TZ8tOdeiVGELewej8ut6U8B7GgsLT7840";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e6d200cfb9b091f1c216c79de5db800713d853b385078ecb706d463cffd01c03";
        filename = "007765.ldb";
        url = "https://arweave.net/Rf2rNOXYklYMYdZPlHs77nHSJHXm8aDRnfOQJiLiWJ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5b8edef728070897945303eddddac9bef15ff7467fe5ae5eb5fffc258b4af26d";
        filename = "007766.ldb";
        url = "https://arweave.net/yu01SBm1Z2sfNrU3Gl394iJqUIgbs2ro4Wy6XltS4EQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cb1d7f3ca8edb908dd0858c1eaec2e448fa944b00564271626a6ea1b9377fb0a";
        filename = "007767.ldb";
        url = "https://arweave.net/7E8EoNUGkvaqqtLs-xB6w4oDOylrF1JgPZix56gjEwU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "543f9068e647b93e4347dfdc6792d09cc11482c5c446338d7a556cc6b5d0e2a0";
        filename = "007768.ldb";
        url = "https://arweave.net/ATWbd9FmotJqfGhHwae1iDgvxCtA8KRzWF33VFnK_5s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d05ad2f9028ed2686d608459a3c3d93292ac9b21c17619af261868f355a08043";
        filename = "007769.ldb";
        url = "https://arweave.net/yZsDK3KeXclj2wgpJjJIKi4QDKGlypCFBABZ89BWB9o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "e09546ae32a3c6239a28102d22958c6e93eba38049e9ff8a4433ae95d0ad5c08";
        filename = "007770.ldb";
        url = "https://arweave.net/bO0PJ8tp5-INTm2kIfKub9fZoSExUeDmCm_2gZyiDsk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "786cca3ab4009d5e81d7aab7f704d8d9fd1383cc0f14ff4c9ee0503da2316991";
        filename = "007771.ldb";
        url = "https://arweave.net/Gs-n0yAfypoBfPW5RjSDX7pdo535CsUh0jovDQfAimg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "95a3323f6c58f4b5cd426566eebe247dfb4815b28f75533129b07017d4633858";
        filename = "007772.ldb";
        url = "https://arweave.net/X-Rle8KOHrDcT2wwWCZbL3w_rY0vKfRR-6tHFOGY5lM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1b23d3b6889bdfc1ac737599287c9ea2ba2b25dac08a1a3be1b64e5f7548d94f";
        filename = "007773.ldb";
        url = "https://arweave.net/VmKzVNRvtqrA1fcUuAsGVD_zZhFsU58l02jR7I-qg70";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "622e6064337076e4a1e628e432456438ec3de75c5fff9122b42f566a361c1e76";
        filename = "007774.ldb";
        url = "https://arweave.net/b7PBM3j_B3riYP9lf2WFGMZQiRnpFVCg1XGBLuMn5jU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d755dc9806ddbed0dc02e903aa6ef2be8c005aeba4bdf2b9ec909e82a464ef78";
        filename = "007775.ldb";
        url = "https://arweave.net/FY0n-ao2LcDoDbmLgGWJWMTBdC7MF9c5sIOlLpLFBLk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3b414304cf51a76b40af041401f6bb073a756f2ff25d3bf0070dfed9e395cd29";
        filename = "007776.ldb";
        url = "https://arweave.net/fWonSIEr4l2ofLLrc2wO1nc0-_WDXOtCy1vFdwN74mU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "01c04134022f0e0e8f302aca71b3245750de7250d6ed7e7490289fd09fe8ffc6";
        filename = "007777.ldb";
        url = "https://arweave.net/ZXSKdh2lWUupq1UtActatNcEOWetnpnI-V6-kWfT6Lk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "5cdf126f497af81aee6a62509ff8558ce3dbfe194597c9729a230ea23837f28d";
        filename = "007778.ldb";
        url = "https://arweave.net/L0kwUI7fwq9zCPaqAMXwzrSegfFKiTlWjONs5ZqVwjI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "4f255ff3c5a401208b4b651441465640aa83917de2de1556d865fe52009c82de";
        filename = "007779.ldb";
        url = "https://arweave.net/tLbdR8dEOZNcDNi2cq1rZm03yC1zAracJEXy7SRqZeA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0f894dfec84649172e4c18675a21ca3a2d4969cb1050cc48e9113d75d324e58e";
        filename = "007780.ldb";
        url = "https://arweave.net/R4ysY0EM9c89dYpqj_pBGnbDNzIG7Ol9z-6IHppZk2o";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "eb538bb6e7c7b6afe873b0c210b344e9d619db99867dd7817e8f575e82e8ba86";
        filename = "007781.ldb";
        url = "https://arweave.net/612TzYp9GooFyZSGZFHRW5XiRVqhv1gMYk6MeOQKCnU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a2630aa01d40baa3c1835e22880963d9c20538e4532cb138e8d2866b952a0687";
        filename = "007782.ldb";
        url = "https://arweave.net/gQj7QamOMj2M9KvcsIcMusnzOhdAFYa2-vT2mRTZxdo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9fc2462ddf91b711d2e6be2a5676e6ecdbebc5f802308b375b65c1ac761531f2";
        filename = "007783.ldb";
        url = "https://arweave.net/-yiYJMEFQfh-CnecsCJ_MCf4m9v0Y2aw-1tZO295ctU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cff18cf40cfadeadaaec92b673358dafade484783f191a26ea187d9286fcc3f0";
        filename = "007784.ldb";
        url = "https://arweave.net/2_Jm1USmkf-ApzTPJkI3vdefoB3TGJCI0zPa4CyxGX0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "51a29ade0c80488dcbd587b93390ae96316f55b3bfc2955b04ad4d5e898c8ccd";
        filename = "007785.ldb";
        url = "https://arweave.net/wIg3TaUwOJxA94GKycdCijq2ZVPAn7prfp8r24JxOZA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6966a5b93ef517b0a5aa2725229a383b9f57e61be3d26174c58eec38f022c1c9";
        filename = "007786.ldb";
        url = "https://arweave.net/IGsH0Ab6S6yJPGTZ8dDv2uBTOdBbARisaYVScG1VmiY";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0cc3273f2945fb1c7423397366235cd3b6b037fb706503c704e1aed7cc410a34";
        filename = "007787.ldb";
        url = "https://arweave.net/Le0Gv8_7zJzFAlC5sE3qOfmpORcHOu28W91UCAxN3dA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "04c268b5c233f1df26e718e87c543968874d4fc4abe810b62357d86338f4524e";
        filename = "007788.ldb";
        url = "https://arweave.net/eyZ_uv0DRaIrFn6MSmMLNaJfIcXdFbZ9e1jQdIwXlKA";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8d58f455bcdc543bf7e431167e98bf3db830be17ed25731d41fd4423b84aa5e3";
        filename = "007789.ldb";
        url = "https://arweave.net/7ZGGJB-LFtTEjjDbTNjhP1DrBs6rchQnj3pALhG4S74";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "843e9b7d443855f741b55a119f43ec68b607dbed73ba34767f9bb2b29bec17e0";
        filename = "007790.ldb";
        url = "https://arweave.net/0BZjPTIe4seHZYyyCrlO1YZ4fDq5UBx7pOKgOuRVHn0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "317c9685ffbb43981ea2fdc622f1f3f0ca9b39479a13418c460f9cd20eb12bab";
        filename = "007791.ldb";
        url = "https://arweave.net/-bQ2l891fmenKUYR3ThK4Ul4ozo-0jReE5ulqhWhUBo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "bccd4fe24bba9211893cbc2679d58f3940bf1629740a72d52c27a5716033a64d";
        filename = "007792.ldb";
        url = "https://arweave.net/e3r-KNtUFgUlbHXcX9oJS-QVpQzShhcBZ0I7AyE9VXo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "fd9493325ed67f27feb364ab71e39c39a2e5580e338c9f6346b834ffd03e5832";
        filename = "007793.ldb";
        url = "https://arweave.net/U7RfvbdNS5YaH-0TqyLTS_1Zf13CZryPE17G4Z5-d6M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "de4f1c33cbad97d9f80038b244f9f149d6be66efacfe2dc2a0e7257545b0465a";
        filename = "007794.ldb";
        url = "https://arweave.net/cWMirrw4ZNXjf765bpfQvxkXYy4fvgqs6aERCH4-FZo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c44670fb3e8be29bb821767b4a3fae4ed2c1ad14f1462491c51b20b4bd24d7bd";
        filename = "007795.ldb";
        url = "https://arweave.net/h6SxO6hSWgIx6B0PgmdUKHHORYKhgzR3a-rvpoolF0s";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "0802f780bc4c65e41318621fd10c079d6dd296303d924f3cbac03c9e3460d9e8";
        filename = "007796.ldb";
        url = "https://arweave.net/RO1rqi-Qm1ydPoP6PXottTMMt2vAQ7_rPS-bcxbsUVM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "682978ad5b54d67b924e1e9f87f8ae2bc514619008d8f8775e3e20391f64ce8f";
        filename = "007797.ldb";
        url = "https://arweave.net/UbXnCtZeQNOcLNFgflChipoebV7Fe1RaXZfYBW6WbPU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "50723eaf9cdaf93728c72a899af81e793b5d3659c073811ac9489fdcf2ce8828";
        filename = "007798.ldb";
        url = "https://arweave.net/Fa1YnKWws9wjsERg8Cje5aQlij6N5Mi5iyjbMXy30uo";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "03bbc26548f54300419ee5cdfe2ff4ff62c3a87fd827341ca602ad4313ff020d";
        filename = "007799.ldb";
        url = "https://arweave.net/oINLQ4jubLiQNoR0Nv5xCIlURK-puJ6lBfQWZKdTiQ0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c7b2575229deda812d13639a9d537464fdcccf4318eea98bad6bf7b87a7e2341";
        filename = "007800.ldb";
        url = "https://arweave.net/pUhqJfIILfdPObp7PGf3T2dced-MkKQaogT25kXLpl8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }        
        
        hash = "c269986409a3e893b73d48a5b59671395fa5d025f004a7642ca8dbec46597605";
        filename = "007801.ldb";
        url = "https://arweave.net/uwla0lr9bTJmreKHzvBfRymKIL8LgofCRvC6ugpRNG0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }        
        
        hash = "d4cea851b4192a8f6606bddff4e402d94bced3c9684e1c2587fed7dbcd6e4383";
        filename = "007802.ldb";
        url = "https://arweave.net/mGKo21i59xzW-3ACNhyBjMNk8GeCvOnEiaiSlZMsSag";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7e14f735c1e463e5c740b9111bf75462700cedfdc9f377c577746629f86aa36b";
        filename = "007803.ldb";
        url = "https://arweave.net/URvMtbWnljXgnTH-Bc1j0RKGohalhdACsRi5sKwOoGQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "14647d492dfe254bf9af8a69e1516440afde5f2cf39f1f6278ababee17dbb6ca";
        filename = "007804.ldb";
        url = "https://arweave.net/YRc9aM1NQ82GbAAhUEYXdqwTOTUbjMTuZ3geZQmLIYU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }
        hash = "c8ace1a1775cd03a62cb5262f2afc1ec859fabcdec33bcbbcb473aaf5bc8ee47";
        filename = "007805.ldb";
        url = "https://arweave.net/2qZBbvlx1SX2drZAJBFghvhLa-DAS8TfWfOCd2qBKj0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "898a14a58534a146667a7ecd4652a795ddbd8aa45012a89bcab4930863cea308";
        filename = "007806.ldb";
        url = "https://arweave.net/JADE7WcXTa2IhQ4QQcT3BcaX5TLzHCaQOjtoTZUMlKc";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "50c116ae1dcd250c4f7b5245fd7e9a2fc93b3bd8245b2ca4c1682f02b970764f";
        filename = "007807.ldb";
        url = "https://arweave.net/kRwghCLoB0WAbZlvEpdPiqWSLrUMxSbrboY_FMCRLO0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "45ea48e7fcd0f6d2627e79066a40a8a181ad456f1f33f84d92ad27157e0230c8";
        filename = "007808.ldb";
        url = "https://arweave.net/JI4Gs5wxuY0GyxlczmOS1SM92O_6WwSXufzBrKWC6Po";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "303409e63ca424bc1badec07ed31e3351df41f9c4c767f4fed83803c2d639508";
        filename = "007809.ldb";
        url = "https://arweave.net/z7_KAJOtLAftGtSd-F-UcwRZ_9_TcoDjWxjI1Ijk2z8";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "288a12c8aaa788e69b4dd56c2a3aebbe0e1c17a8259c65d2574b2563498a29fe";
        filename = "007810.ldb";
        url = "https://arweave.net/7S5kpWip2LM6DFN0Ku9zAVXUeUqVQgrODGonLPNiVbk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "89ac102919bd092bd306357c8cdcc6e6fab8008170951b662482fd41e20ce7f0";
        filename = "007811.ldb";
        url = "https://arweave.net/N6IsiXT3cRA6RusUpYnrwl2xvG7Vo0q0UXFejgKuwtM";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "48cd236ff139df1c6886782714df2ec07b06baed981b6566b7f478ba99b89fcb";
        filename = "007812.ldb";
        url = "https://arweave.net/DscIO8A_pP_F4xMzkZ4Un3UY7-fcNX4Xh1fyOEKE0-0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "24ffd9845c9526484c1eda688981a1efcfa97a259d413391b024847f4317c155";
        filename = "007813.ldb";
        url = "https://arweave.net/2BMYZYmClpXTXi_-n6D8Yc251yIcMzlUKc64OAyVakU";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "a2785cd0979cae689db2639550c33c4db06ca5ff1297251259fba81ea0048cc5";
        filename = "007814.ldb";
        url = "https://arweave.net/ovAJq4JrMrGVkgGjQJa5hRlbsVNam1isLNAyIX0nl7c";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1f897b24e6d6139f3336a24368d54e9b46866e5399948861ed082d3127b33f23";
        filename = "007815.ldb";
        url = "https://arweave.net/F2XDP_PW5TYf-gTgYBRzI0Y0dk6JMKVxflrAYyV5WmE";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "9a3089d1e399168e230f44f0a85d50d3366aa7348e173aa6ee34141ac1e0b46c";
        filename = "007816.ldb";
        url = "https://arweave.net/PkIzlwo9eD7xz529GogIChbmNl4Fkow_ityOdia9EPk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "c49e0872acac3a7c28c775d6aa4a3400e924523a7d9a731060551c23d0980a25";
        filename = "007817.ldb";
        url = "https://arweave.net/mrgSfwX8XGxMJv__W2TgYZHrneAxnMKnIIsAoYiFxXQ";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "8c1d413f9dbbbfba8dead27f5599c1d02a9dfad91b1f03003e731e9c89170f09";
        filename = "007818.ldb";
        url = "https://arweave.net/J7OzWuGfiAXYjEuB1jBc5URNGhN5sPj49iNgo246l9M";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "d64a3cb1334f78d2c9990ce361fdec1a53b13ff0cf4bdd1473461b0860ee7d8f";
        filename = "007819.ldb";
        url = "https://arweave.net/8xAqJhZ1tdTjXIKJA6LeZDGu5eHF22Z5KgVmgko59bI";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "3e3edb218c8135e433fd0d268e82f6dbf5706473b7124d0fc6034cf7b4c365dc";
        filename = "007820.ldb";
        url = "https://arweave.net/U8cel-betXKvg5fGqgl_cEKHpGguoh06jWEFZpNMNYw";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "cc08576afb92ea2446379b536c31e91101c4eea11f58f9d6b546aeee12df3193";
        filename = "007821.ldb";
        url = "https://arweave.net/xDceclPpnj-_leJVQROWHt_KPn7ZY7TeEqoxW95yQzg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1a03bc9853e074b40e3802b02da7f12e47c72d5476d9cb4ae49110f4c8a97668";
        filename = "007822.ldb";
        url = "https://arweave.net/fNLWK48TKqPSI8bGkd07cCOE-rNboC5-FtjiOe3D1N0";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "7caeb05224b877ac62a3b4f6bb0007bc21b5370dad562a54338a8640dbaf32c4";
        filename = "007823.ldb";
        url = "https://arweave.net/ZKW3rg6HElpFNuWV02GpAZPPOM-0keQd0xq9JFdSBmg";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "1714cc96e61869f567e0dc9b20a0ec3a9421f965cc2a05b4d2b4156b4dc4a510";
        filename = "007824.ldb";
        url = "https://arweave.net/GQQd9qtIO-tidakyA1obwdtJfnGvh3YrS9ooU7H2yJk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "2185d28f2be32d33710171900a606591d1c0191e1999c136cbfc44c5bfda34a7";
        filename = "007825.ldb";
        url = "https://arweave.net/Cw0pUlzrnsZ5oGGzRrE8rLB5GQBy3d0C4s13e0iapnk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        hash = "6803d9ecd6e953f2de7170cca2bd1f3539534ad793782a34b0dba43bf5290cbc";
        filename = "007826.ldb";
        url = "https://arweave.net/uPTr5RZQX-HDkAiw4uCjMqWHO8vtLoj0746KWYXmLJk";

        if (!BlockIndexDownload(url, filename, hash)){
            InitError("Could not download initial database. Please try again.\n");
            return false;
        }

        // Download complete!

        // remove all existing files (redundant)
        boost::filesystem::remove_all(blocks_dir);
        boost::filesystem::remove_all(chainstate_dir);
        boost::filesystem::remove_all(database_dir);

        boost::filesystem::rename(tmp_blocks_dir, blocks_dir);
        boost::filesystem::rename(tmp_chainstate_dir, chainstate_dir);
        std::string download_complete_str = "Initial Download Complete: ";

        InitWarning(download_complete_str + std::to_string(initialBlockchainBytesDownloaded) + " Bytes\n");

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
    boost::filesystem::path pk_path = ZC_GetParamsDir() / "sprout-proving.key";
    boost::filesystem::path vk_path = ZC_GetParamsDir() / "sprout-verifying.key";

    // redundant checks on startup is ok and more secure
    if (!(
        boost::filesystem::exists(pk_path) &&
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

    pzcashParams = ZCJoinSplit::Prepared(vk_path.string(), pk_path.string());

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
        } else if (mapArgs.count("-savesproutr1cs")) {
            return InitError(_("Saving the Sprout R1CS requires -experimentalfeatures."));
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
        if (GetBoolArg("-txindex", false))
            return InitError(_("Prune mode is incompatible with -txindex."));
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

    std::string strWalletFile = GetArg("-wallet", "wallet.dat");
#endif // ENABLE_WALLET

    fIsBareMultisigStd = GetBoolArg("-permitbaremultisig", true);
    nMaxDatacarrierBytes = GetArg("-datacarriersize", nMaxDatacarrierBytes);

    fAlerts = GetBoolArg("-alerts", DEFAULT_ALERTS);

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

    // Default value of 0 for mempooltxinputlimit means no limit is applied
    if (mapArgs.count("-mempooltxinputlimit")) {
        int64_t limit = GetArg("-mempooltxinputlimit", 0);
        if (limit < 0) {
            return InitError(_("Mempool limit on transparent inputs to a transaction cannot be negative"));
        } else if (limit > 0) {
            LogPrintf("Mempool configured to reject transactions with greater than %lld transparent inputs\n", limit);
        }
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

    // ********************************************************* Step 4: application initialization: dir lock, daemonize, pidfile, debug log

    // Initialize libsodium
    if (init_and_check_sodium() == -1) {
        return false;
    }

    // Initialize elliptic curve code
    ECC_Start();
    globalVerifyHandle.reset(new ECCVerifyHandle());

    // Sanity check
    if (!InitSanityCheck())
        return InitError(_("Initialization sanity check failed. ZClassic is shutting down."));

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

    // These must be disabled for now, they are buggy and we probably don't
    // want any of libsnark's profiling in production anyway.
    libsnark::inhibit_profiling_info = true;
    libsnark::inhibit_profiling_counters = true;

    // Initialize Zclassic circuit parameters
    ZC_LoadParams(chainparams);

    if (GetBoolArg("-savesproutr1cs", false)) {
        boost::filesystem::path r1cs_path = ZC_GetParamsDir() / "r1cs";

        LogPrintf("Saving Sprout R1CS to %s\n", r1cs_path.string());

        pzcashParams->saveR1CS(r1cs_path.string());
    }

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

    // see Step 2: parameter interactions for more information about these
    fListen = GetBoolArg("-listen", DEFAULT_LISTEN);
    fDiscover = GetBoolArg("-discover", true);
    fNameLookup = GetBoolArg("-dns", true);

    bool fBound = false;
    if (fListen) {
        if (mapArgs.count("-bind") || mapArgs.count("-whitebind")) {
            BOOST_FOREACH(const std::string& strBind, mapMultiArgs["-bind"]) {
                CService addrBind;
                if (!Lookup(strBind.c_str(), addrBind, GetListenPort(), false))
                    return InitError(strprintf(_("Cannot resolve -bind address: '%s'"), strBind));
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

#if ENABLE_ZMQ
    pzmqNotificationInterface = CZMQNotificationInterface::CreateWithArguments(mapArgs);

    if (pzmqNotificationInterface) {
        RegisterValidationInterface(pzmqNotificationInterface);
    }
#endif

#if ENABLE_PROTON
    pAMQPNotificationInterface = AMQPNotificationInterface::CreateWithArguments(mapArgs);

    if (pAMQPNotificationInterface) {

        // AMQP support is currently an experimental feature, so fail if user configured AMQP notifications
        // without enabling experimental features.
        if (!fExperimentalMode) {
            return InitError(_("AMQP support requires -experimentalfeatures."));
        }

        RegisterValidationInterface(pAMQPNotificationInterface);
    }
#endif

    // ********************************************************* Step 7: load block chain

    fReindex = GetBoolArg("-reindex", false);
    fNoFastSync = GetBoolArg("-nofastsync", false);

    // Upgrading to 0.8; hard-link the old blknnnn.dat files into /blocks/
    boost::filesystem::path blocksDir = GetDataDir() / "blocks";
    if (!boost::filesystem::exists(blocksDir))
    {
        boost::filesystem::create_directories(blocksDir);
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
    int64_t nTotalCache = (GetArg("-dbcache", nDefaultDbCache) << 20);
    nTotalCache = std::max(nTotalCache, nMinDbCache << 20); // total cache cannot be less than nMinDbCache
    nTotalCache = std::min(nTotalCache, nMaxDbCache << 20); // total cache cannot be greated than nMaxDbcache
    int64_t nBlockTreeDBCache = nTotalCache / 8;
    if (nBlockTreeDBCache > (1 << 21) && !GetBoolArg("-txindex", false))
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

    bool fLoaded = false;
    while (!fLoaded) {
        bool fReset = fReindex;
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

                pblocktree = new CBlockTreeDB(nBlockTreeDBCache, false, fReindex);
                pcoinsdbview = new CCoinsViewDB(nCoinDBCache, false, fReindex);
                pcoinscatcher = new CCoinsViewErrorCatcher(pcoinsdbview);
                pcoinsTip = new CCoinsViewCache(pcoinscatcher);

                if (fReindex) {
                    pblocktree->WriteReindexing(true);
                    //If we're reindexing in prune mode, wipe away unusable block files and all undo data files
                    if (fPruneMode)
                        CleanupBlockRevFiles();
                }

                if (!LoadBlockIndex()) {
                    strLoadError = _("Error loading block database");
                    break;
                }

                // If the loaded chain has a wrong genesis, bail out immediately
                // (we're likely using a testnet datadir, or the other way around).
                if (!mapBlockIndex.empty() && mapBlockIndex.count(chainparams.GetConsensus().hashGenesisBlock) == 0)
                    return InitError(_("Incorrect or no genesis block found. Wrong datadir for network?"));

                // Initialize the block index (no-op if non-empty database was already loaded)
                if (!InitBlockIndex()) {
                    strLoadError = _("Error initializing block database");
                    break;
                }

                // Check for changed -txindex state
                if (fTxIndex != GetBoolArg("-txindex", false)) {
                    strLoadError = _("You need to rebuild the database using -reindex to change -txindex");
                    break;
                }

                // Check for changed -prune state.  What we are concerned about is a user who has pruned blocks
                // in the past, but is now trying to run unpruned.
                if (fHavePruned && !fPruneMode) {
                    strLoadError = _("You need to rebuild the database using -reindex to go back to unpruned mode.  This will redownload the entire blockchain");
                    break;
                }

                if (!fReindex) {
                    uiInterface.InitMessage(_("Rewinding blocks if needed..."));
                    if (!RewindBlockIndex(chainparams, clearWitnessCaches)) {
                        strLoadError = _("Unable to rewind the database to a pre-upgrade state. You will need to redownload the blockchain");
                        break;
                    }
                }

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
            } catch (const std::exception& e) {
                if (fDebug) LogPrintf("%s\n", e.what());
                strLoadError = _("Error opening block database");
                break;
            }

            fLoaded = true;
        } while(false);

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

    // As LoadBlockIndex can take several minutes, it's possible the user
    // requested to kill the GUI during the last operation. If so, exit.
    // As the program has not fully started yet, Shutdown() is possibly overkill.
    if (fRequestShutdown)
    {
        LogPrintf("Shutdown requested. Exiting.\n");
        return false;
    }
    LogPrintf(" block index %15dms\n", GetTimeMillis() - nStart);

    boost::filesystem::path est_path = GetDataDir() / FEE_ESTIMATES_FILENAME;
    CAutoFile est_filein(fopen(est_path.string().c_str(), "rb"), SER_DISK, CLIENT_VERSION);
    // Allowed to fail as this file IS missing on first startup.
    if (!est_filein.IsNull())
        mempool.ReadFeeEstimates(est_filein);
    fFeeEstimatesInitialized = true;


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
            if (walletdb.ReadBestBlock(locator))
                pindexRescan = FindForkInGlobalIndex(chainActive, locator);
            else
                pindexRescan = chainActive.Genesis();
        }
        if (chainActive.Tip() && chainActive.Tip() != pindexRescan)
        {
            uiInterface.InitMessage(_("Rescanning..."));
            LogPrintf("Rescanning last %i blocks (from block %i)...\n", chainActive.Height() - pindexRescan->nHeight, pindexRescan->nHeight);
            nStart = GetTimeMillis();
            pwalletMain->ScanForWalletTransactions(pindexRescan, true);
            LogPrintf(" rescan      %15dms\n", GetTimeMillis() - nStart);
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
            }
        }
        pwalletMain->SetBroadcastTransactions(GetBoolArg("-walletbroadcast", true));
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
    if (!ActivateBestChain(state))
        strErrors << "Failed to connect best block";

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

    // Start the thread that notifies listeners of transactions that have been
    // recently added to the mempool.
    threadGroup.create_thread(boost::bind(&TraceThread<void (*)()>, "txnotify", &ThreadNotifyRecentlyAdded));

    if (GetBoolArg("-listenonion", DEFAULT_LISTEN_ONION))
        StartTorControl(threadGroup, scheduler);

    StartNode(threadGroup, scheduler);

    // Monitor the chain every minute, and alert if we get blocks much quicker or slower than expected.
    CScheduler::Function f = boost::bind(&PartitionCheck, &IsInitialBlockDownload,
                                         boost::ref(cs_main), boost::cref(pindexBestHeader));
    scheduler.scheduleEvery(f, 60);

#ifdef ENABLE_MINING
    // Generate coins in the background
    GenerateBitcoins(GetBoolArg("-gen", false), GetArg("-genproclimit", 1), Params());
#endif

    // ********************************************************* Step 11: finished

    SetRPCWarmupFinished();
    uiInterface.InitMessage(_("Done loading"));

#ifdef ENABLE_WALLET
    if (pwalletMain) {
        // Add wallet transactions that aren't already in a block to mapTransactions
        pwalletMain->ReacceptWalletTransactions();

        // Run a thread to flush wallet periodically
        threadGroup.create_thread(boost::bind(&ThreadFlushWalletDB, boost::ref(pwalletMain->strWalletFile)));
    }
#endif

    // SENDALERT
    threadGroup.create_thread(boost::bind(ThreadSendAlert));

    return !fRequestShutdown;
}
