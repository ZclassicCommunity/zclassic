// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NET_H
#define BITCOIN_NET_H

#include "bloom.h"
#include "compat.h"
#include "hash.h"
#include "limitedmap.h"
#include "mruset.h"
#include "netbase.h"
#include "protocol.h"
#include "random.h"
#include "streams.h"
#include "sync.h"
#include "uint256.h"
#include "utilstrencodings.h"

#include <atomic>
#include <deque>
#include <stdint.h>

#ifndef WIN32
#include <arpa/inet.h>
#endif

#include <boost/filesystem/path.hpp>
#include <boost/foreach.hpp>
#include <boost/signals2/signal.hpp>

class CAddrInfo;
class CAddrMan;
class CBlockIndex;
class CScheduler;
class CNode;

namespace boost {
    class thread_group;
} // namespace boost

/** Time between pings automatically sent out for latency probing and keepalive (in seconds). */
static const int PING_INTERVAL = 2 * 60;
/** Time after which to disconnect, after waiting for a ping response (or inactivity). */
static const int TIMEOUT_INTERVAL = 20 * 60;
/** The maximum number of entries in an 'inv' protocol message */
static const unsigned int MAX_INV_SZ = 50000;
/** The maximum number of new addresses to accumulate before announcing. */
static const unsigned int MAX_ADDR_TO_SEND = 1000;
/** Tor v3 addresses a peer may add to the onion store unasked: refill rate per second, burst, start. */
static const double ONION_ADDR_TOKENS_PER_SEC = 0.1;
static const double ONION_ADDR_TOKENS_MAX = 1000;
static const double ONION_ADDR_TOKENS_INITIAL = 100;
/** Maximum length of incoming protocol messages (no message over 2 MiB is currently acceptable). */
static const unsigned int MAX_PROTOCOL_MESSAGE_LENGTH = 2 * 1024 * 1024;
/** Maximum length of strSubVer in `version` message */
static const unsigned int MAX_SUBVERSION_LENGTH = 256;
/** -listen default */
static const bool DEFAULT_LISTEN = true;
/** The maximum number of entries in mapAskFor */
static const size_t MAPASKFOR_MAX_SZ = MAX_INV_SZ;
/** The maximum number of entries in setAskFor (larger due to getdata latency)*/
static const size_t SETASKFOR_MAX_SZ = 2 * MAX_INV_SZ;
/** The maximum number of peer connections to maintain. */
static const unsigned int DEFAULT_MAX_PEER_CONNECTIONS = 125;
/** The period before a network upgrade activates, where connections to upgrading peers are preferred (in blocks). */
static const int NETWORK_UPGRADE_PEER_PREFERENCE_BLOCK_PERIOD = 24 * 24 * 3;

unsigned int ReceiveFloodSize();
unsigned int SendBufferSize();

void AddOneShot(const std::string& strDest);
//! False when DNS seed host names must not be queued as one-shot connections
//! because the node is onion-only behind the embedded Tor (see ThreadDNSAddressSeed).
bool DnsSeedOneShotsAllowed();
void AddressCurrentlyConnected(const CService& addr);
CNode* FindNode(const CNetAddr& ip);
CNode* FindNode(const CSubNet& subNet);
CNode* FindNode(const std::string& addrName);
CNode* FindNode(const CService& ip);
/** nTimeout: connect timeout in milliseconds, 0 for -timeout (nConnectTimeout). */
CNode* ConnectNode(CAddress addrConnect, const char *pszDest = NULL, int nTimeout = 0);
bool OpenNetworkConnection(const CAddress& addrConnect, CSemaphoreGrant *grantOutbound = NULL, const char *strDest = NULL, bool fOneShot = false, int nTimeout = 0);
/** Connect timeouts (ms) for a direct (not proxied) outbound dial from the address table,
 *  when -timeout is not given: a live node completes the TCP handshake within a fraction
 *  of a second (measured: under 0.1 s), a dead one never does. The first dial of an address
 *  never dialled or reached gets FIRST_DIAL, any later one DIRECT_DIAL. */
static const int FIRST_DIAL_CONNECT_TIMEOUT = 2000;
static const int DIRECT_DIAL_CONNECT_TIMEOUT = 3000;
/** The connect timeout for an outbound dial: the shorter ones above for a direct dial
 *  without an explicit -timeout, otherwise nDefaultTimeout (-timeout). */
int OutboundConnectTimeout(bool fDirect, bool fTimeoutSet, int nAttempts, int64_t nLastSuccess, int nDefaultTimeout);
unsigned short GetListenPort();
bool BindListenPort(const CService &bindAddr, std::string& strError, bool fWhitelisted = false, bool fOnion = false);
void StartNode(boost::thread_group& threadGroup, CScheduler& scheduler);
bool StopNode();
void SocketSendData(CNode *pnode);

typedef int NodeId;

struct CombinerAll
{
    typedef bool result_type;

    template<typename I>
    bool operator()(I first, I last) const
    {
        while (first != last) {
            if (!(*first)) return false;
            ++first;
        }
        return true;
    }
};

// Signals for message handling
struct CNodeSignals
{
    boost::signals2::signal<int ()> GetHeight;
    boost::signals2::signal<bool (CNode*), CombinerAll> ProcessMessages;
    boost::signals2::signal<bool (CNode*, bool), CombinerAll> SendMessages;
    boost::signals2::signal<void (NodeId, const CNode*)> InitializeNode;
    boost::signals2::signal<void (NodeId)> FinalizeNode;
};


CNodeSignals& GetNodeSignals();


enum
{
    LOCAL_NONE,   // unknown
    LOCAL_IF,     // address a local interface listens on
    LOCAL_BIND,   // address explicit bound to
    LOCAL_UPNP,   // unused (was: address reported by UPnP)
    LOCAL_MANUAL, // address explicitly specified (-externalip=)

    LOCAL_MAX
};

bool IsPeerAddrLocalGood(CNode *pnode);
void AdvertizeLocal(CNode *pnode);
/** Queue our own Tor v3 address for an addrv2 peer that is on the onion side (see doc/tor.md).
 *  False when there is nothing to send yet (no peer addrv2, not an onion peer, service not up). */
bool AdvertizeLocalOnion(CNode *pnode);
/**
 * The loopback address ADD_ONION points the onion service at. Connections
 * accepted there came in through the onion service (inbound onion peers);
 * every other listener is clearnet. Unset when the service targets the main
 * listen port (then inbound onion peers cannot be told from local ones).
 */
void SetOnionServiceTarget(const CService& addr);
bool GetOnionServiceTarget(CService& addrOut);
void SetLimited(enum Network net, bool fLimited = true);
bool IsLimited(enum Network net);
bool IsLimited(const CNetAddr& addr);
bool AddLocal(const CService& addr, int nScore = LOCAL_NONE);
bool AddLocal(const CNetAddr& addr, int nScore = LOCAL_NONE);
bool RemoveLocal(const CService& addr);
bool SeenLocal(const CService& addr);
bool IsLocal(const CService& addr);
/**
 * Best local address for a peer. Privacy rule: an onion peer (fPeerOnion, or a
 * paddrPeer that is a Tor address) is only ever offered our Tor address, and a
 * clearnet peer is never offered it.
 */
bool GetLocal(CService &addr, const CNetAddr *paddrPeer = NULL, bool fPeerOnion = false);
bool IsReachable(enum Network net);
bool IsReachable(const CNetAddr &addr);
CAddress GetLocalAddress(const CNetAddr *paddrPeer = NULL, bool fPeerOnion = false);


extern bool fDiscover;
extern bool fListen;
// Atomic: net threads read it (GetLocalAddress, version push) while the bootstrap
// auto-serve worker may set NODE_BOOTSTRAP on it after sync, so the plain-uint64_t
// read-modify-write was a formal data race (CONC-N1). All set sites use |=/&=
// (atomic fetch_or/fetch_and); serialization/format sites use an explicit .load().
extern std::atomic<uint64_t> nLocalServices;
extern uint64_t nLocalHostNonce;
extern CAddrMan addrman;
/** Tor v3 addresses learned by addrv2 gossip. Separate from addrman so peers.dat
 *  keeps its legacy 16-byte format (a downgrade never sees these); persisted in
 *  onion_peers.dat. */
extern CAddrMan addrmanOnion;
/**
 * The table ThreadOpenConnections picks its next candidate from. The onion
 * store only when the onion network is reachable (fOnionProxy: a Tor proxy is
 * set for it, and it is not limited) and it holds something: always for an
 * onion-only node (IPv4 and IPv6 limited), otherwise when the clearnet table is
 * empty or nRand == 0 (one time in four, nRand is GetRand(4)).
 */
CAddrMan& SelectDialTable(bool fOnionProxy, uint32_t nRand);
/** The next outbound address to dial from man, or an invalid one: not on a network group in
 *  setConnected, not our own, not limited, not tried within the last minute, and a node on a
 *  port other than the default only after enough other draws (see ThreadOpenConnections). */
struct COutboundSkip
{
    /** Hosts (any port) not to dial: our own address as peers see it, the -addnode hosts. */
    std::set<CNetAddr> hosts;
    /** This host has no usable IPv6 route (see HostHasIPv6Route). */
    bool fNoIPv6Route = false;
};
CAddrInfo SelectOutboundCandidate(CAddrMan& man, const std::set<std::vector<unsigned char> >& setConnected, int64_t nANow,
                                  const COutboundSkip& skip = COutboundSkip());
/** Our public address(es) as our peers report it: vReports holds (peer address, the address
 *  that peer says it sees us at). An address counts only when peers on two network groups
 *  report it, so one peer cannot make us avoid dialling some host. */
std::set<CNetAddr> PeerReportedLocal(const std::vector<std::pair<CNetAddr, CNetAddr> >& vReports);
/** Whether the system has a global, non-Teredo IPv6 source address to route to the IPv6
 *  internet (asked of the OS without sending anything; cached for a minute). */
bool HostHasIPv6Route();
/** The fixed seeds go into the table while it holds fewer addresses than this. */
static const size_t FIXED_SEEDS_THIN_TABLE = 16;
bool FixedSeedsWanted(size_t nTableSize);

/** Outbound dialers (opencon threads) that run at once while the node holds fewer than
 *  PARALLEL_DIAL_OUTBOUND_TARGET outbound peers. A dead address costs a whole connect
 *  timeout and on a small network most of the table is dead, so a single dialer spent
 *  most of a fresh start waiting. Above the target only the first dialer runs. */
static const int MAX_PARALLEL_DIALS = 8;
static const int PARALLEL_DIAL_OUTBOUND_TARGET = 8;
/** Whether the extra dialers run, given the number of outbound peers. */
bool ParallelDialWanted(int nOutbound);
int CountOutboundPeers();
/** Whether an outbound peer on this network group is connected. */
bool OutboundGroupConnected(const std::vector<unsigned char>& group);
/** The network groups outbound dials are in progress to. A dialer counts them as
 *  connected, so concurrent dials keep one outbound peer per group. */
std::set<std::vector<unsigned char> > DialingGroups();
/** Take a group for one dial; false when another dial holds it. */
bool ReserveDialGroup(const std::vector<unsigned char>& group);
void ReleaseDialGroup(const std::vector<unsigned char>& group);
/** A group held for the length of one dial. */
class CDialGroupReservation
{
    std::vector<unsigned char> group;
    bool fHeld;
public:
    explicit CDialGroupReservation(const std::vector<unsigned char>& groupIn) : group(groupIn), fHeld(ReserveDialGroup(groupIn)) {}
    ~CDialGroupReservation() { if (fHeld) ReleaseDialGroup(group); }
    CDialGroupReservation(const CDialGroupReservation&) = delete;
    CDialGroupReservation& operator=(const CDialGroupReservation&) = delete;
    explicit operator bool() const { return fHeld; }
};
/** The table an address belongs to: Tor v3 in the onion store, the rest in addrman. */
inline CAddrMan& AddrManFor(const CNetAddr& addr) { return addr.IsTorV3() ? addrmanOnion : addrman; }
/** Maximum number of connections to simultaneously allow (aka connection slots) */
extern int nMaxConnections;

extern std::vector<CNode*> vNodes;
extern CCriticalSection cs_vNodes;
extern std::map<CInv, CDataStream> mapRelay;
extern std::deque<std::pair<int64_t, CInv> > vRelayExpiration;
extern CCriticalSection cs_mapRelay;
extern limitedmap<CInv, int64_t> mapAlreadyAskedFor;

extern std::vector<std::string> vAddedNodes;
extern CCriticalSection cs_vAddedNodes;

extern NodeId nLastNodeId;
extern CCriticalSection cs_nLastNodeId;

/** Subversion as sent to the P2P network in `version` messages */
extern std::string strSubVersion;

struct LocalServiceInfo {
    int nScore;
    int nPort;
};

extern CCriticalSection cs_mapLocalHost;
extern std::map<CNetAddr, LocalServiceInfo> mapLocalHost;

class CNodeStats
{
public:
    NodeId nodeid;
    uint64_t nServices;
    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    std::string addrName;
    int nVersion;
    std::string cleanSubVer;
    bool fInbound;
    int nStartingHeight;
    uint64_t nSendBytes;
    uint64_t nRecvBytes;
    bool fWhitelisted;
    double dPingTime;
    double dPingWait;
    std::string addrLocal;
};




class CNetMessage {
public:
    bool in_data;                   // parsing header (false) or data (true)

    CDataStream hdrbuf;             // partially received header
    CMessageHeader hdr;             // complete header
    unsigned int nHdrPos;

    CDataStream vRecv;              // received message data
    unsigned int nDataPos;

    int64_t nTime;                  // time (in microseconds) of message receipt.

    CNetMessage(const CMessageHeader::MessageStartChars& pchMessageStartIn, int nTypeIn, int nVersionIn) : hdrbuf(nTypeIn, nVersionIn), hdr(pchMessageStartIn), vRecv(nTypeIn, nVersionIn) {
        hdrbuf.resize(24);
        in_data = false;
        nHdrPos = 0;
        nDataPos = 0;
        nTime = 0;
    }

    bool complete() const
    {
        if (!in_data)
            return false;
        return (hdr.nMessageSize == nDataPos);
    }

    void SetVersion(int nVersionIn)
    {
        hdrbuf.SetVersion(nVersionIn);
        vRecv.SetVersion(nVersionIn);
    }

    int readHeader(const char *pch, unsigned int nBytes);
    int readData(const char *pch, unsigned int nBytes);
};





/** Information about a peer */
class CNode
{
public:
    // socket
    uint64_t nServices;
    SOCKET hSocket;
    CDataStream ssSend;
    size_t nSendSize; // total size of all vSendMsg entries
    size_t nSendOffset; // offset inside the first vSendMsg already sent
    uint64_t nSendBytes;
    std::deque<CSerializeData> vSendMsg;
    CCriticalSection cs_vSend;

    std::deque<CInv> vRecvGetData;
    std::deque<CNetMessage> vRecvMsg;
    CCriticalSection cs_vRecvMsg;
    uint64_t nRecvBytes;
    int nRecvVersion;

    int64_t nLastSend;
    int64_t nLastRecv;
    int64_t nTimeConnected;
    int64_t nTimeOffset;
    CAddress addr;
    std::string addrName;
    CService addrLocal;
    int nVersion;
    // strSubVer is whatever byte array we read from the wire. However, this field is intended
    // to be printed out, displayed to humans in various forms and so on. So we sanitize it and
    // store the sanitized version in cleanSubVer. The original should be used when dealing with
    // the network or wire types and the cleaned string used when displayed or logged.
    std::string strSubVer, cleanSubVer;
    bool fWhitelisted; // This peer can bypass DoS banning.
    bool fOneShot;
    bool fClient;
    bool fInbound;
    bool fNetworkNode;
    bool fSuccessfullyConnected;
    bool fDisconnect;
    // We use fRelayTxes for two purposes -
    // a) it allows us to not relay tx invs before receiving the peer's version message
    // b) the peer may tell us in its version message that we should not relay tx invs
    //    until it has initialized its bloom filter.
    bool fRelayTxes;
    bool fSentAddr;
    // BIP155: the peer sent "sendaddrv2" before its verack, so we may send it
    // "addrv2" (and Tor v3 addresses). Unset for every older peer.
    bool fSendAddrV2;
    // Accepted on the listener that ADD_ONION targets: the peer reached us
    // through our onion service (its address is the Tor exit side, 127.0.0.1).
    bool fInboundOnion;
    // our Tor address has been queued for this peer
    bool fOnionAdvertised;
    // The peer is on the onion side of the node: we reached it over Tor (its
    // address is a .onion) or it reached us through the onion service.
    bool IsOnionPeer() const { return fInboundOnion || addr.IsTor(); }
    // The peer's verack arrived; a later "sendaddrv2" no longer counts.
    bool fVerackRecvd;
    CSemaphoreGrant grantOutbound;
    CCriticalSection cs_filter;
    CBloomFilter* pfilter;
    int nRefCount;
    NodeId id;
protected:

    // Denial-of-service detection/prevention
    // Key is IP address, value is banned-until-time
    static std::map<CSubNet, int64_t> setBanned;
    static CCriticalSection cs_setBanned;

    // Whitelisted ranges. Any node connecting from these is automatically
    // whitelisted (as well as those connecting to whitelisted binds).
    static std::vector<CSubNet> vWhitelistedRange;
    static CCriticalSection cs_vWhitelistedRange;

    // Basic fuzz-testing
    void Fuzz(int nChance); // modifies ssSend

public:
    uint256 hashContinue;
    int nStartingHeight;

    // flood relay
    std::vector<CAddress> vAddrToSend;
    CRollingBloomFilter addrKnown;
    bool fGetAddr;
    // Token bucket for the Tor v3 addresses this peer may add to the onion store
    // without having been asked for them (see ProcessAddrList).
    double dOnionAddrTokens;
    int64_t nOnionAddrTokensTime;

    // inventory based relay
    mruset<CInv> setInventoryKnown;
    std::vector<CInv> vInventoryToSend;
    CCriticalSection cs_inventory;
    std::set<uint256> setAskFor;
    std::multimap<int64_t, CInv> mapAskFor;

    // Bootstrap chunk requests are queued and drained from the SendMessages
    // thread so a slow peer cannot pin the message-handler thread. Both kinds
    // (snapshot data chunks and zk-SNARK parameter chunks) share the same
    // queue, throttle, and per-peer cap; the kind tag selects the right serve
    // function at drain time.
    enum BootstrapChunkKind {
        BOOTSTRAP_CHUNK_SNAPSHOT = 0,
        BOOTSTRAP_CHUNK_PARAMS = 1,
    };
    struct BootstrapChunkQueueItem {
        BootstrapChunkKind kind;
        CBootstrapSnapshotChunkRequest request;
    };
    bool QueueBootstrapChunkRequest(BootstrapChunkKind kind, const CBootstrapSnapshotChunkRequest& request);
    void RequeueBootstrapChunkRequest(BootstrapChunkKind kind, const CBootstrapSnapshotChunkRequest& request);
    bool PopBootstrapChunkRequest(BootstrapChunkKind& kind, CBootstrapSnapshotChunkRequest& request);
    bool fBootstrapManifestSent;
    bool fBootstrapParamManifestSent;

    // Ping time measurement:
    // The pong reply we're expecting, or 0 if no pong expected.
    uint64_t nPingNonceSent;
    // Time (in usec) the last ping was sent, or 0 if no ping was ever sent.
    int64_t nPingUsecStart;
    // Last measured round-trip time.
    int64_t nPingUsecTime;
    // Best measured round-trip time.
    int64_t nMinPingUsecTime;
    // Whether a ping is requested.
    bool fPingQueued;

    std::deque<BootstrapChunkQueueItem> vBootstrapChunkRequests;
    CCriticalSection cs_bootstrap_requests;

    CNode(SOCKET hSocketIn, const CAddress &addrIn, const std::string &addrNameIn = "", bool fInboundIn = false);
    ~CNode();

private:
    // Network usage totals
    static CCriticalSection cs_totalBytesRecv;
    static CCriticalSection cs_totalBytesSent;
    static uint64_t nTotalBytesRecv;
    static uint64_t nTotalBytesSent;

    CNode(const CNode&);
    void operator=(const CNode&);

public:

    NodeId GetId() const {
      return id;
    }

    int GetRefCount()
    {
        assert(nRefCount >= 0);
        return nRefCount;
    }

    // requires LOCK(cs_vRecvMsg)
    unsigned int GetTotalRecvSize()
    {
        unsigned int total = 0;
        BOOST_FOREACH(const CNetMessage &msg, vRecvMsg)
            total += msg.vRecv.size() + 24;
        return total;
    }

    // requires LOCK(cs_vRecvMsg)
    bool ReceiveMsgBytes(const char *pch, unsigned int nBytes);

    // requires LOCK(cs_vRecvMsg)
    void SetRecvVersion(int nVersionIn)
    {
        nRecvVersion = nVersionIn;
        BOOST_FOREACH(CNetMessage &msg, vRecvMsg)
            msg.SetVersion(nVersionIn);
    }

    CNode* AddRef()
    {
        nRefCount++;
        return this;
    }

    void Release()
    {
        nRefCount--;
    }



    void AddAddressKnown(const CAddress& addr)
    {
        addrKnown.insert(addr.GetKey());
    }

    void PushAddress(const CAddress& addr)
    {
        // Known checking here is only to save space from duplicates.
        // SendMessages will filter it again for knowns that were added
        // after addresses were pushed.
        // A v3 onion address cannot be sent in the 16-byte addr field (it
        // would arrive as a placeholder or as "::"), so it is only queued for
        // a peer that negotiated addrv2 (BIP155); every other peer keeps
        // getting exactly the legacy addr stream.
        if (addr.IsValid() && (!addr.IsTorV3() || fSendAddrV2) && !addrKnown.contains(addr.GetKey())) {
            if (vAddrToSend.size() >= MAX_ADDR_TO_SEND) {
                vAddrToSend[insecure_rand() % vAddrToSend.size()] = addr;
            } else {
                vAddrToSend.push_back(addr);
            }
        }
    }


    void AddInventoryKnown(const CInv& inv)
    {
        {
            LOCK(cs_inventory);
            setInventoryKnown.insert(inv);
        }
    }

    void PushInventory(const CInv& inv)
    {
        {
            LOCK(cs_inventory);
            if (!setInventoryKnown.count(inv))
                vInventoryToSend.push_back(inv);
        }
    }

    void AskFor(const CInv& inv);

    // TODO: Document the postcondition of this function.  Is cs_vSend locked?
    void BeginMessage(const char* pszCommand) EXCLUSIVE_LOCK_FUNCTION(cs_vSend);

    // TODO: Document the precondition of this function.  Is cs_vSend locked?
    void AbortMessage() UNLOCK_FUNCTION(cs_vSend);

    // TODO: Document the precondition of this function.  Is cs_vSend locked?
    void EndMessage() UNLOCK_FUNCTION(cs_vSend);

    void PushVersion();


    void PushMessage(const char* pszCommand)
    {
        try
        {
            BeginMessage(pszCommand);
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1>
    void PushMessage(const char* pszCommand, const T1& a1)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    template<typename T1, typename T2, typename T3, typename T4, typename T5, typename T6, typename T7, typename T8, typename T9>
    void PushMessage(const char* pszCommand, const T1& a1, const T2& a2, const T3& a3, const T4& a4, const T5& a5, const T6& a6, const T7& a7, const T8& a8, const T9& a9)
    {
        try
        {
            BeginMessage(pszCommand);
            ssSend << a1 << a2 << a3 << a4 << a5 << a6 << a7 << a8 << a9;
            EndMessage();
        }
        catch (...)
        {
            AbortMessage();
            throw;
        }
    }

    void CloseSocketDisconnect();

    // Denial-of-service detection/prevention
    // The idea is to detect peers that are behaving
    // badly and disconnect/ban them, but do it in a
    // one-coding-mistake-won't-shatter-the-entire-network
    // way.
    // IMPORTANT:  There should be nothing I can give a
    // node that it will forward on that will make that
    // node's peers drop it. If there is, an attacker
    // can isolate a node and/or try to split the network.
    // Dropping a node for sending stuff that is invalid
    // now but might be valid in a later version is also
    // dangerous, because it can cause a network split
    // between nodes running old code and nodes running
    // new code.
    static void ClearBanned(); // needed for unit testing
    static bool IsBanned(CNetAddr ip);
    static bool IsBanned(CSubNet subnet);
    static void Ban(const CNetAddr &ip, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    static void Ban(const CSubNet &subNet, int64_t bantimeoffset = 0, bool sinceUnixEpoch = false);
    static bool Unban(const CNetAddr &ip);
    static bool Unban(const CSubNet &ip);
    static void GetBanned(std::map<CSubNet, int64_t> &banmap);

    void copyStats(CNodeStats &stats);

    static bool IsWhitelistedRange(const CNetAddr &ip);
    static void AddWhitelistedRange(const CSubNet &subnet);

    // Network stats
    static void RecordBytesRecv(uint64_t bytes);
    static void RecordBytesSent(uint64_t bytes);

    static uint64_t GetTotalBytesRecv();
    static uint64_t GetTotalBytesSent();
};



class CTransaction;
void RelayTransaction(const CTransaction& tx);
void RelayTransaction(const CTransaction& tx, const CDataStream& ss);

/** Access to the (IP) address database (peers.dat) */
class CAddrDB
{
private:
    boost::filesystem::path pathAddr;
public:
    CAddrDB();
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
};

/**
 * Persistence of the onion store (onion_peers.dat in the datadir). Its own file
 * and format, because peers.dat entries hold 16 address bytes:
 *   magic(4) | version(1) = 1 | count (compact size) |
 *   count x { addr (addrv2 entry) | source (addrv2 entry) | nLastSuccess (int64) | nAttempts (int32) | tried (uint8) } |
 *   hash256 of everything before
 * A node older than this file never opens it.
 */
class COnionAddrDB
{
private:
    boost::filesystem::path pathOnion;
public:
    COnionAddrDB();
    bool Exists() const;
    bool Write(const CAddrMan& addr);
    bool Read(CAddrMan& addr);
};

#endif // BITCOIN_NET_H
