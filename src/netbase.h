// Copyright (c) 2009-2013 The Bitcoin Core developers
// Copyright (c) 2025 The Zclassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "compat.h"
#include "serialize.h"

#include <stdint.h>
#include <string>
#include <vector>

extern int nConnectTimeout;
extern bool fNameLookup;

/** -timeout default */
static const int DEFAULT_CONNECT_TIMEOUT = 5000;

#ifdef WIN32
// In MSVC, this is defined as a macro, undefine it to prevent a compile and link error
#undef SetPort
#endif

enum Network
{
    NET_UNROUTABLE = 0,
    NET_IPV4,
    NET_IPV6,
    NET_TORV3,      // Tor v3 (BIP155) - unified Tor network type
    NET_I2P,        // I2P (BIP155)
    NET_CJDNS,      // CJDNS (BIP155)
    NET_INTERNAL,   // Internal use only

    NET_MAX
};

/** BIP155 network IDs - private enum for serialization */
enum BIP155Network : uint8_t {
    BIP155_IPV4 = 0x01,
    BIP155_IPV6 = 0x02,
    BIP155_TORV2 = 0x03,  // Deprecated
    BIP155_TORV3 = 0x04,
    BIP155_I2P = 0x05,
    BIP155_CJDNS = 0x06,
};

/** BIP155 address sizes */
static const size_t ADDR_IPV4_SIZE = 4;
static const size_t ADDR_IPV6_SIZE = 16;
static const size_t ADDR_TORV3_SIZE = 32;
static const size_t ADDR_I2P_SIZE = 32;
static const size_t ADDR_CJDNS_SIZE = 16;
static const size_t ADDR_MAX_SIZE = 512;  // Maximum address size for safety
/** IP address (IPv6, or IPv4 using mapped IPv6 range (::FFFF:0:0/96)) */
class CNetAddr
{
    protected:
        unsigned char ip[16]; // in network byte order
        std::vector<unsigned char> torv3_addr; // Full 32-byte v3 onion address
        Network m_net{NET_IPV4}; // BIP155: Network type for variable-length addresses

    public:
        CNetAddr();
        CNetAddr(const struct in_addr& ipv4Addr);
        explicit CNetAddr(const char *pszIp, bool fAllowLookup = false);
        explicit CNetAddr(const std::string &strIp, bool fAllowLookup = false);
        CNetAddr(const CNetAddr& other) : torv3_addr(other.torv3_addr), m_net(other.m_net) {
            memcpy(ip, other.ip, sizeof(ip));
        }

        CNetAddr& operator=(const CNetAddr& other) {
            if (this != &other) {
                memcpy(ip, other.ip, sizeof(ip));
                torv3_addr = other.torv3_addr;
                m_net = other.m_net;
            }
            return *this;
        }
        void Init();
        void SetIP(const CNetAddr& ip);

        /**
         * Set raw IPv4 or IPv6 address (in network byte order)
         * @note Only NET_IPV4 and NET_IPV6 are allowed for network.
         */
        void SetRaw(Network network, const uint8_t *data);

        bool SetSpecial(const std::string &strName); // for Tor addresses
        bool IsIPv4() const;    // IPv4 mapped address (::FFFF:0:0/96, 0.0.0.0/0)
        bool IsIPv6() const;    // IPv6 address (not mapped IPv4, not Tor)
        bool IsRFC1918() const; // IPv4 private networks (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
        bool IsRFC2544() const; // IPv4 inter-network communications (192.18.0.0/15)
        bool IsRFC6598() const; // IPv4 ISP-level NAT (100.64.0.0/10)
        bool IsRFC5737() const; // IPv4 documentation addresses (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
        bool IsRFC3849() const; // IPv6 documentation address (2001:0DB8::/32)
        bool IsRFC3927() const; // IPv4 autoconfig (169.254.0.0/16)
        bool IsRFC3964() const; // IPv6 6to4 tunnelling (2002::/16)
        bool IsRFC4193() const; // IPv6 unique local (FC00::/7)
        bool IsRFC4380() const; // IPv6 Teredo tunnelling (2001::/32)
        bool IsRFC4843() const; // IPv6 ORCHID (2001:10::/28)
        bool IsRFC4862() const; // IPv6 autoconfig (FE80::/64)
        bool IsRFC6052() const; // IPv6 well-known prefix (64:FF9B::/96)
        bool IsRFC6145() const; // IPv6 IPv4-translated address (::FFFF:0:0:0/96)
        bool IsTor() const;
        bool IsTorV3() const;
        bool IsI2P() const;
        bool IsCJDNS() const;
        bool IsLocal() const;
        bool IsRoutable() const;
        bool IsValid() const;
        bool IsMulticast() const;
        enum Network GetNetwork() const;

        /** BIP155: Returns true if this address requires addrv2 format */
        bool IsAddrV2() const { return IsTorV3() || IsI2P() || IsCJDNS(); }

        /** BIP155: Get the BIP155 network ID for this address */
        BIP155Network GetBIP155Network() const;

        /** BIP155: Get the expected address size for a BIP155 network ID */
        static size_t GetBIP155AddrSize(BIP155Network net_id);

        /** BIP155: Set address from BIP155 format */
        bool SetFromBIP155(BIP155Network net_id, const std::vector<uint8_t>& addr_bytes);

        /** BIP155: Get address bytes for serialization */
        std::vector<uint8_t> GetAddrBytes() const;
        std::string ToString() const;
        std::string ToStringIP() const;
        unsigned int GetByte(int n) const;
        uint64_t GetHash() const;
        bool GetInAddr(struct in_addr* pipv4Addr) const;
        std::vector<unsigned char> GetGroup() const;
        int GetReachabilityFrom(const CNetAddr *paddrPartner = NULL) const;

        CNetAddr(const struct in6_addr& pipv6Addr);
        bool GetIn6Addr(struct in6_addr* pipv6Addr) const;

        friend bool operator==(const CNetAddr& a, const CNetAddr& b);
        friend bool operator!=(const CNetAddr& a, const CNetAddr& b);
        friend bool operator<(const CNetAddr& a, const CNetAddr& b);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            if (s.GetType() & SER_ADDRV2) {
                // BIP155 addrv2 format: network_id(1) + addr_len(CompactSize) + addr(variable)
                if (ser_action.ForRead()) {
                    uint8_t net_id;
                    READWRITE(net_id);

                    uint64_t addr_len;
                    READWRITE(COMPACTSIZE(addr_len));

                    if (addr_len > ADDR_MAX_SIZE) {
                        throw std::ios_base::failure("Address too long");
                    }

                    std::vector<uint8_t> addr_bytes(addr_len);
                    if (addr_len > 0) {
                        s.read((char*)addr_bytes.data(), addr_len);
                    }

                    // Convert BIP155 network ID to internal representation
                    if (!SetFromBIP155(static_cast<BIP155Network>(net_id), addr_bytes)) {
                        throw std::ios_base::failure("Invalid address for network");
                    }
                } else {
                    // Writing
                    uint8_t net_id = static_cast<uint8_t>(GetBIP155Network());
                    READWRITE(net_id);

                    std::vector<uint8_t> addr_bytes = GetAddrBytes();
                    uint64_t addr_len = addr_bytes.size();
                    READWRITE(COMPACTSIZE(addr_len));

                    if (addr_len > 0) {
                        s.write((const char*)addr_bytes.data(), addr_len);
                    }
                }
            } else {
                // Legacy format: 16-byte IPv6-mapped address
                READWRITE(FLATDATA(ip));
                // After reading legacy format, detect and set m_net based on IP content
                if (ser_action.ForRead()) {
                    if (IsIPv4()) {
                        m_net = NET_IPV4;
                    } else if (IsTor()) {
                        m_net = NET_TORV3;
                    } else {
                        m_net = NET_IPV6;
                    }
                }
            }
        }

        friend class CSubNet;
};

class CSubNet
{
    protected:
        /// Network (base) address
        CNetAddr network;
        /// Netmask, in network byte order
        uint8_t netmask[16];
        /// Is this value valid? (only used to signal parse errors)
        bool valid;

    public:
        CSubNet();
        explicit CSubNet(const std::string &strSubnet, bool fAllowLookup = false);

        bool Match(const CNetAddr &addr) const;

        std::string ToString() const;
        bool IsValid() const;

        friend bool operator==(const CSubNet& a, const CSubNet& b);
        friend bool operator!=(const CSubNet& a, const CSubNet& b);
        friend bool operator<(const CSubNet& a, const CSubNet& b);
};

/** A combination of a network address (CNetAddr) and a (TCP) port */
class CService : public CNetAddr
{
    protected:
        unsigned short port; // host order

    public:
        CService();
        CService(const CNetAddr& ip, unsigned short port);
        CService(const struct in_addr& ipv4Addr, unsigned short port);
        CService(const struct sockaddr_in& addr);
        explicit CService(const char *pszIpPort, int portDefault, bool fAllowLookup = false);
        explicit CService(const char *pszIpPort, bool fAllowLookup = false);
        explicit CService(const std::string& strIpPort, int portDefault, bool fAllowLookup = false);
        explicit CService(const std::string& strIpPort, bool fAllowLookup = false);
        void Init();
        void SetPort(unsigned short portIn);
        unsigned short GetPort() const;
        bool GetSockAddr(struct sockaddr* paddr, socklen_t *addrlen) const;
        bool SetSockAddr(const struct sockaddr* paddr);
        friend bool operator==(const CService& a, const CService& b);
        friend bool operator!=(const CService& a, const CService& b);
        friend bool operator<(const CService& a, const CService& b);
        std::vector<unsigned char> GetKey() const;
        std::string ToString() const;
        std::string ToStringPort() const;
        std::string ToStringIPPort() const;

        CService(const struct in6_addr& ipv6Addr, unsigned short port);
        CService(const struct sockaddr_in6& addr);

        ADD_SERIALIZE_METHODS;

        template <typename Stream, typename Operation>
        inline void SerializationOp(Stream& s, Operation ser_action) {
            if (s.GetType() & SER_ADDRV2) {
                // BIP155 addrv2 format: serialize CNetAddr in addrv2 format + port
                READWRITE(*(CNetAddr*)this);
                // Port is serialized in big-endian (network byte order)
                unsigned short portN = htons(port);
                READWRITE(FLATDATA(portN));
                if (ser_action.ForRead())
                    port = ntohs(portN);
            } else {
                // Legacy format: 16-byte IPv6-mapped address + port
                READWRITE(FLATDATA(ip));
                unsigned short portN = htons(port);
                READWRITE(FLATDATA(portN));
                if (ser_action.ForRead())
                     port = ntohs(portN);
            }
        }
};

class proxyType
{
public:
    proxyType(): randomize_credentials(false) {}
    proxyType(const CService &proxy, bool randomize_credentials=false): proxy(proxy), randomize_credentials(randomize_credentials) {}

    bool IsValid() const { return proxy.IsValid(); }

    CService proxy;
    bool randomize_credentials;
};

enum Network ParseNetwork(std::string net);
std::string GetNetworkName(enum Network net);
void SplitHostPort(std::string in, int &portOut, std::string &hostOut);
bool SetProxy(enum Network net, const proxyType &addrProxy);
bool GetProxy(enum Network net, proxyType &proxyInfoOut);
bool IsProxy(const CNetAddr &addr);
bool SetNameProxy(const proxyType &addrProxy);
bool HaveNameProxy();
bool LookupHost(const char *pszName, std::vector<CNetAddr>& vIP, unsigned int nMaxSolutions = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, CService& addr, int portDefault = 0, bool fAllowLookup = true);
bool Lookup(const char *pszName, std::vector<CService>& vAddr, int portDefault = 0, bool fAllowLookup = true, unsigned int nMaxSolutions = 0);
bool LookupNumeric(const char *pszName, CService& addr, int portDefault = 0);
bool ConnectSocket(const CService &addr, SOCKET& hSocketRet, int nTimeout, bool *outProxyConnectionFailed = 0);
bool ConnectSocketByName(CService &addr, SOCKET& hSocketRet, const char *pszDest, int portDefault, int nTimeout, bool *outProxyConnectionFailed = 0);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET& hSocket);
/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(SOCKET& hSocket, bool fNonBlocking);
/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);

#endif // BITCOIN_NETBASE_H
