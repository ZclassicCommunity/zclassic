// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRV2_H
#define BITCOIN_ADDRV2_H

#include "netbase.h"
#include "protocol.h"
#include "serialize.h"

#include <stdint.h>
#include <string.h>
#include <vector>

/**
 * A subset of BIP155 ("addrv2"): the networks IPv4, IPv6 and Tor v3.
 *
 * One entry of an "addrv2" message is
 *   time        uint32, little endian
 *   services    compact size
 *   network id  uint8
 *   address     compact size length, then that many bytes
 *   port        uint16, big endian
 *
 * Network ids this node understands: IPV4 (1, exactly 4 bytes), IPV6 (2,
 * exactly 16 bytes), TORV2 (3, exactly 10 bytes, parsed and then ignored: Tor
 * v2 is gone) and TORV3 (4, exactly 32 bytes). A known network with the wrong
 * length is malformed and fails the whole message, as in Bitcoin Core. An
 * unknown network id (I2P, CJDNS, future ones) is skipped as long as its
 * address is at most MAX_ADDRV2_SIZE bytes.
 */
static const uint8_t ADDRV2_NET_IPV4  = 1;
static const uint8_t ADDRV2_NET_IPV6  = 2;
static const uint8_t ADDRV2_NET_TORV2 = 3;
static const uint8_t ADDRV2_NET_TORV3 = 4;
static const uint8_t ADDRV2_NET_I2P   = 5;
static const uint8_t ADDRV2_NET_CJDNS = 6;

static const unsigned int ADDRV2_SIZE_IPV4  = 4;
static const unsigned int ADDRV2_SIZE_IPV6  = 16;
static const unsigned int ADDRV2_SIZE_TORV2 = 10;
static const unsigned int ADDRV2_SIZE_TORV3 = 32;

/** Largest address field accepted in an addrv2 entry (BIP155). */
static const unsigned int MAX_ADDRV2_SIZE = 512;
/** Most entries in one addrv2 message (BIP155, same as "addr"). */
static const unsigned int MAX_ADDRV2_ENTRIES = 1000;

class CAddressV2
{
public:
    /** The address; meaningful only when fKnown. */
    CAddress addr;
    /** False for an entry of a network we do not use (unknown id, Tor v2,
     *  IPv6 that is really an IPv4 or OnionCat address): it was parsed and
     *  must be skipped. */
    bool fKnown;

    CAddressV2() : fKnown(false) {}
    explicit CAddressV2(const CAddress& addrIn) : addr(addrIn), fKnown(true) {}

    /** Can this address be written as an addrv2 entry? (IPv4, IPv6, Tor v3 only;
     *  an OnionCat Tor v2 address is not.) */
    static bool CanSend(const CAddress& a)
    {
        return a.IsValid() && !(a.IsTor() && !a.IsTorV3());
    }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        uint32_t nTime = addr.nTime;
        s << nTime;
        WriteCompactSize(s, addr.nServices);
        if (addr.IsTorV3()) {
            uint8_t net = ADDRV2_NET_TORV3;
            s << net;
            WriteCompactSize(s, ADDRV2_SIZE_TORV3);
            s.write((const char*)&addr.GetTorV3()[0], ADDRV2_SIZE_TORV3);
        } else if (addr.IsIPv4()) {
            uint8_t net = ADDRV2_NET_IPV4;
            s << net;
            WriteCompactSize(s, ADDRV2_SIZE_IPV4);
            unsigned char b[4];
            for (int i = 0; i < 4; i++)
                b[i] = (unsigned char)addr.GetByte(3 - i);
            s.write((const char*)b, sizeof(b));
        } else {
            uint8_t net = ADDRV2_NET_IPV6;
            s << net;
            WriteCompactSize(s, ADDRV2_SIZE_IPV6);
            unsigned char b[16];
            for (int i = 0; i < 16; i++)
                b[i] = (unsigned char)addr.GetByte(15 - i);
            s.write((const char*)b, sizeof(b));
        }
        unsigned short portN = htons(addr.GetPort());
        s.write((const char*)&portN, sizeof(portN));
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        addr = CAddress();
        fKnown = false;

        uint32_t nTime;
        s >> nTime;
        uint64_t nServices = ReadCompactSize(s);
        uint8_t net;
        s >> net;
        uint64_t len = ReadCompactSize(s);
        if (len > MAX_ADDRV2_SIZE)
            throw std::ios_base::failure("BIP155 address too long");
        std::vector<unsigned char> raw((size_t)len);
        if (len)
            s.read((char*)&raw[0], (size_t)len);
        unsigned short portN;
        s.read((char*)&portN, sizeof(portN));

        CNetAddr ip;
        bool fOk = false;
        switch (net) {
        case ADDRV2_NET_IPV4:
            if (len != ADDRV2_SIZE_IPV4)
                throw std::ios_base::failure("BIP155 IPv4 address with the wrong length");
            ip.SetRaw(NET_IPV4, &raw[0]);
            fOk = true;
            break;
        case ADDRV2_NET_IPV6: {
            if (len != ADDRV2_SIZE_IPV6)
                throw std::ios_base::failure("BIP155 IPv6 address with the wrong length");
            static const unsigned char pchIPv4[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
            static const unsigned char pchOnionCat[6] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};
            // an IPv4 or OnionCat address in IPv6 clothes must use its own network id
            if (memcmp(&raw[0], pchIPv4, sizeof(pchIPv4)) != 0 &&
                memcmp(&raw[0], pchOnionCat, sizeof(pchOnionCat)) != 0) {
                ip.SetRaw(NET_IPV6, &raw[0]);
                fOk = true;
            }
            break;
        }
        case ADDRV2_NET_TORV2:
            if (len != ADDRV2_SIZE_TORV2)
                throw std::ios_base::failure("BIP155 TORV2 address with the wrong length");
            break; // ignored
        case ADDRV2_NET_TORV3:
            if (len != ADDRV2_SIZE_TORV3)
                throw std::ios_base::failure("BIP155 TORV3 address with the wrong length");
            ip.SetTorV3(&raw[0]);
            fOk = true;
            break;
        default:
            break; // unknown network: skipped
        }
        if (!fOk)
            return;
        addr = CAddress(CService(ip, ntohs(portN)), nServices);
        addr.nTime = nTime;
        fKnown = true;
    }
};

/**
 * Read the entries of an "addrv2" message body. The count is checked before
 * any entry is read; more than MAX_ADDRV2_ENTRIES is refused (false, nothing
 * read). Entries of networks we do not use are dropped, so *pnSeen (when
 * given) reports how many entries the message carried.
 */
template <typename Stream>
bool ReadAddrV2List(Stream& s, std::vector<CAddress>& vOut, uint64_t* pnSeen = NULL)
{
    vOut.clear();
    uint64_t n = ReadCompactSize(s);
    if (pnSeen)
        *pnSeen = n;
    if (n > MAX_ADDRV2_ENTRIES)
        return false;
    for (uint64_t i = 0; i < n; i++) {
        CAddressV2 a;
        s >> a;
        if (a.fKnown)
            vOut.push_back(a.addr);
    }
    return true;
}

#endif // BITCOIN_ADDRV2_H
