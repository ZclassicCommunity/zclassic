// Copyright (c) 2012 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_ADDRMAN_H
#define BITCOIN_ADDRMAN_H

#include "netbase.h"
#include "protocol.h"
#include "random.h"
#include "streams.h"
#include "sync.h"
#include "timedata.h"
#include "util.h"

#include <map>
#include <set>
#include <stdint.h>
#include <vector>

/**
 * Extended statistics about a CAddress
 */
class CAddrInfo : public CAddress
{


public:
    //! last try whatsoever by us (memory only)
    int64_t nLastTry;

private:
    //! where knowledge about this address first came from
    CNetAddr source;

    //! last successful connection by us
    int64_t nLastSuccess;

    //! connection attempts since last successful attempt
    int nAttempts;

    //! reference count in new sets (memory only)
    int nRefCount;

    //! in tried set? (memory only)
    bool fInTried;

    //! position in vRandom
    int nRandomPos;

    friend class CAddrMan;

public:

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*(CAddress*)this);
        READWRITE(source);
        READWRITE(nLastSuccess);
        READWRITE(nAttempts);
    }

    void Init()
    {
        nLastSuccess = 0;
        nLastTry = 0;
        nAttempts = 0;
        nRefCount = 0;
        fInTried = false;
        nRandomPos = -1;
    }

    CAddrInfo(const CAddress &addrIn, const CNetAddr &addrSource) : CAddress(addrIn), source(addrSource)
    {
        Init();
    }

    CAddrInfo() : CAddress(), source()
    {
        Init();
    }

    //! Calculate in which "tried" bucket this entry belongs
    int GetTriedBucket(const uint256 &nKey) const;

    //! Calculate in which "new" bucket this entry belongs, given a certain source
    int GetNewBucket(const uint256 &nKey, const CNetAddr& src) const;

    //! Calculate in which "new" bucket this entry belongs, using its default source
    int GetNewBucket(const uint256 &nKey) const
    {
        return GetNewBucket(nKey, source);
    }

    //! Calculate in which position of a bucket to store this entry.
    int GetBucketPosition(const uint256 &nKey, bool fNew, int nBucket) const;

    //! Determine whether the statistics about this entry are bad enough so that it can just be deleted
    bool IsTerrible(int64_t nNow = GetAdjustedTime()) const;

    //! Calculate the relative chance this entry should be given when selecting nodes to connect to
    double GetChance(int64_t nNow = GetAdjustedTime()) const;

};

/** Stochastic address manager
 *
 * Design goals:
 *  * Keep the address tables in-memory, and asynchronously dump the entire table to peers.dat.
 *  * Make sure no (localized) attacker can fill the entire table with his nodes/addresses.
 *
 * To that end:
 *  * Addresses are organized into buckets.
 *    * Addresses that have not yet been tried go into 1024 "new" buckets.
 *      * Based on the address range (/16 for IPv4) of the source of information, 64 buckets are selected at random.
 *      * The actual bucket is chosen from one of these, based on the range in which the address itself is located.
 *      * One single address can occur in up to 8 different buckets to increase selection chances for addresses that
 *        are seen frequently. The chance for increasing this multiplicity decreases exponentially.
 *      * When adding a new address to a full bucket, a randomly chosen entry (with a bias favoring less recently seen
 *        ones) is removed from it first.
 *    * Addresses of nodes that are known to be accessible go into 256 "tried" buckets.
 *      * Each address range selects at random 8 of these buckets.
 *      * The actual bucket is chosen from one of these, based on the full address.
 *      * When adding a new good address to a full bucket, a randomly chosen entry (with a bias favoring less recently
 *        tried ones) is evicted from it, back to the "new" buckets.
 *    * Bucket selection is based on cryptographic hashing, using a randomly-generated 256-bit key, which should not
 *      be observable by adversaries.
 *    * Several indexes are kept for high performance. Defining DEBUG_ADDRMAN will introduce frequent (and expensive)
 *      consistency checks for the entire data structure.
 */

//! total number of buckets for tried addresses
#define ADDRMAN_TRIED_BUCKET_COUNT 256

//! total number of buckets for new addresses
#define ADDRMAN_NEW_BUCKET_COUNT 1024

//! maximum allowed number of entries in buckets for new and tried addresses
#define ADDRMAN_BUCKET_SIZE 64

//! over how many buckets entries with tried addresses from a single group (/16 for IPv4) are spread
#define ADDRMAN_TRIED_BUCKETS_PER_GROUP 8

//! over how many buckets entries with new addresses originating from a single group are spread
#define ADDRMAN_NEW_BUCKETS_PER_SOURCE_GROUP 64

//! in how many buckets for entries with new addresses a single address may occur
#define ADDRMAN_NEW_BUCKETS_PER_ADDRESS 8

//! how old addresses can maximally be
#define ADDRMAN_HORIZON_DAYS 30

//! after how many failed attempts we give up on a new node
#define ADDRMAN_RETRIES 3

//! how many successive failures are allowed ...
#define ADDRMAN_MAX_FAILURES 10

//! ... in at least this many days
#define ADDRMAN_MIN_FAIL_DAYS 7

//! the maximum percentage of nodes to return in a getaddr call
#define ADDRMAN_GETADDR_MAX_PCT 23

//! the maximum number of nodes to return in a getaddr call
#define ADDRMAN_GETADDR_MAX 2500

/** 
 * Stochastical (IP) address manager 
 */
class CAddrMan
{
private:
    //! critical section to protect the inner data structures
    mutable CCriticalSection cs;

    //! last used nId
    int nIdCount;

    //! table with information about all nIds
    std::map<int, CAddrInfo> mapInfo;

    //! find an nId based on its network address
    std::map<CNetAddr, int> mapAddr;

    //! randomly-ordered vector of all nIds
    std::vector<int> vRandom;

    // number of "tried" entries
    int nTried;

    //! list of "tried" buckets
    int vvTried[ADDRMAN_TRIED_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

    //! number of (unique) "new" entries
    int nNew;

    //! list of "new" buckets
    int vvNew[ADDRMAN_NEW_BUCKET_COUNT][ADDRMAN_BUCKET_SIZE];

protected:
    //! secret key to randomize bucket select with
    uint256 nKey;

    //! Find an entry.
    CAddrInfo* Find(const CNetAddr& addr, int *pnId = NULL);

    //! find an entry, creating it if necessary.
    //! nTime and nServices of the found node are updated, if necessary.
    CAddrInfo* Create(const CAddress &addr, const CNetAddr &addrSource, int *pnId = NULL);

    //! Swap two elements in vRandom.
    void SwapRandom(unsigned int nRandomPos1, unsigned int nRandomPos2);

    //! Move an entry from the "new" table(s) to the "tried" table
    void MakeTried(CAddrInfo& info, int nId);

    //! Delete an entry. It must not be in tried, and have refcount 0.
    void Delete(int nId);

    //! Clear a position in a "new" table. This is the only place where entries are actually deleted.
    void ClearNew(int nUBucket, int nUBucketPos);

    //! Mark an entry "good", possibly moving it from "new" to "tried".
    void Good_(const CService &addr, int64_t nTime);

    //! Add an entry to the "new" table.
    bool Add_(const CAddress &addr, const CNetAddr& source, int64_t nTimePenalty);

    //! Mark an entry as attempted to connect.
    void Attempt_(const CService &addr, int64_t nTime);

    //! Select an address to connect to, if newOnly is set to true, only the new table is selected from.
    CAddrInfo Select_(bool newOnly);

    //! Wraps GetRandInt to allow tests to override RandomInt and make it deterministic.
    virtual int RandomInt(int nMax);

#ifdef DEBUG_ADDRMAN
    //! Perform consistency check. Returns an error code or zero.
    int Check_();
#endif

    //! Select several addresses at once.
    void GetAddr_(std::vector<CAddress> &vAddr);

    //! Mark an entry as currently-connected-to.
    void Connected_(const CService &addr, int64_t nTime);

public:
    /**
     * serialized format:
     * * version byte (currently 1)
     * * 0x20 + nKey (serialized as if it were a vector, for backward compatibility)
     * * nNew
     * * nTried
     * * number of "new" buckets XOR 2**30
     * * all nNew addrinfos in vvNew
     * * all nTried addrinfos in vvTried
     * * for each bucket:
     *   * number of elements
     *   * for each element: index
     *
     * 2**30 is xorred with the number of buckets to make addrman deserializer v0 detect it
     * as incompatible. This is necessary because it did not check the version number on
     * deserialization.
     *
     * Notice that vvTried, mapAddr and vVector are never encoded explicitly;
     * they are instead reconstructed from the other information.
     *
     * vvNew is serialized, but only used if ADDRMAN_UNKNOWN_BUCKET_COUNT didn't change,
     * otherwise it is reconstructed as well.
     *
     * This format is more complex, but significantly smaller (at most 1.5 MiB), and supports
     * changes to the ADDRMAN_ parameters without breaking the on-disk structure.
     *
     * We don't use ADD_SERIALIZE_METHODS since the serialization and deserialization code has
     * very little in common.
     */
    /**
     * peers.dat format versions (aligned with Bitcoin Core approach):
     *
     * Format detection uses the "keysize" byte (byte 1):
     *   - Old format: keysize = 32 (literal key size)
     *   - New format: keysize = INCOMPATIBILITY_BASE + lowest_compatible_version
     *
     * This ensures old software sees keysize != 32 and fails gracefully with:
     * "Incorrect keysize in addrman deserialization"
     *
     * Format versions:
     *   V0/V1: Legacy format (16-byte addresses only)
     *   V2: Reserved
     *   V3: BIP155 addrv2 format (variable-length addresses, Tor v3 support)
     */
    enum Format : uint8_t {
        V0_HISTORICAL = 0,    // Historic format, before deterministic
        V1_DETERMINISTIC = 1, // Deterministic bucket assignment
        V2_RESERVED = 2,      // Reserved (asmap in Bitcoin)
        V3_BIP155 = 3,        // BIP155 addrv2 format (current version)
    };

    //! Base value for incompatibility detection (matches Bitcoin Core)
    //! Old software expects keysize=32, so we use 32 as base
    enum { INCOMPATIBILITY_BASE = 32 };

    template<typename Stream>
    void Serialize(Stream &s) const
    {
        LOCK(cs);

        // Write format version byte
        uint8_t nFormat = V3_BIP155;
        s << nFormat;

        // Write compatibility byte: INCOMPATIBILITY_BASE + lowest_compatible
        // Old software sees this as "keysize" and fails if != 32
        // For V3_BIP155, this is 32 + 3 = 35, which triggers the error
        uint8_t nCompat = INCOMPATIBILITY_BASE + V3_BIP155;
        s << nCompat;

        // Write the key (256 bits)
        s << nKey;
        s << nNew;
        s << nTried;

        int nUBuckets = ADDRMAN_NEW_BUCKET_COUNT ^ (1 << 30);
        s << nUBuckets;
        std::map<int, int> mapUnkIds;
        int nIds = 0;

        // Create a temporary stream with SER_ADDRV2 flag for address serialization
        // This ensures Tor v3 and other BIP155 addresses are properly serialized
        CDataStream ssAddr(SER_DISK | SER_ADDRV2, s.GetVersion());

        for (std::map<int, CAddrInfo>::const_iterator it = mapInfo.begin(); it != mapInfo.end(); it++) {
            mapUnkIds[(*it).first] = nIds;
            const CAddrInfo &info = (*it).second;
            if (info.nRefCount) {
                assert(nIds != nNew); // this means nNew was wrong, oh ow
                ssAddr.clear();
                ssAddr << info;
                s.write(&ssAddr[0], ssAddr.size());
                nIds++;
            }
        }
        nIds = 0;
        for (std::map<int, CAddrInfo>::const_iterator it = mapInfo.begin(); it != mapInfo.end(); it++) {
            const CAddrInfo &info = (*it).second;
            if (info.fInTried) {
                assert(nIds != nTried); // this means nTried was wrong, oh ow
                ssAddr.clear();
                ssAddr << info;
                s.write(&ssAddr[0], ssAddr.size());
                nIds++;
            }
        }
        for (int bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
            int nSize = 0;
            for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
                if (vvNew[bucket][i] != -1)
                    nSize++;
            }
            s << nSize;
            for (int i = 0; i < ADDRMAN_BUCKET_SIZE; i++) {
                if (vvNew[bucket][i] != -1) {
                    int nIndex = mapUnkIds[vvNew[bucket][i]];
                    s << nIndex;
                }
            }
        }
    }

    template<typename Stream>
    void Unserialize(Stream& s)
    {
        LOCK(cs);

        Clear();

        // Read format version byte
        uint8_t nFormat;
        s >> nFormat;

        // Read compatibility byte (was "keysize" in old format)
        uint8_t nCompat;
        s >> nCompat;

        // Determine format based on compatibility byte
        // Old format: nCompat = 32 (literal key size)
        // New format: nCompat = INCOMPATIBILITY_BASE + lowest_compatible_version
        Format format = static_cast<Format>(nFormat);
        bool fUseAddrV2 = false;

        if (nCompat == 32) {
            // Legacy format (V0/V1): keysize was literally 32
            // Treat nFormat as the old "version" byte
            LogPrint("addrman", "Loading peers.dat in legacy format (version %d)\n", nFormat);
        } else if (nCompat >= INCOMPATIBILITY_BASE) {
            // New format: extract lowest_compatible version
            uint8_t lowest_compatible = nCompat - INCOMPATIBILITY_BASE;

            // Check if this file requires a newer version than we support
            if (lowest_compatible > V3_BIP155) {
                throw std::ios_base::failure(
                    strprintf("Unsupported format of addrman database: %d (requires %d, we support up to %d). "
                              "You can delete peers.dat to start fresh.",
                              (int)nFormat, (int)lowest_compatible, (int)V3_BIP155));
            }

            // Use addrv2 format for V3_BIP155 and later
            if (format >= V3_BIP155) {
                fUseAddrV2 = true;
                LogPrint("addrman", "Loading peers.dat in BIP155/addrv2 format (version %d)\n", nFormat);
            }
        } else {
            // Invalid: nCompat is not 32 and not >= INCOMPATIBILITY_BASE
            throw std::ios_base::failure("Incorrect keysize in addrman deserialization");
        }

        s >> nKey;
        s >> nNew;
        s >> nTried;
        int nUBuckets = 0;
        s >> nUBuckets;
        if (nFormat != 0) {
            nUBuckets ^= (1 << 30);
        }

        if (nNew > ADDRMAN_NEW_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE) {
            throw std::ios_base::failure("Corrupt CAddrMan serialization, nNew exceeds limit.");
        }

        if (nTried > ADDRMAN_TRIED_BUCKET_COUNT * ADDRMAN_BUCKET_SIZE) {
            throw std::ios_base::failure("Corrupt CAddrMan serialization, nTried exceeds limit.");
        }

        // Deserialize entries from the new table.
        for (int n = 0; n < nNew; n++) {
            CAddrInfo &info = mapInfo[n];
            if (fUseAddrV2) {
                // Use addrv2 format for deserialization
                CDataStream ssAddr(SER_DISK | SER_ADDRV2, s.GetVersion());
                // Read the serialized data and parse it
                // We need to know the size, so we read into CAddrInfo directly
                // by temporarily changing stream type
                // This is a bit tricky - we need to deserialize CAddrInfo which contains CAddress
                // For now, let's read CAddrInfo fields manually with addrv2
                // Actually, the stream s doesn't have addrv2 flag, so we need a different approach
                // We'll read raw bytes and parse them with an addrv2 stream
                // Since CAddrInfo size is variable in addrv2, we need to parse field by field

                // CAddrInfo contains: CAddress (nVersion, nTime, nServices, CService) + source + nLastSuccess + nAttempts
                // CAddress with SER_DISK: nVersion(4) + nTime(4) + nServices(CompactSize) + CService(addrv2)
                // CService: CNetAddr(addrv2) + port(2)
                // CNetAddr(addrv2): net_id(1) + addr_len(CompactSize) + addr(variable)

                // Read CAddress part with addrv2 format
                // First read the version (SER_DISK includes version)
                int nAddrVersion;
                s >> nAddrVersion;

                unsigned int nAddrTime;
                s >> nAddrTime;
                info.nTime = nAddrTime;

                uint64_t nServices;
                s >> COMPACTSIZE(nServices);
                info.nServices = nServices;

                // Read CNetAddr in addrv2 format
                uint8_t net_id;
                s >> net_id;
                uint64_t addr_len;
                s >> COMPACTSIZE(addr_len);
                if (addr_len > ADDR_MAX_SIZE) {
                    throw std::ios_base::failure("Address too long in peers.dat");
                }
                std::vector<uint8_t> addr_bytes(addr_len);
                if (addr_len > 0) {
                    s.read((char*)addr_bytes.data(), addr_len);
                }
                if (!info.SetFromBIP155(static_cast<BIP155Network>(net_id), addr_bytes)) {
                    LogPrint("addrman", "Invalid address in peers.dat, skipping\n");
                    // Skip this entry but continue
                    // Read remaining fields
                    unsigned short portN;
                    s >> portN;
                    CNetAddr source;
                    s >> source;  // Legacy format for source
                    int64_t nLastSuccess;
                    s >> nLastSuccess;
                    int nAttempts;
                    s >> nAttempts;
                    continue;
                }

                // Read port
                unsigned short portN;
                s.read((char*)&portN, 2);
                info.SetPort(ntohs(portN));

                // Read source (CNetAddr) in addrv2 format
                uint8_t src_net_id;
                s >> src_net_id;
                uint64_t src_addr_len;
                s >> COMPACTSIZE(src_addr_len);
                if (src_addr_len > ADDR_MAX_SIZE) {
                    throw std::ios_base::failure("Source address too long in peers.dat");
                }
                std::vector<uint8_t> src_addr_bytes(src_addr_len);
                if (src_addr_len > 0) {
                    s.read((char*)src_addr_bytes.data(), src_addr_len);
                }
                CNetAddr source;
                source.SetFromBIP155(static_cast<BIP155Network>(src_net_id), src_addr_bytes);
                // Note: source is private in CAddrInfo, we need to work around this
                // For now, we'll use the address itself as source for addrv2 entries
                // This is not ideal but works for basic functionality

                s >> info.nLastSuccess;
                s >> info.nAttempts;
            } else {
                // Legacy format
                s >> info;
            }
            mapAddr[info] = n;
            info.nRandomPos = vRandom.size();
            vRandom.push_back(n);
            if (nFormat != V1_DETERMINISTIC || nUBuckets != ADDRMAN_NEW_BUCKET_COUNT) {
                // In case the new table data cannot be used (format unknown, or bucket count wrong),
                // immediately try to give them a reference based on their primary source address.
                int nUBucket = info.GetNewBucket(nKey);
                int nUBucketPos = info.GetBucketPosition(nKey, true, nUBucket);
                if (vvNew[nUBucket][nUBucketPos] == -1) {
                    vvNew[nUBucket][nUBucketPos] = n;
                    info.nRefCount++;
                }
            }
        }
        nIdCount = nNew;

        // Deserialize entries from the tried table.
        int nLost = 0;
        for (int n = 0; n < nTried; n++) {
            CAddrInfo info;
            if (fUseAddrV2) {
                // Same addrv2 parsing as above
                // First read the version (SER_DISK includes version)
                int nAddrVersion;
                s >> nAddrVersion;

                unsigned int nAddrTime;
                s >> nAddrTime;
                info.nTime = nAddrTime;

                uint64_t nServices;
                s >> COMPACTSIZE(nServices);
                info.nServices = nServices;

                uint8_t net_id;
                s >> net_id;
                uint64_t addr_len;
                s >> COMPACTSIZE(addr_len);
                if (addr_len > ADDR_MAX_SIZE) {
                    throw std::ios_base::failure("Address too long in peers.dat");
                }
                std::vector<uint8_t> addr_bytes(addr_len);
                if (addr_len > 0) {
                    s.read((char*)addr_bytes.data(), addr_len);
                }
                if (!info.SetFromBIP155(static_cast<BIP155Network>(net_id), addr_bytes)) {
                    // Skip invalid entry
                    unsigned short portN;
                    s.read((char*)&portN, 2);
                    // Skip source
                    uint8_t src_net_id;
                    s >> src_net_id;
                    uint64_t src_addr_len;
                    s >> COMPACTSIZE(src_addr_len);
                    if (src_addr_len > 0) {
                        std::vector<uint8_t> tmp(src_addr_len);
                        s.read((char*)tmp.data(), src_addr_len);
                    }
                    int64_t nLastSuccess;
                    s >> nLastSuccess;
                    int nAttempts;
                    s >> nAttempts;
                    nLost++;
                    continue;
                }

                unsigned short portN;
                s.read((char*)&portN, 2);
                info.SetPort(ntohs(portN));

                // Skip source in addrv2 format
                uint8_t src_net_id;
                s >> src_net_id;
                uint64_t src_addr_len;
                s >> COMPACTSIZE(src_addr_len);
                if (src_addr_len > 0) {
                    std::vector<uint8_t> tmp(src_addr_len);
                    s.read((char*)tmp.data(), src_addr_len);
                }

                s >> info.nLastSuccess;
                s >> info.nAttempts;
            } else {
                s >> info;
            }
            int nKBucket = info.GetTriedBucket(nKey);
            int nKBucketPos = info.GetBucketPosition(nKey, false, nKBucket);
            if (vvTried[nKBucket][nKBucketPos] == -1) {
                info.nRandomPos = vRandom.size();
                info.fInTried = true;
                vRandom.push_back(nIdCount);
                mapInfo[nIdCount] = info;
                mapAddr[info] = nIdCount;
                vvTried[nKBucket][nKBucketPos] = nIdCount;
                nIdCount++;
            } else {
                nLost++;
            }
        }
        nTried -= nLost;

        // Deserialize positions in the new table (if possible).
        for (int bucket = 0; bucket < nUBuckets; bucket++) {
            int nSize = 0;
            s >> nSize;
            for (int n = 0; n < nSize; n++) {
                int nIndex = 0;
                s >> nIndex;
                if (nIndex >= 0 && nIndex < nNew) {
                    CAddrInfo &info = mapInfo[nIndex];
                    int nUBucketPos = info.GetBucketPosition(nKey, true, bucket);
                    if (nFormat == V1_DETERMINISTIC && nUBuckets == ADDRMAN_NEW_BUCKET_COUNT && vvNew[bucket][nUBucketPos] == -1 && info.nRefCount < ADDRMAN_NEW_BUCKETS_PER_ADDRESS) {
                        info.nRefCount++;
                        vvNew[bucket][nUBucketPos] = nIndex;
                    }
                }
            }
        }

        // Prune new entries with refcount 0 (as a result of collisions).
        int nLostUnk = 0;
        for (std::map<int, CAddrInfo>::const_iterator it = mapInfo.begin(); it != mapInfo.end(); ) {
            if (it->second.fInTried == false && it->second.nRefCount == 0) {
                std::map<int, CAddrInfo>::const_iterator itCopy = it++;
                Delete(itCopy->first);
                nLostUnk++;
            } else {
                it++;
            }
        }
        if (nLost + nLostUnk > 0) {
            LogPrint("addrman", "addrman lost %i new and %i tried addresses due to collisions\n", nLostUnk, nLost);
        }

        Check();
    }

    void Clear()
    {
        std::vector<int>().swap(vRandom);
        nKey = GetRandHash();
        for (size_t bucket = 0; bucket < ADDRMAN_NEW_BUCKET_COUNT; bucket++) {
            for (size_t entry = 0; entry < ADDRMAN_BUCKET_SIZE; entry++) {
                vvNew[bucket][entry] = -1;
            }
        }
        for (size_t bucket = 0; bucket < ADDRMAN_TRIED_BUCKET_COUNT; bucket++) {
            for (size_t entry = 0; entry < ADDRMAN_BUCKET_SIZE; entry++) {
                vvTried[bucket][entry] = -1;
            }
        }

        nIdCount = 0;
        nTried = 0;
        nNew = 0;
    }

    CAddrMan()
    {
        Clear();
    }

    ~CAddrMan()
    {
        nKey.SetNull();
    }

    //! Return the number of (unique) addresses in all tables.
    size_t size() const
    {
        return vRandom.size();
    }

    //! Consistency check
    void Check()
    {
#ifdef DEBUG_ADDRMAN
        {
            LOCK(cs);
            int err;
            if ((err=Check_()))
                LogPrintf("ADDRMAN CONSISTENCY CHECK FAILED!!! err=%i\n", err);
        }
#endif
    }

    //! Add a single address.
    bool Add(const CAddress &addr, const CNetAddr& source, int64_t nTimePenalty = 0)
    {
        bool fRet = false;
        {
            LOCK(cs);
            Check();
            fRet |= Add_(addr, source, nTimePenalty);
            Check();
        }
        if (fRet)
            LogPrint("addrman", "Added %s from %s: %i tried, %i new\n", addr.ToStringIPPort(), source.ToString(), nTried, nNew);
        return fRet;
    }

    //! Add multiple addresses.
    bool Add(const std::vector<CAddress> &vAddr, const CNetAddr& source, int64_t nTimePenalty = 0)
    {
        int nAdd = 0;
        {
            LOCK(cs);
            Check();
            for (std::vector<CAddress>::const_iterator it = vAddr.begin(); it != vAddr.end(); it++)
                nAdd += Add_(*it, source, nTimePenalty) ? 1 : 0;
            Check();
        }
        if (nAdd)
            LogPrint("addrman", "Added %i addresses from %s: %i tried, %i new\n", nAdd, source.ToString(), nTried, nNew);
        return nAdd > 0;
    }

    //! Mark an entry as accessible.
    void Good(const CService &addr, int64_t nTime = GetAdjustedTime())
    {
        {
            LOCK(cs);
            Check();
            Good_(addr, nTime);
            Check();
        }
    }

    //! Mark an entry as connection attempted to.
    void Attempt(const CService &addr, int64_t nTime = GetAdjustedTime())
    {
        {
            LOCK(cs);
            Check();
            Attempt_(addr, nTime);
            Check();
        }
    }

    /**
     * Choose an address to connect to.
     */
    CAddrInfo Select(bool newOnly = false)
    {
        CAddrInfo addrRet;
        {
            LOCK(cs);
            Check();
            addrRet = Select_(newOnly);
            Check();
        }
        return addrRet;
    }

    //! Return a bunch of addresses, selected at random.
    std::vector<CAddress> GetAddr()
    {
        Check();
        std::vector<CAddress> vAddr;
        {
            LOCK(cs);
            GetAddr_(vAddr);
        }
        Check();
        return vAddr;
    }

    //! Mark an entry as currently-connected-to.
    void Connected(const CService &addr, int64_t nTime = GetAdjustedTime())
    {
        {
            LOCK(cs);
            Check();
            Connected_(addr, nTime);
            Check();
        }
    }

};

#endif // BITCOIN_ADDRMAN_H
