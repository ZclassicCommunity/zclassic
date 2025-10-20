// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include "coins.h"
#include "dbwrapper.h"
#include "amount.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

class CBlockFileInfo;
class CBlockIndex;
struct CDiskTxPos;
class uint256;

// Address index structures
struct CAddressIndexKey {
    uint160 hashBytes;
    unsigned int type;
    uint256 txhash;
    size_t index;
    bool spending;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hashBytes);
        READWRITE(type);
        READWRITE(txhash);
        READWRITE(index);
        READWRITE(spending);
    }

    CAddressIndexKey(uint160 addressHash, unsigned int addressType, uint256 txid, size_t outputIndex, bool isSpending) {
        hashBytes = addressHash;
        type = addressType;
        txhash = txid;
        index = outputIndex;
        spending = isSpending;
    }

    CAddressIndexKey() {
        SetNull();
    }

    void SetNull() {
        hashBytes.SetNull();
        type = 0;
        txhash.SetNull();
        index = 0;
        spending = false;
    }
};

struct CAddressIndexIteratorKey {
    uint160 hashBytes;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hashBytes);
    }

    CAddressIndexIteratorKey(uint160 addressHash) {
        hashBytes = addressHash;
    }

    CAddressIndexIteratorKey() {
        SetNull();
    }

    void SetNull() {
        hashBytes.SetNull();
    }
};

struct CAddressUnspentKey {
    uint160 hashBytes;
    unsigned int type;
    uint256 txhash;
    size_t index;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hashBytes);
        READWRITE(type);
        READWRITE(txhash);
        READWRITE(index);
    }

    CAddressUnspentKey(uint160 addressHash, unsigned int addressType, uint256 txid, size_t outputIndex) {
        hashBytes = addressHash;
        type = addressType;
        txhash = txid;
        index = outputIndex;
    }

    CAddressUnspentKey() {
        SetNull();
    }

    void SetNull() {
        hashBytes.SetNull();
        type = 0;
        txhash.SetNull();
        index = 0;
    }
};

struct CAddressUnspentValue {
    CAmount satoshis;
    CScript script;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(satoshis);
        READWRITE(script);
    }

    CAddressUnspentValue(CAmount sats, CScript scriptPubKey) {
        satoshis = sats;
        script = scriptPubKey;
    }

    CAddressUnspentValue() {
        SetNull();
    }

    void SetNull() {
        satoshis = 0;
        script.clear();
    }
};

//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 450;
//! max. -dbcache (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 16384 : 1024;
//! min. -dbcache in (MiB)
static const int64_t nMinDbCache = 4;

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB : public CCoinsView
{
protected:
    CDBWrapper db;
    CCoinsViewDB(std::string dbName, size_t nCacheSize, bool fMemory = false, bool fWipe = false);
public:
    CCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    // Accessor for database (needed for UTXO scanning)
    CDBWrapper& GetDB() { return db; }

    bool GetSproutAnchorAt(const uint256 &rt, SproutMerkleTree &tree) const;
    bool GetSaplingAnchorAt(const uint256 &rt, SaplingMerkleTree &tree) const;
    bool GetNullifier(const uint256 &nf, ShieldedType type) const;
    bool GetCoins(const uint256 &txid, CCoins &coins) const;
    bool HaveCoins(const uint256 &txid) const;
    uint256 GetBestBlock() const;
    uint256 GetBestAnchor(ShieldedType type) const;
    bool BatchWrite(CCoinsMap &mapCoins,
                    const uint256 &hashBlock,
                    const uint256 &hashSproutAnchor,
                    const uint256 &hashSaplingAnchor,
                    CAnchorsSproutMap &mapSproutAnchors,
                    CAnchorsSaplingMap &mapSaplingAnchors,
                    CNullifiersMap &mapSproutNullifiers,
                    CNullifiersMap &mapSaplingNullifiers);
    bool GetStats(CCoinsStats &stats) const;
};

/** Access to the block database (blocks/index/) */
class CBlockTreeDB : public CDBWrapper
{
public:
    CBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    CBlockTreeDB(const CBlockTreeDB&);
    void operator=(const CBlockTreeDB&);
public:
    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo);
    bool EraseBatchSync(const std::vector<const CBlockIndex*>& blockinfo);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &fileinfo);
    bool ReadLastBlockFile(int &nFile);
    bool WriteReindexing(bool fReindex);
    bool ReadReindexing(bool &fReindex);
    bool ReadTxIndex(const uint256 &txid, CDiskTxPos &pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > &list);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts();
    bool WriteAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount> > &vect);
    bool EraseAddressIndex(const std::vector<std::pair<CAddressIndexKey, CAmount> > &vect);
    bool ReadAddressIndex(uint160 addressHash, int type,
                          std::vector<std::pair<CAddressIndexKey, CAmount> > &addressIndex,
                          int start = 0, int end = 0);
    bool UpdateAddressUnspentIndex(const std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &vect);
    bool ReadAddressUnspentIndex(uint160 addressHash, int type,
                                 std::vector<std::pair<CAddressUnspentKey, CAddressUnspentValue> > &unspentOutputs);
};

#endif // BITCOIN_TXDB_H
