// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Reading peers.dat: the strict decode first, then salvage of a damaged file.

#include "net.h"

#include "addrman.h"
#include "chainparams.h"
#include "clientversion.h"
#include "hash.h"
#include "streams.h"
#include "util.h"

#include <boost/filesystem.hpp>

//! Strict decode of an intact-checksum peers.dat image (magic already verified).
static bool ParsePeersStrict(CDataStream& ssPeers, CAddrMan& addr)
{
    try {
        unsigned char pchMsgTmp[4];
        ssPeers >> FLATDATA(pchMsgTmp);
        ssPeers >> addr;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    return true;
}

/**
 * peers.dat failed its checksum or its strict decode: keep the damaged file
 * aside, then keep whatever complete address records it still holds. Tried
 * flags and success times are trust-bearing, so everything comes back as "new".
 */
static bool SalvagePeers(CAddrMan& addr, const boost::filesystem::path& pathAddr,
                         const std::vector<unsigned char>& vchData, const uint256& hashIn, const char* pszWhy)
{
    boost::filesystem::path pathCorrupt = pathAddr.string() + ".corrupt";
    bool fMoved = RenameOver(pathAddr, pathCorrupt);

    // the whole file image after the magic; the record count bounds the read, so the tail is never parsed
    CDataStream ss((const char*)vchData.data() + 4, (const char*)vchData.data() + vchData.size(), SER_DISK, CLIENT_VERSION);
    ss << hashIn;
    size_t nKept = 0, nDropped = 0;
    try {
        addr.UnserializeSalvage(ss, true, nKept, nDropped);
    }
    catch (const std::exception&) {
        nKept = 0;
    }
    if (nKept == 0)
        addr.Clear();
    LogPrintf("peers.dat: %s, salvaged %u of %u addresses (tried entries demoted); damaged file %s\n",
              pszWhy, (unsigned)nKept, (unsigned)(nKept + nDropped),
              fMoved ? "kept as peers.dat.corrupt" : "could not be moved aside");
    return nKept > 0;
}

bool CAddrDB::Read(CAddrMan& addr)
{
    // open input file, and associate with CAutoFile
    FILE *file = fopen(pathAddr.string().c_str(), "rb");
    CAutoFile filein(file, SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: Failed to open file %s", __func__, pathAddr.string());

    // use file size to size memory buffer
    int fileSize = boost::filesystem::file_size(pathAddr);
    int dataSize = fileSize - sizeof(uint256);
    // Don't try to resize to a negative number if file is small
    if (dataSize < 0)
        dataSize = 0;
    std::vector<unsigned char> vchData;
    vchData.resize(dataSize);
    uint256 hashIn;

    // read data and checksum from file
    try {
        if (dataSize > 0)
            filein.read((char *)&vchData[0], dataSize);
        filein >> hashIn;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }
    filein.fclose();

    CDataStream ssPeers(vchData, SER_DISK, CLIENT_VERSION);

    // verify stored checksum matches input data
    bool fSumOk = (hashIn == Hash(ssPeers.begin(), ssPeers.end()));
    // a file of another network is not damaged, just not ours: never salvaged or moved
    bool fMagicOk = dataSize >= 4 && !memcmp(&vchData[0], Params().MessageStart(), 4);
    if (!fMagicOk)
        return error("%s: %s", __func__, fSumOk ? "Invalid network magic number" : "Checksum mismatch, data corrupted");

    if (fSumOk && ParsePeersStrict(ssPeers, addr))
        return true;
    return SalvagePeers(addr, pathAddr, vchData, hashIn, fSumOk ? "unreadable data" : "checksum mismatch");
}

