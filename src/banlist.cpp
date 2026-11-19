// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// banlist.dat: the persisted ban list (see banlist.h).

#include "banlist.h"

#include "chainparams.h"
#include "clientversion.h"
#include "hash.h"
#include "net.h"
#include "random.h"
#include "streams.h"
#include "util.h"

#include <algorithm>

#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>

static const unsigned char BANLIST_MAGIC[4] = {'Z', 'B', 'A', 'N'};
static const uint32_t BANLIST_VERSION = 1;
static const uint64_t BANLIST_MAX_ENTRIES = 100000;
static const size_t BANLIST_MAX_BYTES = 16 * 1024 * 1024;
static const size_t BANLIST_MIN_BYTES = 4 + 4 + 4 + 1 + sizeof(uint256);

//! The entries to store: all of them, or the BANLIST_MAX_ENTRIES latest-expiring when there are more
//! (Read refuses a larger count, so an oversized write would lose every ban at the next start).
typedef std::pair<CSubNet, int64_t> BanEntry;

static std::vector<BanEntry> BanEntriesToWrite(const banmap_t& banSet)
{
    std::vector<BanEntry> v(banSet.begin(), banSet.end());
    if (v.size() > BANLIST_MAX_ENTRIES) {
        std::sort(v.begin(), v.end(), [](const BanEntry& a, const BanEntry& b) { return a.second > b.second; });
        v.resize(BANLIST_MAX_ENTRIES);
    }
    return v;
}

CBanDB::CBanDB()
{
    pathBanlist = GetDataDir() / "banlist.dat";
}

bool CBanDB::Write(const banmap_t& banSet)
{
    unsigned short randv = 0;
    GetRandBytes((unsigned char*)&randv, sizeof(randv));
    std::string tmpfn = strprintf("banlist.dat.%04x", randv);

    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << FLATDATA(BANLIST_MAGIC);
    ss << BANLIST_VERSION;
    ss << FLATDATA(Params().MessageStart());
    const std::vector<BanEntry> vEntries = BanEntriesToWrite(banSet);
    WriteCompactSize(ss, vEntries.size());
    BOOST_FOREACH(const BanEntry& entry, vEntries) {
        ss << entry.first.ToString();
        ss << (int64_t)entry.second;
    }
    uint256 hash = Hash(ss.begin(), ss.end());
    ss << hash;

    boost::filesystem::path pathTmp = GetDataDir() / tmpfn;
    FILE *file = fopen(pathTmp.string().c_str(), "wb");
    CAutoFile fileout(file, SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: Failed to open file %s", __func__, pathTmp.string());
    try {
        fileout << ss;
    }
    catch (const std::exception& e) {
        return error("%s: Serialize or I/O error - %s", __func__, e.what());
    }
    FileCommit(fileout.Get());
    fileout.fclose();

    if (!RenameOver(pathTmp, pathBanlist))
        return error("%s: Rename-into-place failed", __func__);
    return true;
}

//! Whole file into vch. False when it cannot be opened or read (nothing to judge then).
static bool ReadBanlistBytes(const boost::filesystem::path& path, std::vector<unsigned char>& vch)
{
    FILE *file = fopen(path.string().c_str(), "rb");
    if (!file)
        return false;
    unsigned char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), file)) > 0) {
        vch.insert(vch.end(), buf, buf + n);
        if (vch.size() > BANLIST_MAX_BYTES)
            break; // far beyond any legitimate list; the parse below rejects it
    }
    bool fOk = !ferror(file);
    fclose(file);
    return fOk;
}

//! Check and decode a banlist.dat image. False on any defect; out may then hold a partial result.
static bool ParseBanlist(const std::vector<unsigned char>& vch, banmap_t& out)
{
    if (vch.size() < BANLIST_MIN_BYTES || vch.size() > BANLIST_MAX_BYTES)
        return false;
    const size_t nData = vch.size() - sizeof(uint256);
    uint256 hashIn;
    memcpy(hashIn.begin(), &vch[nData], sizeof(uint256));
    if (hashIn != Hash(vch.begin(), vch.begin() + nData))
        return false;
    try {
        CDataStream ss((const char*)&vch[0], (const char*)&vch[0] + nData, SER_DISK, CLIENT_VERSION);
        unsigned char magic[4], msgStart[4];
        uint32_t nVersion;
        ss >> FLATDATA(magic) >> nVersion >> FLATDATA(msgStart);
        if (memcmp(magic, BANLIST_MAGIC, sizeof(magic)) || nVersion != BANLIST_VERSION ||
            memcmp(msgStart, Params().MessageStart(), sizeof(msgStart)))
            return false;
        uint64_t nCount = ReadCompactSize(ss);
        if (nCount > BANLIST_MAX_ENTRIES)
            return false;
        for (uint64_t i = 0; i < nCount; i++) {
            std::string strSubNet;
            int64_t nBanUntil;
            ss >> strSubNet >> nBanUntil;
            CSubNet subNet(strSubNet);
            if (subNet.IsValid())
                out[subNet] = nBanUntil;
        }
        return ss.empty();
    }
    catch (const std::exception&) {
        return false;
    }
}

bool CBanDB::Read(banmap_t& banSet)
{
    banSet.clear();
    std::vector<unsigned char> vch;
    if (!ReadBanlistBytes(pathBanlist, vch))
        return true; // missing is the normal first-run case

    if (ParseBanlist(vch, banSet))
        return true;

    banSet.clear();
    boost::filesystem::path pathBad = pathBanlist.string() + ".bad";
    bool fMoved = RenameOver(pathBanlist, pathBad);
    LogPrintf("banlist.dat is damaged or from another network; ignoring it%s\n",
              fMoved ? " (kept as banlist.dat.bad)" : " (could not move it aside)");
    return false;
}

void DumpBanlist()
{
    CNode::SweepBanned();
    if (!CNode::fBanlistDirty.exchange(false))
        return;
    banmap_t banmap;
    CNode::GetBanned(banmap);
    CBanDB bandb;
    if (!bandb.Write(banmap))
        CNode::fBanlistDirty = true; // try again at the next run
}

void LoadBanlist()
{
    banmap_t banmap;
    CBanDB bandb;
    bandb.Read(banmap);
    CNode::SetBanned(banmap);
    CNode::SweepBanned();
    CNode::GetBanned(banmap);
    LogPrintf("Loaded %d banned node ips/subnets from banlist.dat\n", (int)banmap.size());
}

