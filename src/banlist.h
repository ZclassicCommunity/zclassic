// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BANLIST_H
#define BITCOIN_BANLIST_H

#include "net.h"

#include <boost/filesystem/path.hpp>

/**
 * Persistence of the ban list (banlist.dat in the datadir):
 *   "ZBAN" (4) | version (uint32) = 1 | network magic (4) | count (compact size) |
 *   count x { subnet (string, CSubNet::ToString) | ban-until (int64) } | hash256 of everything before
 * A file that fails any check is moved to banlist.dat.bad and the list starts empty:
 * a damaged file never stops the node and is never trusted. Older releases never open it.
 */
class CBanDB
{
private:
    boost::filesystem::path pathBanlist;
public:
    CBanDB();
    bool Write(const banmap_t& banSet);
    //! Always leaves banSet valid; a missing file is the normal empty case.
    bool Read(banmap_t& banSet);
};

//! Write banlist.dat if the ban list changed since the last write (scheduler, shutdown).
void DumpBanlist();

//! Start-up: read banlist.dat into the live ban list and drop bans that have ended.
void LoadBanlist();

#endif // BITCOIN_BANLIST_H
