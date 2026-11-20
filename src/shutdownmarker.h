// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHUTDOWNMARKER_H
#define BITCOIN_SHUTDOWNMARKER_H

// Content-bound clean-shutdown marker (design from Z23
// engine/composition/src/boot_shutdown_marker.c).
//
// A clean Shutdown() writes <datadir>/shutdown.clean last, after the block
// index and coins databases are closed. It binds the chain tip, the coins best
// block and a digest of the names, sizes and mtimes of the block files and the
// two LevelDB directories. The next start consumes it (reads, then always
// unlinks) before any database is opened, so it is single use: a crash, kill or
// any change to those files after the clean stop makes the startup check run
// at its full default depth again. Any parse failure means "not verified".
//
// The marker only shortens the local VerifyDB integrity check (same level,
// fewer blocks). It has no effect on block or transaction validity.

#include "uint256.h"

#include <string>

#include <boost/filesystem/path.hpp>

static const char* const SHUTDOWN_MARKER_FILENAME = "shutdown.clean";

struct ShutdownBinding {
    uint256 tipHash;
    int tipHeight;
    uint256 coinsBest;
    uint256 filesDigest;

    ShutdownBinding() : tipHeight(-1) {}
};

/** SHA256 over the sorted "relpath:size:mtime" lines of blocks/blk*.dat,
 *  blocks/rev*.dat and the CURRENT, MANIFEST-*, *.ldb and *.log files of
 *  blocks/index and chainstate. Missing directories contribute no lines. */
uint256 ComputeFilesDigest(const boost::filesystem::path& datadir);

/** key=value lines: magic=ZCLSHUT, version=1, tip, height, coins, files. */
std::string SerializeBinding(const ShutdownBinding& b);

/** Strict inverse of SerializeBinding: a missing, repeated or unknown key, a
 *  bad hex or height value, or the wrong magic/version makes it fail. */
bool ParseBinding(const std::string& text, ShutdownBinding& out);

/** Write <datadir>/shutdown.clean durably (tmp file, commit, rename, directory
 *  sync). Returns false and leaves no marker on any failure. */
bool WriteCleanMarker(const boost::filesystem::path& datadir, const ShutdownBinding& b);

/** Read and parse <datadir>/shutdown.clean, then always remove it (and sync the
 *  directory), whether or not the parse succeeded. Returns the parse result;
 *  false when there is no marker. */
bool ConsumeCleanMarker(const boost::filesystem::path& datadir, ShutdownBinding& out);

#endif // BITCOIN_SHUTDOWNMARKER_H
