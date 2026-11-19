// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PARAMCACHE_H
#define BITCOIN_PARAMCACHE_H

// Verified-params cache: lets startup skip re-hashing a zk parameter file that
// already hashed to the compiled SHA-256 at the same size and mtime.
//
// SAFETY INVARIANT (load-bearing): InitSanityCheck skips the re-hash of a param
// ONLY when ALL of these hold, otherwise it runs the full check_file_hash:
//   (a) file_size(path) == spec.nSize                 (the COMPILED size)
//   (b) cache record exists with size==cur_size AND mtime==cur_mtime
//   (c) record.verifiedHash == spec.sha256hex          (the LIVE COMPILED hash)
//   (d) cache file's binary-epoch == this binary's compiled-table epoch
//   (e) cache file is owner-only (st_uid==geteuid, no group/other write bits)
// The cache NEVER supplies a hash to trust: (c) compares the cached hash to the
// compiled constant (.rodata, not attacker-writable). The cache only answers
// "did THIS (size,mtime) already hash to the value the binary already requires".
// Forging a skip-and-load of malicious identical-size content requires a SHA-256
// second preimage (infeasible). A different-uid planted cache is rejected by (e).
//
// KNOWN, ACCEPTED RESIDUAL: a bit-rot/torn write that preserves BOTH size AND
// mtime is skipped and the corrupt param loads. This is BOUNDED and
// NON-CONSENSUS: zk params are firewalled from block/tx/PoW; a corrupt param
// makes a shielded proof FAIL/REJECT (never forges one or forks the chain),
// fails LOUDLY at use, and self-heals via the existing bootstrap re-fetch.
// Pass -noparamcache to force the full hash.
//
// Any doubt about a cache file (missing, foreign owner, group/other writable,
// malformed, wrong epoch, wrong params dir) means a cold cache: every file is
// fully hashed.
//
// LOCATION: <params dir>/zclassic-params-verify.cache (format v2), so every
// datadir, wallet profile and test node sharing the params reuses one cache:
//   zclassic-params-verify v2
//   epoch <CompiledParamEpoch()>
//   paramsdir <canonical absolute params dir>
//   <name>|<size>|<mtime>|<sha256 hex>      one line per verified file
// The v1 file <datadir>/params-verify.cache of earlier releases is read only
// when the v2 file is absent, and is never written again.

#include <stdint.h>

#include <map>
#include <string>

#include <boost/filesystem/path.hpp>

struct ParamCacheRecord {
    uint64_t size;
    int64_t mtime;            // std::time_t, 1s granularity (boost last_write_time)
    std::string verifiedHash; // 64-hex lowercase

    ParamCacheRecord() : size(0), mtime(0) {}
};

inline bool operator==(const ParamCacheRecord& a, const ParamCacheRecord& b)
{
    return a.size == b.size && a.mtime == b.mtime && a.verifiedHash == b.verifiedHash;
}

typedef std::map<std::string, ParamCacheRecord> ParamCacheRecords;

struct ParamCacheFile {
    int version;           // 1: legacy datadir file; 2: beside the params
    std::string epoch;     // CompiledParamEpoch() of the binary that wrote it
    std::string paramsDir; // canonical params directory the records describe (v2)
    ParamCacheRecords records;

    ParamCacheFile() : version(0) {}
};

/** SHA-256 hex over the compiled spec table (name|hash|size per file). A binary
 *  with any different compiled hash or size yields a different epoch, which
 *  invalidates the whole cache. */
std::string CompiledParamEpoch();

/** The v2 cache text for `in` (its records, epoch and params dir). */
std::string ParamCacheSerialize(const ParamCacheFile& in);

/** Strict parse of cache text, v2 or legacy v1. True only when the text is well
 *  formed and its epoch equals `epoch`; a v2 text must also name `paramsDir`
 *  (a v1 text has no params dir). `out` is set only on success, with
 *  out.version telling which format was read. */
bool ParamCacheParse(const std::string& text, const std::string& epoch,
                     const std::string& paramsDir, ParamCacheFile& out);

/** Read `file` and parse it. On POSIX the file must be a regular file owned by
 *  the effective uid with no group or other write bit. */
bool ParamCacheLoad(const boost::filesystem::path& file, const std::string& epoch,
                    const std::string& paramsDir, ParamCacheFile& out);

/** Atomically replace `file` with ParamCacheSerialize(in): unique temp file
 *  beside it (0600 on POSIX), commit, rename. False with `error` set on any
 *  failure (including a params dir or name the format cannot hold), leaving the
 *  previous file in place. */
bool ParamCacheStore(const boost::filesystem::path& file, const ParamCacheFile& in,
                     std::string& error);

/** <paramsDir>/zclassic-params-verify.cache */
boost::filesystem::path ParamCachePrimaryPath(const boost::filesystem::path& paramsDir);
/** <dataDir>/params-verify.cache (v1, read only) */
boost::filesystem::path ParamCacheLegacyPath(const boost::filesystem::path& dataDir);
/** The canonical absolute form of `paramsDir` as a v2 file records it. */
std::string ParamCacheCanonicalDir(const boost::filesystem::path& paramsDir);

enum ParamCacheSource {
    PARAMCACHE_NONE,    // cold: no usable cache
    PARAMCACHE_PRIMARY, // the v2 file beside the params
    PARAMCACHE_LEGACY,  // the v1 file in the datadir (primary absent)
};

/** The cache InitSanityCheck consults: the primary file when it exists (an
 *  unusable primary means cold, with no fallback), else the legacy file. `out`
 *  is filled only for a usable cache and is empty otherwise. */
ParamCacheSource LoadVerifiedParamCache(const boost::filesystem::path& paramsDir,
                                        const boost::filesystem::path& dataDir,
                                        ParamCacheRecords& out);

/** Persist `recs` as the primary cache for this binary's epoch. A failure (for
 *  example a read-only params dir) is logged once per process and otherwise
 *  ignored: the next start hashes again. */
bool StoreVerifiedParamCache(const boost::filesystem::path& paramsDir, const ParamCacheRecords& recs);

#endif // BITCOIN_PARAMCACHE_H
