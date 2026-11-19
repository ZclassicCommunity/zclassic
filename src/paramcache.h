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
// malformed, wrong epoch) means a cold cache: every file is fully hashed.

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

typedef std::map<std::string, ParamCacheRecord> ParamCacheRecords;

struct ParamCacheFile {
    int version;           // format version of the parsed or serialized text
    std::string epoch;     // CompiledParamEpoch() of the binary that wrote it
    std::string paramsDir; // canonical params directory the records describe (v2)
    ParamCacheRecords records;

    ParamCacheFile() : version(0) {}
};

/** SHA-256 hex over the compiled spec table (name|hash|size per file). A binary
 *  with any different compiled hash or size yields a different epoch, which
 *  invalidates the whole cache. */
std::string CompiledParamEpoch();

/** The cache text for `in` (its records, epoch and params dir). */
std::string ParamCacheSerialize(const ParamCacheFile& in);

/** Strict parse of cache text. True only when the text is well formed and its
 *  epoch equals `epoch`; `out` is set only on success. */
bool ParamCacheParse(const std::string& text, const std::string& epoch,
                     const std::string& paramsDir, ParamCacheFile& out);

/** Read `file` and parse it. On POSIX the file must be a regular file owned by
 *  the effective uid with no group or other write bit. */
bool ParamCacheLoad(const boost::filesystem::path& file, const std::string& epoch,
                    const std::string& paramsDir, ParamCacheFile& out);

/** Atomically replace `file` with ParamCacheSerialize(in): temp file (0600 on
 *  POSIX), commit, rename. False with `error` set on any failure, leaving the
 *  previous file in place. */
bool ParamCacheStore(const boost::filesystem::path& file, const ParamCacheFile& in,
                     std::string& error);

/** The cache InitSanityCheck consults: <dataDir>/params-verify.cache. True and
 *  `out` filled only for a usable cache; `out` is empty otherwise. */
bool LoadVerifiedParamCache(const boost::filesystem::path& dataDir, ParamCacheRecords& out);

/** Persist `recs` as the cache for this binary's epoch. A failure is logged and
 *  otherwise ignored: the next start hashes again. */
void StoreVerifiedParamCache(const boost::filesystem::path& dataDir, const ParamCacheRecords& recs);

#endif // BITCOIN_PARAMCACHE_H
