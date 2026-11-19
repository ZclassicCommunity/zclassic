// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "paramcache.h"

#include "bootstrap.h"
#include "crypto/sha256.h"
#include "random.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#ifndef WIN32
#include <unistd.h>
#endif

#include <atomic>
#include <sstream>
#include <vector>

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace {

/** A cache holds a handful of short lines; anything larger is not ours. */
const size_t PARAM_CACHE_MAX_BYTES = 64 * 1024;

bool IsLowerHex64(const std::string& s)
{
    if (s.size() != 64)
        return false;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

// ---- v1: "v 1", "epoch <hex>", "p <name> <size> <mtime> <hash>" lines

bool ParseV1Record(std::istringstream& ls, ParamCacheRecords& recs)
{
    std::string name, hash;
    unsigned long long sz;
    long long mt;
    if (!(ls >> name >> sz >> mt >> hash))
        return false;
    if (!IsLowerHex64(hash))
        return false;
    if (recs.count(name))
        return false; // duplicate => malformed
    ParamCacheRecord r;
    r.size = (uint64_t)sz;
    r.mtime = (int64_t)mt;
    r.verifiedHash = hash;
    recs[name] = r;
    return true;
}

bool ParseV1Line(const std::string& line, const std::string& wantEpoch, bool& epochOk,
                 ParamCacheRecords& recs)
{
    std::istringstream ls(line);
    std::string key;
    if (!(ls >> key))
        return false;
    if (key == "v") {
        std::string v;
        return (ls >> v) && v == "1"; // unknown format => fail closed
    }
    if (key == "epoch") {
        std::string e;
        if (!(ls >> e) || e.size() != 64)
            return false;
        epochOk = (e == wantEpoch); // mismatch => discard whole cache
        return true;
    }
    if (key == "p")
        return ParseV1Record(ls, recs);
    return false; // unknown key => fail closed
}

bool ParseV1(const std::string& text, const std::string& epoch, ParamCacheFile& out)
{
    std::istringstream in(text);
    std::string line;
    bool epochOk = false;
    ParamCacheRecords recs;
    while (std::getline(in, line)) {
        if (line.empty())
            continue;
        if (!ParseV1Line(line, epoch, epochOk, recs))
            return false;
    }
    if (!epochOk)
        return false; // missing or wrong epoch line
    out.version = 1;
    out.epoch = epoch;
    out.paramsDir.clear();
    out.records.swap(recs);
    return true;
}

// ---- v2: magic, "epoch <hex>", "paramsdir <dir>", then "<name>|<size>|<mtime>|<hash>" lines

const char* const PARAM_CACHE_FAMILY = "zclassic-params-verify";
const char* const PARAM_CACHE_V2_MAGIC = "zclassic-params-verify v2";

bool ParseDecimalU64(const std::string& s, uint64_t& out)
{
    if (s.empty() || s.size() > 20)
        return false;
    uint64_t v = 0;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9')
            return false;
        const uint64_t d = (uint64_t)(s[i] - '0');
        if (v > (UINT64_MAX - d) / 10)
            return false;
        v = v * 10 + d;
    }
    out = v;
    return true;
}

bool ParseDecimalI64(const std::string& s, int64_t& out)
{
    const bool neg = !s.empty() && s[0] == '-';
    uint64_t mag;
    if (!ParseDecimalU64(neg ? s.substr(1) : s, mag) || mag > (uint64_t)INT64_MAX)
        return false;
    out = neg ? -(int64_t)mag : (int64_t)mag;
    return true;
}

/** A name or params dir the line format can carry back unchanged. */
bool FieldIsClean(const std::string& s, bool allowBar)
{
    if (s.empty())
        return false;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\n' || s[i] == '\r' || s[i] == '\0' || (!allowBar && s[i] == '|'))
            return false;
    }
    return true;
}

bool ParseV2Record(const std::string& line, ParamCacheRecords& recs)
{
    std::vector<std::string> f;
    size_t start = 0, bar;
    while ((bar = line.find('|', start)) != std::string::npos) {
        f.push_back(line.substr(start, bar - start));
        start = bar + 1;
    }
    f.push_back(line.substr(start));
    ParamCacheRecord r;
    if (f.size() != 4 || f[0].empty() || recs.count(f[0]))
        return false; // wrong field count, no name, or a duplicate
    if (!ParseDecimalU64(f[1], r.size) || !ParseDecimalI64(f[2], r.mtime) || !IsLowerHex64(f[3]))
        return false;
    r.verifiedHash = f[3];
    recs[f[0]] = r;
    return true;
}

/** Lines of `text`, which must end with a newline and hold no empty line or CR. */
bool SplitStrictLines(const std::string& text, std::vector<std::string>& lines)
{
    if (text.empty() || text[text.size() - 1] != '\n' || text.find('\r') != std::string::npos)
        return false;
    size_t start = 0, nl;
    while ((nl = text.find('\n', start)) != std::string::npos) {
        if (nl == start)
            return false;
        lines.push_back(text.substr(start, nl - start));
        start = nl + 1;
    }
    return true;
}

bool ParseV2(const std::string& text, const std::string& epoch, const std::string& paramsDir,
             ParamCacheFile& out)
{
    std::vector<std::string> lines;
    if (!SplitStrictLines(text, lines) || lines.size() < 3 || lines[0] != PARAM_CACHE_V2_MAGIC)
        return false; // a later or unknown version is cold too
    if (!IsLowerHex64(epoch) || lines[1] != "epoch " + epoch)
        return false;
    if (!FieldIsClean(paramsDir, true) || lines[2] != "paramsdir " + paramsDir)
        return false;
    ParamCacheRecords recs;
    for (size_t i = 3; i < lines.size(); ++i) {
        if (!ParseV2Record(lines[i], recs))
            return false;
    }
    out.version = 2;
    out.epoch = epoch;
    out.paramsDir = paramsDir;
    out.records.swap(recs);
    return true;
}

bool CanSerialize(const ParamCacheFile& in, std::string& error)
{
    if (!IsLowerHex64(in.epoch) || !FieldIsClean(in.paramsDir, true)) {
        error = "epoch or params directory cannot be stored in the cache format";
        return false;
    }
    for (ParamCacheRecords::const_iterator it = in.records.begin(); it != in.records.end(); ++it) {
        if (!FieldIsClean(it->first, false) || !IsLowerHex64(it->second.verifiedHash)) {
            error = "a record cannot be stored in the cache format";
            return false;
        }
    }
    return true;
}

// ---- file access

/** Mandatory on-READ ownership/mode gate: a cache writable by anyone other than
 *  us (group/other-writable, or owned by a different uid) is ignored. 0600 on
 *  write is not enough; an attacker of a DIFFERENT uid must never be able to
 *  plant a honored cache in a misconfigured or shared directory. */
bool ReadOwnerOnlyFile(const fs::path& file, std::string& text)
{
#ifndef WIN32
    const int fd = ::open(file.string().c_str(), O_RDONLY);
    if (fd < 0)
        return false;
    struct stat st;
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & (S_IWGRP | S_IWOTH)) || (uint64_t)st.st_size > PARAM_CACHE_MAX_BYTES) {
        ::close(fd);
        return false;
    }
    FILE* f = fdopen(fd, "rb");
    if (!f) {
        ::close(fd);
        return false;
    }
#else
    FILE* f = fopen(file.string().c_str(), "rb");
    if (!f)
        return false;
#endif
    char buf[4096];
    size_t n;
    text.clear();
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0 && text.size() <= PARAM_CACHE_MAX_BYTES)
        text.append(buf, n);
    const bool ok = !ferror(f) && text.size() <= PARAM_CACHE_MAX_BYTES;
    fclose(f);
    return ok;
}

FILE* CreateTempFile(const fs::path& tmpPath)
{
#ifndef WIN32
    const int fd = ::open(tmpPath.string().c_str(), O_CREAT | O_EXCL | O_WRONLY | O_TRUNC, 0600);
    if (fd < 0)
        return NULL;
    FILE* f = fdopen(fd, "wb");
    if (!f)
        ::close(fd);
    return f;
#else
    return fopen(tmpPath.string().c_str(), "wb");
#endif
}

} // anonymous namespace

std::string CompiledParamEpoch()
{
    std::string acc;
    const std::vector<ZcashParamSpec>& specs = GetZcashParamSpecs();
    for (size_t i = 0; i < specs.size(); ++i) {
        acc += specs[i].name;
        acc += '|';
        acc += specs[i].sha256hex;
        acc += '|';
        acc += std::to_string((unsigned long long)specs[i].nSize);
        acc += '\n';
    }
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(acc.data()), acc.size()).Finalize(digest);
    return HexStr(digest, digest + sizeof(digest));
}

std::string ParamCacheSerialize(const ParamCacheFile& in)
{
    std::string s = std::string(PARAM_CACHE_V2_MAGIC) + "\n";
    s += "epoch " + in.epoch + "\n";
    s += "paramsdir " + in.paramsDir + "\n";
    for (ParamCacheRecords::const_iterator it = in.records.begin(); it != in.records.end(); ++it) {
        s += strprintf("%s|%llu|%lld|%s\n", it->first, (unsigned long long)it->second.size,
                       (long long)it->second.mtime, it->second.verifiedHash);
    }
    return s;
}

bool ParamCacheParse(const std::string& text, const std::string& epoch,
                     const std::string& paramsDir, ParamCacheFile& out)
{
    if (text.compare(0, strlen(PARAM_CACHE_FAMILY), PARAM_CACHE_FAMILY) == 0)
        return ParseV2(text, epoch, paramsDir, out);
    return ParseV1(text, epoch, out);
}

bool ParamCacheLoad(const fs::path& file, const std::string& epoch,
                    const std::string& paramsDir, ParamCacheFile& out)
{
    std::string text;
    if (!ReadOwnerOnlyFile(file, text))
        return false;
    return ParamCacheParse(text, epoch, paramsDir, out);
}

bool ParamCacheStore(const fs::path& file, const ParamCacheFile& in, std::string& error)
{
    if (!CanSerialize(in, error))
        return false;
    const std::string text = ParamCacheSerialize(in);
    // Unique per writer: nodes sharing one params dir may store at the same time.
    const fs::path tmpPath = strprintf("%s.%016x.tmp", file.string(), GetRand(UINT64_MAX));
    boost::system::error_code ec;
    FILE* f = CreateTempFile(tmpPath);
    if (!f) {
        error = strprintf("cannot create %s: %s", tmpPath.string(), strerror(errno));
        return false;
    }
    const bool written = fwrite(text.data(), 1, text.size(), f) == text.size();
    FileCommit(f);
    const bool closed = fclose(f) == 0;
    if (!written || !closed) {
        error = strprintf("cannot write %s", tmpPath.string());
        fs::remove(tmpPath, ec);
        return false;
    }
    if (!RenameOver(tmpPath, file)) {
        error = strprintf("cannot rename %s to %s", tmpPath.string(), file.string());
        fs::remove(tmpPath, ec);
        return false;
    }
    return true;
}

fs::path ParamCachePrimaryPath(const fs::path& paramsDir)
{
    return paramsDir / "zclassic-params-verify.cache";
}

fs::path ParamCacheLegacyPath(const fs::path& dataDir)
{
    return dataDir / "params-verify.cache";
}

std::string ParamCacheCanonicalDir(const fs::path& paramsDir)
{
    boost::system::error_code ec;
    const fs::path canon = fs::canonical(paramsDir, ec);
    if (!ec)
        return canon.string();
    return fs::absolute(paramsDir).string();
}

namespace {

/** True unless `p` certainly does not exist: an error other than "not found"
 *  counts as present, so the caller treats the cache as unusable. */
bool PathPresent(const fs::path& p)
{
    boost::system::error_code ec;
    return fs::symlink_status(p, ec).type() != fs::file_not_found;
}

bool LoadOne(const fs::path& file, int version, const std::string& paramsDir, ParamCacheRecords& out)
{
    ParamCacheFile f;
    if (!ParamCacheLoad(file, CompiledParamEpoch(), paramsDir, f) || f.version != version) {
        LogPrintf("param-cache: %s is not usable (owner, mode, format, epoch or params directory); hashing every file\n",
                  file.string());
        return false;
    }
    out.swap(f.records);
    LogPrintf("param-cache: using %s (%u records)\n", file.string(), (unsigned)out.size());
    return true;
}

} // anonymous namespace

ParamCacheSource LoadVerifiedParamCache(const fs::path& paramsDir, const fs::path& dataDir,
                                        ParamCacheRecords& out)
{
    out.clear();
    const fs::path primary = ParamCachePrimaryPath(paramsDir);
    if (PathPresent(primary))
        return LoadOne(primary, 2, ParamCacheCanonicalDir(paramsDir), out) ? PARAMCACHE_PRIMARY : PARAMCACHE_NONE;
    const fs::path legacy = ParamCacheLegacyPath(dataDir);
    if (PathPresent(legacy))
        return LoadOne(legacy, 1, "", out) ? PARAMCACHE_LEGACY : PARAMCACHE_NONE;
    return PARAMCACHE_NONE;
}

bool StoreVerifiedParamCache(const fs::path& paramsDir, const ParamCacheRecords& recs)
{
    static std::atomic<bool> fFailureLogged(false);
    ParamCacheFile f;
    f.version = 2;
    f.epoch = CompiledParamEpoch();
    f.paramsDir = ParamCacheCanonicalDir(paramsDir);
    f.records = recs;
    std::string error;
    if (ParamCacheStore(ParamCachePrimaryPath(paramsDir), f, error))
        return true;
    if (!fFailureLogged.exchange(true))
        LogPrintf("param-cache: could not store the verified-params cache (%s); continuing without it\n", error);
    return false;
}
