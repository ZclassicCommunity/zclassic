// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "paramcache.h"

#include "bootstrap.h"
#include "crypto/sha256.h"
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

#include <sstream>

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
    std::string s = "v 1\n";
    s += "epoch " + in.epoch + "\n";
    for (ParamCacheRecords::const_iterator it = in.records.begin(); it != in.records.end(); ++it) {
        s += strprintf("p %s %llu %lld %s\n", it->first, (unsigned long long)it->second.size,
                       (long long)it->second.mtime, it->second.verifiedHash);
    }
    return s;
}

bool ParamCacheParse(const std::string& text, const std::string& epoch,
                     const std::string& paramsDir, ParamCacheFile& out)
{
    (void)paramsDir;
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
    const std::string text = ParamCacheSerialize(in);
    const fs::path tmpPath = file.string() + ".tmp";
    boost::system::error_code ec;
    fs::remove(tmpPath, ec); // a stale temp file from a killed run
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

bool LoadVerifiedParamCache(const fs::path& dataDir, ParamCacheRecords& out)
{
    out.clear();
    ParamCacheFile f;
    if (!ParamCacheLoad(dataDir / "params-verify.cache", CompiledParamEpoch(), "", f))
        return false;
    out.swap(f.records);
    return true;
}

void StoreVerifiedParamCache(const fs::path& dataDir, const ParamCacheRecords& recs)
{
    ParamCacheFile f;
    f.version = 1;
    f.epoch = CompiledParamEpoch();
    f.records = recs;
    std::string error;
    if (!ParamCacheStore(dataDir / "params-verify.cache", f, error))
        LogPrintf("param-cache: could not store the verified-params cache: %s\n", error);
}
