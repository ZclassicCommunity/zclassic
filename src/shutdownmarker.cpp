// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "shutdownmarker.h"

#include "crypto/sha256.h"
#include "tinyformat.h"
#include "util.h"
#include "utilstrencodings.h"

#include <algorithm>
#include <map>
#include <stdio.h>
#include <vector>

#include <boost/algorithm/string/predicate.hpp>
#include <boost/filesystem.hpp>

#ifndef WIN32
#include <sys/stat.h>
#endif

namespace fs = boost::filesystem;

static const char* const MARKER_MAGIC = "ZCLSHUT";
static const char* const MARKER_VERSION = "1";
static const size_t MARKER_MAX_BYTES = 4096;

// Modification time with the best resolution the platform offers, so a touch
// within the same second as the clean stop still changes the digest.
static std::string FileMtime(const fs::path& p)
{
#if !defined(WIN32)
    struct stat st;
    if (stat(p.string().c_str(), &st) != 0)
        return "?";
#if defined(__APPLE__)
    return strprintf("%lld.%09ld", (long long)st.st_mtimespec.tv_sec, (long)st.st_mtimespec.tv_nsec);
#else
    return strprintf("%lld.%09ld", (long long)st.st_mtim.tv_sec, (long)st.st_mtim.tv_nsec);
#endif
#else
    boost::system::error_code ec;
    std::time_t t = fs::last_write_time(p, ec);
    return ec ? std::string("?") : strprintf("%lld", (long long)t);
#endif
}

static bool LevelDBFileName(const std::string& n)
{
    if (n == "CURRENT" || boost::algorithm::starts_with(n, "MANIFEST-"))
        return true;
    return boost::algorithm::ends_with(n, ".ldb") || boost::algorithm::ends_with(n, ".log");
}

static bool BlockFileName(const std::string& n)
{
    return (boost::algorithm::starts_with(n, "blk") || boost::algorithm::starts_with(n, "rev")) &&
           boost::algorithm::ends_with(n, ".dat");
}

static void ListDir(const fs::path& datadir, const std::string& rel, bool (*want)(const std::string&),
                    std::vector<std::string>& lines)
{
    boost::system::error_code ec;
    const fs::path dir = datadir / rel;
    if (!fs::is_directory(dir, ec))
        return;
    for (fs::directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec)) {
        const std::string name = it->path().filename().string();
        boost::system::error_code ec2;
        if (!want(name) || !fs::is_regular_file(it->path(), ec2))
            continue;
        const boost::uintmax_t size = fs::file_size(it->path(), ec2);
        lines.push_back(strprintf("%s/%s:%s:%s", rel, name,
                                  ec2 ? std::string("?") : strprintf("%llu", (unsigned long long)size),
                                  FileMtime(it->path())));
    }
    if (ec)
        lines.push_back(strprintf("%s:list-error:%d", rel, ec.value()));
}

uint256 ComputeFilesDigest(const fs::path& datadir)
{
    std::vector<std::string> lines;
    ListDir(datadir, "blocks", BlockFileName, lines);
    ListDir(datadir, "blocks/index", LevelDBFileName, lines);
    ListDir(datadir, "chainstate", LevelDBFileName, lines);
    std::sort(lines.begin(), lines.end());
    CSHA256 h;
    for (const std::string& l : lines) {
        h.Write((const unsigned char*)l.data(), l.size());
        h.Write((const unsigned char*)"\n", 1);
    }
    uint256 out;
    h.Finalize(out.begin());
    return out;
}

std::string SerializeBinding(const ShutdownBinding& b)
{
    return strprintf("magic=%s\nversion=%s\ntip=%s\nheight=%d\ncoins=%s\nfiles=%s\n",
                     MARKER_MAGIC, MARKER_VERSION, b.tipHash.GetHex(), b.tipHeight,
                     b.coinsBest.GetHex(), b.filesDigest.GetHex());
}

static bool ParseHash(const std::string& s, uint256& out)
{
    if (s.size() != 64 || !IsHex(s))
        return false;
    out.SetHex(s);
    return true;
}

bool ParseBinding(const std::string& text, ShutdownBinding& out)
{
    std::map<std::string, std::string> kv;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos)
            return false; // every line, the last included, ends with '\n'
        const std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        const size_t eq = line.find('=');
        if (eq == std::string::npos || eq == 0)
            return false;
        if (!kv.insert(std::make_pair(line.substr(0, eq), line.substr(eq + 1))).second)
            return false; // repeated key
    }
    static const char* const keys[] = {"magic", "version", "tip", "height", "coins", "files"};
    if (kv.size() != sizeof(keys) / sizeof(keys[0]))
        return false;
    for (const char* k : keys)
        if (!kv.count(k))
            return false;
    if (kv["magic"] != MARKER_MAGIC || kv["version"] != MARKER_VERSION)
        return false;
    ShutdownBinding b;
    if (!ParseHash(kv["tip"], b.tipHash) || !ParseHash(kv["coins"], b.coinsBest) ||
        !ParseHash(kv["files"], b.filesDigest))
        return false;
    int32_t height;
    if (!ParseInt32(kv["height"], &height) || height < 0)
        return false;
    b.tipHeight = height;
    out = b;
    return true;
}

bool WriteCleanMarker(const fs::path& datadir, const ShutdownBinding& b)
{
    const fs::path tmp = datadir / (std::string(SHUTDOWN_MARKER_FILENAME) + ".tmp");
    const fs::path dst = datadir / SHUTDOWN_MARKER_FILENAME;
    const std::string text = SerializeBinding(b);
    FILE* f = fopen(tmp.string().c_str(), "wb");
    if (!f) {
        LogPrintf("%s: cannot create %s\n", __func__, tmp.string());
        return false;
    }
    bool ok = fwrite(text.data(), 1, text.size(), f) == text.size();
    if (ok) {
        FileCommit(f);
        ok = !ferror(f);
    }
    ok = (fclose(f) == 0) && ok;
    if (!ok || !RenameOver(tmp, dst)) {
        LogPrintf("%s: cannot write %s\n", __func__, dst.string());
        boost::system::error_code ec;
        fs::remove(tmp, ec);
        return false;
    }
    if (!DirectoryCommit(datadir)) {
        // The rename may not survive a power loss; that only loses the marker.
        LogPrintf("%s: directory sync failed for %s\n", __func__, datadir.string());
    }
    return true;
}

bool ConsumeCleanMarker(const fs::path& datadir, ShutdownBinding& out)
{
    const fs::path tmp = datadir / (std::string(SHUTDOWN_MARKER_FILENAME) + ".tmp");
    const fs::path dst = datadir / SHUTDOWN_MARKER_FILENAME;
    boost::system::error_code ec;
    const bool present = fs::exists(dst, ec) || fs::is_symlink(dst, ec);
    const bool tmpPresent = fs::exists(tmp, ec) || fs::is_symlink(tmp, ec);
    if (!present && !tmpPresent)
        return false;

    bool parsed = false;
    if (present) {
        std::string text;
        FILE* f = fopen(dst.string().c_str(), "rb");
        if (f) {
            char buf[MARKER_MAX_BYTES + 1];
            size_t n = fread(buf, 1, sizeof(buf), f);
            fclose(f);
            if (n <= MARKER_MAX_BYTES) {
                text.assign(buf, n);
                ShutdownBinding b;
                parsed = ParseBinding(text, b);
                if (parsed)
                    out = b;
            }
        }
    }
    // Single use: remove the marker (and any interrupted temp file) whatever the result.
    fs::remove(dst, ec);
    if (ec) {
        LogPrintf("%s: cannot remove %s (%s); not trusting it\n", __func__, dst.string(), ec.message());
        parsed = false;
    }
    fs::remove(tmp, ec);
    if (!DirectoryCommit(datadir))
        LogPrintf("%s: directory sync failed for %s\n", __func__, datadir.string());
    return parsed;
}
