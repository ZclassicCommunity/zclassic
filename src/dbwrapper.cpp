// Copyright (c) 2012-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dbwrapper.h"

#include "util.h"

#include <boost/filesystem.hpp>

#include <leveldb/cache.h>
#include <leveldb/env.h>
#include <leveldb/filter_policy.h>
#include <memenv.h>
#include <stdint.h>

static leveldb::Options GetOptions(size_t nCacheSize)
{
    leveldb::Options options;
    options.block_cache = leveldb::NewLRUCache(nCacheSize / 2);
    options.write_buffer_size = nCacheSize / 4; // up to two write buffers may be held in memory simultaneously
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    options.compression = leveldb::kNoCompression;
    options.max_open_files = 64;
    if (leveldb::kMajorVersion > 1 || (leveldb::kMajorVersion == 1 && leveldb::kMinorVersion >= 16)) {
        // LevelDB versions before 1.16 consider short writes to be corruption. Only trigger error
        // on corruption in later versions.
        options.paranoid_checks = true;
    }
    return options;
}

CDBWrapper::CDBWrapper(const boost::filesystem::path& path, size_t nCacheSize, bool fMemory, bool fWipe)
{
    penv = NULL;
    readoptions.verify_checksums = true;
    iteroptions.verify_checksums = true;
    iteroptions.fill_cache = false;
    syncoptions.sync = true;
    options = GetOptions(nCacheSize);
    options.create_if_missing = true;
    if (fMemory) {
        penv = leveldb::NewMemEnv(leveldb::Env::Default());
        options.env = penv;
    } else {
        if (fWipe) {
            LogPrintf("Wiping LevelDB in %s\n", path.string());
            leveldb::Status result = leveldb::DestroyDB(path.string(), options);
            dbwrapper_private::HandleError(result);
        }
        try {
            TryCreateDirectory(path);
        } catch (const boost::filesystem::filesystem_error& e) {
            // Surface the OS reason (permissions, read-only filesystem, path too long, a file in the way)
            // as a database error: none of these is repaired by -reindex.
            LogPrintf("Cannot create the database directory %s: %s\n", path.string(), e.code().message());
            throw dbwrapper_error("Database I/O error: cannot create " + path.string() + ": " + e.code().message(), true);
        }
        LogPrintf("Opening LevelDB in %s\n", path.string());
    }
    leveldb::Status status = leveldb::DB::Open(options, path.string(), &pdb);
    dbwrapper_private::HandleError(status);
    LogPrintf("Opened LevelDB successfully\n");
}

CDBWrapper::~CDBWrapper()
{
    delete pdb;
    pdb = NULL;
    delete options.filter_policy;
    options.filter_policy = NULL;
    delete options.block_cache;
    options.block_cache = NULL;
    delete penv;
    options.env = NULL;
}

bool CDBWrapper::WriteBatch(CDBBatch& batch, bool fSync)
{
    leveldb::Status status = pdb->Write(fSync ? syncoptions : writeoptions, &batch.batch);
    dbwrapper_private::HandleError(status);
    return true;
}

bool CDBWrapper::IsEmpty()
{
    boost::scoped_ptr<CDBIterator> it(NewIterator());
    it->SeekToFirst();
    return !(it->Valid());
}

CDBIterator::~CDBIterator() { delete piter; }
bool CDBIterator::Valid() { return piter->Valid(); }
void CDBIterator::SeekToFirst() { piter->SeekToFirst(); }
void CDBIterator::Next() { piter->Next(); }

namespace dbwrapper_private {

bool IsEnvironmentalIOError(const std::string& statusText)
{
    // strerror()/Windows texts that leveldb appends to "IO error: <path>: ". A missing or
    // truncated table file is repairable by -reindex and is deliberately not listed.
    static const char* const markers[] = {
        "Permission denied", "Access is denied", "Read-only file system", "No space left",
        "disk is full", "File name too long", "path too long", "Resource temporarily unavailable",
        "Too many open files", "Not a directory", "Is a directory", "already held", "being used by another process",
        "Operation not permitted", "Quota exceeded"};
    for (const char* m : markers) {
        if (statusText.find(m) != std::string::npos)
            return true;
    }
    return false;
}

void HandleError(const leveldb::Status& status)
{
    if (status.ok())
        return;
    const std::string text = status.ToString();
    LogPrintf("%s\n", text);
    if (status.IsCorruption())
        throw dbwrapper_error("Database corrupted: " + text);
    if (status.IsIOError())
        throw dbwrapper_error("Database I/O error: " + text, IsEnvironmentalIOError(text));
    if (status.IsNotFound())
        throw dbwrapper_error("Database entry missing: " + text);
    throw dbwrapper_error("Unknown database error: " + text);
}

};
