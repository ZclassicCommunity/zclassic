// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// The ZSLP index service: owns the store and a reconcile worker that follows
// the active chain. It is notified through ChainTip, but it does not trust the
// notification: the worker compares its own best block with chainActive and
// connects or disconnects until they agree, so a missed, coalesced or
// reordered notification, a crash, a reindex or a restart cannot leave it
// wrong. It never holds cs_main while it reads a block or writes its store.

#ifndef BITCOIN_ZSLP_ZSLPSERVICE_H
#define BITCOIN_ZSLP_ZSLPSERVICE_H

#include "validationinterface.h"
#include "zslp/zslpindex.h"

#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace zslp {

struct ServiceInfo {
    bool running;
    bool synced;        //! the index tip is the active chain tip
    int startHeight;    //! first height the index looks at
    bool hasIndexed;
    int indexedHeight;
    uint256 indexedHash;
    int chainHeight;
    std::string error;  //! last problem the worker is retrying, "" when none
    ServiceInfo() : running(false), synced(false), startHeight(0), hasIndexed(false), indexedHeight(-1), chainHeight(-1) {}
};

class ZslpService : public CValidationInterface
{
public:
    /** Takes ownership of kv. */
    ZslpService(KV* kv, int startHeight);
    ~ZslpService();

    /** Opens the index and starts the worker thread. */
    bool Start(std::string& err);
    void Stop();

    ZslpIndex& Index() { return index; }
    ServiceInfo GetInfo() const;

    /** One reconcile step (exposed for tests): connect, disconnect or nothing. True if it changed the index. */
    bool Step();

protected:
    void ChainTip(const CBlockIndex* pindex, const CBlock* pblock, const SproutMerkleTree& sproutTree,
                  const SaplingMerkleTree& saplingTree, bool added);

private:
    void Run();
    void SetError(const std::string& e);

    std::unique_ptr<KV> kv;
    ZslpIndex index;
    int startHeight;
    std::thread worker;
    mutable std::mutex m;
    std::condition_variable cv;
    bool fStop;
    bool fRunning;
    int chainHeight;
    std::string lastError;
};

/** Starts the service from the command line options (-zslpindexstart); false with err on failure. */
bool StartService(std::string& err);
/** Stops and deletes the service. Safe to call when it never started. */
void StopService();
/** First height the index reads when -zslpindexstart is not given. */
int DefaultStartHeight();

/** The running service, or NULL when -zslpindex is off. Set by init, read by RPC. */
extern ZslpService* pzslpService;

} // namespace zslp

#endif // BITCOIN_ZSLP_ZSLPSERVICE_H
