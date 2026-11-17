// Replays the shielded consensus checks over real mainnet blocks read straight
// from blk*.dat files. No chain state, no network, no datadir.
//
//   ZCL_MAINNET_BLK_FILES=/path/blk00030.dat:/path/blk00051.dat \
//   ZCL_MAINNET_BLK_THREADS=8 ./zcash-gtest --gtest_filter=MainnetBlocks.*
//
// Without ZCL_MAINNET_BLK_FILES the test does nothing (the data is not in git).
// The files are opened read-only; point it at COPIES, never at a live datadir.
//
// For every transaction with Sapling or JoinSplit components it runs
//   - ContextualCheckTransaction() at the block's own height (BIP34 height in
//     the coinbase) with a "not in initial block download" predicate: Sapling
//     spend proofs, spendAuthSigs, output proofs and the binding signature;
//   - CheckTransaction() with a strict ProofVerifier: every JoinSplit proof
//     (Groth16 after Sapling, PHGR13 before; ZCL_MAINNET_BLK_PHGR=0 skips the
//     slow PHGR13 ones).
// These are blocks the network accepted, so every check must pass. A daemon
// importing the same files would skip ContextualCheckTransaction entirely
// (initial block download), which is why this test exists.
#include <gtest/gtest.h>

#include "chainparams.h"
#include "clientversion.h"
#include "compat/endian.h"
#include "consensus/validation.h"
#include "init.h" // pzcashParams: what CheckTransaction() verifies JoinSplits with
#include "main.h"
#include "primitives/block.h"
#include "script/script.h"
#include "streams.h"
#include "util.h"
#include "zcash/JoinSplit.hpp"
#include "zcash/Proof.hpp"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include <boost/thread.hpp>

extern ZCJoinSplit* params;       // gtest/main.cpp: loaded Sprout keys


namespace {

bool NotInIBD() { return false; }

struct ShieldedBlock {
    int height;
    uint256 hash;
    std::vector<CTransaction> txs; // only the transactions with shielded parts
};

// BIP34 height from the coinbase scriptSig, or -1.
int CoinbaseHeight(const CBlock& block)
{
    if (block.vtx.empty() || block.vtx[0].vin.empty())
        return -1;
    const CScript& sig = block.vtx[0].vin[0].scriptSig;
    CScript::const_iterator pc = sig.begin();
    opcodetype op;
    std::vector<unsigned char> data;
    if (!sig.GetOp(pc, op, data))
        return -1;
    if (op >= OP_1 && op <= OP_16)
        return CScript::DecodeOP_N(op);
    if (data.empty() || data.size() > 4)
        return -1;
    int h;
    try {
        h = CScriptNum(data, false).getint();
    } catch (const scriptnum_error&) {
        return -1;
    }
    // A first push that is not a height (a legacy "04ffff001d"-style coinbase).
    return (h >= 0 && h < 100000000) ? h : -1;
}

bool HasShielded(const CTransaction& tx)
{
    return !tx.vjoinsplit.empty() || !tx.vShieldedSpend.empty() || !tx.vShieldedOutput.empty();
}

// Same framing as LoadExternalBlockFile(): network magic, 4-byte length, block.
bool ReadBlkFile(const std::string& path, std::vector<ShieldedBlock>& out,
                 uint64_t& nBlocks, int& minHeight, int& maxHeight, std::string& err)
{
    FILE* f = fopen(path.c_str(), "rb");
    if (!f) {
        err = "cannot open " + path;
        return false;
    }
    std::vector<char> buf;
    {
        char chunk[1 << 16];
        size_t n;
        while ((n = fread(chunk, 1, sizeof(chunk), f)) > 0)
            buf.insert(buf.end(), chunk, chunk + n);
        fclose(f);
    }
    const unsigned char* magic = Params().MessageStart();
    size_t pos = 0;
    while (pos + 8 <= buf.size()) {
        if (memcmp(&buf[pos], magic, 4) != 0) {
            pos++; // zero padding between/after blocks
            continue;
        }
        uint32_t nSize;
        memcpy(&nSize, &buf[pos + 4], 4);
        nSize = le32toh(nSize);
        if (nSize < 80 || nSize > GENEROUS_BLOCK_SIZE_LIMIT || pos + 8 + nSize > buf.size()) {
            pos++;
            continue;
        }
        CBlock block;
        try {
            CDataStream ss(&buf[pos + 8], &buf[pos + 8] + nSize, SER_DISK, CLIENT_VERSION);
            ss >> block;
        } catch (const std::exception& e) {
            err = strprintf("%s: block at offset %u does not deserialize: %s", path, (unsigned)pos, e.what());
            return false;
        }
        pos += 8 + nSize;
        nBlocks++;
        int h = CoinbaseHeight(block);
        if (h < 0) {
            // Genesis has no height push; it has no shielded data either.
            continue;
        }
        ShieldedBlock sb;
        sb.height = h;
        for (const CTransaction& tx : block.vtx)
            if (HasShielded(tx))
                sb.txs.push_back(tx);
        if (!sb.txs.empty()) {
            if (h < minHeight) minHeight = h;
            if (h > maxHeight) maxHeight = h;
            sb.hash = block.GetHash();
            out.push_back(std::move(sb));
        }
    }
    return true;
}

} // namespace

TEST(MainnetBlocks, ShieldedConsensusChecksAcceptRealBlocks)
{
    const char* env = getenv("ZCL_MAINNET_BLK_FILES");
    if (env == nullptr || env[0] == '\0') {
        printf("[  SKIPPED ] set ZCL_MAINNET_BLK_FILES=<blk file>[:<blk file>...] to run\n");
        return;
    }
    const char* tenv = getenv("ZCL_MAINNET_BLK_THREADS");
    int nThreads = tenv ? atoi(tenv) : 1;
    if (nThreads < 1) nThreads = 1;
    if (nThreads > 64) nThreads = 64;
    const char* penv = getenv("ZCL_MAINNET_BLK_PHGR");
    const bool fPHGR = !(penv && penv[0] == '0');

    SelectParams(CBaseChainParams::MAIN);
    ZCJoinSplit* savedParams = pzcashParams;
    pzcashParams = params;
    ASSERT_TRUE(pzcashParams != nullptr);

    std::vector<ShieldedBlock> blocks;
    uint64_t nBlocks = 0;
    int minHeight = 0x7fffffff, maxHeight = -1;
    std::string list(env);
    size_t start = 0;
    int nFiles = 0;
    while (start <= list.size()) {
        size_t end = list.find(':', start);
        if (end == std::string::npos) end = list.size();
        std::string path = list.substr(start, end - start);
        start = end + 1;
        if (path.empty()) continue;
        std::string err;
        ASSERT_TRUE(ReadBlkFile(path, blocks, nBlocks, minHeight, maxHeight, err)) << err;
        nFiles++;
    }
    ASSERT_GT(nBlocks, 0u) << "no mainnet blocks found in ZCL_MAINNET_BLK_FILES";

    std::atomic<size_t> next(0);
    std::atomic<uint64_t> nTx(0), nSpend(0), nOutput(0), nGroth(0), nPHGR(0), nPHGRSkipped(0), nFail(0);
    std::mutex failMutex;
    std::vector<std::string> failures;

    auto worker = [&]() {
        for (;;) {
            size_t i = next.fetch_add(1);
            if (i >= blocks.size())
                return;
            const ShieldedBlock& sb = blocks[i];
            for (const CTransaction& tx : sb.txs) {
                std::string why;
                bool ok = true;
                if (!tx.vShieldedSpend.empty() || !tx.vShieldedOutput.empty() || !tx.vjoinsplit.empty()) {
                    CValidationState state;
                    if (!ContextualCheckTransaction(tx, state, sb.height, 100, NotInIBD)) {
                        ok = false;
                        why = "ContextualCheckTransaction: " + state.GetRejectReason();
                    }
                }
                if (ok && !tx.vjoinsplit.empty()) {
                    // As in transaction serialization: the JoinSplit proof is Groth16
                    // exactly when the transaction is a Sapling-version one, else PHGR13.
                    const bool groth = tx.fOverwintered && tx.nVersion >= SAPLING_TX_VERSION;
                    if (groth || fPHGR) {
                        auto verifier = libzcash::ProofVerifier::Strict();
                        CValidationState state;
                        if (!CheckTransaction(tx, state, verifier)) {
                            ok = false;
                            why = "CheckTransaction: " + state.GetRejectReason();
                        }
                        (groth ? nGroth : nPHGR) += tx.vjoinsplit.size();
                    } else {
                        nPHGRSkipped += tx.vjoinsplit.size();
                    }
                }
                nTx++;
                nSpend += tx.vShieldedSpend.size();
                nOutput += tx.vShieldedOutput.size();
                if (!ok) {
                    nFail++;
                    std::lock_guard<std::mutex> lock(failMutex);
                    if (failures.size() < 20)
                        failures.push_back(strprintf("height %d block %s tx %s: %s",
                            sb.height, sb.hash.GetHex(), tx.GetHash().GetHex(), why));
                }
            }
        }
    };
    boost::thread_group threads;
    for (int t = 0; t < nThreads; t++)
        threads.create_thread(worker);
    threads.join_all();

    printf("[ MAINNET  ] files=%d blocks=%llu blocks_with_shielded=%llu shielded_heights=%d..%d "
           "shielded_txs=%llu sapling_spends=%llu sapling_outputs=%llu "
           "joinsplits_groth16=%llu joinsplits_phgr13=%llu joinsplits_phgr13_skipped=%llu failures=%llu threads=%d\n",
           nFiles, (unsigned long long)nBlocks, (unsigned long long)blocks.size(), minHeight, maxHeight,
           (unsigned long long)nTx.load(),
           (unsigned long long)nSpend.load(), (unsigned long long)nOutput.load(),
           (unsigned long long)nGroth.load(), (unsigned long long)nPHGR.load(),
           (unsigned long long)nPHGRSkipped.load(), (unsigned long long)nFail.load(), nThreads);
    for (const std::string& s : failures)
        ADD_FAILURE() << s;
    EXPECT_EQ(nFail.load(), 0u);

    pzcashParams = savedParams;
}
