// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "txmempool.h"
#include "util.h"

#include "test/test_bitcoin.h"

#include <boost/test/unit_test.hpp>
#include <list>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(mempool_cap_tests, TestingSetup)

static CMutableTransaction MakeCapTx(unsigned int seed)
{
    CMutableTransaction tx;
    tx.vin.resize(1);
    tx.vin[0].scriptSig = CScript() << OP_11;
    tx.vin[0].prevout.hash = uint256S(strprintf("%064x", seed + 1));
    tx.vin[0].prevout.n = 0;
    tx.vout.resize(1);
    tx.vout[0].scriptPubKey = CScript() << OP_11 << OP_EQUAL;
    tx.vout[0].nValue = 11000LL;
    return tx;
}

BOOST_AUTO_TEST_CASE(MempoolCapFillsRefusesAndFreesRoom)
{
    const uint64_t savedCap = nMempoolMaxBytes;
    TestMemPoolEntryHelper entry;
    CTxMemPool pool(CFeeRate(0));

    CMutableTransaction probe = MakeCapTx(0);
    const size_t txSize = ::GetSerializeSize(CTransaction(probe), SER_NETWORK, PROTOCOL_VERSION);
    BOOST_REQUIRE(txSize > 0);

    // Room for exactly three transactions.
    nMempoolMaxBytes = 3 * txSize;
    std::string err;

    std::vector<CMutableTransaction> txs;
    for (unsigned int i = 0; i < 3; i++) {
        txs.push_back(MakeCapTx(i));
        BOOST_CHECK_MESSAGE(CheckMempoolCapacity(pool, txSize, err), "tx " << i << " fits: " << err);
        pool.addUnchecked(txs[i].GetHash(), entry.Fee(10000LL).FromTx(txs[i]));
    }
    BOOST_CHECK_EQUAL(pool.size(), 3u);
    BOOST_CHECK_EQUAL(pool.GetTotalTxSize(), 3 * txSize);

    // Exactly at the cap: the next one is refused, with the reason, and nothing is evicted.
    CMutableTransaction extra = MakeCapTx(3);
    BOOST_CHECK(!CheckMempoolCapacity(pool, txSize, err));
    BOOST_CHECK(err.find("mempool full") != std::string::npos);
    BOOST_CHECK(err.find("-mempoolmaxbytes") != std::string::npos);
    BOOST_CHECK_EQUAL(pool.size(), 3u);
    for (const CMutableTransaction& t : txs)
        BOOST_CHECK(pool.exists(t.GetHash()));

    // Removal frees room for one more, and only one more.
    std::list<CTransaction> removed;
    pool.remove(CTransaction(txs[1]), removed, false);
    BOOST_CHECK_EQUAL(pool.size(), 2u);
    BOOST_CHECK(CheckMempoolCapacity(pool, txSize, err));
    pool.addUnchecked(extra.GetHash(), entry.Fee(10000LL).FromTx(extra));
    BOOST_CHECK(!CheckMempoolCapacity(pool, txSize, err));

    // Raising the cap makes room again.
    nMempoolMaxBytes = 4 * txSize;
    BOOST_CHECK(CheckMempoolCapacity(pool, txSize, err));

    nMempoolMaxBytes = savedCap;
}

BOOST_AUTO_TEST_CASE(MempoolCapDefaults)
{
    BOOST_CHECK_EQUAL(DEFAULT_MEMPOOL_MAX_BYTES, 300000000u);
    BOOST_CHECK_EQUAL(MIN_MEMPOOL_MAX_BYTES, 5000000u);
}

BOOST_AUTO_TEST_SUITE_END()
