// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Unit tests for z_sendmany coin-control (the optional "inputs" parameter).
//
// NON-CONSENSUS: coin-control only restricts which already-valid inputs the
// wallet may select. These tests exercise (a) the constructor wiring that
// carries the pinned sets into the operation, and (b) the exact set-membership
// filter semantics used by find_utxos()/find_unspent_notes() to restrict the
// spend to the pinned inputs and to reject a pinned input that is not available.

#include <gtest/gtest.h>

#include <set>
#include <tuple>
#include <vector>

#include "amount.h"
#include "chainparams.h"
#include "key_io.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "wallet/asyncrpcoperation_sendmany.h"
#include "wallet/wallet.h"
#include "zcash/Address.hpp"
#include "zcash/Note.hpp"

using namespace libzcash;

namespace {

uint256 TxidFromByte(unsigned char b) {
    uint256 h;
    h.begin()[0] = b;
    return h;
}

SendManyInputUTXO MakeUtxo(unsigned char idByte, int vout, CAmount amount, bool coinbase = false) {
    return SendManyInputUTXO(TxidFromByte(idByte), vout, amount, coinbase);
}

SaplingNoteEntry MakeSaplingEntry(unsigned char idByte, uint32_t outindex, CAmount amount) {
    SaplingNoteEntry e;
    e.op = SaplingOutPoint(TxidFromByte(idByte), outindex);
    diversifier_t d = {{0}};
    e.note = SaplingNote(d, uint256(), (uint64_t)amount, uint256());
    e.confirmations = 10;
    return e;
}

SendManyInputJSOP MakeSproutInput(unsigned char idByte, uint64_t js, uint8_t n, CAmount amount) {
    JSOutPoint jsop(TxidFromByte(idByte), js, n);
    SproutNote note(uint256(), (uint64_t)amount, uint256(), uint256());
    return SendManyInputJSOP(jsop, note, amount);
}

// Replicates the exact filter the production find_utxos() applies when
// useInputSelection_ is true: keep only pinned UTXOs, and throw (here: report
// via the `missing` out-param) if a pinned outpoint is not in the available set.
std::vector<SendManyInputUTXO> FilterTransparent(
        const std::vector<SendManyInputUTXO>& available,
        const std::set<COutPoint>& pinned,
        bool& missing) {
    missing = false;
    std::set<COutPoint> have;
    for (const SendManyInputUTXO& t : available) {
        have.insert(COutPoint(std::get<0>(t), std::get<1>(t)));
    }
    for (const COutPoint& op : pinned) {
        if (!have.count(op)) {
            missing = true;
        }
    }
    std::vector<SendManyInputUTXO> filtered;
    for (const SendManyInputUTXO& t : available) {
        if (pinned.count(COutPoint(std::get<0>(t), std::get<1>(t)))) {
            filtered.push_back(t);
        }
    }
    return filtered;
}

std::vector<SaplingNoteEntry> FilterSapling(
        const std::vector<SaplingNoteEntry>& available,
        const std::set<SaplingOutPoint>& pinned,
        bool& missing) {
    missing = false;
    std::set<SaplingOutPoint> have;
    for (const SaplingNoteEntry& e : available) {
        have.insert(e.op);
    }
    for (const SaplingOutPoint& op : pinned) {
        if (!have.count(op)) {
            missing = true;
        }
    }
    std::vector<SaplingNoteEntry> filtered;
    for (const SaplingNoteEntry& e : available) {
        if (pinned.count(e.op)) {
            filtered.push_back(e);
        }
    }
    return filtered;
}

std::vector<SendManyInputJSOP> FilterSprout(
        const std::vector<SendManyInputJSOP>& available,
        const std::set<JSOutPoint>& pinned,
        bool& missing) {
    missing = false;
    std::set<JSOutPoint> have;
    for (const SendManyInputJSOP& t : available) {
        have.insert(std::get<0>(t));
    }
    for (const JSOutPoint& op : pinned) {
        if (!have.count(op)) {
            missing = true;
        }
    }
    std::vector<SendManyInputJSOP> filtered;
    for (const SendManyInputJSOP& t : available) {
        if (pinned.count(std::get<0>(t))) {
            filtered.push_back(t);
        }
    }
    return filtered;
}

CAmount TotalTransparent(const std::vector<SendManyInputUTXO>& v) {
    CAmount total = 0;
    for (const SendManyInputUTXO& t : v) {
        total += std::get<2>(t);
    }
    return total;
}

} // namespace

// Transparent: only the pinned UTXOs survive the filter; the unpinned ones are
// dropped even though they are spendable.
TEST(CoinControl, TransparentFilterSelectsOnlyPinned) {
    std::vector<SendManyInputUTXO> available = {
        MakeUtxo(0x01, 0, 100),
        MakeUtxo(0x02, 0, 200),
        MakeUtxo(0x03, 1, 300),
    };
    std::set<COutPoint> pinned = {
        COutPoint(TxidFromByte(0x01), 0),
        COutPoint(TxidFromByte(0x03), 1),
    };

    bool missing = false;
    auto filtered = FilterTransparent(available, pinned, missing);
    EXPECT_FALSE(missing);
    ASSERT_EQ(filtered.size(), 2u);
    // The 200-value unpinned UTXO must be gone.
    for (const auto& t : filtered) {
        EXPECT_NE(std::get<2>(t), CAmount(200));
    }
    EXPECT_EQ(TotalTransparent(filtered), CAmount(400));
}

// Transparent: a pinned outpoint that is not in the available (spendable,
// confirmed, owned) set must be detected so the operation fails pre-send.
TEST(CoinControl, TransparentPinnedAbsentIsDetected) {
    std::vector<SendManyInputUTXO> available = {
        MakeUtxo(0x01, 0, 100),
    };
    std::set<COutPoint> pinned = {
        COutPoint(TxidFromByte(0x01), 0),
        COutPoint(TxidFromByte(0x09), 7), // not available
    };

    bool missing = false;
    FilterTransparent(available, pinned, missing);
    EXPECT_TRUE(missing);
}

// Transparent: pinning a subset whose total is below the target is recognised
// as insufficient (the operation's existing target check fails pre-send).
TEST(CoinControl, TransparentPinnedSubsetInsufficient) {
    std::vector<SendManyInputUTXO> available = {
        MakeUtxo(0x01, 0, 100),
        MakeUtxo(0x02, 0, 9000),
    };
    // Pin only the small UTXO.
    std::set<COutPoint> pinned = { COutPoint(TxidFromByte(0x01), 0) };

    bool missing = false;
    auto filtered = FilterTransparent(available, pinned, missing);
    EXPECT_FALSE(missing);
    CAmount targetAmount = 500; // > 100 pinned
    EXPECT_LT(TotalTransparent(filtered), targetAmount);
}

// Sapling: only pinned notes survive; an absent pinned note is detected.
TEST(CoinControl, SaplingFilterSelectsOnlyPinned) {
    std::vector<SaplingNoteEntry> available = {
        MakeSaplingEntry(0x10, 0, 1000),
        MakeSaplingEntry(0x11, 0, 2000),
        MakeSaplingEntry(0x11, 1, 3000),
    };
    std::set<SaplingOutPoint> pinned = {
        SaplingOutPoint(TxidFromByte(0x11), 1),
    };

    bool missing = false;
    auto filtered = FilterSapling(available, pinned, missing);
    EXPECT_FALSE(missing);
    ASSERT_EQ(filtered.size(), 1u);
    EXPECT_EQ(filtered[0].note.value(), (uint64_t)3000);

    std::set<SaplingOutPoint> badPin = { SaplingOutPoint(TxidFromByte(0xFF), 0) };
    FilterSapling(available, badPin, missing);
    EXPECT_TRUE(missing);
}

// Sprout: only pinned notes survive; an absent pinned note is detected.
TEST(CoinControl, SproutFilterSelectsOnlyPinned) {
    std::vector<SendManyInputJSOP> available = {
        MakeSproutInput(0x20, 0, 0, 500),
        MakeSproutInput(0x20, 0, 1, 700),
        MakeSproutInput(0x21, 3, 1, 900),
    };
    std::set<JSOutPoint> pinned = {
        JSOutPoint(TxidFromByte(0x20), 0, 1),
    };

    bool missing = false;
    auto filtered = FilterSprout(available, pinned, missing);
    EXPECT_FALSE(missing);
    ASSERT_EQ(filtered.size(), 1u);
    EXPECT_EQ(std::get<2>(filtered[0]), CAmount(700));

    std::set<JSOutPoint> badPin = { JSOutPoint(TxidFromByte(0x20), 9, 0) };
    FilterSprout(available, badPin, missing);
    EXPECT_TRUE(missing);
}

// Constructor wiring: the new coin-control args are carried into the operation
// and surfaced through the test friend. Default construction leaves selection
// disabled (so existing callers / change routing are untouched).
TEST(CoinControl, ConstructorCarriesPinnedSets) {
    // The from-address below is a TESTNET taddr; decode it under TESTNET params.
    SelectParams(CBaseChainParams::TESTNET);

    CMutableTransaction mtx;
    mtx.nVersion = 2;

    std::vector<SendManyRecipient> recipients = {
        SendManyRecipient("dummy", CAmount(1), "")
    };

    std::set<COutPoint> pinnedT = { COutPoint(TxidFromByte(0x01), 0) };
    std::set<SaplingOutPoint> pinnedS;
    std::set<JSOutPoint> pinnedJ;

    // A transparent from-address keeps construction lightweight (no spending-key
    // lookup for a zaddr). We never run main(); we only inspect the wiring.
    std::shared_ptr<AsyncRPCOperation_sendmany> op(
        new AsyncRPCOperation_sendmany(
            boost::none, mtx, "tmRr6yJonqGK23UVhrKuyvTpF8qxQQjKigJ",
            recipients, {}, 1,
            ASYNC_RPC_OPERATION_DEFAULT_MINERS_FEE, NullUniValue,
            /*useInputSelection=*/true, pinnedT, pinnedS, pinnedJ));
    TEST_FRIEND_AsyncRPCOperation_sendmany proxy(op);

    EXPECT_TRUE(proxy.useInputSelection());
    EXPECT_EQ(proxy.pinnedTransparent().size(), 1u);
    EXPECT_EQ(proxy.pinnedSapling().size(), 0u);
    EXPECT_EQ(proxy.pinnedSprout().size(), 0u);
    EXPECT_EQ(proxy.pinnedTransparent().count(COutPoint(TxidFromByte(0x01), 0)), 1u);

    // Default (no coin-control) construction must leave selection disabled.
    std::shared_ptr<AsyncRPCOperation_sendmany> opDefault(
        new AsyncRPCOperation_sendmany(
            boost::none, mtx, "tmRr6yJonqGK23UVhrKuyvTpF8qxQQjKigJ",
            recipients, {}, 1));
    TEST_FRIEND_AsyncRPCOperation_sendmany proxyDefault(opDefault);
    EXPECT_FALSE(proxyDefault.useInputSelection());
    EXPECT_EQ(proxyDefault.pinnedTransparent().size(), 0u);
}
