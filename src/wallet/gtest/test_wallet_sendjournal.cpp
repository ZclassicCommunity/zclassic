// The send journal ("send once" for z_sendmany): the canonical request digest, the state
// machine, the wallet.dat record, and the wallet-side steps.

#include <gtest/gtest.h>

#include "chainparams.h"
#include "crypto/sha256.h"
#include "utilstrencodings.h"
#include "utiltime.h"
#include "key.h"
#include "primitives/transaction.h"
#include "pubkey.h"
#include "rpc/protocol.h"
#include "script/script.h"
#include "streams.h"
#include "util.h"
#include "wallet/sendjournal.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"

#include <boost/filesystem.hpp>

namespace fs = boost::filesystem;

namespace {

std::vector<SendOnceRecipient> Recips()
{
    std::vector<SendOnceRecipient> v;
    SendOnceRecipient a; a.address = "zs1aaaa"; a.amount = 150000000; a.memoHex = "AbCd";
    SendOnceRecipient b; b.address = "t1bbbb"; b.amount = 7; b.memoHex = "";
    v.push_back(a); v.push_back(b);
    return v;
}

CSendOnceRecord Rec(uint8_t state, uint32_t expiry = 0, int64_t built = 1000)
{
    CSendOnceRecord r;
    r.state = state;
    r.opid = "opid-1";
    r.requestDigest = uint256S("11");
    r.txid = state >= SENDONCE_BUILT ? uint256S("22") : uint256();
    r.nExpiryHeight = expiry;
    r.nTimeStarted = 900;
    r.nTimeBuilt = built;
    return r;
}

} // namespace

TEST(SendJournal, KeyValidation) {
    EXPECT_TRUE(IsValidSendOnceKey("a"));
    EXPECT_TRUE(IsValidSendOnceKey("order-2026.11:18_X"));
    EXPECT_TRUE(IsValidSendOnceKey(std::string(128, 'k')));
    EXPECT_FALSE(IsValidSendOnceKey(""));
    EXPECT_FALSE(IsValidSendOnceKey(std::string(129, 'k')));
    EXPECT_FALSE(IsValidSendOnceKey("has space"));
    EXPECT_FALSE(IsValidSendOnceKey("slash/"));
    EXPECT_FALSE(IsValidSendOnceKey(std::string("a\0b", 3)));
    EXPECT_FALSE(IsValidSendOnceKey("\xc3\xa9"));
    EXPECT_NE(SendOnceKeyHash("a"), SendOnceKeyHash("b"));
    EXPECT_EQ(SendOnceKeyHash("a"), SendOnceKeyHash("a"));
}

TEST(SendJournal, KeyHashIsPlainSha256) {
    // SHA-256("abc")
    EXPECT_EQ(std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
              [] { uint256 h = SendOnceKeyHash("abc"); return HexStr(h.begin(), h.end()); }());
}

TEST(SendJournal, RequestDigestIsCanonical) {
    const uint256 base = SendOnceRequestDigest("zsfrom", Recips(), 1, 10000);
    EXPECT_EQ(base, SendOnceRequestDigest("zsfrom", Recips(), 1, 10000));
    // every field is part of the request
    EXPECT_NE(base, SendOnceRequestDigest("zsother", Recips(), 1, 10000));
    EXPECT_NE(base, SendOnceRequestDigest("zsfrom", Recips(), 2, 10000));
    EXPECT_NE(base, SendOnceRequestDigest("zsfrom", Recips(), 1, 10001));
    {
        auto r = Recips(); r[0].amount++;
        EXPECT_NE(base, SendOnceRequestDigest("zsfrom", r, 1, 10000));
    }
    {
        auto r = Recips(); r[0].address = "zs1aaab";
        EXPECT_NE(base, SendOnceRequestDigest("zsfrom", r, 1, 10000));
    }
    {
        auto r = Recips(); r[0].memoHex = "abce";
        EXPECT_NE(base, SendOnceRequestDigest("zsfrom", r, 1, 10000));
    }
    {   // the order of recipients is part of the request
        auto r = Recips(); std::swap(r[0], r[1]);
        EXPECT_NE(base, SendOnceRequestDigest("zsfrom", r, 1, 10000));
    }
    {   // one recipient fewer
        auto r = Recips(); r.pop_back();
        EXPECT_NE(base, SendOnceRequestDigest("zsfrom", r, 1, 10000));
    }
    // the memo is hashed lower-cased: AbCd and abcd are one request
    {
        auto r = Recips(); r[0].memoHex = "abcd";
        EXPECT_EQ(base, SendOnceRequestDigest("zsfrom", r, 1, 10000));
    }
    // the fields are length-prefixed: moving a character from one field to the next changes the digest
    {
        std::vector<SendOnceRecipient> a(1), b(1);
        a[0].address = "ab"; a[0].amount = 1; a[0].memoHex = "c";
        b[0].address = "a";  b[0].amount = 1; b[0].memoHex = "bc";
        EXPECT_NE(SendOnceRequestDigest("f", a, 1, 1), SendOnceRequestDigest("f", b, 1, 1));
        EXPECT_NE(SendOnceRequestDigest("fa", a, 1, 1), SendOnceRequestDigest("f", std::vector<SendOnceRecipient>(), 1, 1));
    }
}

TEST(SendJournal, RequestDigestKnownAnswer) {
    // Pins the canonical form: SHA-256 of
    //   0x17 "z23-sendonce-request-v1" | 0x01 "f" | 01 00 00 00 | 0a 00.. (int64 10) | 01 00 00 00 |
    //   0x01 "a" | 05 00.. (int64 5) | 0x02 "ab"
    CDataStream ss(SER_GETHASH, 0);
    ss << std::string("z23-sendonce-request-v1") << std::string("f") << (int32_t)1 << (int64_t)10 << (uint32_t)1
       << std::string("a") << (int64_t)5 << std::string("ab");
    static const unsigned char expect[] = {
        0x17, 'z','2','3','-','s','e','n','d','o','n','c','e','-','r','e','q','u','e','s','t','-','v','1',
        0x01, 'f', 1,0,0,0, 10,0,0,0,0,0,0,0, 1,0,0,0, 0x01, 'a', 5,0,0,0,0,0,0,0, 0x02, 'a','b'};
    ASSERT_EQ(sizeof(expect), ss.size());
    EXPECT_EQ(0, memcmp(expect, ss.data(), sizeof(expect)));
    std::vector<SendOnceRecipient> r(1);
    r[0].address = "a"; r[0].amount = 5; r[0].memoHex = "AB";
    uint256 want;
    CSHA256().Write(expect, sizeof(expect)).Finalize(want.begin());
    EXPECT_EQ(want, SendOnceRequestDigest("f", r, 1, 10));
}

TEST(SendJournal, RecordRoundTripAndContent) {
    CSendOnceRecord r = Rec(SENDONCE_BUILT, 77);
    r.nErrorCode = -26;
    r.strError = "txn-mempool-conflict";
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << r;
    CSendOnceRecord back;
    ss >> back;
    EXPECT_EQ(r.requestDigest, back.requestDigest);
    EXPECT_EQ(r.state, back.state);
    EXPECT_EQ(r.opid, back.opid);
    EXPECT_EQ(r.txid, back.txid);
    EXPECT_EQ(77u, back.nExpiryHeight);
    EXPECT_EQ(r.nTimeStarted, back.nTimeStarted);
    EXPECT_EQ(r.nTimeBuilt, back.nTimeBuilt);
    EXPECT_EQ(-26, back.nErrorCode);
    EXPECT_EQ("txn-mempool-conflict", back.strError);
    EXPECT_EQ(SENDONCE_RECORD_VERSION, back.nRecordVersion);

    // the record is built from hashes: the key and request text never reach it
    const std::string key = "my-secret-idempotency-key";
    const std::string from = "zs1sourceaddressxyz";
    std::vector<SendOnceRecipient> rec(1);
    rec[0].address = "zs1destinationaddr"; rec[0].amount = 123456789; rec[0].memoHex = "deadbeefcafe";
    CSendOnceRecord q = Rec(SENDONCE_STARTED);
    q.requestDigest = SendOnceRequestDigest(from, rec, 1, 10000);
    CDataStream sq(SER_DISK, CLIENT_VERSION);
    sq << q;
    const std::string bytes(sq.begin(), sq.end());
    EXPECT_EQ(std::string::npos, bytes.find(key));
    EXPECT_EQ(std::string::npos, bytes.find(from));
    EXPECT_EQ(std::string::npos, bytes.find("zs1destinationaddr"));
    EXPECT_EQ(std::string::npos, bytes.find("deadbeefcafe"));
}

TEST(SendJournal, ResolveStateMachine) {
    SendOnceFacts f;
    f.tipHeight = 100;
    f.now = 5000;

    // STARTED: live operation stays started; without one the key is released (record erased)
    {
        f.opLive = true;
        SendOnceResolution r = ResolveSendOnce(Rec(SENDONCE_STARTED), f);
        EXPECT_EQ(SendOnceLabel::STARTED, r.label);
        EXPECT_FALSE(r.fErase);
        f.opLive = false;
        r = ResolveSendOnce(Rec(SENDONCE_STARTED), f);
        EXPECT_EQ(SendOnceLabel::RELEASED, r.label);
        EXPECT_TRUE(r.fErase);
    }
    // BUILT: in the mempool or a block -> committed
    {
        f.opLive = false;
        f.txInMempool = true;
        SendOnceResolution r = ResolveSendOnce(Rec(SENDONCE_BUILT, 500), f);
        EXPECT_EQ(SendOnceLabel::COMMITTED, r.label);
        EXPECT_EQ((int)SENDONCE_COMMITTED, r.newState);
        f.txInMempool = false; f.txMined = true;
        r = ResolveSendOnce(Rec(SENDONCE_BUILT, 500), f);
        EXPECT_EQ(SendOnceLabel::COMMITTED, r.label);
        f.txMined = false;
    }
    // BUILT, nowhere: outcome unknown up to expiry height + margin, then expired
    {
        SendOnceResolution r = ResolveSendOnce(Rec(SENDONCE_BUILT, 100), f);        // tip == expiry
        EXPECT_EQ(SendOnceLabel::OUTCOME_UNKNOWN, r.label);
        EXPECT_EQ(0, r.newState);
        f.tipHeight = 100 + SENDONCE_EXPIRY_MARGIN;                                  // tip == expiry + margin: still unknown
        EXPECT_EQ(SendOnceLabel::OUTCOME_UNKNOWN, ResolveSendOnce(Rec(SENDONCE_BUILT, 100), f).label);
        f.tipHeight = 100 + SENDONCE_EXPIRY_MARGIN + 1;                              // beyond: expired, released
        r = ResolveSendOnce(Rec(SENDONCE_BUILT, 100), f);
        EXPECT_EQ(SendOnceLabel::EXPIRED, r.label);
        EXPECT_EQ((int)SENDONCE_EXPIRED, r.newState);
        f.tipHeight = 100;
    }
    // the margin is beyond the deepest reorg the node accepts
    EXPECT_GT(SENDONCE_EXPIRY_MARGIN, (int)MAX_REORG_LENGTH);
    // BUILT or COMMITTED without an expiry height: never released, however long ago and however high the tip
    {
        f.now = 5000 + 10LL * 365 * 24 * 3600;
        f.tipHeight = 1000000;
        SendOnceResolution r = ResolveSendOnce(Rec(SENDONCE_BUILT, 0, 5000), f);
        EXPECT_EQ(SendOnceLabel::OUTCOME_UNKNOWN, r.label);
        EXPECT_EQ(0, r.newState);
        EXPECT_FALSE(r.fErase);
        EXPECT_EQ(SendOnceLabel::COMMITTED, ResolveSendOnce(Rec(SENDONCE_COMMITTED, 0, 5000), f).label);
        f.now = 5000;
        f.tipHeight = 100;
    }
    // a committed send that is in neither a block nor the mempool once its expiry has passed is released too;
    // one that is in a block is final whatever the tip
    {
        f.tipHeight = 100 + SENDONCE_EXPIRY_MARGIN + 1;
        SendOnceResolution r = ResolveSendOnce(Rec(SENDONCE_COMMITTED, 100), f);
        EXPECT_EQ(SendOnceLabel::EXPIRED, r.label);
        EXPECT_EQ((int)SENDONCE_EXPIRED, r.newState);
        f.txInMempool = true;
        EXPECT_EQ(SendOnceLabel::COMMITTED, ResolveSendOnce(Rec(SENDONCE_COMMITTED, 100), f).label);
        f.txInMempool = false; f.txMined = true;
        EXPECT_EQ(SendOnceLabel::COMMITTED, ResolveSendOnce(Rec(SENDONCE_COMMITTED, 100), f).label);
        f.txMined = false;
        // in neither, still minable (tip below the expiry height): committed
        f.tipHeight = 99;
        EXPECT_EQ(SendOnceLabel::COMMITTED, ResolveSendOnce(Rec(SENDONCE_COMMITTED, 100), f).label);
        // in neither and past its expiry height, not yet beyond any reorg: undecided, never "committed", not released
        f.tipHeight = 100;
        SendOnceResolution u = ResolveSendOnce(Rec(SENDONCE_COMMITTED, 100), f);
        EXPECT_EQ(SendOnceLabel::OUTCOME_UNKNOWN, u.label);
        EXPECT_EQ(0, u.newState);
        EXPECT_FALSE(u.fErase);
        f.tipHeight = 100 + SENDONCE_EXPIRY_MARGIN;
        EXPECT_EQ(SendOnceLabel::OUTCOME_UNKNOWN, ResolveSendOnce(Rec(SENDONCE_COMMITTED, 100), f).label);
        f.tipHeight = 100;
    }
    // final states stay
    EXPECT_EQ(SendOnceLabel::COMMITTED, ResolveSendOnce(Rec(SENDONCE_COMMITTED), f).label);
    EXPECT_EQ(SendOnceLabel::EXPIRED, ResolveSendOnce(Rec(SENDONCE_EXPIRED), f).label);
    // a state from a newer version is never released
    {
        SendOnceResolution r = ResolveSendOnce(Rec(99), f);
        EXPECT_EQ(SendOnceLabel::OUTCOME_UNKNOWN, r.label);
        EXPECT_FALSE(r.fErase);
        EXPECT_EQ(0, r.newState);
    }
}

TEST(SendJournal, DecideOnCall) {
    const uint256 d1 = uint256S("11"), d2 = uint256S("33");
    SendOnceFacts f;
    f.tipHeight = 100; f.now = 5000;

    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(NULL, d1, f));

    // started and running: same request -> stored; different -> reject
    f.opLive = true;
    CSendOnceRecord st = Rec(SENDONCE_STARTED);
    EXPECT_EQ(SendOnceAction::RETURN_STORED, DecideSendOnce(&st, d1, f));
    EXPECT_EQ(SendOnceAction::REJECT_DIFFERENT, DecideSendOnce(&st, d2, f));
    // started, operation gone (restart): released, either request may proceed
    f.opLive = false;
    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(&st, d1, f));
    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(&st, d2, f));

    // built, outcome unknown: the stored outcome, never a second build; a different request is rejected
    CSendOnceRecord bt = Rec(SENDONCE_BUILT, 150);
    EXPECT_EQ(SendOnceAction::RETURN_STORED, DecideSendOnce(&bt, d1, f));
    EXPECT_EQ(SendOnceAction::REJECT_DIFFERENT, DecideSendOnce(&bt, d2, f));
    // built and in the mempool: committed, stored
    f.txInMempool = true;
    SendOnceResolution res;
    EXPECT_EQ(SendOnceAction::RETURN_STORED, DecideSendOnce(&bt, d1, f, &res));
    EXPECT_EQ((int)SENDONCE_COMMITTED, res.newState);
    f.txInMempool = false;
    // built, expired: released, a retry proceeds (also with another request)
    f.tipHeight = 150 + SENDONCE_EXPIRY_MARGIN + 1;
    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(&bt, d1, f, &res));
    EXPECT_EQ((int)SENDONCE_EXPIRED, res.newState);
    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(&bt, d2, f));

    // committed: stored for the same request, rejected for another, forever
    CSendOnceRecord ct = Rec(SENDONCE_COMMITTED);
    EXPECT_EQ(SendOnceAction::RETURN_STORED, DecideSendOnce(&ct, d1, f));
    EXPECT_EQ(SendOnceAction::REJECT_DIFFERENT, DecideSendOnce(&ct, d2, f));
    // an expired record is a released key
    CSendOnceRecord et = Rec(SENDONCE_EXPIRED);
    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(&et, d1, f));
    EXPECT_EQ(SendOnceAction::PROCEED, DecideSendOnce(&et, d2, f));
}

namespace {

class SendJournalWalletTest : public ::testing::Test {
protected:
    fs::path dataDir;
    std::string prevDataDir, walletFile;
    CWallet* wallet = NULL;

    void Open() {
        wallet = new CWallet(walletFile);
        bool fFirstRun = true;
        ASSERT_EQ(DB_LOAD_OK, wallet->LoadWallet(fFirstRun));
    }
    void Reopen() {
        delete wallet;
        wallet = NULL;
        bitdb.Flush(true);
        bitdb.Reset();
        Open();
    }
    void SetUp() override {
        SelectParams(CBaseChainParams::REGTEST);
        bitdb.Flush(true);
        bitdb.Reset();
        dataDir = fs::temp_directory_path() / UniquePath("zcl-sendjournal-%%%%-%%%%-%%%%");
        fs::create_directories(dataDir);
        prevDataDir = mapArgs.count("-datadir") ? mapArgs["-datadir"] : "";
        mapArgs["-datadir"] = dataDir.string();
        ClearDatadirCache();
        mapArgs["-keypool"] = "5";
        walletFile = "sendjournal-test.dat";
        Open();
    }
    void TearDown() override {
        delete wallet;
        wallet = NULL;
        bitdb.Flush(true);
        bitdb.Reset();
        if (prevDataDir.empty()) mapArgs.erase("-datadir"); else mapArgs["-datadir"] = prevDataDir;
        ClearDatadirCache();
        boost::system::error_code ec; // best effort: never fail a test on a leftover temp dir
        fs::remove_all(dataDir, ec);
    }
};

CTransaction SomeTx(uint32_t expiry)
{
    CMutableTransaction m;
    m.fOverwintered = true;
    m.nVersion = SAPLING_TX_VERSION;
    m.nVersionGroupId = SAPLING_VERSION_GROUP_ID;
    m.nExpiryHeight = expiry;
    m.vin.push_back(CTxIn(COutPoint(uint256S("abcdef"), 0)));
    m.vout.push_back(CTxOut(1000, CScript() << OP_TRUE));
    return CTransaction(m);
}

} // namespace

TEST_F(SendJournalWalletTest, StepsAreDurableAndReload) {
    const uint256 key = SendOnceKeyHash("k1");
    const uint256 digest = uint256S("1234");
    CTransaction tx = SomeTx(321);
    {
        LOCK2(cs_main, wallet->cs_wallet);
        std::string opid;
        ASSERT_EQ(SendOnceBeginResult::PROCEED, SendOnceBegin(wallet, key, digest, opid));
        SendOnceStart(wallet, key, digest, "opid-abc");
    }
    Reopen();
    {
        LOCK(wallet->cs_wallet);
        ASSERT_EQ(1u, wallet->mapSendOnce.size());
        const CSendOnceRecord& r = wallet->mapSendOnce.begin()->second;
        EXPECT_EQ((int)SENDONCE_STARTED, (int)r.state);
        EXPECT_EQ("opid-abc", r.opid);
        EXPECT_EQ(digest, r.requestDigest);
    }
    // restart with STARTED and no live operation: released at start, the key is free
    SendOnceResolveAtStart(wallet);
    {
        LOCK(wallet->cs_wallet);
        EXPECT_TRUE(wallet->mapSendOnce.empty());
    }
    Reopen();
    {
        LOCK(wallet->cs_wallet);
        EXPECT_TRUE(wallet->mapSendOnce.empty());
    }

    // started -> built -> reload
    {
        LOCK2(cs_main, wallet->cs_wallet);
        SendOnceStart(wallet, key, digest, "opid-abc");
    }
    ASSERT_TRUE(SendOnceBuilt(wallet, key, tx));
    Reopen();
    {
        LOCK2(cs_main, wallet->cs_wallet);
        ASSERT_EQ(1u, wallet->mapSendOnce.size());
        const CSendOnceRecord r = wallet->mapSendOnce.begin()->second;
        EXPECT_EQ((int)SENDONCE_BUILT, (int)r.state);
        EXPECT_EQ(tx.GetHash(), r.txid);
        EXPECT_EQ(321u, r.nExpiryHeight);
        // a retry with the same request: the stored outcome, no second build
        std::string opid;
        EXPECT_EQ(SendOnceBeginResult::STORED, SendOnceBegin(wallet, key, digest, opid));
        EXPECT_EQ("opid-abc", opid);
        // another request: error
        try {
            SendOnceBegin(wallet, key, uint256S("9999"), opid);
            ADD_FAILURE() << "expected an error";
        } catch (const UniValue& e) {
            EXPECT_EQ("idempotency key reused with different parameters", find_value(e, "message").get_str());
        }
        // the stored result is reported as an operation that is still undecided
        UniValue st = SendOnceOperationStatus(wallet, "opid-abc");
        ASSERT_TRUE(st.isObject());
        EXPECT_EQ("executing", find_value(st, "status").get_str());
        EXPECT_EQ("outcome_unknown", find_value(st, "journal").get_str());
        UniValue list = SendOnceList(wallet);
        ASSERT_EQ(1u, list.size());
        EXPECT_EQ("outcome_unknown", find_value(list[0], "state").get_str());
        EXPECT_EQ(16u, find_value(list[0], "keyhash").get_str().size());
    }
    // a failed broadcast after BUILT keeps BUILT and stores the error
    SendOnceFailed(wallet, key, -26, "bad-txns\nsomething");
    {
        LOCK(wallet->cs_wallet);
        const CSendOnceRecord& r = wallet->mapSendOnce.begin()->second;
        EXPECT_EQ((int)SENDONCE_BUILT, (int)r.state);
        EXPECT_EQ(-26, r.nErrorCode);
        EXPECT_EQ("bad-txns something", r.strError);
    }
    // committed
    SendOnceCommitted(wallet, key);
    Reopen();
    {
        LOCK2(cs_main, wallet->cs_wallet);
        ASSERT_EQ(1u, wallet->mapSendOnce.size());
        EXPECT_EQ((int)SENDONCE_COMMITTED, (int)wallet->mapSendOnce.begin()->second.state);
        EXPECT_EQ(0, wallet->mapSendOnce.begin()->second.nErrorCode);
        UniValue st = SendOnceOperationStatus(wallet, "opid-abc");
        EXPECT_EQ("success", find_value(st, "status").get_str());
        EXPECT_EQ(tx.GetHash().GetHex(), find_value(find_value(st, "result"), "txid").get_str());
        std::string opid;
        EXPECT_EQ(SendOnceBeginResult::STORED, SendOnceBegin(wallet, key, digest, opid));
        EXPECT_TRUE(SendOnceOperationStatus(wallet, "opid-unknown").isNull());
    }
}

TEST_F(SendJournalWalletTest, FailureBeforeBuildReleasesTheKey) {
    const uint256 key = SendOnceKeyHash("k2");
    const uint256 digest = uint256S("77");
    {
        LOCK2(cs_main, wallet->cs_wallet);
        SendOnceStart(wallet, key, digest, "opid-x");
    }
    SendOnceFailed(wallet, key, -4, "Insufficient funds");
    Reopen();
    LOCK2(cs_main, wallet->cs_wallet);
    EXPECT_TRUE(wallet->mapSendOnce.empty());
    std::string opid;
    EXPECT_EQ(SendOnceBeginResult::PROCEED, SendOnceBegin(wallet, key, uint256S("88"), opid));
}

TEST_F(SendJournalWalletTest, BuiltWithoutExpiryIsNeverReleased) {
    const uint256 key = SendOnceKeyHash("k3");
    const uint256 digest = uint256S("77");
    {
        LOCK2(cs_main, wallet->cs_wallet);
        SendOnceStart(wallet, key, digest, "opid-y");
    }
    // expiry height 0 and built a year ago: nothing bounds when it could still be mined, so the key stays held
    CTransaction tx = SomeTx(0);
    ASSERT_TRUE(SendOnceBuilt(wallet, key, tx));
    {
        LOCK(wallet->cs_wallet);
        CSendOnceRecord r = wallet->mapSendOnce.begin()->second;
        r.nTimeBuilt = GetTime() - 365LL * 24 * 3600;
        CWalletDB db(wallet->strWalletFile);
        ASSERT_TRUE(db.WriteSendOnce(key, r));
        wallet->mapSendOnce[key] = r;
    }
    LOCK2(cs_main, wallet->cs_wallet);
    std::string opid;
    // a different request: still an error, the key is not released
    try {
        SendOnceBegin(wallet, key, uint256S("5555"), opid);
        ADD_FAILURE() << "expected an error";
    } catch (const UniValue& e) {
        EXPECT_EQ("idempotency key reused with different parameters", find_value(e, "message").get_str());
    }
    // the same request: the stored operation, no second build
    EXPECT_EQ(SendOnceBeginResult::STORED, SendOnceBegin(wallet, key, digest, opid));
    EXPECT_EQ("opid-y", opid);
    EXPECT_EQ((int)SENDONCE_BUILT, (int)wallet->mapSendOnce[key].state);
    UniValue st = SendOnceOperationStatus(wallet, "opid-y");
    EXPECT_EQ("executing", find_value(st, "status").get_str());
}

TEST_F(SendJournalWalletTest, Pruning) {
    LOCK2(cs_main, wallet->cs_wallet);
    const int64_t now = GetTime();
    // 3 old finished records, 1 old in-flight (never pruned), 2 recent finished
    for (int i = 0; i < 6; i++) {
        CSendOnceRecord r = Rec(i == 3 ? SENDONCE_BUILT : (i % 2 ? SENDONCE_COMMITTED : SENDONCE_EXPIRED), 10);
        r.nTimeUpdated = i < 4 ? now - SENDONCE_PRUNE_AGE - 100 - i : now - 10;
        r.opid = strprintf("opid-%d", i);
        CWalletDB db(wallet->strWalletFile);
        uint256 h = SendOnceKeyHash(strprintf("p%d", i));
        ASSERT_TRUE(db.WriteSendOnce(h, r));
        wallet->mapSendOnce[h] = r;
    }
    SendOncePrune(wallet);
    EXPECT_EQ(3u, wallet->mapSendOnce.size());   // the in-flight BUILT one and the two recent
    size_t built = 0;
    for (const auto& i : wallet->mapSendOnce) built += i.second.state == SENDONCE_BUILT;
    EXPECT_EQ(1u, built);
}
