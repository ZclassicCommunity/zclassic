#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <gtest/gtest.h>

#include "netbase.h"

#include <set>
#include <string>

// T3 (BIP155) stage 1: a v3 onion's identity lives in the 32-byte torv3_addr, while
// ip[16] is all-zero. Before this fix, operator==/GetHash/GetKey/GetGroup all read
// ip[16], so EVERY v3 onion collapsed to a single address (== 0.0.0.0) in addrman and
// any std::set/dedup. These tests pin the load-bearing identity paths so two distinct
// onions stay distinct everywhere addrman keys/buckets/dedups them.
//
// The two onion strings below are real tor-generated v3 addresses (so their embedded
// checksums validate in SetSpecial); ONION_A is the P2P onion published during the live
// embedded-Tor bring-up test.
namespace {
const char* ONION_A = "c3jj5rang52ev5ijv3v2zlnez2uymsbdxyh7n5b5lf7b42urt3fhmrad.onion";
const char* ONION_B = "xwginc6aorwufvdztjqsap5je7zeo2uhg5cr2vsdkll54naiksypudyd.onion";
}

TEST(TorV3Identity, ParsesAndRoundTrips)
{
    CNetAddr a, b;
    ASSERT_TRUE(a.SetSpecial(ONION_A)) << "ONION_A failed checksum/parse";
    ASSERT_TRUE(b.SetSpecial(ONION_B)) << "ONION_B failed checksum/parse";
    EXPECT_TRUE(a.IsTor());
    EXPECT_TRUE(b.IsTor());
    EXPECT_EQ(a.GetNetwork(), NET_ONION);
    EXPECT_TRUE(a.IsRoutable());
    // base32 encode is lowercase; inputs are already lowercase.
    EXPECT_EQ(a.ToStringIP(), std::string(ONION_A));
    EXPECT_EQ(b.ToStringIP(), std::string(ONION_B));
}

TEST(TorV3Identity, DistinctOnionsAreDistinct)
{
    CNetAddr a, b;
    ASSERT_TRUE(a.SetSpecial(ONION_A));
    ASSERT_TRUE(b.SetSpecial(ONION_B));

    EXPECT_TRUE(a == a);
    EXPECT_FALSE(a == b);          // the bug this fix kills: these used to be equal
    EXPECT_TRUE(a != b);
    EXPECT_TRUE((a < b) || (b < a));   // strict-weak ordering distinguishes them
    EXPECT_FALSE(a < a);

    EXPECT_NE(a.GetHash(), b.GetHash());
    EXPECT_NE(a.GetGroup(), b.GetGroup());   // distinct bucket source-groups
}

TEST(TorV3Identity, NotEqualToClearnet)
{
    CNetAddr a;
    ASSERT_TRUE(a.SetSpecial(ONION_A));
    CNetAddr clearnet("8.8.8.8");
    EXPECT_FALSE(a == clearnet);
    EXPECT_TRUE(a != clearnet);
    // v3 (torv3_addr non-empty) must never collide with the all-zero unroutable addr.
    CNetAddr zero;
    EXPECT_FALSE(a == zero);
    EXPECT_NE(a.GetHash(), zero.GetHash());
}

TEST(TorV3Identity, ServiceKeyIsOnionWidthAndDistinct)
{
    CNetAddr na, nb;
    ASSERT_TRUE(na.SetSpecial(ONION_A));
    ASSERT_TRUE(nb.SetSpecial(ONION_B));
    CService a(na, 8033), b(nb, 8033), a2(na, 8033);

    EXPECT_EQ(a.GetKey().size(), (size_t)(32 + 2));   // 32-byte pubkey + 2-byte port
    EXPECT_EQ(a.GetKey(), a2.GetKey());               // same onion+port -> same key
    EXPECT_NE(a.GetKey(), b.GetKey());                // distinct onions -> distinct keys

    // different port on the same onion must change the key too
    CService aOtherPort(na, 18033);
    EXPECT_NE(a.GetKey(), aOtherPort.GetKey());
}

TEST(TorV3Identity, SetDedupKeepsBothOnions)
{
    CNetAddr na, nb;
    ASSERT_TRUE(na.SetSpecial(ONION_A));
    ASSERT_TRUE(nb.SetSpecial(ONION_B));
    std::set<CService> s;
    s.insert(CService(na, 8033));
    s.insert(CService(nb, 8033));
    s.insert(CService(na, 8033));   // duplicate of the first
    EXPECT_EQ(s.size(), (size_t)2);  // both onions retained, the dup folded
}
