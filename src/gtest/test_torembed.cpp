#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include <gtest/gtest.h>

#include "torembed.h"

#include <algorithm>
#include <cctype>
#include <string>

// T1 build-integration smoke test: proves libtor is compiled in and linked, and
// that no Zcash coin name leaks into a surfaced string (coin is ZCL, never ZEC).
#ifdef ENABLE_TOR

TEST(TorEmbed, AvailableWhenCompiledIn)
{
    EXPECT_TRUE(TorEmbedAvailable());
}

TEST(TorEmbed, ProviderVersionMentionsTor)
{
    std::string v = TorEmbedProviderVersion();
    ASSERT_FALSE(v.empty());
    std::string lower(v);
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c){ return (char)std::tolower(c); });
    EXPECT_NE(lower.find("tor"), std::string::npos) << "provider version: " << v;
}

TEST(TorEmbed, NoZcashCoinNameLeak)
{
    // ZClassic, never "ZEC" in any surfaced string.
    EXPECT_EQ(TorEmbedProviderVersion().find("ZEC"), std::string::npos);
}

#else

TEST(TorEmbed, StubsWhenDisabled)
{
    EXPECT_FALSE(TorEmbedAvailable());
    EXPECT_TRUE(TorEmbedProviderVersion().empty());
}

#endif
