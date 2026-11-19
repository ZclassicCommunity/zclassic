#include <gtest/gtest.h>

#include "asyncrpcoperation.h"

#include <cctype>
#include <set>
#include <string>

TEST(AsyncRPCOperationId, Format)
{
    // opid-xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx, lowercase hex, y in 8,9,a,b
    for (int i = 0; i < 64; i++) {
        AsyncRPCOperation op;
        const std::string id = op.getId();
        ASSERT_EQ(id.size(), 5u + 36u);
        ASSERT_EQ(id.compare(0, 5, "opid-"), 0);
        const std::string u = id.substr(5);
        for (size_t k = 0; k < u.size(); k++) {
            if (k == 8 || k == 13 || k == 18 || k == 23) {
                ASSERT_EQ(u[k], '-');
            } else {
                ASSERT_TRUE(isxdigit((unsigned char)u[k]) && !isupper((unsigned char)u[k])) << id;
            }
        }
        ASSERT_EQ(u[14], '4') << id;
        ASSERT_NE(std::string("89ab").find(u[19]), std::string::npos) << id;
    }
}

TEST(AsyncRPCOperationId, Unique)
{
    std::set<std::string> seen;
    for (int i = 0; i < 1000; i++) {
        EXPECT_TRUE(seen.insert(RandomUuidV4()).second);
    }
}
