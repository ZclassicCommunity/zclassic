#include <gtest/gtest.h>

#include "utilstrencodings.h"
#include "version.h"
#include "serialize.h"
#include "streams.h"

#include <univalue.h>

UniValue
read_json(const std::string& jsondata);

// #define PRINT_JSON 1

template<typename T>
void expect_deser_same(const T& expected)
{
    CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
    ss1 << expected;

    auto serialized_size = ss1.size();
    // Reading the complete CDataStream clears its buffer. Save the bytes before
    // deserializing instead of dereferencing an emptied stream afterward.
    const std::string serialized = ss1.str();

    T object;
    ss1 >> object;
    ASSERT_TRUE(ss1.empty());

    CDataStream ss2(SER_NETWORK, PROTOCOL_VERSION);
    ss2 << object;

    ASSERT_EQ(serialized_size, ss2.size());
    ASSERT_EQ(serialized, ss2.str());
}

template<typename T, typename U>
void expect_test_vector(T& v, const U& expected)
{
    expect_deser_same(expected);

    CDataStream ss1(SER_NETWORK, PROTOCOL_VERSION);
    ss1 << expected;

    #ifdef PRINT_JSON
    std::cout << "\t\"" ;
    std::cout << HexStr(ss1.begin(), ss1.end()) << "\",\n";
    #else
    std::string raw = v.get_str();
    CDataStream ss2(ParseHex(raw), SER_NETWORK, PROTOCOL_VERSION);

    ASSERT_EQ(ss1.size(), ss2.size());
    ASSERT_EQ(ss1.str(), ss2.str());
    #endif
}
