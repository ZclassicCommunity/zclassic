// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "protocol.h"
#include "uint256.h"
#include "test/test_bitcoin.h"

#include <stdexcept>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(protocol_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cinv_tostring_known_type_unchanged)
{
    uint256 h = uint256S("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CInv inv(MSG_TX, h);
    BOOST_CHECK_EQUAL(inv.ToString(), std::string("tx ") + h.ToString());
    BOOST_CHECK_EQUAL(std::string(inv.GetCommand()), "tx");
}

BOOST_AUTO_TEST_CASE(cinv_tostring_unknown_type_does_not_throw)
{
    uint256 h = uint256S("00000000000000000000000000000000000000000000000000000000000000ff");
    CInv inv(9999, h);
    BOOST_CHECK(!inv.IsKnownType());
    std::string s;
    BOOST_CHECK_NO_THROW(s = inv.ToString());
    BOOST_CHECK_EQUAL(s, std::string("unknown(9999) ") + h.ToString());
    BOOST_CHECK_THROW(inv.GetCommand(), std::out_of_range); // message construction still refuses it
}

BOOST_AUTO_TEST_SUITE_END()
