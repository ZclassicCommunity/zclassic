#include "a.h"
#include <boost/test/unit_test.hpp>
BOOST_AUTO_TEST_SUITE(foo_tests)
BOOST_AUTO_TEST_CASE(a_is_one)
{
    BOOST_CHECK_EQUAL(a_value(), 1);
}
BOOST_AUTO_TEST_SUITE_END()
TEST(Suite, first_case)
{
    ASSERT_EQ(1, 1);
}
TEST_F(Fix, second_case)
{
    ASSERT_EQ(2, 2);
}
