#include "a.h"
#include <boost/test/unit_test.hpp>
BOOST_AUTO_TEST_SUITE(foo_tests)
BOOST_AUTO_TEST_CASE(a_is_one)
{
    BOOST_CHECK_EQUAL(a_value(), 1);
}
BOOST_AUTO_TEST_SUITE_END()
