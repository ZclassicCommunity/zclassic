/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <cassert>
#include <algorithm>
#include <cstdio>
#include "zcash/jubjub_scalar.h"
int main() {
    using boost::multiprecision::cpp_int;
    const cpp_int modulus("0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7");
    unsigned count = 0;
    auto check = [&](cpp_int number) {
        std::array<unsigned char,64> in{};
        auto encoding = number;
        for (auto& byte : in) { byte=(encoding & 255).convert_to<unsigned>(); encoding >>= 8; }
        std::array<unsigned char,32> out{};
        zcl_jubjub_to_scalar(in.data(),out.data());
        cpp_int actual = 0;
        for (int i=31;i>=0;--i) { actual <<= 8; actual += out[i]; }
        assert(actual == number % modulus);
        zcl_jubjub_to_scalar(in.data(),in.data());
        assert(std::equal(out.begin(),out.end(),in.begin()));
        ++count;
    };
    const cpp_int max = (cpp_int(1)<<512)-1;
    check(0); check(max);
    for (int i=0;i<512;++i) { check(cpp_int(1)<<i); check(max-(cpp_int(1)<<i)); }
    for (int k=1;k<=3;++k) for (int d=-1;d<=1;++d) check(modulus*k+d);
    uint64_t state=0x9176bcb10fa43765ULL;
    for (int i=0;i<2048;++i) {
        cpp_int n=0;
        for (int j=0;j<64;++j) { state^=state<<13;state^=state>>7;state^=state<<17;n<<=8;n+=state&255; }
        check(n);
    }
    printf("PASS: %u independent scalar-reduction vectors, including overlapping buffers\n",count);
}
