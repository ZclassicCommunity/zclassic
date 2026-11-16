/* Copyright 2026 Rhett Creighton. SPDX-License-Identifier: Apache-2.0 */
#include <gtest/gtest.h>
#include <boost/multiprecision/cpp_int.hpp>
#include <array>
#include <algorithm>
#include <chrono>
#include <iostream>
#include "librustzcash.h"
#include "zcash/jubjub_scalar.h"

namespace {
using Bytes64 = std::array<unsigned char, 64>;
using Bytes32 = std::array<unsigned char, 32>;

void CheckScalar(const Bytes64& input) {
    Bytes32 actual, rust;
    zcl_jubjub_to_scalar(input.data(), actual.data());
    librustzcash_to_scalar(input.data(), rust.data());
    EXPECT_EQ(actual, rust);

    // Independent integer remainder oracle; deliberately not constant-time.
    using boost::multiprecision::cpp_int;
    cpp_int number = 0;
    for (size_t i = input.size(); i > 0; --i) {
        number <<= 8;
        number += input[i - 1];
    }
    const cpp_int modulus("0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7");
    cpp_int reduced = number % modulus;
    Bytes32 independent;
    for (auto& byte : independent) {
        byte = static_cast<unsigned char>((reduced & 255).convert_to<unsigned>());
        reduced >>= 8;
    }
    EXPECT_EQ(actual, independent);
    Bytes64 overlapping = input;
    zcl_jubjub_to_scalar(overlapping.data(), overlapping.data());
    EXPECT_TRUE(std::equal(actual.begin(), actual.end(), overlapping.begin()));
}
}

TEST(C23Scalar, DifferentialReduction) {
    Bytes64 input = {};
    CheckScalar(input);
    input.fill(255);
    CheckScalar(input);
    using boost::multiprecision::cpp_int;
    const cpp_int modulus("0x0e7db4ea6533afa906673b0101343b00a6682093ccc81082d0970e5ed6f72cb7");
    for (unsigned multiple = 1; multiple <= 3; ++multiple) {
        for (int delta = -1; delta <= 1; ++delta) {
            cpp_int boundary = modulus * multiple + delta;
            for (auto& byte : input) {
                byte = static_cast<unsigned char>((boundary & 255).convert_to<unsigned>());
                boundary >>= 8;
            }
            CheckScalar(input);
        }
    }
    for (size_t bit = 0; bit < 512; ++bit) {
        input.fill(0);
        input[bit / 8] = static_cast<unsigned char>(1u << (bit % 8));
        CheckScalar(input);
        for (auto& byte : input) byte = static_cast<unsigned char>(~byte);
        CheckScalar(input);
    }
    uint64_t state = 0x9176bcb10fa43765ULL;
    for (unsigned vector = 0; vector < 2048; ++vector) {
        for (auto& byte : input) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            byte = static_cast<unsigned char>(state);
        }
        CheckScalar(input);
    }
}

TEST(C23Scalar, ReportTimings) {
    Bytes64 input;
    input.fill(0xa5);
    Bytes32 out;
    const auto begin = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < 4096; ++i) librustzcash_to_scalar(input.data(), out.data());
    const auto middle = std::chrono::steady_clock::now();
    for (unsigned i = 0; i < 4096; ++i) zcl_jubjub_to_scalar(input.data(), out.data());
    const auto end = std::chrono::steady_clock::now();
    std::cout << "Scalar reduction 4096 calls: rust_us="
              << std::chrono::duration_cast<std::chrono::microseconds>(middle - begin).count()
              << " c23_us="
              << std::chrono::duration_cast<std::chrono::microseconds>(end - middle).count()
              << std::endl;
}
