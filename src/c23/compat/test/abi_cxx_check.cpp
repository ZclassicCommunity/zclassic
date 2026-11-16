// zclassicd-owned. TEST-ONLY: the replacement librustzcash.h compiles as a
// C++ header (extern "C") and links against the C objects with the same
// argument types zclassicd's call sites use (uint256::begin() is
// unsigned char*, std::array<unsigned char, N>::data(), path::native()).
// Built by compat/test/build-smoke.sh with g++ -std=gnu++17 -Werror.
#include "librustzcash.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>

// init.cpp, gtest/main.cpp and test_bitcoin.cpp static_assert this.
#if defined(WIN32) || defined(_WIN32)
static_assert(sizeof(codeunit) == sizeof(wchar_t), "librustzcash not configured correctly");
#else
static_assert(sizeof(codeunit) == sizeof(char), "librustzcash not configured correctly");
#endif

// Every declaration the daemon uses, by type (the 31 names of report 01).
static_assert(std::is_same<decltype(&librustzcash_to_scalar), void (*)(const unsigned char *, unsigned char *)>::value, "to_scalar");
static_assert(std::is_same<decltype(&librustzcash_ask_to_ak), void (*)(const unsigned char *, unsigned char *)>::value, "ask_to_ak");
static_assert(std::is_same<decltype(&librustzcash_nsk_to_nk), void (*)(const unsigned char *, unsigned char *)>::value, "nsk_to_nk");
static_assert(std::is_same<decltype(&librustzcash_crh_ivk), void (*)(const unsigned char *, const unsigned char *, unsigned char *)>::value, "crh_ivk");
static_assert(std::is_same<decltype(&librustzcash_check_diversifier), bool (*)(const unsigned char *)>::value, "check_diversifier");
static_assert(std::is_same<decltype(&librustzcash_ivk_to_pkd), bool (*)(const unsigned char *, const unsigned char *, unsigned char *)>::value, "ivk_to_pkd");
static_assert(std::is_same<decltype(&librustzcash_init_zksnark_params), void (*)(const codeunit *, size_t, const char *, const codeunit *, size_t, const char *, const codeunit *, size_t, const char *)>::value, "init");
static_assert(std::is_same<decltype(&librustzcash_tree_uncommitted), void (*)(unsigned char *)>::value, "tree_uncommitted");
static_assert(std::is_same<decltype(&librustzcash_merkle_hash), void (*)(size_t, const unsigned char *, const unsigned char *, unsigned char *)>::value, "merkle_hash");
static_assert(std::is_same<decltype(&librustzcash_sapling_spend_sig), bool (*)(const unsigned char *, const unsigned char *, const unsigned char *, unsigned char *)>::value, "spend_sig");
static_assert(std::is_same<decltype(&librustzcash_sapling_proving_ctx_init), void *(*)()>::value, "proving_ctx_init");
static_assert(std::is_same<decltype(&librustzcash_sapling_spend_proof), bool (*)(void *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, const unsigned char *, unsigned char *, unsigned char *, unsigned char *)>::value, "spend_proof");
static_assert(std::is_same<decltype(&librustzcash_sapling_output_proof), bool (*)(void *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, unsigned char *, unsigned char *)>::value, "output_proof");
static_assert(std::is_same<decltype(&librustzcash_sapling_binding_sig), bool (*)(const void *, int64_t, const unsigned char *, unsigned char *)>::value, "binding_sig");
static_assert(std::is_same<decltype(&librustzcash_sapling_proving_ctx_free), void (*)(void *)>::value, "proving_ctx_free");
static_assert(std::is_same<decltype(&librustzcash_sapling_verification_ctx_init), void *(*)()>::value, "verification_ctx_init");
static_assert(std::is_same<decltype(&librustzcash_sapling_check_spend), bool (*)(void *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *)>::value, "check_spend");
static_assert(std::is_same<decltype(&librustzcash_sapling_check_output), bool (*)(void *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *)>::value, "check_output");
static_assert(std::is_same<decltype(&librustzcash_sapling_final_check), bool (*)(void *, int64_t, const unsigned char *, const unsigned char *)>::value, "final_check");
static_assert(std::is_same<decltype(&librustzcash_sapling_verification_ctx_free), void (*)(void *)>::value, "verification_ctx_free");
static_assert(std::is_same<decltype(&librustzcash_sapling_compute_nf), bool (*)(const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, unsigned char *)>::value, "compute_nf");
static_assert(std::is_same<decltype(&librustzcash_sapling_compute_cm), bool (*)(const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, unsigned char *)>::value, "compute_cm");
static_assert(std::is_same<decltype(&librustzcash_sapling_ka_agree), bool (*)(const unsigned char *, const unsigned char *, unsigned char *)>::value, "ka_agree");
static_assert(std::is_same<decltype(&librustzcash_sapling_ka_derivepublic), bool (*)(const unsigned char *, const unsigned char *, unsigned char *)>::value, "ka_derivepublic");
static_assert(std::is_same<decltype(&librustzcash_sapling_generate_r), void (*)(unsigned char *)>::value, "generate_r");
static_assert(std::is_same<decltype(&librustzcash_sprout_prove), void (*)(unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, const unsigned char *, uint64_t, const unsigned char *, uint64_t, uint64_t)>::value, "sprout_prove");
static_assert(std::is_same<decltype(&librustzcash_sprout_verify), bool (*)(const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, const unsigned char *, uint64_t, uint64_t)>::value, "sprout_verify");
static_assert(std::is_same<decltype(&librustzcash_zip32_xsk_master), void (*)(const unsigned char *, size_t, unsigned char *)>::value, "xsk_master");
static_assert(std::is_same<decltype(&librustzcash_zip32_xsk_derive), void (*)(const unsigned char *, uint32_t, unsigned char *)>::value, "xsk_derive");
static_assert(std::is_same<decltype(&librustzcash_zip32_xfvk_derive), bool (*)(const unsigned char *, uint32_t, unsigned char *)>::value, "xfvk_derive");
static_assert(std::is_same<decltype(&librustzcash_zip32_xfvk_address), bool (*)(const unsigned char *, const unsigned char *, unsigned char *, unsigned char *)>::value, "xfvk_address");

int main()
{
    // Call through the C linkage names with C++ container types.
    std::array<unsigned char, 32> u{};
    librustzcash_tree_uncommitted(u.data());
    std::array<unsigned char, 32> h{};
    librustzcash_merkle_hash(0, u.data(), u.data(), h.data());
    std::array<unsigned char, 169> m{};
    std::string seed(32, '\0');
    librustzcash_zip32_xsk_master(reinterpret_cast<const unsigned char *>(seed.data()), seed.size(), m.data());
    void *ctx = librustzcash_sapling_proving_ctx_init();
    std::array<unsigned char, 32> sighash{};
    std::array<unsigned char, 64> sig{};
    bool ok = u[0] == 1 && h[0] == 0x81 && h[31] == 0x55 && m[0] == 0 &&
              librustzcash_sapling_binding_sig(ctx, 0, sighash.data(), sig.data());
    librustzcash_sapling_proving_ctx_free(ctx);
    std::printf("%s C++ include + link of librustzcash.h (C ABI from g++)\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
