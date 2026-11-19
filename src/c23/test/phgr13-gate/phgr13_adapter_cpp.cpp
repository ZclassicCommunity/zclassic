// PHGR13 differential gate, C++ half (test-only). Built with
// -Dlibzcash=libzcash_new so the daemon's Proof.hpp/Proof.cpp (no libsnark) can
// live in the same binary as the reference's own Proof.cpp.
//
// zc23_phgr13_verify is JoinSplitCircuit::verify, line for line,
// (src/zcash/JoinSplit.cpp) with h_sig supplied by the caller: deserialize the
// 296 bytes with the daemon's PHGRProof (lead-byte checks), serialize back,
// call the shim. gtest/test_phgr13.cpp runs mutations through the real
// JSDescription::Verify.
#include "Proof.hpp"
#include "streams.h"
#include "version.h"
#include <cstdlib>

extern "C" {
#include "phgr13_c23.h"
#include "zcl_c23_phgr13.h"
bool zc23_adapter_decode_only(const uint8_t proof[ZC23_PHGR13_PROOF_SIZE]);
}

// Proof.cpp draws randomness only in random_invalid(); the gate never calls it.
void GetRandBytes(unsigned char*, size_t) { abort(); }

extern "C" bool zc23_phgr13_verify(const zc23_phgr13_vk*, const uint8_t proof[ZC23_PHGR13_PROOF_SIZE],
                                   const uint8_t rt[32], const uint8_t h_sig[32],
                                   const uint8_t nf1[32], const uint8_t nf2[32],
                                   const uint8_t mac1[32], const uint8_t mac2[32],
                                   const uint8_t cm1[32], const uint8_t cm2[32],
                                   uint64_t vpub_old, uint64_t vpub_new)
{
    try {
        // Transaction deserialization: refuses a bad lead byte.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss.write((const char*)proof, ZC23_PHGR13_PROOF_SIZE);
        libzcash_new::PHGRProof p;
        ss >> p;

        unsigned char wire[libzcash_new::PHGR_PROOF_SIZE];
        p.ToBytes(wire);
        return zcl_c23_phgr13_verify(wire, rt, h_sig, mac1, mac2, nf1, nf2, cm1, cm2, vpub_old, vpub_new);
    } catch (...) {
        return false;
    }
}
