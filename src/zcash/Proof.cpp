#include "Proof.hpp"

#include "random.h"
#include "streams.h"
#include "version.h"

#include <assert.h>
#include <algorithm>
#include <string.h>

namespace libzcash {

void PHGRProof::ToBytes(unsigned char out[PHGR_PROOF_SIZE]) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    assert(ss.size() == PHGR_PROOF_SIZE);
    std::copy(ss.begin(), ss.end(), (char*)out);
}

PHGRProof PHGRProof::random_invalid()
{
    // Offsets of the lead bytes in the wire format (see PHGR_PROOF_SIZE):
    // g_A 0, g_A' 33, g_B 66 (65 bytes), g_B' 131, g_C 164, g_C' 197, g_K 230, g_H 263.
    unsigned char wire[PHGR_PROOF_SIZE];
    GetRandBytes(wire, sizeof(wire));
    static const size_t g1_offsets[] = {0, 33, 131, 164, 197, 230, 263};
    for (size_t off : g1_offsets) {
        wire[off] = G1_PREFIX_MASK | (wire[off] & 1);
    }
    wire[66] = G2_PREFIX_MASK | (wire[66] & 1);

    PHGRProof p;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss.write((const char*)wire, sizeof(wire));
    ss >> p;
    return p;
}

ProofVerifier ProofVerifier::Strict() {
    return ProofVerifier(true);
}

ProofVerifier ProofVerifier::Disabled() {
    return ProofVerifier(false);
}

}
