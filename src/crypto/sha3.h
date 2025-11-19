// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SHA3_H
#define BITCOIN_CRYPTO_SHA3_H

#include <stdint.h>
#include <stdlib.h>

//! The Keccak-f[1600] transform.
void KeccakF(uint64_t (&st)[25]);

class SHA3_256
{
private:
    uint64_t m_state[25];
    unsigned char m_buffer[8];
    unsigned m_bufsize;
    unsigned m_pos;

    //! Sponge rate in bits.
    static const unsigned RATE_BITS = 1088;

    //! Sponge rate expressed as a multiple of the buffer size.
    static const unsigned RATE_BUFFERS = RATE_BITS / (8 * sizeof(m_buffer));

public:
    static const size_t OUTPUT_SIZE = 32;

    SHA3_256();
    SHA3_256& Write(const unsigned char* data, size_t len);
    SHA3_256& Finalize(unsigned char* output);
    SHA3_256& Reset();
};

#endif // BITCOIN_CRYPTO_SHA3_H
