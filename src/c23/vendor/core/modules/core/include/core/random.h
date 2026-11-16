/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2014 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#ifndef BITCOIN_RANDOM_H
#define BITCOIN_RANDOM_H

#include "core/uint256.h"
#include <stdbool.h>
#include <stdint.h>

void GetRandBytes(unsigned char *buf, size_t num);
uint64_t GetRand(uint64_t nMax);
int GetRandInt(int nMax);

#endif
