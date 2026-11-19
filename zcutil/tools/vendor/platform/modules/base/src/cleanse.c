/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2015 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. */

#include "base/cleanse.h"
#include <string.h>

void memory_cleanse(void *ptr, size_t len)
{
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
}
