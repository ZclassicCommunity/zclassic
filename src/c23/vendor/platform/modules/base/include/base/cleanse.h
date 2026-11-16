/* Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2015 The Bitcoin Core developers
 * Copyright 2026 Rhett Creighton - Apache License 2.0
 * Distributed under the MIT software license; see platform/modules/base/NOTICE. */
#ifndef ZCL_BASE_CLEANSE_H
#define ZCL_BASE_CLEANSE_H

#include <stddef.h>

/* Overwrite len bytes and keep the store visible across optimization and
 * translation-unit boundaries. */
void memory_cleanse(void *ptr, size_t len);

#endif /* ZCL_BASE_CLEANSE_H */
