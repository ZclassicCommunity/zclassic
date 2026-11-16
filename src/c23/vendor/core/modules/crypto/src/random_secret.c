/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Implementation of `zcl_random_secret_bytes`. See
 * `crypto/random_secret.h` for the rationale. */

#include "crypto/random_secret.h"
#include "core/random.h"
#include "support/cleanse.h"
#include "util/log_macros.h"
#include <stdio.h>

bool zcl_random_secret_bytes(uint8_t *buf, size_t n, const char *label)
{
    if (!buf || n == 0)
        LOG_FAIL("crypto",
                 "zcl_random_secret_bytes: invalid args (buf=%p n=%zu)",
                 (const void *)buf, n);

    GetRandBytes(buf, n);

    /* Detect the GetRandBytes "open(/dev/urandom) failed" zero-fill
     * (core/modules/core/src/random.c:15-19). The probability of legitimate
     * all-zero output from a CSPRNG is 2^-(8n); for n>=16 this is
     * vanishingly small, well below the chance that we are simply
     * running with a misconfigured entropy source. */
    uint8_t accum = 0;
    for (size_t i = 0; i < n; i++) accum |= buf[i];
    if (accum == 0) {
        memory_cleanse(buf, n);
        LOG_FAIL("crypto",
                 "RNG returned all-zero output for %zu-byte secret (label=%s) — refusing to proceed",
                 n, label ? label : "?");
    }
    return true;
}
