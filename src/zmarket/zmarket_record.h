// Copyright 2026 Rhett Creighton - Apache License 2.0
//
// Canonical signed-record framing for ZMARKET spider/router/index records.
// This parser is allocation-free and does not verify signatures itself; the
// daemon bridge supplies crypto and chain callbacks after the frame is bounded.

#ifndef ZCLASSIC_ZMARKET_RECORD_H
#define ZCLASSIC_ZMARKET_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZMARKET_RECORD_MAGIC "ZMRK"
#define ZMARKET_RECORD_VERSION 1u
#define ZMARKET_ID_LEN 32u

enum zmarket_record_type {
    ZMARKET_RECORD_INVALID            = 0,
    ZMARKET_RECORD_LISTING            = 1,
    ZMARKET_RECORD_BUYREQ_ROUTE       = 2,
    ZMARKET_RECORD_SEALED_OFFER_ROUTE = 3,
    ZMARKET_RECORD_CANCEL             = 4,
    ZMARKET_RECORD_MANIFEST           = 5,
    ZMARKET_RECORD_MIRROR             = 6,
    ZMARKET_RECORD_MIRROR_SET         = 7,

    /* Compatibility name for early beta7 scaffolding. Public listings are not
     * buyer-specific settlement offers; final buys still revalidate the sealed
     * ZNFTOFFER1 flow before spending. */
    ZMARKET_RECORD_OFFER = ZMARKET_RECORD_LISTING
};

enum zmarket_record_error {
    ZMARKET_RECORD_OK = 0,
    ZMARKET_RECORD_ERR_NULL,
    ZMARKET_RECORD_ERR_SHORT,
    ZMARKET_RECORD_ERR_MAGIC,
    ZMARKET_RECORD_ERR_VERSION,
    ZMARKET_RECORD_ERR_TYPE,
    ZMARKET_RECORD_ERR_SIZE,
    ZMARKET_RECORD_ERR_TRAILING
};

struct zmarket_record_view {
    enum zmarket_record_type type;
    uint32_t flags;
    uint64_t expires_unix;
    const uint8_t *payload;
    uint32_t payload_len;
    const uint8_t *signer_key;
    uint16_t signer_key_len;
    const uint8_t *signature;
    uint16_t signature_len;
};

enum zmarket_record_error
zmarket_record_parse(const uint8_t *bytes, size_t len,
                     uint32_t max_record_bytes,
                     struct zmarket_record_view *out);

uint32_t zmarket_record_type_max_payload(enum zmarket_record_type type);
bool zmarket_record_type_is_routable(enum zmarket_record_type type);
const char *zmarket_record_error_string(enum zmarket_record_error err);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* ZCLASSIC_ZMARKET_RECORD_H */
