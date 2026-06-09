// Copyright 2026 Rhett Creighton - Apache License 2.0

#include "zmarket/zmarket_record.h"

#include <string.h>

static uint16_t rd16le(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32le(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64le(const uint8_t *p)
{
    uint64_t lo = rd32le(p);
    uint64_t hi = rd32le(p + 4);
    return lo | (hi << 32);
}

uint32_t zmarket_record_type_max_payload(enum zmarket_record_type type)
{
    switch (type) {
    case ZMARKET_RECORD_OFFER:      return 8u * 1024u;
    case ZMARKET_RECORD_MANIFEST:   return 64u * 1024u;
    case ZMARKET_RECORD_MIRROR:     return 8u * 1024u;
    case ZMARKET_RECORD_MIRROR_SET: return 16u * 1024u;
    default:                        return 0u;
    }
}

bool zmarket_record_type_is_routable(enum zmarket_record_type type)
{
    return type == ZMARKET_RECORD_OFFER ||
           type == ZMARKET_RECORD_MANIFEST ||
           type == ZMARKET_RECORD_MIRROR ||
           type == ZMARKET_RECORD_MIRROR_SET;
}

enum zmarket_record_error
zmarket_record_parse(const uint8_t *bytes, size_t len,
                     uint32_t max_record_bytes,
                     struct zmarket_record_view *out)
{
    size_t off = 0;
    uint16_t version, type, signer_len, sig_len;
    uint32_t payload_len, type_cap;

    if (!bytes || !out) return ZMARKET_RECORD_ERR_NULL;
    memset(out, 0, sizeof(*out));
    out->type = ZMARKET_RECORD_INVALID;

    if (max_record_bytes == 0 || len > max_record_bytes)
        return ZMARKET_RECORD_ERR_SIZE;
    if (len < 4 + 2 + 2 + 4 + 8 + 4 + 2 + 2)
        return ZMARKET_RECORD_ERR_SHORT;
    if (memcmp(bytes, ZMARKET_RECORD_MAGIC, 4) != 0)
        return ZMARKET_RECORD_ERR_MAGIC;
    off += 4;

    version = rd16le(bytes + off); off += 2;
    if (version != ZMARKET_RECORD_VERSION)
        return ZMARKET_RECORD_ERR_VERSION;

    type = rd16le(bytes + off); off += 2;
    if (type < ZMARKET_RECORD_OFFER || type > ZMARKET_RECORD_MIRROR_SET)
        return ZMARKET_RECORD_ERR_TYPE;

    out->type = (enum zmarket_record_type)type;
    out->flags = rd32le(bytes + off); off += 4;
    out->expires_unix = rd64le(bytes + off); off += 8;

    payload_len = rd32le(bytes + off); off += 4;
    type_cap = zmarket_record_type_max_payload(out->type);
    if (payload_len > type_cap || off + payload_len > len)
        return ZMARKET_RECORD_ERR_SIZE;
    out->payload = bytes + off;
    out->payload_len = payload_len;
    off += payload_len;

    if (off + 2 > len) return ZMARKET_RECORD_ERR_SHORT;
    signer_len = rd16le(bytes + off); off += 2;
    if (signer_len == 0 || signer_len > 128 || off + signer_len > len)
        return ZMARKET_RECORD_ERR_SIZE;
    out->signer_key = bytes + off;
    out->signer_key_len = signer_len;
    off += signer_len;

    if (off + 2 > len) return ZMARKET_RECORD_ERR_SHORT;
    sig_len = rd16le(bytes + off); off += 2;
    if (sig_len == 0 || sig_len > 128 || off + sig_len > len)
        return ZMARKET_RECORD_ERR_SIZE;
    out->signature = bytes + off;
    out->signature_len = sig_len;
    off += sig_len;

    if (off != len)
        return ZMARKET_RECORD_ERR_TRAILING;
    return ZMARKET_RECORD_OK;
}

const char *zmarket_record_error_string(enum zmarket_record_error err)
{
    switch (err) {
    case ZMARKET_RECORD_OK:          return "ok";
    case ZMARKET_RECORD_ERR_NULL:    return "null argument";
    case ZMARKET_RECORD_ERR_SHORT:   return "record too short";
    case ZMARKET_RECORD_ERR_MAGIC:   return "bad magic";
    case ZMARKET_RECORD_ERR_VERSION: return "unsupported version";
    case ZMARKET_RECORD_ERR_TYPE:    return "unsupported type";
    case ZMARKET_RECORD_ERR_SIZE:    return "record size violation";
    case ZMARKET_RECORD_ERR_TRAILING:return "trailing bytes";
    default:                         return "unknown record error";
    }
}
