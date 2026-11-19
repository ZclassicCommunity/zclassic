/* Copyright 2026 Rhett Creighton - Apache License 2.0
 *
 * Transport-neutral MCP JSON-RPC 2.0 core. One frame in, at most one reply
 * frame out: no I/O, no globals, no threads. The caller owns framing
 * (newline-delimited for stdio, an HTTP body for HTTPS), the tool table and
 * the authority and executor callbacks. */

#ifndef ZCL_TOOLS_MCP_RPC_H
#define ZCL_TOOLS_MCP_RPC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "json/json.h"

#ifdef __cplusplus
extern "C" {
#endif

/* JSON-RPC / MCP error codes. */
enum {
    MCP_ERR_PARSE = -32700,
    MCP_ERR_INVALID_REQUEST = -32600,
    MCP_ERR_METHOD_NOT_FOUND = -32601,
    MCP_ERR_INVALID_PARAMS = -32602,
    MCP_ERR_INTERNAL = -32603,
    /* initialize refused by on_initialize (server-defined range). */
    MCP_ERR_INITIALIZE_REFUSED = -32001
};

/* Growing output buffer, always NUL-terminated once used. oom is sticky. */
struct mcp_buf {
    char *p;
    size_t len;
    size_t cap;
    bool oom;
};
void mcp_buf_init(struct mcp_buf *b);
void mcp_buf_free(struct mcp_buf *b);
void mcp_buf_put(struct mcp_buf *b, const char *s, size_t n);
void mcp_buf_str(struct mcp_buf *b, const char *s);
/* Quoted and escaped JSON string. */
void mcp_buf_json_str(struct mcp_buf *b, const char *s);
void mcp_buf_json_str_n(struct mcp_buf *b, const char *s, size_t n);
/* A parsed value, serialized (NULL writes null). */
void mcp_buf_json_value(struct mcp_buf *b, const struct json_value *v);

/* One tool. input_schema_json is a complete JSON object, emitted verbatim. */
struct mcp_tool {
    const char *name;
    const char *description;
    const char *input_schema_json;
    bool read_only; /* annotations.readOnlyHint */
};

/* Typed refusal. Becomes a tools/call result with isError:true and the text
 * {"ok":false,"error":{"code":..,"message":..,"detail":..}} (detail omitted
 * when NULL). It is not a JSON-RPC error. */
struct mcp_refusal {
    const char *code;
    const char *message;
    const char *detail;
    const char *did_you_mean_json; /* complete JSON array, or NULL */
};

/* Authority: runs after tool lookup and before call, with the arguments
 * object (never NULL; an empty object when absent). Return true to allow;
 * false must fill *why. */
typedef bool (*mcp_authority_fn)(void *ctx, const struct mcp_tool *tool,
                                 const struct json_value *args,
                                 struct mcp_refusal *why);

/* Executor: append the result text (normally one JSON document) to text.
 * Set *is_error for a tool-level failure (still a successful JSON-RPC
 * reply with isError:true). Return false only for an internal failure
 * (reported as MCP_ERR_INTERNAL). */
typedef bool (*mcp_call_fn)(void *ctx, const struct mcp_tool *tool,
                            const struct json_value *args,
                            struct mcp_buf *text, bool *is_error);

struct mcp_endpoint {
    const char *server_name;
    const char *server_version;
    /* Read after on_initialize returns, so the callback may fill the
     * storage this points at. May be NULL. */
    const char *instructions;
    const struct mcp_tool *tools;
    size_t tool_count;
    mcp_authority_fn authority; /* NULL allows everything */
    mcp_call_fn call;           /* required */
    void *ctx;
    /* Cap on one tools/call result text, enforced by mcp_reply_tool_text.
     * 0 means unlimited. */
    size_t max_reply_bytes;
    /* Optional. Runs at initialize with the client's clientInfo.name and
     * protocolVersion (either may be NULL when absent). Returning false
     * answers the initialize with MCP_ERR_INITIALIZE_REFUSED carrying why. */
    bool (*on_initialize)(void *ctx, const char *client_name,
                          const char *protocol, struct mcp_refusal *why);
};

/* Echo the client's protocolVersion when supported, else the newest.
 * Supported: 2025-06-18, 2025-03-26, 2024-11-05. */
const char *mcp_negotiate_version(const char *asked);

enum mcp_dispatch_result {
    MCP_REPLY = 0,    /* reply holds exactly one frame, no trailing newline */
    MCP_NO_REPLY = 1, /* notification or client response; reply untouched */
    MCP_FATAL = 2     /* out of memory; send nothing */
};

/* Handle one frame: parse, validate, route initialize, ping,
 * notifications, tools/list and tools/call. Malformed JSON answers
 * MCP_ERR_PARSE with id null; a non-object frame (batches included) answers
 * MCP_ERR_INVALID_REQUEST; an unknown method MCP_ERR_METHOD_NOT_FOUND; a bad
 * tools/call shape or unknown tool MCP_ERR_INVALID_PARAMS. */
enum mcp_dispatch_result mcp_dispatch(const struct mcp_endpoint *ep,
                                      const char *frame, size_t len,
                                      struct mcp_buf *reply);

/* Envelope builders, exposed for reuse and tests. id may be NULL (null). */
void mcp_reply_error(struct mcp_buf *b, const struct json_value *id, int code,
                     const char *message);
void mcp_reply_tools_list(struct mcp_buf *b, const struct json_value *id,
                          const struct mcp_endpoint *ep);
/* Wrap text as a tools/call result, capped at ep->max_reply_bytes. */
void mcp_reply_tool_text(struct mcp_buf *b, const struct json_value *id,
                         const struct mcp_endpoint *ep, const char *text,
                         size_t n, bool is_error);

/* Cap text at max_bytes (0 = no cap). Within the cap it is copied unchanged
 * and false is returned. Above it, out receives a JSON object of at most
 * max_bytes bytes:
 *   {"truncated":true,"original_bytes":N,"partial":"<escaped prefix>"}
 * when text is a JSON object (its first non-space byte is '{'); otherwise
 * the raw prefix followed by "\n[truncated: N bytes total]". Returns true
 * when it truncated. A prefix never splits a UTF-8 sequence. When the object
 * parses and has a `data` object, "fields" follows original_bytes: the
 * serialized size of each data member (at most 32), so the caller can pick a
 * select instead of reading an escaped prefix. */
bool mcp_cap_text(struct mcp_buf *out, const char *text, size_t n,
                  size_t max_bytes);

/* select: an array of 1..8 dot paths, each 1..128 bytes, whose segments are
 * object keys, decimal array indexes or `*` (every element of an array).
 * False names the problem in *why. */
bool mcp_select_valid(const struct json_value *select, const char **why);

/* Project a command reply onto a valid select:
 *   {"ok":..,"status":..,"select":{"<path>":<value>,..}}
 * with null where a path does not resolve. When any path does not resolve
 * the reply also carries
 *   "select_missing":{"<path>":{"resolved":"<deepest prefix that resolved>",
 *                               "keys":[..up to 32 names, then "..."]}}
 * ("length":N instead of keys when that prefix is an array), so a caller can
 * tell a missing key from a null value; it is absent, and the reply
 * byte-identical, when every path resolves. False, with out untouched, when
 * text is not a JSON object; false with out->oom set when text is valid JSON
 * that could not be parsed for lack of memory. */
bool mcp_select_reply(struct mcp_buf *out, const char *text, size_t n,
                      const struct json_value *select);

#ifdef __cplusplus
}
#endif

#endif
