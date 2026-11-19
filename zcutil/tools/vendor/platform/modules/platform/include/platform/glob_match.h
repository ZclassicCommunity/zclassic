/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: bounded portable matching for repository path globs. */
#ifndef ZCL_PLATFORM_GLOB_MATCH_H
#define ZCL_PLATFORM_GLOB_MATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

enum { PLATFORM_GLOB_INPUT_MAX = 4096 };

static inline unsigned char platform_glob_class_byte(const char *pattern,
                                                      size_t *i)
{
    unsigned char c = (unsigned char)pattern[(*i)++];
    if (c == '\\' && pattern[*i]) c = (unsigned char)pattern[(*i)++];
    return c;
}

static inline bool platform_glob_class_item(const char *pattern, size_t *i,
                                             unsigned char value)
{
    unsigned char first = platform_glob_class_byte(pattern, i);
    if (pattern[*i] == '-' && pattern[*i + 1] && pattern[*i + 1] != ']') {
        ++*i;
        unsigned char last = platform_glob_class_byte(pattern, i);
        return first <= value && value <= last;
    }
    return first == value;
}

static inline bool platform_glob_class_match(const char *pattern,
                                             size_t *consumed,
                                             unsigned char value)
{
    size_t i = 1;
    bool negate = false;
    bool matched = false;
    if (pattern[i] == '!' || pattern[i] == '^') {
        negate = true;
        i++;
    }
    if (pattern[i] == ']') {
        matched = value == (unsigned char)']';
        i++;
    }
    while (pattern[i] && pattern[i] != ']') {
        if (platform_glob_class_item(pattern, &i, value)) matched = true;
    }
    if (pattern[i] != ']') return false;
    *consumed = i + 1;
    return negate ? !matched : matched;
}

static inline void platform_glob_transition(const char *pattern, size_t i,
                                             const char *text, size_t text_len,
                                             bool pathname, const bool *state,
                                             bool *next, size_t *consumed)
{
    unsigned char token = (unsigned char)pattern[i];
    bool is_class = token == '[';
    *consumed = 1;
    if (token == '\\' && pattern[i + 1u]) {
        token = (unsigned char)pattern[i + 1u];
        *consumed = 2;
        is_class = false;
    }
    for (size_t j = 1; j <= text_len; j++) {
        unsigned char value = (unsigned char)text[j - 1u];
        if (pathname && value == '/' && (token == '?' || is_class)) continue;
        bool matches;
        if (token == '?') matches = true;
        else if (is_class) {
            size_t class_size = 0;
            matches = platform_glob_class_match(pattern + i, &class_size, value);
            if (class_size != 0) *consumed = class_size;
            else matches = value == (unsigned char)'[';
        } else matches = token == value;
        next[j] = state[j - 1u] && matches;
    }
}

/* Supports '*', '?', bracket classes/ranges/negation, and backslash escapes.
 * When pathname is true, wildcards never consume '/'. Inputs above the fixed
 * repository-path bound fail closed. Dynamic programming avoids exponential
 * wildcard backtracking and keeps runtime O(pattern * text). */
static inline bool platform_glob_match(const char *pattern, const char *text,
                                       bool pathname)
{
    if (!pattern || !text) return false;
    size_t text_len = strnlen(text, PLATFORM_GLOB_INPUT_MAX + 1u);
    size_t pattern_len = strnlen(pattern, PLATFORM_GLOB_INPUT_MAX + 1u);
    if (text_len > PLATFORM_GLOB_INPUT_MAX ||
        pattern_len > PLATFORM_GLOB_INPUT_MAX) return false;
    bool state[PLATFORM_GLOB_INPUT_MAX + 1u] = { false };
    bool next[PLATFORM_GLOB_INPUT_MAX + 1u];
    state[0] = true;
    for (size_t i = 0; i < pattern_len;) {
        memset(next, 0, (text_len + 1u) * sizeof(next[0]));
        unsigned char token = (unsigned char)pattern[i];
        if (token == '*') {
            while (i < pattern_len && pattern[i] == '*') i++;
            next[0] = state[0];
            for (size_t j = 1; j <= text_len; j++) {
                bool consumable = !pathname || text[j - 1u] != '/';
                next[j] = state[j] || (consumable && next[j - 1u]);
            }
        } else {
            size_t consumed;
            platform_glob_transition(pattern, i, text, text_len, pathname,
                                     state, next, &consumed);
            i += consumed;
        }
        memcpy(state, next, (text_len + 1u) * sizeof(state[0]));
    }
    return state[text_len];
}

#endif
