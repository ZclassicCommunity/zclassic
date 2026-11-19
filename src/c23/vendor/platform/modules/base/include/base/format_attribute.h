/* Copyright 2026 Rhett Creighton - Apache License 2.0
 * Purpose: portable compile-time checking for printf-style functions. */

#ifndef ZCL_BASE_FORMAT_ATTRIBUTE_H
#define ZCL_BASE_FORMAT_ATTRIBUTE_H

/* MinGW's plain `printf` format archetype follows the Microsoft CRT dialect,
 * which diagnoses ISO C length modifiers such as %zu even though the UCRT
 * accepts them.  The GNU archetype describes the ISO/POSIX format strings the
 * project intentionally uses while retaining compile-time argument checking.
 */
/* clang implements no `gnu_printf` archetype at all.  It reaches the same
 * result a different way: on a MinGW target its `printf` archetype already
 * follows the ISO/POSIX dialect and accepts %zu, and naming an archetype it
 * does not know is not a fallback but a HARD ERROR
 * (-Werror,-Wignored-attributes), so every translation unit that includes a
 * logging header stops.  Ask which compiler is reading this, not only which
 * target it is aiming at. */
#if (defined(__MINGW32__) || defined(__MINGW64__)) && !defined(__clang__)
#define ZCL_PRINTF_FORMAT_ARCHETYPE __gnu_printf__
#else
#define ZCL_PRINTF_FORMAT_ARCHETYPE __printf__
#endif

#if defined(__has_attribute)
#if __has_attribute(format)
#define ZCL_PRINTF_LIKE(format_index, first_argument_index)                 \
    __attribute__((__format__(ZCL_PRINTF_FORMAT_ARCHETYPE, format_index,    \
                              first_argument_index)))
#else
#define ZCL_PRINTF_LIKE(format_index, first_argument_index)
#endif
#elif defined(__GNUC__)
#define ZCL_PRINTF_LIKE(format_index, first_argument_index)                 \
    __attribute__((__format__(ZCL_PRINTF_FORMAT_ARCHETYPE, format_index,    \
                              first_argument_index)))
#else
#define ZCL_PRINTF_LIKE(format_index, first_argument_index)
#endif

#endif /* ZCL_BASE_FORMAT_ATTRIBUTE_H */
