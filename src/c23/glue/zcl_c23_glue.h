/* zclassicd-owned. Seams between the C23 glue and zclassicd C++. */
#ifndef ZCL_C23_GLUE_H
#define ZCL_C23_GLUE_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Implemented in zcl_c23_log.cpp (daemon) or zcl_c23_test_glue.c (tests). */
void zcl_c23_log_sink(const char *line);        /* one already-formatted line */
bool zcl_c23_log_category_enabled(void);        /* -debug=zc23 (or -debug=1) */
void zcl_c23_network_id(char *buf, size_t cap); /* "main" / "test" / "regtest" */

/* Implemented in zcl_c23_glue.c. Call once after command-line parsing. */
void zcl_c23_log_refresh(void);

#ifdef __cplusplus
}
#endif
#endif
