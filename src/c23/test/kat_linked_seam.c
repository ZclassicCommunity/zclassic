/* TEST-ONLY. The three C++ seams of the production glue (zcl_c23_glue.c), for
 * running the KAT programs against the libzcl_c23.a the daemon links
 * (run.sh --linked). In zclassicd these come from c23/glue/zcl_c23_log.cpp.
 * Never part of any shipped binary. */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void zcl_c23_log_sink(const char *line);
bool zcl_c23_log_category_enabled(void);
void zcl_c23_network_id(char *buf, size_t cap);

void zcl_c23_log_sink(const char *line)
{
    if (line)
        fputs(line, stderr);
}

bool zcl_c23_log_category_enabled(void)
{
    const char *e = getenv("KAT_ZC23_LOG");
    return e && e[0] == '1';
}

void zcl_c23_network_id(char *buf, size_t cap)
{
    if (!buf || cap == 0)
        return;
    strncpy(buf, "main", cap - 1);
    buf[cap - 1] = '\0';
}
