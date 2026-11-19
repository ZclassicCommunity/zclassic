/* list_fixture.c: golden input for `zcl-dev mutate list`. A line marked NOSITE must yield no site.
 * Operators in this comment: a < b && c == 1 || return true; NOSITE
 */
#include <stdio.h> /* NOSITE */
#if CAP > 16 /* NOSITE */
#endif
#define CAP 32
#define LIMIT(x) ((x) < CAP)

static const char *msg = "a < b && c == 1"; /* NOSITE */
static const char quote = '<'; /* NOSITE */
static int table[8]; /* NOSITE */

static int in_range(int v, int lo, int hi)
{
    // v < lo && v > hi NOSITE
    if (v < lo || v > hi)
        return 0;
    return v >= lo && v <= hi;
}

static int ok(int v)
{
    if (v == 0x10 || v != 0755) /* hex and octal are not boundary sites */
        return true;
    return false;
}

void touch(int *p)
{
    table[3] = 1;
    printf("%d\n", *p);
    int x = in_range(*p, 1, 9);
    fflush(stdout);
    if (x) puts(msg);
    (void)quote;
    *p = ok(x) << 2;
    *p >>= 1;
    *p = *p > 1 ? 2 : 3;
    return;
}
