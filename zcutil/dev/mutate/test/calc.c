/* calc.c: fixture for `zcl-dev mutate run`. `mutate_test --role check` kills every mutant except the
 * two equivalent ones in clamp(): `v < lo` -> `v <= lo` and `v > hi` -> `v >= hi` (lines 7 and 8). */
#include <stdio.h>
#include <stdlib.h>
static int clamp(int v, int lo, int hi)
{
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int is_even(int v)
{
    return v % 2 == 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    int v = atoi(argv[1]);
    printf("%d %d\n", clamp(v, 0, 10), is_even(v));
    return 0;
}
