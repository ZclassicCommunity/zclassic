/* purpose: standalone build/bin/jsonq entry point that delegates to jsonq_main */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

/* Standalone build/bin/jsonq: the same walker as `z23 jsonq`, kept as its own
 * binary because many scripts and gates name build/bin/jsonq directly. */

#include "multicall.h"

int main(int argc, char **argv)
{
    return jsonq_main(argc, argv);
}
