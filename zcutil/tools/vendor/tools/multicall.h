/* purpose: in-process entry points (jsonq_main, sqlq_main) for the jsonq and sqlq query tools */
/* Copyright 2026 Rhett Creighton - Apache License 2.0 */

#ifndef ZCL_TOOLS_MULTICALL_H
#define ZCL_TOOLS_MULTICALL_H

/* In-process entry points for the small query tools. Each takes its own
 * argv (argv[0] is the tool name, as for a standalone main) and returns its
 * exit status. The standalone binaries (build/bin/jsonq) call these with
 * their own argv; `z23 jsonq ...` calls them with argv+1, so the output is
 * the same either way. */
int jsonq_main(int argc, char **argv);
int sqlq_main(int argc, char **argv);

#endif /* ZCL_TOOLS_MULTICALL_H */
