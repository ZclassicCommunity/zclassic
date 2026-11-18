/* zclassicd glue for the vendored Z23 ZNAM parser (src/c23/services).
 *
 * Stands in for Z23's script/standard.h. The vendored znam.c reads exactly one
 * name from it, MAX_OP_RETURN_RELAY: the longest OP_RETURN script a builder
 * may emit, because a longer one does not relay. The value is Z23's
 * (core/modules/script/include/script/standard.h:33) and is also zclassicd's own
 * (src/script/standard.h), so a record built here relays on both.
 *
 * Found through -iquote, searched before -I, so it wins over zclassicd's C++
 * header of the same name inside this C library only. */
#ifndef ZCL_SERVICES_GLUE_SCRIPT_STANDARD_H
#define ZCL_SERVICES_GLUE_SCRIPT_STANDARD_H

#define MAX_OP_RETURN_RELAY 223

#endif
