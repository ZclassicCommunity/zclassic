/* zclassicd-owned. Compiles the vendored Z23 bn254.c with one name left alone.
 *
 * Every object of libzcl_c23.a is built with -include zcl_c23_symbol_prefix.h,
 * which renames each global of the core (g2_in_subgroup, a BLS12-381 function,
 * becomes zc23_g2_in_subgroup). bn254_engine.inc builds its function names by
 * token pasting (E_(g2_in_subgroup) is bne_portable_g2_in_subgroup), and the
 * pasted argument is macro-expanded first, so the definition would be named
 * bne_portable_zc23_g2_in_subgroup while the engine tables in bn254.c spell
 * bne_portable_g2_in_subgroup. bn254.c does not use the BLS12-381 function, so
 * it is released here for this one translation unit; nothing else is changed
 * and no symbol leaves bn254.c under a new name (check-c23-tor-symbols and the
 * archive symbol check still hold). The vendored file is included verbatim. */
#include "zcl_c23_symbol_prefix.h"
#undef g2_in_subgroup
#include "../vendor/core/modules/sapling/src/bn254.c"
