#ifndef FX_A_H
#define FX_A_H
#include "b.h"
// a cycle: b.h includes a.h back
int a_value();
#endif
