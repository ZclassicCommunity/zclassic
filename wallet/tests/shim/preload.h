#ifndef ZCL_LOGIC_TEST_PRELOAD_H
#define ZCL_LOGIC_TEST_PRELOAD_H

// Load the existing isolation shims before product quoted includes. qmake's
// PCH support handles GCC/Clang/MSVC without changing compiler feature probes.
#include "rpc.h"
#include "addressbook.h"

#endif
