// zclassicd-owned C++ side of the C23 glue seams. Belongs in a C++ library that
// can see util.h / chainparams.h (see WIRING.md).
#include <cstring>
#include <string>

#include "chainparams.h"
#include "util.h"

#include "zcl_c23_glue.h"

extern "C" void zcl_c23_log_sink(const char *line)
{
    if (line == nullptr)
        return;
    LogPrintStr(std::string("zc23: ") + line);
}

extern "C" bool zcl_c23_log_category_enabled(void)
{
    return LogAcceptCategory("zc23");
}

extern "C" void zcl_c23_network_id(char *buf, size_t cap)
{
    if (buf == nullptr || cap == 0)
        return;
    // NetworkIDString() returns by value; copy it out, never hand out c_str().
    const std::string id = Params().NetworkIDString();
    const size_t n = id.size() < cap - 1 ? id.size() : cap - 1;
    std::memcpy(buf, id.data(), n);
    buf[n] = '\0';
}
