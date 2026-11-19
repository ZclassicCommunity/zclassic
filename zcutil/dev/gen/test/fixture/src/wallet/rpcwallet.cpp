// fixture: a table whose actor is defined in another file
#include "rpc/server.h"

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
    { "wallet",             "getbalance",             &getbalance,             false },
};
