// fixture: network commands, a table with preprocessor lines and a comment in a row
#include "rpc/server.h"

UniValue getconnectioncount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw runtime_error(
            "getconnectioncount\n"
            "\nReturns the number of connections to other nodes.\n"
            "\nResult:\n"
            "n          (numeric) The connection count\n"
            "\nExamples:\n"
            + HelpExampleCli("getconnectioncount", "")
            + HelpExampleRpc("getconnectioncount", "")
        );
    return 0;
}

UniValue addnode(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "addnode \"node\" \"add|remove|onetry\"\n"
            "\nAttempts add or remove a node from the addnode list.\n"
            + strprintf("Default port %d\n", 8033)
        );
    return NullUniValue;
}

static const CRPCCommand commands[] =
{ //  category              name                      actor (function)         okSafeMode
    { "network",            "getconnectioncount",     &getconnectioncount,     true  },
#ifdef ENABLE_ADDNODE
    { "network",            "addnode",                &addnode,                true  }, /* comment in a row */
#endif
};
