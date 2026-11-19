// fixture: actor definition apart from its table
#include "rpc/server.h"

UniValue getbalance(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 1)
        throw runtime_error(
            "getbalance ( minconf )\n"
            "\nReturns the wallet balance.\n"
            "\nArguments:\n"
            "1. minconf     (numeric, optional, default=1) Only count confirmed funds\n"
        );
    return 0;
}
