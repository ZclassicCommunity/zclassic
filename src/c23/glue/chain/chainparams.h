/* zclassicd-owned shim for the Z23 include "chain/chainparams.h" (the only
 * Z23 consumer is vendor params_init.c). One field: the network id string
 * ("main", "test", "regtest"). Filled from zclassicd Params() at call time. */
#ifndef ZCL_C23_CHAIN_CHAINPARAMS_H
#define ZCL_C23_CHAIN_CHAINPARAMS_H

struct chain_params {
    const char *strNetworkID;
};

/* Never NULL; the pointer is valid until the calling thread's next call. */
const struct chain_params *chain_params_get(void);

#endif
