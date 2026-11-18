// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Name resolution over the ZNAM index, for paying a name.
//
// Resolution is a local read of the index: nothing is sent to any peer, so
// which name you look up is not observable. What it returns is a CHOICE of
// address for the caller to show and confirm. It is never a payment: no
// transaction ever carries a name. Every answer says which block and
// transaction set the address and whether that was recent, because a name
// whose address just changed is the signature of a hijacked owner key.

#ifndef BITCOIN_ZNAM_ZNAMRESOLVE_H
#define BITCOIN_ZNAM_ZNAMRESOLVE_H

#include "znam/znamindex.h"

#include <string>
#include <vector>

namespace znam {

/** A name registered within this many blocks is flagged by the default GUI/RPC settings, and so is an address change. */
static const int DEFAULT_RECENT_BLOCKS = 100;

enum PayKind {
    PAY_NONE = 0,        //! not an address this wallet can pay
    PAY_TRANSPARENT = 1, //! a t-address (P2PKH or P2SH) of this chain
    PAY_SAPLING = 2,
    PAY_SPROUT = 3
};

const char* PayKindName(PayKind k);

/** Z23's name syntax, and nothing else: 1-63 of a-z 0-9 and '-', no leading or trailing '-'. A name with an embedded NUL
 *  is invalid (a C string would silently cut it short). */
bool ValidName(const std::string& name);

/** Is `value` a payable address of the kind the record's `type` declares, on the active chain? `why` says what is
 *  wrong when not. Types other than t-address and z-address are never payable. */
PayKind ClassifyAddress(unsigned int type, const std::string& value, std::string& why);

/** One place a name points at. */
struct Candidate {
    unsigned int type;
    std::string value;
    bool fromRecord;   //! a SET_RECORD address record (else the primary target)
    int height;        //! the block that set it (for the primary target: the last REGISTER/UPDATE/TRANSFER)
    uint256 txid;
    PayKind kind;
    std::string why;   //! why it is not payable, when kind is PAY_NONE and type is t- or z-address
    Candidate() : type(0), fromRecord(false), height(0), kind(PAY_NONE) {}
};

struct Resolution {
    enum Status {
        OK = 0,
        MALFORMED = 1,  //! not a valid name: nothing was looked up
        ABSENT = 2,     //! valid, not registered
        NO_TARGET = 3   //! registered, but no record of the asked type (or none payable)
    };
    Status status;
    Entry entry;
    std::vector<Candidate> candidates; //! the primary target, then the address records, in type order
    int selected;                      //! index into candidates, -1 when none
    int changeHeight;                  //! when what the answer rests on last changed (name, owner or the record used)
    uint256 changeTxid;
    int blocksSinceChange;
    bool recent;                       //! blocksSinceChange < recentBlocks
    bool expired;                      //! bookkeeping term lapsed (still resolves, as in Z23)
    std::vector<std::string> warnings;
    Resolution() : status(MALFORMED), selected(-1), changeHeight(0), blocksSinceChange(0), recent(false), expired(false) {}
};

/** Resolve `name`. wantType 0 means "an address to pay": the primary target when it is a payable t- or z-address,
 *  else a payable t-address record, else a payable z-address record. A non-zero wantType is Z23's name_resolve:
 *  the primary target when it has that type, else the SET_RECORD of that type. */
Resolution Resolve(const ZnamIndex& index, const std::string& name, unsigned int wantType, int tipHeight, int recentBlocks);

} // namespace znam

#endif // BITCOIN_ZNAM_ZNAMRESOLVE_H
