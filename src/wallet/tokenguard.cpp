// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "wallet/tokenguard.h"

#include "script/script.h"
#include "tinyformat.h"
#include "utilmoneystr.h"

#include "c23/services/glue/zcl_token_guard.h"

void TokenGuardClassify(const CTransaction& tx, std::vector<unsigned char>& vRolesRet)
{
    vRolesRet.clear();

    const size_t nOut = tx.vout.size();
    if (nOut < 2)
        return;

    // Reading A: the message must be vout[0]. Reading B: the message is the
    // first OP_RETURN output at any position. The first output whose script
    // starts with OP_RETURN is the candidate under B, and it is vout[0]
    // exactly when A has a candidate at all, so one scan covers the union.
    // A transaction with no OP_RETURN output is never handed to the parser.
    size_t nMessage = nOut;
    for (size_t i = 0; i < nOut; i++) {
        const CScript& script = tx.vout[i].scriptPubKey;
        if (!script.empty() && script[0] == OP_RETURN) {
            nMessage = i;
            break;
        }
    }
    if (nMessage == nOut)
        return;

    const CScript& message = tx.vout[nMessage].scriptPubKey;
    std::vector<unsigned char> vRoles(nOut, TOKEN_ROLE_NONE);
    const uint256 txid = tx.GetHash();
    size_t nProtected = zcl_token_guard_roles(&message[0], message.size(),
                                              txid.begin(), nOut,
                                              &vRoles[0], vRoles.size());
    if (nProtected == 0)
        return;

    // An OP_RETURN output is unspendable whatever a message says about it.
    vRoles[nMessage] = TOKEN_ROLE_NONE;
    vRolesRet.swap(vRoles);
}

unsigned char TokenGuardOutputRole(const CTransaction& tx, unsigned int n)
{
    std::vector<unsigned char> vRoles;
    TokenGuardClassify(tx, vRoles);
    return n < vRoles.size() ? vRoles[n] : TOKEN_ROLE_NONE;
}

std::string TokenGuardExcludedNote(const CTokenGuardReport& report)
{
    if (report.nExcluded == 0)
        return "";
    // No currency unit: the messages this is appended to print bare amounts too.
    return strprintf(" (%u token-bearing output%s holding %s %s protected and %s not used: "
                     "spending %s as ordinary funds would burn the ZSLP tokens or mint baton %s)",
                     report.nExcluded, report.nExcluded == 1 ? "" : "s",
                     FormatMoney(report.nExcludedValue),
                     report.nExcluded == 1 ? "is" : "are",
                     report.nExcluded == 1 ? "was" : "were",
                     report.nExcluded == 1 ? "it" : "them",
                     report.nExcluded == 1 ? "it carries" : "they carry");
}

std::string TokenGuardRefusedText(const COutPoint& outpoint)
{
    return strprintf("Input %s:%u carries ZSLP tokens or a mint baton and is protected: "
                     "spending it in a transaction that is not a matching token transfer burns them. "
                     "It was chosen explicitly, so nothing was selected in its place; "
                     "to spend it anyway, request the token-input override explicitly",
                     outpoint.hash.GetHex(), outpoint.n);
}
