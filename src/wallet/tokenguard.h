// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCLASSIC_WALLET_TOKENGUARD_H
#define ZCLASSIC_WALLET_TOKENGUARD_H

#include "amount.h"
#include "primitives/transaction.h"

#include <string>
#include <vector>

/**
 * Wallet token guard.
 *
 * ZSLP tokens are SLP Token Type 1 messages: an OP_RETURN output whose pushes
 * start with the lokad id "SLP\0". The token quantities and the mint baton do
 * not live in that output. They ride on ordinary dust outputs of the same
 * transaction (vout[1] and vout[mint_baton_vout] for GENESIS and MINT,
 * vout[i+1] for the i-th SEND quantity). To this wallet those outputs look
 * like any other coin, and spending one as fee or payment burns the tokens.
 *
 * The check is structural and needs no index: an output is protected when its
 * OWN transaction carries a parseable SLP message that assigns a nonzero
 * quantity or the mint baton to that vout. It does not ask whether the token
 * lineage is valid; leaving 546 zatoshi untouched is cheap, burning an asset
 * is not. The message is parsed by Z23's wire parser, vendored verbatim under
 * src/c23/services/vendor.
 *
 * Which output may carry the message is not settled (vout[0] only, or the
 * first OP_RETURN output at any position). Both readings are applied and their
 * union is protected: the message is taken from the first output whose script
 * starts with OP_RETURN, which is vout[0] whenever vout[0] is an OP_RETURN.
 *
 * This is wallet coin selection only. It is not consensus, not mempool policy
 * and not relay, and it stores nothing in wallet.dat.
 */

/** Role of an output, as written by TokenGuardClassify. */
static const unsigned char TOKEN_ROLE_NONE = 0;
static const unsigned char TOKEN_ROLE_TOKEN = 1;      //!< carries a nonzero token quantity
static const unsigned char TOKEN_ROLE_MINT_BATON = 2; //!< carries the mint baton

/**
 * Classify every output of tx. vRolesRet is left EMPTY when no output is
 * protected (the common case, and the only case for a transaction without an
 * OP_RETURN output, which is never parsed); otherwise it has tx.vout.size()
 * entries.
 */
void TokenGuardClassify(const CTransaction& tx, std::vector<unsigned char>& vRolesRet);

/** Uncached convenience form of TokenGuardClassify for a single output. */
unsigned char TokenGuardOutputRole(const CTransaction& tx, unsigned int n);

/** What a coin-gathering step left out because of the token guard. */
struct CTokenGuardReport
{
    //! spendable token-bearing outputs that were left out of the candidate set
    unsigned int nExcluded;
    //! their total value
    CAmount nExcludedValue;
    //! an explicitly chosen input was refused (no override given)
    bool fRefusedSelected;
    COutPoint refusedOutpoint;

    CTokenGuardReport() : nExcluded(0), nExcludedValue(0), fRefusedSelected(false) {}

    void Exclude(CAmount nValue)
    {
        nExcluded++;
        nExcludedValue += nValue;
    }
};

/**
 * Text to append to an "insufficient funds" style error so the user learns
 * why visible balance was not used. Empty when nothing was excluded.
 */
std::string TokenGuardExcludedNote(const CTokenGuardReport& report);

/** Error text for an explicitly chosen token-bearing input that was refused. */
std::string TokenGuardRefusedText(const COutPoint& outpoint);

#endif // ZCLASSIC_WALLET_TOKENGUARD_H
