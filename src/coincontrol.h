// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_COINCONTROL_H
#define BITCOIN_COINCONTROL_H

#include "primitives/transaction.h"

/** Coin Control Features. */
class CCoinControl
{
public:
    CTxDestination destChange;
    //! If false, allows unselected inputs, but requires all selected inputs be used
    bool fAllowOtherInputs;
    //! Wallet token guard override. If false (the default), an explicitly
    //! selected input that carries ZSLP tokens or a mint baton makes coin
    //! selection fail. If true, explicitly selected token-bearing inputs are
    //! spent as asked. It never makes the wallet pick a token-bearing output
    //! on its own: only outputs in the selected set are affected.
    bool fAllowTokenOutputs;
    //! Put the ZCL change output LAST instead of at a random position. Used by
    //! the ZSLP token transactions, whose token outputs are named by position
    //! (vout[1]..vout[n]) and must not be shifted. Default false: unchanged.
    bool fChangeLast;
    //! Pay exactly this fee instead of the estimated one (-1: estimate, the
    //! default). It must still meet the minimum relay fee. Used by zslp_send.
    CAmount nFixedFee;

    CCoinControl()
    {
        SetNull();
    }

    void SetNull()
    {
        destChange = CNoDestination();
        fAllowOtherInputs = false;
        fAllowTokenOutputs = false;
        fChangeLast = false;
        nFixedFee = -1;
        setSelected.clear();
    }

    bool HasSelected() const
    {
        return (setSelected.size() > 0);
    }

    bool IsSelected(const uint256& hash, unsigned int n) const
    {
        COutPoint outpt(hash, n);
        return (setSelected.count(outpt) > 0);
    }

    void Select(const COutPoint& output)
    {
        setSelected.insert(output);
    }

    void UnSelect(const COutPoint& output)
    {
        setSelected.erase(output);
    }

    void UnSelectAll()
    {
        setSelected.clear();
    }

    void ListSelected(std::vector<COutPoint>& vOutpoints) const
    {
        vOutpoints.assign(setSelected.begin(), setSelected.end());
    }

private:
    std::set<COutPoint> setSelected;
};

#endif // BITCOIN_COINCONTROL_H
