// Copyright (c) 2019 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "params.h"

#include "upgrades.h"

namespace Consensus {
    bool Params::NetworkUpgradeActive(int nHeight, Consensus::UpgradeIndex idx) const {
        return NetworkUpgradeState(nHeight, *this, idx) == UPGRADE_ACTIVE;
    }

    int Params::Halving(int nHeight) const {
        if (NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BUTTERCUP)) {
            int buttercupActivationHeight = vUpgrades[Consensus::UPGRADE_BUTTERCUP].nActivationHeight;
            int halvings = (nHeight - SubsidySlowStartShift() - buttercupActivationHeight) / nPostButtercupSubsidyHalvingInterval;
            return halvings + 3; // Triple halving
        } else {
            return (nHeight - SubsidySlowStartShift()) / nPreButtercupSubsidyHalvingInterval;
        }
    }

    int64_t Params::PoWTargetSpacing(int nHeight) const {
        bool buttercupActive = NetworkUpgradeActive(nHeight, Consensus::UPGRADE_BUTTERCUP);
        return buttercupActive ? nPostButtercupPowTargetSpacing : nPreButtercupPowTargetSpacing;
    }

    int64_t Params::AveragingWindowTimespan(int nHeight) const {
        return nPowAveragingWindow * PoWTargetSpacing(nHeight);
    }

    int64_t Params::MinActualTimespan(int nHeight) const {
        return (AveragingWindowTimespan(nHeight) * (100 - nPowMaxAdjustUp)) / 100;
    }

    int64_t Params::MaxActualTimespan(int nHeight) const {
        return (AveragingWindowTimespan(nHeight) * (100 + nPowMaxAdjustDown)) / 100;
    }
}
