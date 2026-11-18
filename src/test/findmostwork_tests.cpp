// Copyright (c) 2026 The ZClassic developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// FindMostWorkChain() keeps a memo of the part of the candidate path it already
// verified. These tests compare it with the reference implementation (the
// original full walk) on identical states: same selected block, same changes to
// every flag, candidate, unlinked-block and parked/invalid marker.

#include "chain.h"
#include "clientversion.h"
#include "main.h"
#include "streams.h"
#include "test/test_bitcoin.h"
#include "uint256.h"
#include "util.h"

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <vector>

namespace {

struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed * 0x9E3779B97F4A7C15ULL + 0x1234567ULL) {}
    uint32_t Next() {
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return uint32_t((s * 0x2545F4914F6CDD1DULL) >> 32);
    }
    uint32_t Below(uint32_t n) { return Next() % n; }
};

const unsigned int GOOD = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;

/** A block index forest registered in mapBlockIndex; removes itself on destruction. */
struct Forest {
    std::deque<CBlockIndex> blocks;
    std::deque<uint256> hashes;
    std::vector<CBlockIndex*> all;
    Rng rng;

    explicit Forest(uint64_t seed) : rng(seed) {}
    ~Forest() {
        chainActive.SetTip(NULL);
        BestChainStateRestore(BestChainState(), std::vector<CBlockIndex*>());
        for (CBlockIndex* p : all)
            mapBlockIndex.erase(*p->phashBlock);
    }

    CBlockIndex* Add(CBlockIndex* parent, unsigned int status)
    {
        blocks.emplace_back();
        CBlockIndex* p = &blocks.back();
        hashes.push_back(ArithToUint256(arith_uint256(all.size() + 1)));
        p->pprev = parent;
        p->nHeight = parent ? parent->nHeight + 1 : 0;
        p->nChainWork = (parent ? parent->nChainWork : arith_uint256()) + arith_uint256(1 + rng.Below(2));
        p->nChainTx = p->nHeight + 1; // the path walk asserts that this is non-zero
        p->nTx = 1;
        // Unique per block, so that the candidate order never falls back to comparing
        // addresses and a run is exactly reproducible (the work is often tied).
        p->nSequenceId = uint32_t(all.size() * 7919 % 100003);
        p->nStatus = status;
        p->BuildSkip();
        auto it = mapBlockIndex.insert(std::make_pair(hashes.back(), p)).first;
        p->phashBlock = &it->first;
        all.push_back(p);
        return p;
    }
};

/** Re-derive the parked-block index after nStatus was written directly. */
void SyncParked(const std::vector<CBlockIndex*>& all)
{
    BestChainStateRestore(BestChainStateSave(all), all);
}

/**
 * Run the reference and the memoised walk from the same state (same flags,
 * candidates, unlinked blocks, markers, memo and epoch) and compare the selected
 * block and every change they made. Leaves the state the memoised walk produced.
 * mode 1: the memoised walk alone; mode 2: through FindMostWorkChain(), whose own
 * -checkblockindex cross-check (fCheckBlockIndex is on in the test setup) runs too.
 */
bool Differential(const std::vector<CBlockIndex*>& all, int mode, CBlockIndex** selected = NULL)
{
    const BestChainState s0 = BestChainStateSave(all);
    CBlockIndex* ref = FindMostWorkChainForTest(0);
    const BestChainState sref = BestChainStateSave(all);

    BestChainStateRestore(s0, all);
    CBlockIndex* fast = FindMostWorkChainForTest(mode);
    const BestChainState sfast = BestChainStateSave(all);
    if (selected) *selected = fast;

    return ref == fast && BestChainStateSame(sref, sfast);
}

void SetTipTo(CBlockIndex* p) { chainActive.SetTip(p); }

} // namespace

BOOST_FIXTURE_TEST_SUITE(findmostwork_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(status_epoch_counts_exactly_the_path_walk_bits)
{
    CBlockIndex b;
    uint64_t e = BlockPathWalkEpoch();
    // Bits the path walk does not read, and rewriting the same value, do not advance the epoch.
    b.nStatus |= BLOCK_VALID_TREE;
    b.nStatus |= BLOCK_HAVE_UNDO;
    b.nStatus |= BLOCK_ACTIVATES_UPGRADE;
    BOOST_CHECK(b.RaiseValidity(BLOCK_VALID_SCRIPTS));
    b.nStatus = static_cast<unsigned int>(b.nStatus);
    BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e);
    // Every bit the path walk reads advances it on each change, and only on a change.
    const unsigned int bits[] = {BLOCK_HAVE_DATA, BLOCK_FAILED_VALID, BLOCK_FAILED_CHILD,
                                 BLOCK_PARKED_FLAG, BLOCK_PARKED_PARENT_FLAG};
    for (unsigned int bit : bits) {
        b.nStatus = 0;
        e = BlockPathWalkEpoch();
        b.nStatus |= bit;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 1);
        b.nStatus |= bit;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 1);
        b.nStatus &= ~bit;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 2);
        b.nStatus &= ~bit;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 2);
        b.nStatus = static_cast<unsigned int>(b.nStatus) | bit;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 3);
        b.nStatus = 0;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 4);
        b.nStatus = BLOCK_VALID_SCRIPTS;
        BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 4);
    }
    // Copying an entry is not a change to the block graph; assigning to a copy is.
    CBlockIndex d;
    d.nStatus = BLOCK_HAVE_DATA;
    e = BlockPathWalkEpoch();
    CBlockIndex f(d);
    BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e);
    f.nStatus = 0;
    BOOST_CHECK_EQUAL(BlockPathWalkEpoch(), e + 1);
}

BOOST_AUTO_TEST_CASE(status_disk_format_is_unchanged)
{
    CBlockIndex b;
    b.nHeight = 1234;
    b.nTx = 7;
    b.nFile = 3;
    b.nDataPos = 99;
    b.nStatus = BLOCK_VALID_SCRIPTS | BLOCK_HAVE_DATA | BLOCK_PARKED_FLAG | BLOCK_FAILED_CHILD;
    CDiskBlockIndex out(&b);
    CDataStream ss(SER_DISK, CLIENT_VERSION);
    ss << out;
    // Reconstruct the expected leading bytes with plain integers: nVersion, nHeight, nStatus, nTx, nFile, nDataPos.
    CDataStream expected(SER_DISK, CLIENT_VERSION);
    int nVersion = CLIENT_VERSION;
    int nHeight = 1234;
    unsigned int nStatus = out.nStatus, nTx = 7, nFile = 3, nDataPos = 99;
    expected << VARINT(nVersion) << VARINT(nHeight) << VARINT(nStatus) << VARINT(nTx) << VARINT(nFile) << VARINT(nDataPos);
    BOOST_REQUIRE(ss.size() > expected.size());
    BOOST_CHECK(std::equal(expected.begin(), expected.end(), ss.begin()));
    CDiskBlockIndex in;
    ss >> in;
    BOOST_CHECK_EQUAL(unsigned(in.nStatus), unsigned(out.nStatus));
    BOOST_CHECK_EQUAL(in.nHeight, out.nHeight);
    BOOST_CHECK_EQUAL(in.nDataPos, out.nDataPos);
}

BOOST_AUTO_TEST_CASE(memo_skips_validated_path_and_is_dropped_on_any_status_change)
{
    Forest f(1);
    std::vector<CBlockIndex*> chain;
    chain.push_back(f.Add(NULL, GOOD));
    for (int i = 1; i < 100; ++i) chain.push_back(f.Add(chain.back(), GOOD));
    SetTipTo(chain[10]);
    BestChainState s = BestChainStateSave(f.all);
    s.candidates.assign(1, chain[99]);
    BestChainStateRestore(s, f.all);

    // First call: full walk, memo records the fork point as its floor.
    CBlockIndex* sel = NULL;
    BOOST_REQUIRE(Differential(f.all, 1, &sel));
    BOOST_CHECK(sel == chain[99]);
    s = BestChainStateSave(f.all);
    BOOST_CHECK(s.memoIndex == chain[99]);
    BOOST_CHECK(s.memoFloor == chain[10]);
    BOOST_CHECK_EQUAL(s.memoEpoch, BlockPathWalkEpoch());

    // The tip advances along the path: the walk is skipped, the memo is kept as it was.
    SetTipTo(chain[42]);
    BOOST_REQUIRE(Differential(f.all, 2, &sel));
    BOOST_CHECK(sel == chain[99]);
    s = BestChainStateSave(f.all);
    BOOST_CHECK(s.memoFloor == chain[10]);
    BOOST_CHECK_EQUAL(s.memoEpoch, BlockPathWalkEpoch());

    // A reorg to below the memo floor walks only the missing segment and lowers the floor.
    SetTipTo(chain[5]);
    BOOST_REQUIRE(Differential(f.all, 2, &sel));
    BOOST_CHECK(sel == chain[99]);
    s = BestChainStateSave(f.all);
    BOOST_CHECK(s.memoFloor == chain[5]);

    // A flag change on the path must be seen even though the candidate is unchanged.
    chain[60]->nStatus |= BLOCK_FAILED_VALID;
    BOOST_CHECK(BestChainStateSave(f.all).memoEpoch != BlockPathWalkEpoch());
    BOOST_REQUIRE(Differential(f.all, 2, &sel));
    BOOST_CHECK(sel == NULL);
    BOOST_CHECK(chain[99]->nStatus & BLOCK_FAILED_CHILD);

    // Missing data on the path, likewise.
    for (int i = 60; i < 100; ++i) chain[i]->nStatus &= ~BLOCK_FAILED_MASK;
    s = BestChainStateSave(f.all);
    s.candidates.assign(1, chain[99]);
    BestChainStateRestore(s, f.all);
    BOOST_REQUIRE(Differential(f.all, 2, &sel));
    BOOST_CHECK(sel == chain[99]);
    chain[70]->nStatus &= ~BLOCK_HAVE_DATA;
    BOOST_REQUIRE(Differential(f.all, 2, &sel));
    BOOST_CHECK(sel == NULL);
}

BOOST_AUTO_TEST_CASE(connecting_toward_a_far_ahead_candidate_does_not_rewalk_the_path)
{
    // The shape of -reindex-chainstate: the best candidate is the far end of a long
    // chain and the tip moves toward it in steps of up to 32 blocks, one
    // FindMostWorkChain() call per step.
    const int n = 60000;
    Forest f(7);
    CBlockIndex* last = f.Add(NULL, GOOD);
    for (int i = 1; i < n; ++i) last = f.Add(last, GOOD);
    BestChainState s = BestChainStateSave(f.all);
    s.candidates.assign(1, last);
    BestChainStateRestore(s, f.all);

    int64_t usec[2] = {0, 0};
    int steps[2] = {0, 0};
    for (int mode = 0; mode < 2; ++mode) {
        SetTipTo(f.all[0]);
        const int64_t t0 = GetTimeMicros();
        for (;;) {
            CBlockIndex* sel = FindMostWorkChainForTest(mode);
            BOOST_REQUIRE(sel == last);
            if (chainActive.Tip() == last) break;
            SetTipTo(last->GetAncestor(std::min(chainActive.Height() + 32, last->nHeight)));
            ++steps[mode];
        }
        usec[mode] = GetTimeMicros() - t0;
    }
    BOOST_CHECK_EQUAL(steps[0], steps[1]);
    BOOST_TEST_MESSAGE(steps[0] << " steps over " << n << " blocks: reference walk " << usec[0] / 1000
                       << " ms, memoised walk " << usec[1] / 1000 << " ms");
    BOOST_CHECK(usec[1] < usec[0]);
}

BOOST_AUTO_TEST_CASE(randomized_differential_against_reference)
{
    const int trials = 40;
    const int steps = 220;
    int checks = 0, nonNull = 0;
    for (int trial = 0; trial < trials; ++trial) {
        Forest f(1000 + trial);
        Rng& rng = f.rng;
        f.Add(NULL, GOOD | BLOCK_VALID_SCRIPTS);
        for (int i = 0; i < 30; ++i)
            f.Add(f.all[rng.Below(f.all.size())], rng.Below(8) ? GOOD : BLOCK_VALID_TREE);
        SetTipTo(f.all[0]);
        {
            BestChainState s = BestChainStateSave(f.all);
            s.candidates.assign(1, f.all.back());
            for (CBlockIndex* p : f.all)
                if ((p->nStatus & BLOCK_HAVE_DATA) && rng.Below(3) == 0) s.candidates.push_back(p);
            BestChainStateRestore(s, f.all);
        }

        for (int step = 0; step < steps; ++step) {
            const std::vector<CBlockIndex*>& all = f.all;
            auto randomBlock = [&]() { return all[rng.Below(all.size())]; };
            auto descendantsOf = [&](CBlockIndex* base) {
                std::vector<CBlockIndex*> v;
                for (CBlockIndex* p : all)
                    if (p->nHeight >= base->nHeight && p->GetAncestor(base->nHeight) == base) v.push_back(p);
                return v;
            };
            auto anyParked = [&]() {
                for (CBlockIndex* p : all)
                    if (p->nStatus & BLOCK_PARKED_MASK) return true;
                return false;
            };
            auto addCandidate = [&](CBlockIndex* p) {
                BestChainState s = BestChainStateSave(all);
                s.candidates.push_back(p);
                BestChainStateRestore(s, all);
            };
            if (!chainActive.Tip()) SetTipTo(all[rng.Below(all.size())]);

            switch (rng.Below(15)) {
            case 0: case 1: case 2: { // new block, mostly extending recent ones
                CBlockIndex* parent = rng.Below(5) ? all[all.size() - 1 - rng.Below(std::min<size_t>(8, all.size()))] : randomBlock();
                const bool data = rng.Below(8) != 0;
                CBlockIndex* p = f.Add(parent, data ? GOOD : BLOCK_VALID_TREE);
                if (data && rng.Below(3) != 0) addCandidate(p);
                if (!data) {
                    BestChainState s = BestChainStateSave(all);
                    s.blocksUnlinked.push_back(std::make_pair(parent, p));
                    BestChainStateRestore(s, all);
                }
                break;
            }
            case 3: { // invalidateblock-like: failed block and some failed descendants
                CBlockIndex* b = randomBlock();
                b->nStatus |= BLOCK_FAILED_VALID;
                for (CBlockIndex* d : descendantsOf(b))
                    if (d != b && rng.Below(2)) d->nStatus |= BLOCK_FAILED_CHILD;
                break;
            }
            case 4: { // reconsiderblock: the real function
                SyncParked(all);
                ResetBlockFailureFlags(randomBlock());
                break;
            }
            case 5: { // parkblock-like
                CBlockIndex* b = randomBlock();
                b->nStatus |= BLOCK_PARKED_FLAG;
                for (CBlockIndex* d : descendantsOf(b))
                    if (d != b) d->nStatus |= BLOCK_PARKED_PARENT_FLAG;
                SyncParked(all);
                break;
            }
            case 6: { // unparkblock: the real functions
                SyncParked(all);
                if (rng.Below(2)) UnparkBlock(randomBlock());
                else UnparkBlockAndChildren(randomBlock());
                break;
            }
            case 7: { // data pruned / arrived
                CBlockIndex* b = randomBlock();
                if (b->nStatus & BLOCK_HAVE_DATA) b->nStatus &= ~BLOCK_HAVE_DATA;
                else b->nStatus |= BLOCK_HAVE_DATA;
                break;
            }
            case 8: case 9: { // activate: advance the tip toward the best candidate
                const BestChainState s = BestChainStateSave(all);
                if (!s.candidates.empty()) {
                    CBlockIndex* best = s.candidates.back();
                    int h = std::min(chainActive.Height() + 1 + int(rng.Below(40)), best->nHeight);
                    SetTipTo(best->GetAncestor(h));
                }
                break;
            }
            case 10: // reorg / disconnect: tip anywhere
                SetTipTo(randomBlock());
                break;
            case 11: { // finalization point
                BestChainState s = BestChainStateSave(all);
                if (!rng.Below(3) || !chainActive.Tip()) s.pindexFinalized = NULL;
                else s.pindexFinalized = chainActive.Tip()->GetAncestor(std::max(0, chainActive.Height() - int(rng.Below(6))));
                BestChainStateRestore(s, all);
                break;
            }
            case 12: { // candidate set edits
                CBlockIndex* b = randomBlock();
                BestChainState s = BestChainStateSave(all);
                if (rng.Below(2)) {
                    if (b->nStatus & BLOCK_HAVE_DATA) s.candidates.push_back(b);
                } else if (!s.candidates.empty()) {
                    s.candidates.erase(s.candidates.begin() + rng.Below(s.candidates.size()));
                }
                BestChainStateRestore(s, all);
                break;
            }
            case 13: // initialisation-like: no tip (only when no parked block could be unparked)
                if (!anyParked()) {
                    BestChainState s = BestChainStateSave(all);
                    s.pindexFinalized = NULL;
                    BestChainStateRestore(s, all);
                    SetTipTo(NULL);
                }
                break;
            default: // nothing changes: repeat the call
                break;
            }

            const int calls = 1 + rng.Below(3);
            for (int c = 0; c < calls; ++c) {
                CBlockIndex* sel = NULL;
                const bool ok = Differential(all, 1 + ((step + c) & 1), &sel);
                BOOST_REQUIRE_MESSAGE(ok, "memoised and reference walks differ: trial " << trial << " step " << step << " call " << c);
                ++checks;
                if (sel) ++nonNull;
                if (sel && rng.Below(2) && chainActive.Tip()) {
                    // as ActivateBestChain does: move toward what was selected, in chunks of up to 32
                    int h = std::min(chainActive.Height() + 1 + int(rng.Below(32)), sel->nHeight);
                    if (h >= 0) SetTipTo(sel->GetAncestor(h));
                }
            }
        }
    }
    BOOST_TEST_MESSAGE("differential checks: " << checks << ", with a selected block: " << nonNull);
    BOOST_CHECK(checks > 5000);
    BOOST_CHECK(nonNull > 1000);
}

// Reviewer extension: a longer randomized differential run with more operation
// types, aimed at the memo specifically (bit flips on the memoised path and on
// the segment below its floor, tip moves below the floor, heavy parked branches
// that the walk unparks by PoW, no-tip walks, finalization points off the
// active chain, toggling -parkdeepreorg, ABA flips). FMW_TRIALS / FMW_STEPS /
// FMW_SEED override the size. A NULL tip is never combined with parked blocks:
// UnparkBlock() (and so the reference walk) dereferences the tip then.
BOOST_AUTO_TEST_CASE(randomized_differential_reviewer_extension)
{
    const char* envTrials = getenv("FMW_TRIALS");
    const char* envSteps = getenv("FMW_STEPS");
    const char* envSeed = getenv("FMW_SEED");
    const int trials = envTrials ? atoi(envTrials) : 60;
    const int steps = envSteps ? atoi(envSteps) : 300;
    const uint64_t seed0 = envSeed ? strtoull(envSeed, NULL, 10) : 777000;
    int checks = 0, nonNull = 0, memoHitSkip = 0, memoHitSegment = 0, unparkedByWalk = 0;
    int opCount[24] = {0};
    for (int trial = 0; trial < trials; ++trial) {
        Forest f(seed0 + trial);
        Rng& rng = f.rng;
        f.Add(NULL, GOOD | BLOCK_VALID_SCRIPTS);
        const int initial = 10 + rng.Below(60);
        for (int i = 0; i < initial; ++i)
            f.Add(f.all[f.all.size() - 1 - rng.Below(std::min<size_t>(f.all.size(), rng.Below(2) ? 3 : f.all.size()))],
                  rng.Below(10) ? GOOD : BLOCK_VALID_TREE);
        SetTipTo(f.all[0]);
        {
            BestChainState s = BestChainStateSave(f.all);
            s.candidates.assign(1, f.all.back());
            for (CBlockIndex* p : f.all)
                if ((p->nStatus & BLOCK_HAVE_DATA) && rng.Below(3) == 0) s.candidates.push_back(p);
            BestChainStateRestore(s, f.all);
        }

        for (int step = 0; step < steps; ++step) {
            const std::vector<CBlockIndex*>& all = f.all;
            auto randomBlock = [&]() { return all[rng.Below(all.size())]; };
            auto parkedAny = [&]() { for (CBlockIndex* p : all) if (p->nStatus & BLOCK_PARKED_MASK) return true; return false; };
            auto addCandidate = [&](CBlockIndex* p) {
                BestChainState s = BestChainStateSave(all);
                s.candidates.push_back(p);
                BestChainStateRestore(s, all);
            };
            const unsigned int flipBits[] = {BLOCK_HAVE_DATA, BLOCK_FAILED_VALID, BLOCK_FAILED_CHILD,
                                             BLOCK_PARKED_FLAG, BLOCK_PARKED_PARENT_FLAG};
            auto flip = [&](CBlockIndex* b, bool aba) {
                const unsigned int bit = flipBits[rng.Below(5)];
                const unsigned int old = b->nStatus;
                b->nStatus = old ^ bit;
                if (aba) b->nStatus = old; // changed and changed back: the epoch still moved twice
                SyncParked(all);
            };
            const BestChainState cur = BestChainStateSave(all);
            if (!chainActive.Tip()) SetTipTo(randomBlock()); // ResetBlockFailureFlags/UnparkBlock also dereference the tip

            const int op = rng.Below(24);
            ++opCount[op];
            switch (op) {
            case 0: case 1: case 2: { // new block
                CBlockIndex* parent = rng.Below(4) ? all[all.size() - 1 - rng.Below(std::min<size_t>(8, all.size()))] : randomBlock();
                const bool data = rng.Below(8) != 0;
                CBlockIndex* p = f.Add(parent, data ? GOOD : BLOCK_VALID_TREE);
                if (data && rng.Below(3) != 0) addCandidate(p);
                if (!data) {
                    BestChainState s = BestChainStateSave(all);
                    s.blocksUnlinked.push_back(std::make_pair(parent, p));
                    BestChainStateRestore(s, all);
                }
                break;
            }
            case 3: { // invalidate-like, recorded as a failed block
                CBlockIndex* b = randomBlock();
                b->nStatus |= BLOCK_FAILED_VALID;
                for (CBlockIndex* d : all)
                    if (d != b && d->nHeight > b->nHeight && d->GetAncestor(b->nHeight) == b && rng.Below(3)) d->nStatus |= BLOCK_FAILED_CHILD;
                BestChainState s = BestChainStateSave(all);
                s.failedBlocks.insert(b);
                BestChainStateRestore(s, all);
                break;
            }
            case 4: SyncParked(all); ResetBlockFailureFlags(randomBlock()); break;
            case 5: { // park-like
                CBlockIndex* b = randomBlock();
                b->nStatus |= BLOCK_PARKED_FLAG;
                for (CBlockIndex* d : all)
                    if (d != b && d->nHeight > b->nHeight && d->GetAncestor(b->nHeight) == b) d->nStatus |= BLOCK_PARKED_PARENT_FLAG;
                SyncParked(all);
                break;
            }
            case 6: SyncParked(all); if (rng.Below(2)) UnparkBlock(randomBlock()); else UnparkBlockAndChildren(randomBlock()); break;
            case 7: flip(randomBlock(), false); break;
            case 8: case 9: { // advance toward the best candidate
                if (!cur.candidates.empty()) {
                    CBlockIndex* best = cur.candidates.back();
                    SetTipTo(best->GetAncestor(std::min(chainActive.Height() + 1 + int(rng.Below(40)), best->nHeight)));
                }
                break;
            }
            case 10: SetTipTo(randomBlock()); break;
            case 11: { // finalization point: on the active chain, or anywhere
                BestChainState s = BestChainStateSave(all);
                if (!rng.Below(3) || !chainActive.Tip()) s.pindexFinalized = NULL;
                else if (rng.Below(4)) s.pindexFinalized = chainActive.Tip()->GetAncestor(std::max(0, chainActive.Height() - int(rng.Below(6))));
                else s.pindexFinalized = randomBlock();
                BestChainStateRestore(s, all);
                break;
            }
            case 12: { // candidate set edits
                CBlockIndex* b = randomBlock();
                BestChainState s = BestChainStateSave(all);
                if (rng.Below(2)) { if (b->nStatus & BLOCK_HAVE_DATA) s.candidates.push_back(b); }
                else if (!s.candidates.empty()) s.candidates.erase(s.candidates.begin() + rng.Below(s.candidates.size()));
                BestChainStateRestore(s, all);
                break;
            }
            case 13: { // no tip (not with parked blocks: UnparkBlock with a NULL tip dereferences it in the reference too)
                if (parkedAny()) break;
                BestChainState s = BestChainStateSave(all);
                s.pindexFinalized = NULL;
                BestChainStateRestore(s, all);
                SetTipTo(NULL);
                break;
            }
            case 14: { // heavy parked branch: the walk may unpark it by PoW
                CBlockIndex* base = chainActive.Tip() && rng.Below(3) ? chainActive.Tip()->GetAncestor(std::max(0, chainActive.Height() - int(rng.Below(5)))) : randomBlock();
                const int len = 1 + rng.Below(30);
                CBlockIndex* p = base;
                for (int i = 0; i < len; ++i) {
                    p = f.Add(p, GOOD | (i == 0 ? BLOCK_PARKED_FLAG : BLOCK_PARKED_PARENT_FLAG));
                    p->nChainWork = p->pprev->nChainWork + arith_uint256(1 + rng.Below(6));
                }
                SyncParked(all);
                addCandidate(p);
                break;
            }
            case 15: // toggle -parkdeepreorg
                if (mapArgs.count("-parkdeepreorg")) mapArgs.erase("-parkdeepreorg");
                else mapArgs["-parkdeepreorg"] = "0";
                break;
            case 16: { // extend the memoised candidate, or its path
                CBlockIndex* m = cur.memoIndex ? cur.memoIndex : randomBlock();
                CBlockIndex* p = f.Add(rng.Below(2) ? m : m->GetAncestor(std::max(0, m->nHeight - int(rng.Below(5)))), GOOD);
                addCandidate(p);
                break;
            }
            case 17: case 18: { // flip a bit on the memoised path (above the floor), possibly ABA
                if (!cur.memoIndex) break;
                const int lo = cur.memoFloorHeight + 1;
                const int h = lo + int(rng.Below(std::max(1, cur.memoIndex->nHeight - lo + 1)));
                flip(cur.memoIndex->GetAncestor(std::min(h, cur.memoIndex->nHeight)), op == 18);
                break;
            }
            case 19: { // flip a bit at or below the memo floor
                if (!cur.memoFloor) break;
                flip(const_cast<CBlockIndex*>(cur.memoFloor)->GetAncestor(std::max(0, cur.memoFloorHeight - int(rng.Below(6)))), false);
                break;
            }
            case 20: { // tip to below the memo floor on the same path (segment walk), or to a side branch of it
                if (!cur.memoFloor) break;
                CBlockIndex* fl = const_cast<CBlockIndex*>(cur.memoFloor);
                CBlockIndex* t = fl->GetAncestor(std::max(0, cur.memoFloorHeight - 1 - int(rng.Below(10))));
                if (rng.Below(3) == 0) t = f.Add(t, GOOD);
                SetTipTo(t);
                break;
            }
            case 21: { // tip onto the memoised path, above the floor
                if (!cur.memoIndex) break;
                const int lo = std::max(0, cur.memoFloorHeight);
                SetTipTo(cur.memoIndex->GetAncestor(lo + int(rng.Below(std::max(1, cur.memoIndex->nHeight - lo + 1)))));
                break;
            }
            default: break; // repeat the call unchanged
            }

            const int calls = 1 + rng.Below(3);
            for (int c = 0; c < calls; ++c) {
                const BestChainState before = BestChainStateSave(all);
                const bool hit = before.memoIndex && before.memoEpoch == BlockPathWalkEpoch() &&
                                 !before.candidates.empty() && before.candidates.back() == before.memoIndex;
                const CBlockIndex* fork = hit ? chainActive.FindFork(before.memoIndex) : NULL;
                CBlockIndex* sel = NULL;
                const bool ok = Differential(all, 1 + ((step + c) & 1), &sel);
                BOOST_REQUIRE_MESSAGE(ok, "memoised and reference walks differ: seed " << (seed0 + trial) << " step " << step << " call " << c << " op " << op);
                ++checks;
                if (hit) { if ((fork ? fork->nHeight : -1) >= before.memoFloorHeight) ++memoHitSkip; else ++memoHitSegment; }
                const BestChainState after = BestChainStateSave(all);
                for (size_t i = 0; i < all.size(); ++i)
                    if ((before.status[i] & BLOCK_PARKED_MASK) && !(after.status[i] & BLOCK_PARKED_MASK)) { ++unparkedByWalk; break; }
                if (sel) ++nonNull;
                if (sel && rng.Below(2) && chainActive.Tip()) {
                    int h = std::min(chainActive.Height() + 1 + int(rng.Below(32)), sel->nHeight);
                    if (h >= 0) SetTipTo(sel->GetAncestor(h));
                }
            }
        }
        mapArgs.erase("-parkdeepreorg");
    }
    std::string ops;
    for (int i = 0; i < 24; ++i) ops += strprintf(" %d:%d", i, opCount[i]);
    BOOST_TEST_MESSAGE("reviewer differential checks: " << checks << ", selected: " << nonNull << ", memo skip hits: " << memoHitSkip
                       << ", memo segment hits: " << memoHitSegment << ", walks that unparked: " << unparkedByWalk << ", ops:" << ops);
    BOOST_CHECK(checks > 0);
    BOOST_CHECK(memoHitSkip > 0);
    BOOST_CHECK(memoHitSegment > 0);
    BOOST_CHECK(unparkedByWalk > 0);
}

BOOST_AUTO_TEST_SUITE_END()
