// Distributed under the MIT software license; see COPYING.
#ifdef PARKED_BLOCK_INDEX_STANDALONE
#define BOOST_TEST_MODULE parkedblockindex_tests
#include <boost/test/included/unit_test.hpp>
#else
#include <boost/test/unit_test.hpp>
#endif
#include "parkedblockindex.h"
#include <chrono>
#include <vector>

namespace {
struct Effects {
    std::set<int> dirty, candidates, failed;
    void Changed(CBlockIndex* node, int id, bool descendant) {
        dirty.insert(id);
        if (node->IsValid()) failed.erase(id);
        if (descendant && node->IsValid(BLOCK_VALID_TRANSACTIONS) && node->nChainTx && node->nHeight > 3)
            candidates.insert(id);
    }
};

// Independent reference: original UpdateFlags traversal, including its
// descendant/ancestor side-effect asymmetry and target-first operation.
void Reference(std::vector<CBlockIndex>& nodes, size_t targetId, bool children, Effects& effects) {
    CBlockIndex* target = &nodes[targetId];
    auto update = [&](CBlockIndex* node, unsigned int mask, bool descendant) {
        const auto status = node->nStatus & ~mask;
        if (status != node->nStatus) {
            node->nStatus = status;
            effects.Changed(node, int(node - nodes.data()), descendant);
        }
    };
    update(target, BLOCK_PARKED_MASK, true);
    for (auto& node : nodes) {
        if (node.GetAncestor(target->nHeight) == target)
            update(&node, children ? BLOCK_PARKED_MASK : BLOCK_PARKED_PARENT_FLAG, true);
    }
    for (CBlockIndex* node = target; node; node = node->pprev)
        update(node, BLOCK_PARKED_MASK, false);
}
}

BOOST_AUTO_TEST_SUITE(parkedblockindex_tests)

BOOST_AUTO_TEST_CASE(branched_tree_differential)
{
    uint32_t random = 0x12345678;
    auto next = [&]() { random ^= random << 13; random ^= random >> 17; random ^= random << 5; return random; };
    for (int trial = 0; trial < 100; ++trial) {
        const size_t count = 128;
        std::vector<CBlockIndex> actual(count), reference(count);
        ParkedBlockIndex index;
        for (size_t i = 0; i < count; ++i) {
            const size_t parent = i ? (next() % i) : 0;
            const unsigned int status = (next() % 6) | ((next() % 4) << 8) |
                ((next() % 5 == 0) ? BLOCK_FAILED_VALID : 0) | BLOCK_HAVE_DATA;
            for (auto* tree : {&actual, &reference}) {
                auto& node = (*tree)[i];
                node.pprev = i ? &(*tree)[parent] : nullptr;
                node.nHeight = node.pprev ? node.pprev->nHeight + 1 : 0;
                node.BuildSkip();
                node.nStatus = status;
                node.nChainTx = i % 3;
            }
            index.Update(&actual[i]);
        }
        // Repeated operations include already-unparked targets and independent
        // parked descendants. Introduce fresh flags between operations as well.
        for (int step = 0; step < 32; ++step) {
            const size_t changed = next() % count;
            actual[changed].nStatus |= BLOCK_PARKED_MASK;
            reference[changed].nStatus |= BLOCK_PARKED_MASK;
            index.Update(&actual[changed]);
            const size_t target = next() % count;
            const bool children = (step % 2) != 0;
            Effects a, b;
            for (size_t i = 0; i < count; ++i) { a.failed.insert(int(i)); b.failed.insert(int(i)); }
            Reference(reference, target, children, b);
            index.Unpark(&actual[target], children, [&](CBlockIndex* node, bool descendant) {
                a.Changed(node, int(node - actual.data()), descendant);
            });
            BOOST_CHECK(a.dirty == b.dirty);
            BOOST_CHECK(a.candidates == b.candidates);
            BOOST_CHECK(a.failed == b.failed);
            size_t parked = 0;
            for (size_t i = 0; i < count; ++i) {
                BOOST_REQUIRE_EQUAL(actual[i].nStatus, reference[i].nStatus);
                const bool expected = (actual[i].nStatus & BLOCK_PARKED_MASK) != 0;
                BOOST_REQUIRE_EQUAL(index.Contains(&actual[i]), expected);
                parked += expected;
            }
            BOOST_REQUIRE_EQUAL(index.Size(), parked);
        }
        index.Clear();
        BOOST_CHECK_EQUAL(index.Size(), 0U);
        // Simulate loading flags from disk, then removing indexes on rewind.
        for (auto& node : actual) index.Update(&node);
        for (auto& node : actual) { index.Erase(&node); BOOST_CHECK(!index.Contains(&node)); }
        BOOST_CHECK_EQUAL(index.Size(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(long_chain_sparse_flags)
{
    const size_t count = 100000;
    std::vector<CBlockIndex> nodes(count);
    ParkedBlockIndex index;
    for (size_t i = 0; i < count; ++i) {
        nodes[i].nHeight = int(i);
        nodes[i].pprev = i ? &nodes[i - 1] : nullptr;
        nodes[i].BuildSkip();
    }
    // A parked ancestor plus a late out-of-order block: no linear ancestor walk.
    nodes[1].nStatus |= BLOCK_PARKED_FLAG;
    nodes[count - 1].nStatus |= BLOCK_PARKED_FLAG;
    index.Update(&nodes[1]);
    index.Update(&nodes[count - 1]);
    size_t callbacks = 0;
    const auto start = std::chrono::steady_clock::now();
    index.Unpark(&nodes[count - 1], false, [&](CBlockIndex*, bool) { ++callbacks; });
    const auto us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - start).count();
    BOOST_CHECK_EQUAL(callbacks, 2U);
    BOOST_CHECK_EQUAL(index.Size(), 0U);
    BOOST_CHECK_EQUAL(nodes[1].nStatus & BLOCK_PARKED_MASK, 0U);
    BOOST_TEST_MESSAGE("100000-block sparse unpark: " << us << " us");
}

BOOST_AUTO_TEST_SUITE_END()
