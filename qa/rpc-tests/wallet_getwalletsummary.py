#!/usr/bin/env python
# Copyright (C) 2022-2026 zclassic Community
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import sys; assert sys.version_info < (3,), ur"This script does not run under Python 3. Please use Python 2.7.x."

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_true, assert_false, \
    initialize_chain_clean, start_nodes, connect_nodes_bi

from decimal import Decimal


# getwalletsummary emits money via FormatMoney (string), matching
# z_gettotalbalance; getbalance / getwalletinfo emit numeric. Normalize both
# sides through Decimal before comparing.
def D(x):
    return Decimal(str(x))


class WalletGetWalletSummaryTest(BitcoinTestFramework):

    def setup_chain(self):
        print("Initializing test directory " + self.options.tmpdir)
        initialize_chain_clean(self.options.tmpdir, 3)

    def setup_network(self, split=False):
        self.nodes = start_nodes(3, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 1, 2)
        connect_nodes_bi(self.nodes, 0, 2)
        self.is_network_split = False
        self.sync_all()

    def check_consistency(self, node, minconf=1):
        """getwalletsummary must agree with the legacy RPCs it aggregates."""
        summary = node.getwalletsummary(minconf)
        getbal = node.getbalance()
        walletinfo = node.getwalletinfo()
        ztotal = node.z_gettotalbalance(minconf)
        chaininfo = node.getblockchaininfo()

        # transparent confirmed == getbalance() == getwalletinfo().balance
        #                      == z_gettotalbalance(minconf).transparent
        assert_equal(D(summary['transparent']), D(getbal))
        assert_equal(D(summary['transparent']), D(walletinfo['balance']))
        assert_equal(D(summary['transparent']), D(ztotal['transparent']))

        # private == z_gettotalbalance(minconf).private (slow path, day-one correct);
        # both honor the SAME minconf, so they must match exactly.
        assert_equal(D(summary['private']), D(ztotal['private']))

        # total == transparent(confirmed) + private
        assert_equal(D(summary['total']), D(summary['transparent']) + D(summary['private']))

        # unconfirmed / immature mirror the in-memory accessors
        assert_equal(D(summary['transparentunconfirmed']), D(walletinfo['unconfirmed_balance']))
        assert_equal(D(summary['transparentimmature']), D(walletinfo['immature_balance']))

        # the slow path is in use until the cached wave lands
        assert_false(summary['shieldedcached'])

        # chain metadata matches getblockchaininfo / getwalletinfo
        assert_equal(summary['height'], chaininfo['blocks'])
        assert_equal(summary['bestblockhash'], chaininfo['bestblockhash'])
        assert_equal(summary['txcount'], walletinfo['txcount'])
        return summary

    def run_test(self):
        # ---- mature some coinbase on node 0 ----
        print "Mining blocks..."
        self.nodes[0].generate(101)
        self.sync_all()

        # immature/confirmed split should be reflected before maturity, too
        self.check_consistency(self.nodes[0])

        # ---- fund node 1 with a transparent balance via a t->t send ----
        taddr1 = self.nodes[1].getnewaddress()
        self.nodes[0].sendtoaddress(taddr1, Decimal('10.0'))
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()

        # node 1 now has a confirmed transparent balance
        s1 = self.check_consistency(self.nodes[1])
        assert_true(D(s1['transparent']) >= Decimal('10.0'))

        # ---- a t->t spend on node 1, then verify summary still agrees ----
        taddr1b = self.nodes[1].getnewaddress()
        self.nodes[1].sendtoaddress(taddr1b, Decimal('4.0'))
        self.sync_all()
        self.nodes[0].generate(1)
        self.sync_all()
        self.check_consistency(self.nodes[1])
        self.check_consistency(self.nodes[0])

        # ---- minconf variations are honored consistently ----
        self.check_consistency(self.nodes[1], minconf=1)
        self.check_consistency(self.nodes[1], minconf=2)

        # ---- reorg: invalidate then reconsider the tip; summary must
        #      recompute correctly WITHOUT a daemon restart ----
        tip = self.nodes[0].getbestblockhash()
        before = self.nodes[0].getwalletsummary()

        self.nodes[0].invalidateblock(tip)
        after_invalidate = self.nodes[0].getwalletsummary()
        chaininfo = self.nodes[0].getblockchaininfo()
        # height/besthash track the rolled-back chain immediately
        assert_equal(after_invalidate['height'], chaininfo['blocks'])
        assert_equal(after_invalidate['bestblockhash'], chaininfo['bestblockhash'])
        assert_true(after_invalidate['height'] == before['height'] - 1)
        # balances remain internally consistent after the rollback
        self.check_consistency(self.nodes[0])

        self.nodes[0].reconsiderblock(tip)
        after_reconsider = self.nodes[0].getwalletsummary()
        assert_equal(after_reconsider['height'], before['height'])
        assert_equal(after_reconsider['bestblockhash'], before['bestblockhash'])
        assert_equal(D(after_reconsider['transparent']), D(before['transparent']))
        assert_equal(D(after_reconsider['private']), D(before['private']))
        assert_equal(D(after_reconsider['total']), D(before['total']))
        self.check_consistency(self.nodes[0])

        print "getwalletsummary consistency, minconf, and reorg checks passed."


if __name__ == '__main__':
    WalletGetWalletSummaryTest().main()
