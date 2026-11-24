#!/usr/bin/env python

from __future__ import annotations

import unittest

from pymisp import MISPGalaxyCluster


class TestMISPGalaxyCluster(unittest.TestCase):

    def test_default_cluster_keeps_server_distribution(self) -> None:
        # MISP serves every default cluster with distribution 3, so parsing one
        # must not raise and must keep what the server sent.
        cluster = MISPGalaxyCluster()
        cluster.from_dict(default=True, distribution="3", uuid="b72ec96f-5cd8-4971-b1c5-3cd2fac3b14f", value="wiper")
        self.assertTrue(cluster.default)
        self.assertEqual(cluster.distribution, 3)
