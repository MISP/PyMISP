#!/usr/bin/env python

from __future__ import annotations

import unittest

from pymisp import MISPGalaxyCluster
from pymisp.exceptions import NewGalaxyClusterError


class TestMISPGalaxyCluster(unittest.TestCase):

    def test_default_cluster_rejects_distribution_fields(self) -> None:
        for field in ("distribution", "sharing_group_id"):
            with self.subTest(field=field):
                cluster = MISPGalaxyCluster()
                with self.assertRaisesRegex(NewGalaxyClusterError, field):
                    cluster.from_dict(default=True, **{field: 1})
