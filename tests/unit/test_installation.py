# SPDX-License-Identifier: Apache-2.0
"""Smoke test the installed namespace and distribution metadata."""

import importlib
import unittest
from importlib.metadata import version


class InstallationTest(unittest.TestCase):
    def test_import_and_distribution_metadata(self) -> None:
        module = importlib.import_module("quaecer.seal")
        self.assertEqual(module.__name__, "quaecer.seal")
        self.assertTrue(version("quaecer-seal").startswith("1.0.0"))
