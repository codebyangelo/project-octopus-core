import unittest
import os
import sys

# Add src to sys.path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))

import octopus
from octopus.core.profiler import PolyglotProfiler
from octopus.core.engine import UniversalEngine


class TestOctopus(unittest.TestCase):
    def test_package_metadata(self):
        self.assertEqual(octopus.__version__, "2.0.0")
        self.assertEqual(octopus.__author__, "Angelo Ayton")

    def test_project_profiler_init(self):
        profiler = PolyglotProfiler(".")
        profile = profiler.profile()
        self.assertEqual(profile.target_path, os.path.abspath("."))
        self.assertTrue(profile.files_count > 0)


if __name__ == '__main__':
    unittest.main()
