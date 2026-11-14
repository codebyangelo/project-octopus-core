# -*- coding: utf-8 -*-
"""
Tests for Project Octopus CLI interface
"""

import unittest
from octopus.cli import create_parser


class TestOctopusCLI(unittest.TestCase):
    def test_parser_defaults(self):
        parser = create_parser()
        args = parser.parse_args([])
        self.assertEqual(args.target, ".")
        self.assertEqual(args.output_dir, "./reports")
        self.assertEqual(args.adapter, "auto")
        self.assertIsNone(args.tests)
        self.assertIsNone(args.pack)
        self.assertFalse(args.profile_only)

    def test_parser_custom_args(self):
        parser = create_parser()
        args = parser.parse_args([
            "--target", "/tmp",
            "--adapter", "native",
            "--profile-only",
            "--output-dir", "/tmp/reports"
        ])
        self.assertEqual(args.target, "/tmp")
        self.assertEqual(args.adapter, "native")
        self.assertTrue(args.profile_only)
        self.assertEqual(args.output_dir, "/tmp/reports")


if __name__ == "__main__":
    unittest.main()
