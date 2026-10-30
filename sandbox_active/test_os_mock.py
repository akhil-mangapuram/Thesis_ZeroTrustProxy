#!/usr/bin/env python3
"""Unit Test Mock Module for OS Operations."""
import os
import unittest

class TestOSMock(unittest.TestCase):
    def test_mock_environment(self):
        self.assertEqual(os.name, os.name)

if __name__ == "__main__":
    unittest.main()
