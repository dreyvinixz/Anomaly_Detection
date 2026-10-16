"""Negative control metrics must never be confused with Week 2 F1."""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from anomaly_detection.negative_control import get_data

class NegativeControlTests(unittest.TestCase):
    def test_does_not_accept_week_with_attacks(self):
        with TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                get_data(2, Path(folder))

    def test_does_not_accept_test_weeks_without_clean_label(self):
        with TemporaryDirectory() as folder:
            with self.assertRaises(ValueError):
                get_data(4, Path(folder))

if __name__=="__main__":
    unittest.main()
