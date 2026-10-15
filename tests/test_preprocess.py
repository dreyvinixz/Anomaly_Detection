import unittest
from anomaly_detection.preprocess import aggregate


class PreprocessingTests(unittest.TestCase):
    def test_fixed_60_second_buckets(self):
        self.assertEqual(list(aggregate(["120.1,100", "125.0,40", "180.3,80"])),
                         [(120, 2, 140), (180, 1, 80)])

    def test_short_gaps_zero_long_gaps_unknown(self):
        self.assertEqual(
            list(aggregate(["120.1,60", "300.1,70", "1020.1,80"], max_gap_minutes=2)),
            [(120, 1, 60), (180, 0, 0), (240, 0, 0),
             (300, 1, 70), (1020, 1, 80)],
        )

    def test_unsorted_rejected(self):
        with self.assertRaises(ValueError):
            list(aggregate(["180.1,40", "60.1,40"]))


if __name__ == "__main__":
    unittest.main()
