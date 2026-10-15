import unittest
from datetime import datetime, timedelta, timezone
from anomaly_detection.detect import ewma_mad


def sample(values, start=None):
    start = start or datetime(1999, 3, 8, tzinfo=timezone.utc)
    return [
        {"window_start_utc": (start + timedelta(minutes=i)).isoformat(),
         "pps": value, "packets": value * 60, "bytes_total": value * 60 * 64}
        for i, value in enumerate(values)
    ]


class DetectorTests(unittest.TestCase):
    def test_spike_detected_after_warmup(self):
        values = ewma_mad(sample([10] * 40 + [100]), warmup=20)
        self.assertEqual(sum(row["is_anomaly"] for row in values[:40]), 0)
        self.assertEqual(values[-1]["is_anomaly"], 1)

    def test_no_lookahead(self):
        base = ewma_mad(sample([10] * 40 + [10]), warmup=20)
        spike = ewma_mad(sample([10] * 40 + [500]), warmup=20)
        self.assertEqual(base[-1]["predicted_pps"], spike[-1]["predicted_pps"])

    def test_gap_resets_model(self):
        values = sample([10] * 40) + sample(
            [500] * 5, datetime(1999, 3, 9, tzinfo=timezone.utc))
        rows = ewma_mad(values, warmup=20)
        self.assertEqual(rows[40]["predicted_pps"], 500)
        self.assertEqual(rows[40]["is_warmup"], 1)


if __name__ == "__main__":
    unittest.main()
