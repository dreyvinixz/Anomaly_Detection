"""Event-onset semantics and no-invented-false-positive regression tests."""

import unittest
from datetime import datetime, timezone
from pathlib import Path

from anomaly_detection.evaluate_week2 import (
    official_onset_utc, load_official, prepare_rows, compare, audit_alerts
)


class OfficialAttackTests(unittest.TestCase):
    def test_est_to_utc_1999(self):
        self.assertEqual(
            official_onset_utc("1999-03-08", "08:01:01"),
            datetime(1999, 3, 8, 13, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(
            official_onset_utc("1999-03-12", "17:43:18"),
            datetime(1999, 3, 12, 22, 43, 18, tzinfo=timezone.utc),
        )

    def test_official_source_has_all_43_ids(self):
        path = Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv")
        events = load_official(path)
        self.assertEqual(len(events), 43)
        self.assertEqual({e["day"] for e in events}, {
            "monday", "tuesday", "wednesday", "thursday", "friday"
        })
        self.assertEqual(events[0]["onset_minute"],
                         datetime(1999, 3, 8, 13, 1, tzinfo=timezone.utc))

    def test_proximity_buckets_and_warmup(self):
        event = {
            "id": "1", "attack": "example", "destination": "host",
            "date_local": "1999-03-08", "start_local": "08:01:01",
            "onset_utc": datetime(1999, 3, 8, 13, 1, 1, tzinfo=timezone.utc),
            "onset_minute": datetime(1999, 3, 8, 13, 1, tzinfo=timezone.utc),
            "day": "monday",
        }
        rows = prepare_rows([
            {"source_day": "monday", "window_start_utc": "1999-03-08T13:01:00+00:00",
             "pps": "10.0", "is_anomaly": "0", "is_warmup": "1",
             "predicted_pps": "10.0", "robust_score": "0.0"},
            {"source_day": "monday", "window_start_utc": "1999-03-08T13:02:00+00:00",
             "pps": "300", "is_anomaly": "1", "is_warmup": "0",
             "predicted_pps": "10.0", "robust_score": "7.0"},
        ])
        exact, _, _ = compare([event], rows, 0)
        self.assertEqual(exact["matched_onsets_all"], 0)
        one_minute, detailed, linked = compare([event], rows, 1)
        self.assertEqual(one_minute["captured_onsets"], 1)
        self.assertEqual(one_minute["scorable_onsets"], 0)
        self.assertEqual(one_minute["matched_onsets_all"], 1)
        self.assertEqual(one_minute["matched_scorable_onsets"], 0)
        audit = audit_alerts(rows, linked)
        self.assertEqual(audit[0]["near_official_start_within_5_min"], 1)
        self.assertNotIn("false_positive", audit[0]["interpretation"])


if __name__ == "__main__":
    unittest.main()
