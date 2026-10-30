import csv
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from anomaly_detection.part_b import sma_mad
from anomaly_detection.evaluate_confusion_week2 import (
    assess_scored_windows, check_onset_proximity, run_stage3
)

BASE = datetime(1999, 3, 8, 13, tzinfo=timezone.utc)


def samples(n=25, spike=20):
    return [{
        "source_day": "monday",
        "window_start_utc": (BASE + timedelta(minutes=i)).isoformat(),
        "pps": "100" if i == spike else "10",
    } for i in range(n)]


def labeled_for(rows, verified=None):
    verified = verified or {}
    return [{
        "source_day": row["source_day"],
        "window_start_utc": row["window_start_utc"],
        "pps": row["pps"],
        "is_attack": verified.get(i, ""),
        "label_status": (
            "verified_attack" if verified.get(i) == "1" else
            "verified_benign" if verified.get(i) == "0" else "unknown"
        ),
    } for i, row in enumerate(rows)]


def predictions(n=25):
    return sma_mad(samples(n), window=10)


class ConfusionStage3Tests(unittest.TestCase):
    def test_real_missing_truth_means_no_global_confusion(self):
        p = predictions()
        metrics = assess_scored_windows(p, labeled_for(samples()))
        self.assertIsNone(metrics["confusion_matrix"])
        self.assertIsNone(metrics["classification_metrics"])
        self.assertIsNone(metrics["verified_subset_counts"])
        self.assertEqual(metrics["coverage"]["scored_windows"], 5)
        self.assertEqual(metrics["coverage"]["unknown_scored_windows"], 5)
        self.assertEqual(metrics["coverage"]["unknown_alarm_windows"], 1)

    def test_complete_labels_unlock_correct_2_by_2(self):
        raw = samples(spike=24)
        p = sma_mad(raw, window=10)
        labels = labeled_for(raw, {20: "0", 21: "0", 22: "0", 23: "0", 24: "1"})
        metrics = assess_scored_windows(p, labels)
        matrix = metrics["confusion_matrix"]
        self.assertEqual([matrix[k] for k in ("tp", "fp", "fn", "tn")], [1, 0, 0, 4])
        self.assertEqual(metrics["coverage"]["verified_coverage_fraction"], 1)
        self.assertEqual(metrics["classification_metrics"]["recall"], 1.0)

    def test_partial_truth_has_descriptive_subset_only(self):
        raw = samples(spike=24)
        p = sma_mad(raw, window=10)
        labels = labeled_for(raw, {23: "0", 24: "1"})
        result = assess_scored_windows(p, labels)
        self.assertIsNone(result["confusion_matrix"])
        self.assertIsNone(result["classification_metrics"])
        self.assertEqual(result["verified_subset_counts"]["tp"], 1)
        self.assertEqual(result["verified_subset_counts"]["tn"], 1)
        self.assertEqual(result["coverage"]["unknown_scored_windows"], 3)

    def test_conflicting_label_status_rejected(self):
        raw = samples()
        bad = labeled_for(raw)
        bad[20]["is_attack"] = "0"
        with self.assertRaisesRegex(ValueError, "inconsistente"):
            assess_scored_windows(sma_mad(raw), bad)

    def test_time_misalignment_rejected(self):
        raw = samples()
        bad = labeled_for(raw)
        bad[-1]["window_start_utc"] = BASE.isoformat()
        with self.assertRaisesRegex(ValueError, "desalinhados"):
            assess_scored_windows(sma_mad(raw), bad)

    def test_day_misalignment_rejected(self):
        raw = samples()
        bad = labeled_for(raw)
        bad[22]["source_day"] = "friday"
        with self.assertRaisesRegex(ValueError, "source_day"):
            assess_scored_windows(sma_mad(raw), bad)

    def test_onset_proximity_is_not_recall(self):
        p = predictions()
        official = [{
            "id": 17, "attack": "satan", "destination": "host",
            "onset": BASE + timedelta(minutes=20, seconds=13),
            "minute": BASE + timedelta(minutes=20),
        }]
        summary, audit = check_onset_proximity(p, official)
        self.assertEqual(audit[0]["alert_within_0min"], 1)
        self.assertEqual(audit[0]["onset_scorable"], 1)
        self.assertEqual(summary[2]["scorable_onsets_with_nearby_alert"], 1)
        self.assertEqual(summary[2]["meaning"], "temporal_proximity_not_recall")

    def test_warmup_onset_excluded_from_scorable(self):
        p = predictions()
        official = [{
            "id": 1, "attack": "x", "destination": "host",
            "onset": BASE + timedelta(minutes=1, seconds=5),
            "minute": BASE + timedelta(minutes=1),
        }]
        summary, audit = check_onset_proximity(p, official)
        self.assertEqual(audit[0]["onset_scorable"], 0)
        self.assertEqual(summary[2]["onsets_scorable"], 0)
        self.assertEqual(summary[2]["scorable_onset_proximity_rate"], "")

    def test_real_data_artifacts_and_no_fabricated_confusion(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            result = run_stage3(
                root / "reports/week2-1999/data/traffic_60s.csv",
                root / "data/ground_truth/darpa1999_week2_official_attack_starts.csv",
                root / "data/ground_truth/week2_intervals_review.csv",
                out,
            )
            self.assertEqual(result["coverage"]["total_windows"], 6424)
            self.assertEqual(result["coverage"]["scored_windows"], 6324)
            self.assertEqual(result["coverage"]["alarm_windows"], 149)
            self.assertEqual(result["coverage"]["unknown_scored_windows"], 6324)
            self.assertEqual(result["coverage"]["unknown_alarm_windows"], 149)
            self.assertEqual(len(result["onset_proximity"]), 4)
            self.assertIsNone(result["classification_metrics"])
            self.assertIsNone(result["confusion_matrix"])
            self.assertFalse((out / "confusion_matrix.csv").exists())
            self.assertTrue((out / "alarm_label_coverage.csv").exists())
            self.assertTrue((out / "official_onset_alert_audit.csv").exists())
            self.assertTrue((out / "README.md").exists())


if __name__ == "__main__":
    unittest.main()
