import csv
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from anomaly_detection.part_b import (
    confusion_matrix, prediction_metrics, read_labels, run_part_b, sma_mad
)


def samples(values, start=None):
    start = start or datetime(1999, 3, 8, 13, tzinfo=timezone.utc)
    return [
        {"source_day": "monday",
         "window_start_utc": (start + timedelta(minutes=i)).isoformat(),
         "pps": str(value)}
        for i, value in enumerate(values)
    ]


class PartBTests(unittest.TestCase):
    def test_sma10_is_one_step_causal(self):
        rows = sma_mad(samples(list(range(10)) + [100] + [10] * 10))
        self.assertEqual([r["predicted_pps"] for r in rows[:10]], [""] * 10)
        self.assertEqual(rows[10]["predicted_pps"], 4.5)
        self.assertEqual(rows[10]["residual_pps"], 95.5)

    def test_no_lookahead(self):
        baseline = sma_mad(samples([10] * 20 + [10]))
        changed = sma_mad(samples([10] * 20 + [200]))
        self.assertEqual(baseline[20]["predicted_pps"],
                         changed[20]["predicted_pps"])

    def test_spike_alert_after_warmup(self):
        rows = sma_mad(samples([10] * 20 + [100]))
        self.assertEqual(sum(r["is_anomaly"] for r in rows[:20]), 0)
        self.assertEqual(rows[19]["is_warmup"], 1)
        self.assertEqual(rows[20]["is_warmup"], 0)
        self.assertEqual(rows[20]["is_anomaly"], 1)

    def test_gap_and_day_change_reset(self):
        first = samples([10] * 21)
        after = samples([10] * 21, datetime(1999, 3, 9, 13, tzinfo=timezone.utc))
        for row in after:
            row["source_day"] = "tuesday"
        rows = sma_mad(first + after)
        self.assertEqual(rows[21]["predicted_pps"], "")
        self.assertEqual(rows[31]["predicted_pps"], 10)
        self.assertEqual(rows[41]["is_warmup"], 0)

    def test_nmse_and_mape_definitions(self):
        rows = [{"pps": "1", "predicted_pps": 2},
                {"pps": "3", "predicted_pps": 2},
                {"pps": "0", "predicted_pps": 2}]
        result = prediction_metrics(rows)
        self.assertAlmostEqual(result["nmse"], 1.28571429)
        self.assertAlmostEqual(result["mape_percent"], 66.666667, places=5)
        self.assertEqual(result["mape_excluded_zero_windows"], 1)

    def test_constant_zero_nulled_metrics(self):
        result = prediction_metrics(sma_mad(samples([0] * 25)))
        self.assertIsNone(result["nmse"])
        self.assertIsNone(result["mape_percent"])
        self.assertEqual(result["mape_excluded_zero_windows"], 15)

    def test_binary_confusion_matrix(self):
        rows = sma_mad(samples([10] * 24 + [100]))
        labels = {datetime.fromisoformat(r["window_start_utc"]): 0 for r in rows}
        labels[datetime.fromisoformat(rows[-1]["window_start_utc"])] = 1
        cm = confusion_matrix(rows, labels)
        self.assertEqual((cm["tp"], cm["fp"], cm["fn"], cm["tn"]), (1, 0, 0, 4))

    def test_partial_ground_truth_rejected(self):
        rows = sma_mad(samples([10] * 25))
        labels = {datetime.fromisoformat(rows[-1]["window_start_utc"]): 1}
        with self.assertRaisesRegex(ValueError, "Rótulos ausentes"):
            confusion_matrix(rows, labels)

    def test_out_of_order_rejected(self):
        rows = samples([5, 10])
        with self.assertRaisesRegex(ValueError, "crescentes"):
            sma_mad(rows + [rows[1]])

    def test_end_to_end_csv_and_unlabeled_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            series = root / "series.csv"
            with series.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=[
                    "source_day", "window_start_utc", "pps"])
                writer.writeheader()
                writer.writerows(samples([10] * 24 + [100]))
            metrics = run_part_b(series, root / "results")
            self.assertEqual(metrics["alarm_windows"], 1)
            self.assertEqual(metrics["scored_alarm_windows"], 5)
            self.assertIsNone(metrics["confusion_matrix"])
            self.assertTrue((root / "results" / "predictions.csv").exists())
            self.assertFalse((root / "results" / "confusion_matrix.csv").exists())
            labels = root / "labels.csv"
            with labels.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["window_start_utc", "is_attack"])
                writer.writeheader()
                for i, row in enumerate(samples([10] * 24 + [100])):
                    writer.writerow({
                        "window_start_utc": row["window_start_utc"],
                        "is_attack": int(i == 24),
                    })
            parsed = read_labels(labels)
            self.assertEqual(len(parsed), 25)
            results = run_part_b(series, root / "labeled", labels)
            self.assertEqual(results["confusion_matrix"]["tp"], 1)
            self.assertTrue((root / "labeled" / "confusion_matrix.csv").exists())
            self.assertEqual(json.loads((root / "labeled" / "metrics.json").read_text())["window_size"], 10)


if __name__ == "__main__":
    unittest.main()
