import csv
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from anomaly_detection.ground_truth_week2 import (
    LABEL_FIELDS, audit, build_labels, covers_whole_minute, events_from_csv,
    intervals_from_csv
)

T0 = datetime(1999, 3, 8, 13, tzinfo=timezone.utc)


def at(minutes, seconds=0):
    return T0 + timedelta(minutes=minutes, seconds=seconds)


def series():
    return [{"source_day": "monday", "window_start_utc": at(i).isoformat(), "pps": "4"}
            for i in range(5)]


def events():
    return [{"id": 1, "minute": at(1), "onset": at(1, 20),
             "date_local": "1999-03-08", "start_local": "08:01:20",
             "attack": "sample", "destination": "host"}]


def interval(label, start, end, status="verified", attack_id=None):
    return {"label": label, "start": at(start), "end": at(end),
            "status": status, "attack_id": attack_id,
            "url": "https://example.org", "reviewer": "tester", "notes": ""}


class Week2GroundTruthTests(unittest.TestCase):
    def test_onset_does_not_prove_duration(self):
        labels = build_labels(series(), events(), [])
        self.assertEqual(labels[1]["label_status"], "official_onset_only")
        self.assertTrue(all(row["is_attack"] == "" for row in labels))

    def test_verified_attack_labels_only_intersections(self):
        labels = build_labels(series(), events(), [
            interval("attack", 1, 3, attack_id=1)
        ])
        self.assertEqual([row["is_attack"] for row in labels], ["", "1", "1", "", ""])

    def test_candidate_does_not_create_truth(self):
        labels = build_labels(series(), events(), [
            interval("attack", 2, 3, "candidate", 1)
        ])
        self.assertEqual(labels[2]["label_status"], "candidate_attack")
        self.assertEqual(labels[2]["is_attack"], "")

    def test_verified_benign_requires_full_minute(self):
        partial = interval("benign", 3, 4)
        partial["start"] = at(3, 10)
        self.assertEqual(build_labels(series(), events(), [partial])[3]["is_attack"], "")
        self.assertEqual(build_labels(series(), events(),
                         [interval("benign", 3, 4)])[3]["is_attack"], "0")

    def test_union_of_benign_evidence(self):
        one = interval("benign", 3, 4)
        one["end"] = at(3, 30)
        two = interval("benign", 3, 4)
        two["start"] = at(3, 30)
        self.assertTrue(covers_whole_minute(at(3), at(4), [two, one]))
        self.assertEqual(build_labels(series(), events(), [one, two])[3]["is_attack"], "0")

    def test_conflict_official_onset_and_benign(self):
        with self.assertRaisesRegex(ValueError, "Conflito"):
            build_labels(series(), events(), [interval("benign", 1, 2)])

    def test_conflict_candidate_attack_and_benign(self):
        with self.assertRaisesRegex(ValueError, "Conflito"):
            build_labels(series(), events(), [
                interval("benign", 2, 3),
                interval("attack", 2, 3, "candidate", 1),
            ])

    def test_other_week_intervals_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "intervals.csv"
            with path.open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=[
                    "attack_id", "label", "start_utc", "end_utc",
                    "review_status", "evidence_url", "reviewer", "notes"])
                writer.writeheader()
                writer.writerow({
                    "attack_id": "1", "label": "attack",
                    "start_utc": "1999-03-29T08:00:00-05:00",
                    "end_utc": "1999-03-29T08:05:00-05:00",
                    "review_status": "verified", "evidence_url": "https://example.org",
                    "reviewer": "tester", "notes": "",
                })
            with self.assertRaisesRegex(ValueError, "fora da semana"):
                intervals_from_csv(path, events())

    def test_verified_provenance_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "intervals.csv"
            with path.open("w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=[
                    "attack_id", "label", "start_utc", "end_utc",
                    "review_status", "evidence_url", "reviewer", "notes"])
                writer.writeheader()
                writer.writerow({
                    "attack_id": "1", "label": "attack",
                    "start_utc": at(1).isoformat(), "end_utc": at(2).isoformat(),
                    "review_status": "verified", "evidence_url": "",
                    "reviewer": "", "notes": "",
                })
            with self.assertRaisesRegex(ValueError, "HTTPS"):
                intervals_from_csv(path, events())

    def test_real_week2_produces_unknown_not_fabricated_labels(self):
        root = Path(__file__).resolve().parents[1]
        onsets = root / "data/ground_truth/darpa1999_week2_official_attack_starts.csv"
        self.assertEqual(len(events_from_csv(onsets)), 43)
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            summary = audit(
                root / "reports/week2-1999/data/traffic_60s.csv", onsets,
                root / "data/ground_truth/week2_intervals_review.csv", out,
                root / "reports/week2-1999/stage5-packet-evidence/four_attack_event_evidence.csv"
            )
            self.assertEqual(summary["total_windows"], 6424)
            self.assertEqual(summary["official_events"], 43)
            self.assertEqual(summary["events_with_protocol_evidence"], 4)
            self.assertEqual(summary["verified_attack_windows"], 0)
            self.assertEqual(summary["verified_benign_windows"], 0)
            self.assertEqual(summary["unknown_windows"], 6424)
            self.assertFalse(summary["confusion_matrix_ready"])
            self.assertFalse((out / "labels_complete_for_part_b.csv").exists())
            with (out / "minute_labels_tri_state.csv").open(newline="") as file:
                labels = list(csv.DictReader(file))
            self.assertEqual(len(labels), 6424)
            self.assertEqual(set(labels[0]), set(LABEL_FIELDS))


if __name__ == "__main__":
    unittest.main()
