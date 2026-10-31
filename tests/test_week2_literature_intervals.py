import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from anomaly_detection.verify_week2_pcap import spec_from_registry, zero_stats, add
from anomaly_detection.ground_truth_week2 import (
    intervals_from_csv, events_from_csv, build_labels,
)
from anomaly_detection.part_b import read_series


class LiteratureCandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(__file__).resolve().parents[1]
        cls.official = cls.base / "data/ground_truth/darpa1999_week2_official_attack_starts.csv"
        cls.registry = cls.base / "data/ground_truth/week2_intervals_review.csv"

    def test_15_candidate_attacks_and_disputed_25_excluded(self):
        rows = intervals_from_csv(self.registry, events_from_csv(self.official))
        self.assertEqual(len(rows), 15)
        self.assertTrue(all(x["status"] == "candidate" for x in rows))
        self.assertNotIn(25, {x["attack_id"] for x in rows})

    def test_cannot_generate_truth_from_candidates(self):
        rows = read_series(self.base / "reports/week2-1999/data/traffic_60s.csv")
        actual = build_labels(
            rows, events_from_csv(self.official),
            intervals_from_csv(self.registry, events_from_csv(self.official)),
        )
        self.assertEqual(len(actual), 6424)
        self.assertEqual(sum(x["is_attack"] != "" for x in actual), 0)
        self.assertTrue(any(x["label_status"] == "candidate_attack" for x in actual))

    def test_packet_cross_check_scoped_and_source_pinned(self):
        specs = spec_from_registry(self.official, self.registry)
        self.assertEqual(set(specs), {17, 26, 36})
        self.assertEqual(specs[26]["dst"], "172.16.114.207")

    def test_syn_packet_filter(self):
        t = datetime(1999, 3, 11, 16, 5, tzinfo=timezone.utc)
        spec = {"start": t-timedelta(minutes=1), "end": t+timedelta(minutes=1),
                "src": "209.117.157.183", "dst": "172.16.114.207"}
        def frame(flags, dst="172.16.114.207", when=t):
            return [str(when.timestamp()), "64", "209.117.157.183",
                    dst, "6", "80", "", flags]
        stats = zero_stats()
        add(stats, spec, frame("0x0002"))
        add(stats, spec, frame("0x0012"))
        add(stats, spec, frame("0x0002", dst="172.16.114.99"))
        add(stats, spec, frame("0x0002", when=t+timedelta(minutes=9)))
        self.assertEqual(stats["pair_packets"], 2)
        self.assertEqual(stats["syn_no_ack"], 1)
        self.assertEqual(stats["syn_inside"], 1)
        self.assertEqual(len(stats["ports"]), 1)


if __name__ == "__main__":
    unittest.main()
