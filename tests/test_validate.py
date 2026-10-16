"""Synthetic 60-second series audit; does not need original PCAP files."""

import csv
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from anomaly_detection.download import DAYS
from anomaly_detection.validate import validate


class ValidationTests(unittest.TestCase):
    def test_five_captures_60s_and_pps(self):
        with TemporaryDirectory() as folder:
            output = Path(folder) / "capture_validation.json"
            series = Path(folder) / "traffic_60s.csv"
            with series.open("w", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(["source_day", "window_start_utc", "packets",
                                 "bytes_total", "pps", "bytes_per_second"])
                for offset, day in enumerate(DAYS):
                    stamp = datetime(1999, 3, 8, tzinfo=timezone.utc) + timedelta(days=offset, hours=14)
                    writer.writerow([day, stamp.isoformat(), 120, 6000, 2, 100])
            report = validate(series, output)
            self.assertEqual(report["total_windows"], 5)
            self.assertEqual(report["total_packets"], 600)
            self.assertEqual(set(report["per_capture"]), set(DAYS))
            self.assertTrue(output.exists())

    def test_reject_incorrect_pps(self):
        with TemporaryDirectory() as folder:
            series = Path(folder) / "traffic.csv"
            series.write_text(
                "source_day,window_start_utc,packets,bytes_total,pps,bytes_per_second\n"
                "monday,1999-03-08T14:00:00+00:00,120,6000,999,100\n")
            with self.assertRaises(ValueError):
                validate(series, Path(folder) / "audit.json")


if __name__ == "__main__":
    unittest.main()
