"""Validate all five DARPA Week 2 captures and their 60-second UTC series.

This audit is streaming and checks alignment, chronological order, source-day
provenance and PPS = packets/60. It preserves distinct capture gaps.
"""

import argparse
import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo
from .download import DAYS

NY = ZoneInfo("America/New_York")


def validate(series: Path, output: Path) -> dict:
    sources = {day: {"windows": 0, "packets": 0, "bytes": 0,
                     "zero_windows": 0, "first": None, "last": None} for day in DAYS}
    previous = None
    previous_source_index = -1
    gaps = []
    with series.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        required = {"source_day", "window_start_utc", "packets", "bytes_total",
                    "pps", "bytes_per_second"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Missing columns: {sorted(missing)}")
        for line_number, row in enumerate(reader, 2):
            day = row["source_day"]
            if day not in sources:
                raise ValueError(f"Invalid source_day on line {line_number}: {day}")
            index = DAYS.index(day)
            if index < previous_source_index:
                raise ValueError("Daily captures are not in chronological Monday-Friday order")
            previous_source_index = index
            stamp = datetime.fromisoformat(row["window_start_utc"])
            if stamp.tzinfo is None:
                raise ValueError(f"Missing UTC offset on line {line_number}")
            stamp = stamp.astimezone(timezone.utc)
            epoch = int(stamp.timestamp())
            if epoch % 60 or stamp.microsecond:
                raise ValueError(f"Window not aligned to minute boundary: {stamp}")
            if not (datetime(1999, 3, 8, tzinfo=timezone.utc)
                    <= stamp < datetime(1999, 3, 15, tzinfo=timezone.utc)):
                raise ValueError(f"Timestamp outside DARPA Week 2: {stamp}")
            if previous is not None:
                delta = epoch - previous
                if delta <= 0 or delta % 60:
                    raise ValueError(f"Non-monotonic/duplicate 60-second window on line {line_number}")
                if delta > 60:
                    gaps.append({"after_epoch": previous, "before_epoch": epoch,
                                 "missing_windows": delta // 60 - 1})
            previous = epoch
            n, size = int(row["packets"]), int(row["bytes_total"])
            pps, bps = float(row["pps"]), float(row["bytes_per_second"])
            if n < 0 or size < 0:
                raise ValueError(f"Negative counts on line {line_number}")
            if abs(pps - n / 60) > 0.000001 or abs(bps - size / 60) > 0.000001:
                raise ValueError(f"Incorrect PPS/bytes per second on line {line_number}")
            item = sources[day]
            item["windows"] += 1
            item["packets"] += n
            item["bytes"] += size
            item["zero_windows"] += int(n == 0)
            item["first"] = item["first"] or stamp
            item["last"] = stamp
    for day, item in sources.items():
        if item["windows"] == 0 or item["packets"] == 0:
            raise ValueError(f"Missing/empty capture for {day}")
        for side in ("first", "last"):
            stamp = item.pop(side)
            item[side + "_utc"] = stamp.isoformat()
            item[side + "_new_york"] = stamp.astimezone(NY).isoformat()
        item["mean_pps"] = round(item["packets"] / (item["windows"] * 60), 6)
    result = {
        "dataset": "DARPA 1999 Week 2 - inside tcpdump",
        "granularity_seconds": 60,
        "total_windows": sum(item["windows"] for item in sources.values()),
        "total_packets": sum(item["packets"] for item in sources.values()),
        "gaps_count": len(gaps),
        "gaps_first_100": gaps[:100],
        "gaps_truncated": len(gaps) > 100,
        "per_capture": sources,
        "note": "UTC versus America/New_York shown; official attack label timezone must be verified separately.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    for day, item in sources.items():
        print(f"[validate] {day}: {item['windows']} windows, {item['packets']} packets; "
              f"{item['first_utc']} - {item['last_utc']}")
    print(f"[validate] total: {result['total_windows']} windows; "
          f"{result['gaps_count']} observed gaps")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate DARPA 1999 60s windows")
    parser.add_argument("--series", type=Path, default=Path("data/processed/traffic_60s.csv"))
    parser.add_argument("--output", type=Path, default=Path("results/capture_validation.json"))
    args = parser.parse_args()
    validate(args.series, args.output)


if __name__ == "__main__":
    main()
