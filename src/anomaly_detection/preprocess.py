"""Stream compressed packet captures to a 60-second UTC time series.

Compressed PCAP is passed directly into TShark; no giant intermediate PCAP
or packet-level CSV is created.
"""

import csv
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone
from pathlib import Path
import shutil
import subprocess

from .download import paths


def packet_fields(path: Path) -> Iterator[str]:
    """Return frame.time_epoch and frame.len for each captured packet."""
    if not path.is_file():
        raise FileNotFoundError(path)
    for tool in ("gzip", "tshark"):
        if shutil.which(tool) is None:
            raise RuntimeError(f"Install required command: {tool}")
    unzip = subprocess.Popen(["gzip", "-dc", str(path)],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert unzip.stdout is not None
    try:
        tshark = subprocess.Popen(
            ["tshark", "-r", "-", "-T", "fields",
             "-e", "frame.time_epoch", "-e", "frame.len",
             "-E", "separator=,", "-E", "quote=n"],
            stdin=unzip.stdout, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, text=True)
    except Exception:
        unzip.stdout.close()
        unzip.wait()
        raise
    unzip.stdout.close()
    assert tshark.stdout is not None
    try:
        yield from tshark.stdout
    finally:
        tshark.stdout.close()
        tshark_code = tshark.wait()
        unzip_code = unzip.wait()
        if tshark_code or unzip_code:
            raise RuntimeError(f"Capture decoding failed: {path} "
                               f"(tshark={tshark_code}, gzip={unzip_code})")


def aggregate(lines: Iterable[str], max_gap_minutes: int = 5) -> Iterator[tuple[int, int, int]]:
    """Yield (UTC epoch minute start, packet count, total frame bytes).

    Zero-fill only short intra-capture gaps. Long gaps are unknown coverage,
    not proven zero traffic. Input must be chronological.
    """
    if max_gap_minutes < 0:
        raise ValueError("max_gap_minutes must be >= 0")
    current = None
    packets, size = 0, 0
    for line_number, raw in enumerate(lines, 1):
        raw = raw.strip()
        if not raw:
            continue
        fields = raw.split(",")
        if len(fields) != 2:
            raise ValueError(f"Bad packet row {line_number}: {raw[:100]}")
        try:
            bucket = int(float(fields[0]) // 60) * 60
            length = int(fields[1])
        except (ValueError, OverflowError) as exc:
            raise ValueError(f"Bad epoch/length at row {line_number}") from exc
        if length < 0:
            raise ValueError(f"Negative length at row {line_number}")
        if current is None:
            current = bucket
        elif bucket < current:
            raise ValueError(f"Non-chronological packets at row {line_number}")
        elif bucket > current:
            yield current, packets, size
            missing = (bucket - current) // 60 - 1
            if 0 < missing <= max_gap_minutes:
                for offset in range(1, missing + 1):
                    yield current + 60 * offset, 0, 0
            current, packets, size = bucket, 0, 0
        packets += 1
        size += length
    if current is not None:
        yield current, packets, size


def preprocess(input_dir: Path, output_csv: Path, max_gap_minutes: int = 5) -> int:
    """Concatenate all five daily packet streams logically (not via binary cat)."""
    daily_paths = paths(input_dir)
    for path in daily_paths:
        if not path.is_file():
            raise FileNotFoundError(f"Missing {path}. Run the download command.")
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    previous, windows = None, 0
    try:
        with output_csv.open("w", newline="", encoding="utf-8") as stream:
            writer = csv.writer(stream)
            writer.writerow(["source_day", "window_start_utc", "packets", "bytes_total", "pps", "bytes_per_second"])
            for path in daily_paths:
                print(f"[process] {path}")
                count = 0
                for minute, packets, size in aggregate(packet_fields(path), max_gap_minutes):
                    if previous is not None and minute <= previous:
                        raise ValueError(f"Overlapping or unsorted captures near {path}")
                    writer.writerow([
                        path.parent.name, datetime.fromtimestamp(minute, tz=timezone.utc).isoformat(),
                        packets, size, f"{packets / 60:.6f}", f"{size / 60:.6f}"
                    ])
                    previous, windows, count = minute, windows + 1, count + 1
                if count == 0:
                    raise ValueError(f"Empty capture: {path}")
    except BaseException:
        output_csv.unlink(missing_ok=True)
        raise
    print(f"[done] {windows} windows -> {output_csv}")
    return windows
