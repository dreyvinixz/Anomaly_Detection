"""Scientific plots with traffic axes expressed in packets per second."""

import csv
from datetime import datetime, timezone
from pathlib import Path
import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt


def plot(detection_csv: Path, figures_dir: Path) -> Path:
    with detection_csv.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("No detections found")
    times = [datetime.fromisoformat(row["window_start_utc"]) for row in rows]
    values = [float(row["pps"]) for row in rows]
    expected = [float(row["predicted_pps"]) for row in rows]
    flagged = [row["is_anomaly"] == "1" for row in rows]
    fig, ax = plt.subplots(figsize=(15, 5))
    ax.plot(times, values, lw=0.7, label="Observed")
    ax.plot(times, expected, lw=0.8, label="EWMA prediction", alpha=0.75)
    ax.scatter([x for x, y in zip(times, flagged) if y],
               [x for x, y in zip(values, flagged) if y],
               color="crimson", s=10, label="Alert", zorder=3)
    ax.set(title="DARPA 1999 Week 2 - Inside capture", xlabel="Timestamp (UTC)",
           ylabel="Packets per second (PPS)")
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%d %b %H:%M", tz=timezone.utc))
    ax.legend()
    ax.grid(alpha=0.2)
    fig.autofmt_xdate()
    fig.tight_layout()
    figures_dir.mkdir(parents=True, exist_ok=True)
    out = figures_dir / "traffic_pps.png"
    fig.savefig(out, dpi=180)
    plt.close(fig)
    return out
