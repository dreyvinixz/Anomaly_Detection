"""Rebuild gap-aware Stage 2 figures from versioned detection CSV data.

Run: python scripts/plot_stage2.py
All traffic plots have Y axes expressed in packets per second (PPS).
"""
import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as dates
import matplotlib.pyplot as plt

DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
NAMES = ("Segunda", "Terça", "Quarta", "Quinta", "Sexta")


def figures(csv_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    groups = defaultdict(list)
    with csv_path.open(encoding="utf-8", newline="") as stream:
        for row in csv.DictReader(stream):
            if row["source_day"] not in DAYS:
                raise ValueError("Unexpected capture source_day")
            groups[row["source_day"]].append(
                (datetime.fromisoformat(row["window_start_utc"]).astimezone(timezone.utc),
                 float(row["pps"]), float(row["predicted_pps"]),
                 row["is_anomaly"] == "1"))
    if set(groups) != set(DAYS):
        raise ValueError("Five inside capture days required")

    # IMPORTANT: each daily line is rendered separately. This avoids
    # connecting packet counts across capture outages or overnight gaps.
    fig, ax = plt.subplots(figsize=(16, 6))
    for i, day in enumerate(DAYS):
        points = groups[day]
        ax.plot([p[0] for p in points], [p[1] for p in points],
                linewidth=0.7, color="#215da8",
                label="PPS observado" if i == 0 else None)
        ax.plot([p[0] for p in points], [p[2] for p in points],
                linewidth=0.8, color="#e59332", alpha=0.8,
                label="EWMA previsto" if i == 0 else None)
        alerts = [p for p in points if p[3]]
        ax.scatter([p[0] for p in alerts], [p[1] for p in alerts],
                   s=12, color="#b52c47", zorder=3,
                   label="Anomalia sinalizada" if i == 0 else None)
    ax.set_title("DARPA 1999 - Week 2 - inside tcpdump (lacunas preservadas)")
    ax.set_ylabel("Pacotes por segundo (PPS)")
    ax.set_xlabel("Data e horário (UTC)")
    ax.xaxis.set_major_formatter(dates.DateFormatter("%d/%m %H:%M", tz=timezone.utc))
    ax.grid(alpha=0.25)
    ax.legend(loc="upper right")
    fig.autofmt_xdate()
    fig.tight_layout()
    fig.savefig(out_dir / "traffic_pps_gap_aware.png", dpi=160)
    plt.close(fig)

    # Small multiples let readers inspect each individual recording.
    fig, axes = plt.subplots(5, 1, figsize=(15, 15))
    for ax, day, name in zip(axes, DAYS, NAMES):
        points = groups[day]
        alert = [p for p in points if p[3]]
        ax.plot([p[0] for p in points], [p[1] for p in points], lw=0.75, color="#215da8")
        ax.scatter([p[0] for p in alert], [p[1] for p in alert],
                   s=11, color="#b52c47", zorder=3)
        ax.set_title(f"{name} - {len(points)} janelas, {len(alert)} alertas", loc="left")
        ax.set_ylabel("Pacotes por segundo (PPS)")
        ax.set_xlabel("Data e horário (UTC)")
        ax.xaxis.set_major_formatter(dates.DateFormatter("%d/%m %H:%M", tz=timezone.utc))
        ax.tick_params(axis="x", labelrotation=15)
        ax.grid(alpha=0.25)
    fig.tight_layout()
    fig.savefig(out_dir / "traffic_pps_by_day.png", dpi=160)
    plt.close(fig)

    # Descriptive PPS rates by capture; both series have the same unit.
    mean = [sum(p[1] for p in groups[d]) / len(groups[d]) for d in DAYS]
    peak = [max(p[1] for p in groups[d]) for d in DAYS]
    positions = list(range(5))
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar([x - 0.18 for x in positions], mean, width=0.36,
           label="PPS médio", color="#215da8")
    ax.bar([x + 0.18 for x in positions], peak, width=0.36,
           label="PPS máximo", color="#e59332")
    ax.set_xticks(positions, NAMES)
    ax.set_ylabel("Pacotes por segundo (PPS)")
    ax.set_title("PPS médio e máximo por captura")
    ax.grid(axis="y", alpha=0.25)
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "daily_pps.png", dpi=160)
    plt.close(fig)
    print("Generated 3 PPS figures without bridging overnight capture gaps")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--detections", type=Path,
                        default=Path("reports/week2-1999/results/detections.csv"))
    parser.add_argument("--figures", type=Path,
                        default=Path("reports/week2-1999/figures"))
    args = parser.parse_args()
    figures(args.detections, args.figures)


if __name__ == "__main__":
    main()
