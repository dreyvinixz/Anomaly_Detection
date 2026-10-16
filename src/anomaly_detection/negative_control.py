"""Evaluate EWMA/MAD on MIT-designated ATTACK-FREE Weeks 1 and 3.

This independent negative-control analysis estimates the fraction of scored
windows with alerts on MIT-labeled attack-free traffic. It does NOT license
labeling Week 2 unmatched alerts as false positives nor calculating F1 for
Week 2 without exhaustive attack intervals.

Run: python -m anomaly_detection.negative_control --week 1 --output results/negative_control/week1
"""

import argparse
import csv
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

from .download import DAYS
from .preprocess import packet_fields, aggregate
from .detect import ewma_mad

ROOT = "https://archive.ll.mit.edu/ideval/data/1999/training"


def get_data(week: int, data_dir: Path) -> list[Path]:
    if week not in (1, 3):
        raise ValueError("Only MIT-designated attack-free training weeks 1 and 3")
    results = []
    for day in DAYS:
        dest = data_dir / ("week" + str(week)) / day / "inside.tcpdump.gz"
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists() or dest.stat().st_size == 0:
            url = f"{ROOT}/week{week}/{day}/inside.tcpdump.gz"
            print(f"[download] {url}", flush=True)
            request = Request(url, headers={"User-Agent": "DARPA1999-NegativeControl/0.1"})
            partial = dest.with_name(dest.name + ".partial")
            try:
                with urlopen(request, timeout=120) as response, partial.open("wb") as writer:
                    shutil.copyfileobj(response, writer, length=1024*1024)
                if partial.stat().st_size == 0:
                    raise IOError("Empty download " + url)
                partial.replace(dest)
            except BaseException:
                partial.unlink(missing_ok=True)
                raise
        results.append(dest)
    return results


def run(week: int, data_dir: Path, output: Path):
    paths = get_data(week, data_dir)
    output.mkdir(parents=True, exist_ok=True)
    series = []
    per_day = {}
    last_epoch = None
    for day, path in zip(DAYS, paths):
        print("[parse]", day, flush=True)
        day_packets, day_windows = 0, 0
        for epoch, n, size in aggregate(packet_fields(path), max_gap_minutes=5):
            if last_epoch is not None and epoch <= last_epoch:
                raise ValueError("Non-monotonic timestamps across days")
            last_epoch = epoch
            row = {
                "source_day": day,
                "window_start_utc": datetime.fromtimestamp(epoch, timezone.utc).isoformat(),
                "packets": n, "bytes_total": size,
                "pps": n / 60, "bytes_per_second": size / 60,
            }
            series.append(row)
            day_packets += n
            day_windows += 1
        per_day[day] = {"packets": day_packets, "windows": day_windows}
    if not series or len(series) < 300:
        raise ValueError("Attack-free dataset too small for evaluation")
    detected = ewma_mad(series, alpha=0.2, threshold=4.5, warmup=30,
                        history=120, scale_floor=0.5, reset_gap_minutes=5)
    alert = [r for r in detected if r["is_anomaly"]]
    scored = [r for r in detected if not r["is_warmup"]]
    per_day_alerts = {}
    for day in DAYS:
        portion = [r for r in detected if r["source_day"] == day]
        n_alerts = sum(r["is_anomaly"] for r in portion)
        n_scored = sum(not r["is_warmup"] for r in portion)
        per_day_alerts[day] = {
            **per_day[day],
            "scored_windows": n_scored,
            "alerts": n_alerts,
            "alert_rate_on_attack_free": round(n_alerts/n_scored, 8) if n_scored else None
        }
    result = {
        "dataset": f"DARPA 1999 Week {week} INSIDE (MIT-designated attack-free)",
        "source": f"https://archive.ll.mit.edu/ideval/data/1999/training/week{week}/index.html",
        "label_scope": "MIT states attack-free WEEK; not per-packet independently verified",
        "packets": sum(x["packets"] for x in per_day.values()),
        "windows": len(detected),
        "scored_windows": len(scored),
        "alert_windows": len(alert),
        "alert_rate_on_attack_free": round(len(alert)/len(scored), 8) if scored else None,
        "possible_false_alarm_rate_control_only": round(len(alert)/len(scored), 8) if scored else None,
        "limitations": "Not a Week2 precision/F1 or a proof that all Week2 distant alerts are false.",
        "parameters": {"alpha": 0.2, "threshold": 4.5, "warmup": 30,
                       "history": 120, "scale_floor_pps": 0.5,
                       "gap_reset_min": 5},
        "per_day": per_day_alerts,
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2)+"\n")
    with (output / "alert_windows.csv").open("w", newline="") as handle:
        cols = ["source_day","window_start_utc","pps","predicted_pps","residual_pps","robust_score"]
        w=csv.DictWriter(handle, fieldnames=cols);w.writeheader()
        for r in alert:
            w.writerow({k:r[k] for k in cols})
    (output / "README.md").write_text(
        f"# Negative control — Week {week}\n\n"
        f"MIT describes this week as free of attacks. The fraction of alerts "
        f"over scored 60-second windows is **{result['alert_rate_on_attack_free']:.6%}** "
        f"({len(alert)}/{len(scored)}).\n\n"
        "**Interpretation:** empirical false-alarm proxy on MIT-designated "
        "attack-free traffic; not Week2 precision, not Week2 F1, "
        "and not fully verified packet-by-packet benign labeling.\n\n"
        "Source: " + result["source"] + "\n"
    )
    print(json.dumps(result, indent=2),flush=True)
    return result


def main():
    p=argparse.ArgumentParser()
    p.add_argument("--week",type=int,choices=[1,3],required=True)
    p.add_argument("--data-dir",type=Path,default=Path("data/negative_control/raw"))
    p.add_argument("--output",type=Path,required=True)
    args=p.parse_args()
    run(args.week,args.data_dir,args.output)


if __name__=="__main__":
    main()
