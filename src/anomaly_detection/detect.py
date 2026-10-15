"""Causal, one-step EWMA forecasting with rolling median/MAD anomaly scores."""

import csv
import json
from collections import deque
from datetime import datetime
from math import sqrt
from pathlib import Path
from statistics import mean, median


def ewma_mad(rows: list[dict], alpha: float = 0.2, threshold: float = 4.5,
             warmup: int = 30, history: int = 120,
             scale_floor: float = 0.5, reset_gap_minutes: int = 5) -> list[dict]:
    """Only past residuals determine an anomaly score; never peek ahead.

    Flagged errors are excluded from the historical residual reference,
    while EWMA still adapts to observed traffic. Gaps reset forecast state.
    """
    if not 0 < alpha <= 1 or threshold <= 0 or warmup < 2 or history < warmup:
        raise ValueError("Invalid alpha/threshold/warmup/history")
    if scale_floor <= 0 or reset_gap_minutes < 0:
        raise ValueError("Invalid scale_floor/reset_gap_minutes")
    errors = deque(maxlen=history)
    estimate, previous_time = None, None
    result = []
    for row in rows:
        observed = float(row["pps"])
        when = datetime.fromisoformat(row["window_start_utc"])
        if when.tzinfo is None:
            raise ValueError("Timestamps must include their UTC offset")
        if previous_time is not None:
            gap = (when - previous_time).total_seconds()
            if gap <= 0:
                raise ValueError("Series must be chronological and unique")
            if gap > max(1, reset_gap_minutes) * 60:
                estimate = None
                errors.clear()
        previous_time = when
        expected = observed if estimate is None else estimate
        residual = observed - expected
        is_warmup = len(errors) < warmup
        score = 0.0
        if not is_warmup:
            center = median(errors)
            mad = median(abs(e - center) for e in errors)
            score = abs(residual - center) / max(1.4826 * mad, scale_floor)
        flagged = not is_warmup and score > threshold
        result.append({
            **row,
            "predicted_pps": round(expected, 6),
            "residual_pps": round(residual, 6),
            "robust_score": round(score, 6),
            "is_anomaly": int(flagged),
            "is_warmup": int(is_warmup),
        })
        if not flagged:
            errors.append(residual)
        estimate = alpha * observed + (1 - alpha) * expected
    return result


def detect(series_csv: Path, output_dir: Path, **params) -> dict:
    """Write predictions, anomaly windows and descriptive statistics."""
    with series_csv.open(newline="", encoding="utf-8") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("Preprocessed CSV has no windows")
    detected = ewma_mad(rows, **params)
    alerts = [row for row in detected if row["is_anomaly"]]
    output_dir.mkdir(parents=True, exist_ok=True)
    fields = list(detected[0])
    for filename, content in (("detections.csv", detected), ("anomalies.csv", alerts)):
        with (output_dir / filename).open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(content)
    scored = [row for row in detected if not row["is_warmup"]]
    residuals = [row["residual_pps"] for row in scored]
    pps = [float(row["pps"]) for row in detected]
    metrics = {
        "windows": len(detected),
        "scored_windows": len(scored),
        "anomaly_windows": len(alerts),
        "alert_rate": round(len(alerts) / len(scored), 6) if scored else None,
        "mean_pps": round(mean(pps), 6),
        "median_pps": round(median(pps), 6),
        "max_pps": round(max(pps), 6),
        "mae_pps": round(mean(abs(e) for e in residuals), 6) if residuals else None,
        "rmse_pps": round(sqrt(mean(e * e for e in residuals)), 6) if residuals else None,
        "ground_truth": "not integrated; no precision, recall or F1 reported",
        "parameters": {
            "alpha": params.get("alpha", 0.2),
            "threshold": params.get("threshold", 4.5),
            "warmup": params.get("warmup", 30),
            "history": params.get("history", 120),
            "scale_floor": params.get("scale_floor", 0.5),
            "reset_gap_minutes": params.get("reset_gap_minutes", 5),
        },
    }
    (output_dir / "metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    print(f"[done] {len(alerts)} anomalous / {len(scored)} scored windows")
    return metrics
