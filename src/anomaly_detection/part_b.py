"""Parte B: previsão SMA(10) causal, erros NMSE/MAPE e alarmes.

Matriz de confusão exige rótulos *exaustivos* para as janelas pontuadas.
Inícios conhecidos de ataques não são rótulos binários de toda a série.
"""

import argparse
import csv
import json
from collections import deque
from datetime import datetime, timedelta, timezone
from math import fsum, isfinite
from pathlib import Path
from statistics import mean, median


def utc_instant(text: str) -> datetime:
    """Require an explicit timezone and normalize timestamps to UTC."""
    instant = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError(f"Timestamp sem fuso horário: {text}")
    return instant.astimezone(timezone.utc)


def read_series(path: Path) -> list[dict]:
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not {"window_start_utc", "pps"}.issubset(reader.fieldnames or []):
            raise ValueError("Série requer window_start_utc e pps")
        rows = list(reader)
    if not rows:
        raise ValueError("Série vazia")
    return rows


def sma_mad(
    rows: list[dict],
    window: int = 10,
    threshold: float = 4.5,
    residual_warmup: int = 10,
    residual_history: int = 120,
    scale_floor: float = 0.5,
) -> list[dict]:
    """One-step SMA from 10 *previous* minute samples; causal MAD alarms.

    Require consecutive UTC minute buckets, reset on capture/day boundaries
    or gaps. The current observation enters the sliding window only AFTER
    forecasting and deciding whether an alarm is generated.
    """
    if window < 1 or residual_warmup < 1 or residual_history < residual_warmup:
        raise ValueError("Tamanho de janela/histórico inválido")
    if threshold <= 0 or scale_floor <= 0:
        raise ValueError("threshold e scale_floor devem ser positivos")
    history = deque(maxlen=window)
    errors = deque(maxlen=residual_history)
    previous_time = previous_day = None
    output = []
    for row in rows:
        instant = utc_instant(row["window_start_utc"])
        if instant.second != 0 or instant.microsecond != 0:
            raise ValueError("Série deve estar alinhada em minutos")
        pps = float(row["pps"])
        if not isfinite(pps) or pps < 0:
            raise ValueError("PPS deve ser finito e não negativo")
        source_day = row.get("source_day")
        if previous_time is not None and instant <= previous_time:
            raise ValueError("Série deve ter timestamps únicos e crescentes")
        if previous_time is not None and (
            instant - previous_time != timedelta(minutes=1)
            or source_day != previous_day
        ):
            history.clear()
            errors.clear()
        previous_time, previous_day = instant, source_day

        prediction = mean(history) if len(history) == window else None
        residual = pps - prediction if prediction is not None else None
        scored = residual is not None and len(errors) >= residual_warmup
        score = None
        if scored:
            center = median(errors)
            mad = median(abs(e - center) for e in errors)
            score = abs(residual - center) / max(1.4826 * mad, scale_floor)
        alert = bool(scored and score > threshold)
        output.append({
            **row,
            "predicted_pps": round(prediction, 6) if prediction is not None else "",
            "residual_pps": round(residual, 6) if residual is not None else "",
            "robust_score": round(score, 6) if score is not None else "",
            "is_warmup": int(not scored),
            "is_anomaly": int(alert),
        })
        # Errors from confirmed alarm candidates are kept out of the MAD
        # reference; this does NOT imply attacks were confirmed.
        if residual is not None and not alert:
            errors.append(residual)
        history.append(pps)
    return output


def prediction_metrics(rows: list[dict]) -> dict:
    """NMSE = SSE / total variance; MAPE ignores actual zeros explicitly."""
    predicted = [r for r in rows if r["predicted_pps"] != ""]
    y = [float(r["pps"]) for r in predicted]
    yhat = [float(r["predicted_pps"]) for r in predicted]
    if not y:
        return {
            "prediction_windows": 0, "nmse": None, "mape_percent": None,
            "mape_nonzero_windows": 0, "mape_excluded_zero_windows": 0,
        }
    sse = fsum((a - b) ** 2 for a, b in zip(y, yhat))
    ymean = mean(y)
    sst = fsum((a - ymean) ** 2 for a in y)
    nonzero = [(a, b) for a, b in zip(y, yhat) if a != 0]
    mape = (100 * mean(abs(a - b) / abs(a) for a, b in nonzero)
            if nonzero else None)
    return {
        "prediction_windows": len(y),
        "nmse": round(sse / sst, 8) if sst > 0 else None,
        "mape_percent": round(mape, 6) if mape is not None else None,
        "mape_nonzero_windows": len(nonzero),
        "mape_excluded_zero_windows": len(y) - len(nonzero),
    }


def read_labels(path: Path) -> dict[datetime, int]:
    """Explicit 0/1 labels for complete 60-second buckets; no inference."""
    result = {}
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not {"window_start_utc", "is_attack"}.issubset(reader.fieldnames or []):
            raise ValueError("Rótulos requerem window_start_utc,is_attack")
        for row in reader:
            instant = utc_instant(row["window_start_utc"])
            if instant in result:
                raise ValueError(f"Timestamp duplicado em rótulos: {instant}")
            if row["is_attack"] not in {"0", "1"}:
                raise ValueError("is_attack deve ser 0 ou 1; sem rótulo desconhecido")
            result[instant] = int(row["is_attack"])
    if not result:
        raise ValueError("Arquivo de rótulos vazio")
    return result


def confusion_matrix(rows: list[dict], labels: dict[datetime, int]) -> dict:
    """Classify ONLY scored windows, and only with complete binary labels."""
    scored = [row for row in rows if not row["is_warmup"]]
    expected = {utc_instant(row["window_start_utc"]) for row in scored}
    missing = expected - labels.keys()
    if missing:
        raise ValueError(
            f"Rótulos ausentes para {len(missing)} de {len(expected)} "
            "janelas pontuadas; matriz parcial não é permitida"
        )
    # Labels in warmup rows are fine; labels outside input series are not.
    observed = {utc_instant(row["window_start_utc"]) for row in rows}
    unexpected = labels.keys() - observed
    if unexpected:
        raise ValueError(f"Rótulos fora da série: {len(unexpected)}")
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    for row in scored:
        actual = labels[utc_instant(row["window_start_utc"])]
        alarm = int(row["is_anomaly"])
        counts[("tp" if actual else "fp") if alarm else
               ("fn" if actual else "tn")] += 1
    tp, fp, fn, tn = (counts[k] for k in ("tp", "fp", "fn", "tn"))

    def ratio(numerator, denominator):
        return round(numerator / denominator, 6) if denominator else None

    return {
        **counts,
        "evaluated_windows": len(scored),
        "accuracy": ratio(tp + tn, len(scored)),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
        "specificity": ratio(tn, tn + fp),
        "f1": ratio(2 * tp, 2 * tp + fp + fn),
        "interpretation": "window_level_60s_with_complete_labels",
    }


def write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run_part_b(
    series_csv: Path, output_dir: Path, labels_csv: Path | None = None,
    threshold: float = 4.5, residual_warmup: int = 10,
) -> dict:
    rows = read_series(series_csv)
    forecasts = sma_mad(
        rows, window=10, threshold=threshold, residual_warmup=residual_warmup
    )
    stats = prediction_metrics(forecasts)
    scored = [row for row in forecasts if not row["is_warmup"]]
    alerts = [row for row in scored if row["is_anomaly"]]
    matrix = confusion_matrix(forecasts, read_labels(labels_csv)) if labels_csv else None
    metrics = {
        "predictor": "SMA",
        "window_size": 10,
        "granularity_seconds": 60,
        "total_windows": len(rows),
        "scored_alarm_windows": len(scored),
        "alarm_windows": len(alerts),
        "threshold_mad": threshold,
        "residual_warmup": residual_warmup,
        "nmse_definition": "sum((y-yhat)^2) / sum((y-mean(y))^2)",
        "mape_definition": "100*mean(abs((y-yhat)/y)) for y != 0",
        **stats,
        "confusion_matrix": matrix,
        "ground_truth_status": (
            "complete_binary_window_labels" if matrix is not None
            else "not_available: official attack onsets alone are insufficient"
        ),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    fields = list(forecasts[0].keys())
    write_csv(output_dir / "predictions.csv", forecasts, fields)
    write_csv(output_dir / "alarms.csv", alerts, fields)
    if matrix is not None:
        write_csv(
            output_dir / "confusion_matrix.csv",
            [
                {"real": "attack", "predicted_alarm": matrix["tp"],
                 "predicted_no_alarm": matrix["fn"]},
                {"real": "normal", "predicted_alarm": matrix["fp"],
                 "predicted_no_alarm": matrix["tn"]},
            ],
            ["real", "predicted_alarm", "predicted_no_alarm"],
        )
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return metrics


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="DARPA 1999 - entrega Parte B")
    parser.add_argument("--series", type=Path,
                        default=Path("reports/week2-1999/data/traffic_60s.csv"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/part-b"))
    parser.add_argument("--labels", type=Path, help="CSV completo: window_start_utc,is_attack")
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument("--residual-warmup", type=int, default=10)
    args = parser.parse_args(argv)
    result = run_part_b(
        args.series, args.out_dir, args.labels, args.threshold, args.residual_warmup
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
