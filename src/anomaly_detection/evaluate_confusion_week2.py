"""Stage 3: validated confusion evaluation of SMA(10) alarms.

Never convert unlabeled Week 2 minutes to benign windows. With partial truth,
report a three-class *coverage table*, not a misleading 2x2 confusion matrix.
Official attack *onsets* allow a separate proximity audit, not TP/FP labels.
"""

import argparse
import json
from collections import Counter
from datetime import timedelta
from pathlib import Path

from .ground_truth_week2 import (
    build_labels, events_from_csv, intervals_from_csv, write_csv, sha256,
)
from .part_b import (
    confusion_matrix, prediction_metrics, read_series, sma_mad, utc_instant,
)

TOLERANCES_MIN = (0, 1, 5, 10)


def assess_scored_windows(predictions: list[dict], labeled: list[dict]) -> dict:
    """Align each source minute strictly; evaluate only non-warmup windows.

    A verified-subset matrix is not a full-dataset confusion matrix. Only
    full coverage unlocks global TP/FP/FN/TN, precision, recall and F1.
    """
    if not predictions or len(predictions) != len(labeled):
        raise ValueError("Predicoes e rotulos devem cobrir a mesma serie nao vazia")
    cells = {
        "verified_attack": {"alarm": 0, "no_alarm": 0},
        "verified_benign": {"alarm": 0, "no_alarm": 0},
        "unknown": {"alarm": 0, "no_alarm": 0},
    }
    verified_labels = {}
    scored_dates = set()
    total_warmup = 0
    for prediction, label in zip(predictions, labeled):
        t = utc_instant(prediction["window_start_utc"])
        if t != utc_instant(label["window_start_utc"]):
            raise ValueError("Predicao e rotulo desalinhados em timestamp")
        if t in scored_dates:
            raise ValueError("Timestamp repetido")
        scored_dates.add(t)
        if prediction.get("source_day", "") != label.get("source_day", ""):
            raise ValueError("source_day divergente")
        if float(prediction["pps"]) != float(label["pps"]):
            raise ValueError("Valores PPS divergentes na comparacao")
        actual = label["is_attack"]
        status = label["label_status"]
        if actual not in {"0", "1", ""}:
            raise ValueError("is_attack deve ser 0, 1 ou vazio")
        if ((actual == "1" and status != "verified_attack")
            or (actual == "0" and status != "verified_benign")
            or (actual == "" and status in {"verified_attack", "verified_benign"})):
            raise ValueError("Status de verificacao inconsistente com is_attack")
        if prediction["is_warmup"] not in {0, 1}:
            raise ValueError("is_warmup invalido")
        if prediction["is_warmup"] == 1:
            total_warmup += 1
            if prediction["is_anomaly"] != 0:
                raise ValueError("Alarme em warmup")
            continue
        if prediction["is_anomaly"] not in {0, 1}:
            raise ValueError("is_anomaly invalido")
        cell = ("verified_attack" if actual == "1" else
                "verified_benign" if actual == "0" else "unknown")
        cells[cell]["alarm" if prediction["is_anomaly"] else "no_alarm"] += 1
        if actual in {"0", "1"}:
            verified_labels[t] = int(actual)

    total = sum(sum(group.values()) for group in cells.values())
    labeled_count = sum(sum(cells[k].values()) for k in ("verified_attack", "verified_benign"))
    alert_count = sum(group["alarm"] for group in cells.values())
    if total == 0:
        raise ValueError("Nenhuma janela pontuavel")
    # These four numbers are auditable *within the verified subset only*.
    subset = None
    if labeled_count:
        subset = {
            "tp": cells["verified_attack"]["alarm"],
            "fn": cells["verified_attack"]["no_alarm"],
            "fp": cells["verified_benign"]["alarm"],
            "tn": cells["verified_benign"]["no_alarm"],
            "n_verified": labeled_count,
            "warning": "Descriptive only: verified subset may be selected and unrepresentative.",
        }
    full = None
    if labeled_count == total:
        # Reuse the validated 2x2 evaluation from Part B, without relaxing
        # its requirement for a label on every scored minute.
        full = confusion_matrix(predictions, verified_labels)
    coverage = {
        "total_windows": len(predictions),
        "warmup_unscored": total_warmup,
        "scored_windows": total,
        "alarm_windows": alert_count,
        "no_alarm_windows": total - alert_count,
        "verified_attack_windows": sum(cells["verified_attack"].values()),
        "verified_benign_windows": sum(cells["verified_benign"].values()),
        "verified_scored_windows": labeled_count,
        "unknown_scored_windows": sum(cells["unknown"].values()),
        "unknown_alarm_windows": cells["unknown"]["alarm"],
        "unknown_no_alarm_windows": cells["unknown"]["no_alarm"],
        "verified_coverage_fraction": round(labeled_count / total, 8),
        "full_binary_confusion_available": full is not None,
    }
    return {
        "coverage": coverage,
        "coverage_table": cells,
        "verified_subset_counts": subset,
        "confusion_matrix": full,
        "classification_metrics": (
            {k: full[k] for k in ("accuracy", "precision", "recall", "specificity", "f1")}
            if full is not None else None
        ),
    }


def check_onset_proximity(predictions: list[dict], events: list[dict]) -> tuple[list[dict], list[dict]]:
    """Event/onset proximity NOT attack-detection ground truth.

    Only same-capture day and scored alert minutes are eligible.
    Count each documented event once even if multiple alerts match it.
    """
    mapped = {}
    by_day = {}
    for row in predictions:
        minute = utc_instant(row["window_start_utc"])
        key = (row.get("source_day", ""), minute)
        if key in mapped:
            raise ValueError("Janela duplicada em auditoria de inicios")
        mapped[key] = row
        by_day.setdefault(key[0], []).append((minute, row))
    event_audit = []
    for event in events:
        day = event["onset"].strftime("%A").lower()
        minute = event["minute"]
        at_onset = mapped.get((day, minute))
        scorable = at_onset is not None and at_onset["is_warmup"] == 0
        matched = {}
        for tolerance in TOLERANCES_MIN:
            eligible = [
                (abs(int((t - minute).total_seconds() // 60)), t)
                for t, row in by_day.get(day, [])
                if row["is_warmup"] == 0
                and row["is_anomaly"] == 1
                and abs((t - minute).total_seconds()) <= tolerance * 60
            ]
            eligible.sort()
            matched[tolerance] = eligible[0] if eligible else None
        nearest = matched[5]
        event_audit.append({
            "attack_id": event["id"],
            "attack": event["attack"],
            "destination": event["destination"],
            "onset_utc": event["onset"].isoformat(),
            "onset_minute_utc": minute.isoformat(),
            "onset_captured": int(at_onset is not None),
            "onset_scorable": int(scorable),
            "alert_within_0min": int(matched[0] is not None),
            "alert_within_1min": int(matched[1] is not None),
            "alert_within_5min": int(nearest is not None),
            "alert_within_10min": int(matched[10] is not None),
            "closest_alert_5min_utc": nearest[1].isoformat() if nearest else "",
            "distance_minute_buckets": nearest[0] if nearest else "",
            "interpretation": "proximity_only_not_confirmed_attack_detection",
        })
    scorable_total = sum(r["onset_scorable"] for r in event_audit)
    summary = []
    for tolerance in TOLERANCES_MIN:
        field = f"alert_within_{tolerance}min"
        matches_scorable = sum(
            row[field] and row["onset_scorable"] for row in event_audit
        )
        summary.append({
            "tolerance_minutes": tolerance,
            "official_onsets": len(events),
            "onsets_captured": sum(r["onset_captured"] for r in event_audit),
            "onsets_scorable": scorable_total,
            "scorable_onsets_with_nearby_alert": matches_scorable,
            "scorable_onset_proximity_rate": (
                round(matches_scorable / scorable_total, 6)
                if scorable_total else ""
            ),
            "meaning": "temporal_proximity_not_recall",
        })
    return summary, event_audit


def evaluation_report(result: dict, onset: list[dict], forecast: dict) -> str:
    c = result["coverage"]
    lines = [
        "# Etapa 3 — Avaliacao dos alarmes SMA(10) (DARPA 1999 Week 2)",
        "",
        "## Cobertura e alarmes",
        "",
        f"- Janelas totais: **{c['total_windows']}**; aquecimento: **{c['warmup_unscored']}**.",
        f"- Janelas pontuadas: **{c['scored_windows']}**.",
        f"- Alarmes SMA(10)/MAD: **{c['alarm_windows']}**.",
        f"- Alarmes com classe desconhecida: **{c['unknown_alarm_windows']}**.",
        f"- Janelas com rotulo validado: **{c['verified_scored_windows']}** "
        f"({100*c['verified_coverage_fraction']:.2f}% das pontuadas).",
        "",
        "## Tabela de cobertura (nao confundir com matriz binaria)",
        "",
        "| Classe real validada | Alarme sim | Alarme nao |",
        "|---|---:|---:|",
    ]
    for name, display in (("verified_attack", "Ataque verificado"),
                          ("verified_benign", "Benigno verificado"),
                          ("unknown", "Desconhecido")):
        row = result["coverage_table"][name]
        lines.append(f"| {display} | {row['alarm']} | {row['no_alarm']} |")
    lines += ["", "## Matriz de confusao e metricas", ""]
    full = result["confusion_matrix"]
    if full is None:
        lines += [
            "**Indisponiveis.** Nao ha rotulos completos de ataque/normal",
            "em todas as janelas pontuadas. Nao existem TP, FP, FN, TN,",
            "precision, recall ou F1 **definitivos** para esta semana.",
            "Em especial, alarme sem inicio proximo nao implica falso positivo.",
        ]
    else:
        lines += [
            "| Real / Predicao | Alarme | Sem alarme |",
            "|---|---:|---:|",
            f"| Ataque | {full['tp']} (TP) | {full['fn']} (FN) |",
            f"| Normal | {full['fp']} (FP) | {full['tn']} (TN) |",
            "",
            f"Precision={full['precision']}, Recall={full['recall']}, "
            f"F1={full['f1']}, Accuracy={full['accuracy']}, "
            f"Specificity={full['specificity']}.",
        ]
    lines += [
        "",
        "## Predicao e coincidencia temporal",
        "",
        f"- NMSE={forecast['nmse']}; MAPE={forecast['mape_percent']}%.",
        "- Coincidencia entre alerta e inicio oficial NAO eh detecao de ataque confirmada.",
        "",
        "| Tolerancia | Inicios pontuaveis | Com alerta proximo |",
        "|---:|---:|---:|",
    ]
    for row in onset:
        lines.append(
            f"| +/-{row['tolerance_minutes']} min | {row['onsets_scorable']} | "
            f"{row['scorable_onsets_with_nearby_alert']} |"
        )
    lines += [
        "",
        "## Limites de validade",
        "",
        "A serie usa apenas PCAP INSIDE da segunda semana de treinamento.",
        "O MIT lista 43 inicios, sem duracao exaustiva na tabela de detections.",
        "Os intervalos rotulados precisam de origem e validacao por sessoes;",
        "a lista de identificacao dos testes 29/03+ nao pode ser",
        "aplicada automaticamente a 08-12/03.",
        "Metrica de proximidade de inicios nao eh recall.",
        "",
    ]
    return "\n".join(lines)


def run_stage3(series_path: Path, onsets_path: Path, intervals_path: Path,
               out_dir: Path, threshold: float = 4.5,
               residual_warmup: int = 10) -> dict:
    """Rerun both prediction and truth generation from shared canonical inputs."""
    source = read_series(series_path)
    events = events_from_csv(onsets_path)
    intervals = intervals_from_csv(intervals_path, events)
    predicted = sma_mad(
        source, window=10, threshold=threshold, residual_warmup=residual_warmup
    )
    labels = build_labels(source, events, intervals)
    result = assess_scored_windows(predicted, labels)
    onset_summary, onset_details = check_onset_proximity(predicted, events)
    forecasting = prediction_metrics(predicted)
    report = {
        "dataset": "DARPA_1999_training_week2_inside_60s",
        "predictor": "causal_SMA10_MAD",
        "threshold": threshold,
        "residual_warmup": residual_warmup,
        "input_sha256": {
            "traffic_60s_csv": sha256(series_path),
            "official_onsets": sha256(onsets_path),
            "verified_intervals_registry": sha256(intervals_path),
        },
        **result,
        "prediction_metrics": forecasting,
        "onset_proximity": onset_summary,
        "ground_truth_status": (
            "complete_validated_scored_windows"
            if result["confusion_matrix"] is not None
            else "incomplete_verified_scored_windows_NO_GLOBAL_CONFUSION"
        ),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "alarm_label_coverage.csv", [
        {"actual_label": group, "predicted_alarm": cells["alarm"],
         "predicted_no_alarm": cells["no_alarm"]}
        for group, cells in result["coverage_table"].items()
    ], ["actual_label", "predicted_alarm", "predicted_no_alarm"])
    write_csv(out_dir / "onset_proximity_summary.csv", onset_summary,
              list(onset_summary[0]))
    write_csv(out_dir / "official_onset_alert_audit.csv", onset_details,
              list(onset_details[0]))
    matrix_file = out_dir / "confusion_matrix.csv"
    if result["confusion_matrix"] is None:
        matrix_file.unlink(missing_ok=True)
    else:
        matrix = result["confusion_matrix"]
        write_csv(matrix_file, [
            {"real": "attack", "predicted_alarm": matrix["tp"],
             "predicted_no_alarm": matrix["fn"]},
            {"real": "benign", "predicted_alarm": matrix["fp"],
             "predicted_no_alarm": matrix["tn"]},
        ], ["real", "predicted_alarm", "predicted_no_alarm"])
    (out_dir / "evaluation.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "README.md").write_text(
        evaluation_report(result, onset_summary, forecasting), encoding="utf-8"
    )
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Etapa 3: matriz de confusao com ground truth validado"
    )
    parser.add_argument("--series", type=Path,
                        default=Path("reports/week2-1999/data/traffic_60s.csv"))
    parser.add_argument("--official", type=Path,
                        default=Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"))
    parser.add_argument("--intervals", type=Path,
                        default=Path("data/ground_truth/week2_intervals_review.csv"))
    parser.add_argument("--out-dir", type=Path,
                        default=Path("results/stage3-confusion"))
    parser.add_argument("--threshold", type=float, default=4.5)
    parser.add_argument("--residual-warmup", type=int, default=10)
    args = parser.parse_args(argv)
    result = run_stage3(args.series, args.official, args.intervals,
                        args.out_dir, args.threshold, args.residual_warmup)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
