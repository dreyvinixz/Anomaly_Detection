"""Reproducible Stage 3/4 DARPA 1999 Week 2 evaluation.

Distinguishes alerts NEAR documented attack STARTS from attack confirmation.
The MIT list has onset timestamps, destinations and names but no complete
per-attack durations. We MUST NOT report event-onset matches as precision,
recall or F1 against fully labeled malicious/benign 60-second windows.
"""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from statistics import mean
from zoneinfo import ZoneInfo

import matplotlib
matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

from anomaly_detection.detect import ewma_mad

EASTERN = ZoneInfo("America/New_York")
DAYS = ("monday", "tuesday", "wednesday", "thursday", "friday")
OFFICIAL_URL = "https://archive.ll.mit.edu/ideval/docs/detections_1999.html"
SOURCE_RUN = "https://github.com/dreyvinixz/Anomaly_Detection/actions/runs/38824820433"
TOLERANCES = (0, 1, 5, 10, 30)
PRIMARY_TOLERANCE = 5


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def write_csv(path: Path, rows: list[dict], fields: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def official_onset_utc(date_local: str, time_local: str) -> datetime:
    """The MIT evaluation local clock in March 1999 was EST (UTC-05:00)."""
    local = datetime.strptime(date_local + " " + time_local,
                              "%Y-%m-%d %H:%M:%S").replace(tzinfo=EASTERN)
    if local.utcoffset() != timedelta(hours=-5):
        raise ValueError("Expected historical EST UTC-05:00 in March 1999")
    return local.astimezone(timezone.utc)


def load_official(path: Path) -> list[dict]:
    events = read_csv(path)
    if len(events) != 43 or [int(e["id"]) for e in events] != list(range(1, 44)):
        raise ValueError("The official onset file must contain 43 unique IDs 1..43")
    for event in events:
        onset = official_onset_utc(event["date_local"], event["start_local"])
        if not (datetime(1999, 3, 8, tzinfo=timezone.utc)
                <= onset < datetime(1999, 3, 13, tzinfo=timezone.utc)):
            raise ValueError("An official attack timestamp is outside Week 2")
        event["onset_utc"] = onset
        event["day"] = onset.astimezone(EASTERN).strftime("%A").lower()
        if event["day"] not in DAYS:
            raise ValueError("Unexpected day of week")
        event["onset_minute"] = onset.replace(second=0, microsecond=0)
    return events


def prepare_rows(rows: list[dict]) -> list[dict]:
    for row in rows:
        dt = datetime.fromisoformat(row["window_start_utc"]).astimezone(timezone.utc)
        row["_time"] = dt
        row["_alert"] = int(row["is_anomaly"]) == 1
        row["_warmup"] = int(row["is_warmup"]) == 1
        row["_pps"] = float(row["pps"])
    return rows


def compare(events: list[dict], rows: list[dict], tolerance: int):
    """Attack-onset proximity evaluation, not ground-truth classification.

    Each attack is marked observable/scorable only if its exact onset-minute
    exists in the INSIDE capture and was scored. Matching is restricted to the
    corresponding daily capture and a symmetric number of minute BUCKETS.
    One observed alert may be associated with more than one onset.
    """
    by_day = defaultdict(list)
    coverage = {}
    for row in rows:
        by_day[row["source_day"]].append(row)
        coverage[(row["source_day"], row["_time"])] = row
    matching_alerts = set()
    event_rows = []
    for e in events:
        first = coverage.get((e["day"], e["onset_minute"]))
        eligible = [r for r in by_day[e["day"]]
                    if r["_alert"] and abs((r["_time"] - e["onset_minute"]).total_seconds()) <= tolerance * 60]
        eligible.sort(key=lambda r: (abs((r["_time"] - e["onset_minute"]).total_seconds()),
                                     -float(r["robust_score"])))
        matched = eligible[0] if eligible else None
        for row in eligible:
            matching_alerts.add((row["source_day"], row["_time"]))
        event_rows.append({
            "attack_id": int(e["id"]),
            "attack": e["attack"],
            "destination": e["destination"],
            "source_day": e["day"],
            "start_local_est": e["date_local"] + " " + e["start_local"],
            "start_utc": e["onset_utc"].isoformat(),
            "onset_window_utc": e["onset_minute"].isoformat(),
            "capture_present_at_onset": int(first is not None),
            "onset_scored": int(first is not None and not first["_warmup"]),
            "matching_alert": int(matched is not None),
            "closest_alert_utc": matched["_time"].isoformat() if matched else "",
            "closest_alert_pps": round(matched["_pps"], 6) if matched else "",
            "closest_alert_score": matched["robust_score"] if matched else "",
            "distance_minute_buckets": (int(abs((matched["_time"] - e["onset_minute"]).total_seconds()) / 60)
                                        if matched else ""),
        })
    observed = sum(r["capture_present_at_onset"] for r in event_rows)
    scoreable = sum(r["onset_scored"] for r in event_rows)
    matches = sum(r["matching_alert"] for r in event_rows)
    matched_scoreable = sum(r["matching_alert"] for r in event_rows if r["onset_scored"])
    alerts = [r for r in rows if r["_alert"]]
    record = {
        "tolerance_minutes": tolerance,
        "official_onsets": len(events),
        "captured_onsets": observed,
        "scorable_onsets": scoreable,
        "matched_onsets_all": matches,
        "matched_scorable_onsets": matched_scoreable,
        "matched_alert_windows": len(matching_alerts),
        "unassociated_alert_windows": len(alerts) - len(matching_alerts),
        "onset_match_rate_scoreable": round(matched_scoreable / scoreable, 6)
        if scoreable else None,
    }
    return record, event_rows, matching_alerts


def audit_alerts(rows: list[dict], matched: set) -> list[dict]:
    """Unassociated ≠ false positive without complete attack-duration labels."""
    out = []
    for r in rows:
        if not r["_alert"]:
            continue
        near = (r["source_day"], r["_time"]) in matched
        out.append({
            "source_day": r["source_day"],
            "window_start_utc": r["window_start_utc"],
            "pps": r["pps"],
            "predicted_pps": r["predicted_pps"],
            "robust_score": r["robust_score"],
            "near_official_start_within_5_min": int(near),
            "interpretation": ("near_documented_onset_not_verified_attack" if near
                               else "outside_onset_window_not_verified_false_positive"),
        })
    return out


def hyperparameter_experiments(events: list[dict], series: list[dict]) -> list[dict]:
    records = []
    # Fixed grid, selected BEFORE observing event-onset match quality.
    for alpha in (0.1, 0.2, 0.4):
        for threshold in (3.0, 4.5, 6.0):
            for warmup in (15, 30, 60):
                rows = prepare_rows(ewma_mad(
                    series, alpha=alpha, threshold=threshold, warmup=warmup,
                    history=120, scale_floor=0.5, reset_gap_minutes=5))
                comparisons, _, _ = compare(events, rows, PRIMARY_TOLERANCE)
                scored = [r for r in rows if not r["_warmup"]]
                residuals = [float(r["residual_pps"]) for r in scored]
                n_alerts = sum(r["_alert"] for r in rows)
                records.append({
                    "alpha": alpha, "threshold": threshold, "warmup": warmup,
                    "scored_windows": len(scored),
                    "alert_windows": n_alerts,
                    "alert_rate_pct": round(100 * n_alerts / len(scored), 4),
                    "mae_pps": round(mean(abs(x) for x in residuals), 6),
                    "rmse_pps": round((mean(x * x for x in residuals)) ** 0.5, 6),
                    "official_onsets_near_alert_5min": comparisons["matched_onsets_all"],
                    "scorable_onsets_near_alert_5min": comparisons["matched_scorable_onsets"],
                    "scorable_onsets": comparisons["scorable_onsets"],
                    "onset_match_rate_scoreable": comparisons["onset_match_rate_scoreable"],
                    "unassociated_alerts_5min": comparisons["unassociated_alert_windows"],
                })
    return records


def charts(events: list[dict], rows: list[dict], grid: list[dict], output: Path) -> None:
    figdir = output / "figures"
    figdir.mkdir(parents=True, exist_ok=True)
    colors = plt.rcParams["axes.prop_cycle"].by_key()["color"]
    by_day = defaultdict(list)
    for row in rows:
        by_day[row["source_day"]].append(row)
    fig, axes = plt.subplots(5, 1, figsize=(15, 16), sharex=False)
    for i, (ax, day) in enumerate(zip(axes, DAYS)):
        series = by_day[day]
        ax.plot([r["_time"] for r in series], [r["_pps"] for r in series],
                lw=0.85, label="Observed PPS")
        matched_onsets = [e for e in events if e["day"] == day]
        for j, event in enumerate(matched_onsets):
            ax.axvline(event["onset_utc"], alpha=0.3, lw=0.9, color=colors[2],
                       label="MIT attack onset (not duration)" if j == 0 else None)
        alerts = [r for r in series if r["_alert"]]
        ax.scatter([r["_time"] for r in alerts], [r["_pps"] for r in alerts],
                   s=12, color=colors[3], label="EWMA/MAD alerts")
        ax.set_title(f"{day.title()}: {len(matched_onsets)} official onsets / {len(alerts)} alerts")
        ax.set_ylabel("Packets per second (PPS)")
        ax.set_xlabel("Time (UTC)")
        ax.xaxis.set_major_formatter(mdates.DateFormatter("%d/%m %H:%M", tz=timezone.utc))
        ax.grid(alpha=0.2)
        if i == 0:
            ax.legend(loc="upper right", fontsize=8)
    fig.tight_layout()
    fig.savefig(figdir / "attack_onsets_pps.png", dpi=160)
    plt.close(fig)

    subset = sorted([r for r in grid if r["threshold"] == 4.5 and r["warmup"] == 30],
                    key=lambda r: r["alpha"])
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.plot([r["alpha"] for r in subset], [r["mae_pps"] for r in subset],
            marker="o", label="MAE")
    ax.plot([r["alpha"] for r in subset], [r["rmse_pps"] for r in subset],
            marker="s", label="RMSE")
    ax.set_xlabel("EWMA alpha (threshold=4.5, warmup=30)")
    ax.set_ylabel("Prediction error (PPS)")
    ax.set_title("EWMA prediction error sensitivity")
    ax.legend()
    ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(figdir / "sensitivity_prediction_error_pps.png", dpi=160)
    plt.close(fig)

    fig, axs = plt.subplots(1, 2, figsize=(13, 5))
    for alpha in (0.1, 0.2, 0.4):
        items = sorted([r for r in grid if r["alpha"] == alpha and r["warmup"] == 30],
                       key=lambda r: r["threshold"])
        axs[0].plot([r["threshold"] for r in items], [r["alert_rate_pct"] for r in items],
                    marker="o", label=f"alpha={alpha}")
        axs[1].plot([r["threshold"] for r in items],
                    [r["scorable_onsets_near_alert_5min"] for r in items],
                    marker="o", label=f"alpha={alpha}")
    axs[0].set(xlabel="MAD alert threshold", ylabel="Alert rate (%)",
               title="Alert volume vs threshold")
    axs[1].set(xlabel="MAD alert threshold", ylabel="Official onsets near alert (count)",
               title="Onset proximity (±5 min), NOT confirmed attacks")
    for ax in axs:
        ax.legend()
        ax.grid(alpha=0.2)
    fig.tight_layout()
    fig.savefig(figdir / "sensitivity_thresholds.png", dpi=160)
    plt.close(fig)


def report(summary: dict, grid: list[dict]) -> str:
    baseline = summary["baseline"]
    near = summary["onset_tolerances"]
    selected = [r for r in grid if r["alpha"] == 0.2 and r["threshold"] == 4.5]
    rows = [
        "# Etapas 3 e 4 — Ground truth e experimentos (DARPA 1999 Week 2)",
        "",
        "## Fonte e interpretação",
        "",
        f"- **Tabela de ataques**: [MIT Lincoln Laboratory]({OFFICIAL_URL}) — "
        "43 ataques com data, início, destino e nome. Não informa os limites "
        "completos de duração de cada ataque.",
        "- Horário oficial interpretado como America/New_York (EST, UTC−05:00 "
        "em março de 1999), verificado contra o início das capturas às 08:00 "
        "locais / 13:00 UTC.",
        f"- **Detecções e PPS**: [execução reproduzível]({SOURCE_RUN}) "
        "e reports/week2-1999/results/detections.csv.",
        "- **Matching exploratório**: considera um ataque próximo a um alerta "
        "quando o bucket de 60s do alerta ocorre dentro de ±N buckets do "
        "bucket contendo o início oficial e pertence à mesma captura diária.",
        "- **Isso NÃO comprova que o alerta detectou aquele ataque**: não "
        "verificamos IP de destino ou duração, pois o modelo contém apenas "
        "a variável agregada PPS. Múltiplos ataques poderiam coincidir "
        "com o mesmo alerta.",
        "- **Não reportamos TP, FP, TN, FN, precision, recall nem F1 definitivos** "
        "porque o conjunto disponível tem inícios de ataques, não rotulagem "
        "benigno/malicioso completa das 6.424 janelas.",
        "",
        "## Cobertura e correspondência temporal",
        "",
        f"- **Inícios documentados**: {baseline['official_onsets']}.",
        f"- **Inícios com janela capturada**: {baseline['captured_onsets']}.",
        f"- **Inícios pontuáveis**: {baseline['scorable_onsets']} "
        "(demais estão em warmup ou sem cobertura).",
        f"- **Inícios associados a algum alerta em ±5 minutos**: "
        f"{baseline['matched_onsets_all']} (dos quais "
        f"{baseline['matched_scorable_onsets']} com bucket inicial pontuável).",
        f"- **Janelas de alerta dentro de ±5 minutos de algum início oficial**: "
        f"{baseline['matched_alert_windows']}.",
        f"- **Janelas de alerta fora dessas vizinhanças**: "
        f"{baseline['unassociated_alert_windows']} — casos por investigar; "
        "**não** são automaticamente falsos positivos.",
        "",
        "| Tolerância ± (min) | Inícios próximos de alerta | Inícios pontuáveis próximos | Alertas próximos | Alertas fora da janela |",
        "|---:|---:|---:|---:|---:|",
    ]
    for d in near:
        rows.append(f"| {d['tolerance_minutes']} | {d['matched_onsets_all']} | "
                    f"{d['matched_scorable_onsets']} | {d['matched_alert_windows']} | "
                    f"{d['unassociated_alert_windows']} |")
    rows += [
        "",
        "## Sensibilidade aos hiperparâmetros",
        "",
        "Grid pré-definido: alpha in {0.1, 0.2, 0.4}, MAD threshold in "
        "{3.0, 4.5, 6.0}, warmup in {15, 30, 60}; "
        "history=120, scale_floor=0.5 PPS, reset_gap_minutes=5.",
        "Todas as configurações usam a **mesma semana**; esta é uma análise "
        "descritiva de sensibilidade, não seleção validada em teste independente.",
        "",
        "| Alpha | Threshold | Warmup | Alertas | Alert rate (%) | MAE (PPS) | RMSE (PPS) | Onsets próximos (±5 min) |",
        "|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for r in grid:
        rows.append(f"| {r['alpha']} | {r['threshold']} | {r['warmup']} | "
                    f"{r['alert_windows']} | {r['alert_rate_pct']:.3f} | "
                    f"{r['mae_pps']:.3f} | {r['rmse_pps']:.3f} | "
                    f"{r['official_onsets_near_alert_5min']} |")
    rows += [
        "",
        "## Gráficos",
        "",
        "### Ataques documentados sobre série temporal em PPS",
        "![PPS, alertas e inícios de ataques](figures/attack_onsets_pps.png)",
        "",
        "As linhas verticais representam apenas o instante de início oficial, "
        "não a duração do ataque.",
        "",
        "### Erros de previsão em PPS por alpha",
        "![MAE RMSE PPS](figures/sensitivity_prediction_error_pps.png)",
        "",
        "### Sensibilidade do volume de alertas e da proximidade temporal",
        "![Análise threshold](figures/sensitivity_thresholds.png)",
        "",
        "## Arquivos e reprodutibilidade",
        "",
        "- official_attack_onset_matches_5min.csv: os 43 eventos com status "
        "de observabilidade e alerta mais próximo;",
        "- alerts_start_proximity_audit.csv: os 115 alertas classificados "
        "como próximos ou distantes do INÍCIO oficial (não como TP/FP);",
        "- onset_tolerance.csv: tolerâncias 0/1/5/10/30 minutos;",
        "- hyperparameter_grid.csv: os 27 experimentos completos;",
        "- summary.json: resumo e hashes SHA256 das entradas;",
        "- figures: gráficos PNG; todos os gráficos de tráfego/erro de previsão "
        "utilizam PPS no eixo Y.",
        "",
        "Execução: python -m anomaly_detection.evaluate_week2 "
        "--labels data/ground_truth/darpa1999_week2_official_attack_starts.csv "
        "--detections reports/week2-1999/results/detections.csv "
        "--series reports/week2-1999/data/traffic_60s.csv "
        "--output reports/week2-1999/stage3-4",
        "",
        "## Limites e próxima validação",
        "",
        "Para classificar um alerta como verdadeiro ou falso positivo, é necessário "
        "obter intervalos reais de ataque e verificar tráfego destinado às máquinas "
        "oficiais (ou rotulagem pacote/fluxo confiável). Como o detector atual só "
        "usa PPS, o matching por horário demonstra proximidade, não causalidade. "
        "Não é lícito maximizar F1 usando rótulos de janelas inventados a partir "
        "de inícios sem duração.",
        "",
    ]
    return "\n".join(rows)


def run(labels: Path, detection_csv: Path, series_csv: Path, output: Path) -> dict:
    events = load_official(labels)
    rows = prepare_rows(read_csv(detection_csv))
    series = read_csv(series_csv)
    if len(rows) != 6424 or len(series) != len(rows):
        raise ValueError("Expected the 6,424-window validated Stage 2 snapshot")
    for one, two in zip(rows, series):
        if one["window_start_utc"] != two["window_start_utc"]:
            raise ValueError("Detection and series timestamps differ")
        if abs(one["_pps"] - float(two["pps"])) > 0.000001:
            raise ValueError("Detection and series PPS differ")
    if sum(r["_alert"] for r in rows) != 115:
        raise ValueError("Expected precisely 115 baseline flags")

    # Rerun same algorithm and assert every binary alert was reproducible.
    replay = ewma_mad(series, alpha=0.2, threshold=4.5, warmup=30,
                      history=120, scale_floor=0.5, reset_gap_minutes=5)
    if [int(r["is_anomaly"]) for r in replay] != [int(r["_alert"]) for r in rows]:
        raise AssertionError("Recomputed baseline alerts differ from Stage 2")

    tolerances, selected, linked = [], None, None
    for tolerance in TOLERANCES:
        metric, detail, matched = compare(events, rows, tolerance)
        tolerances.append(metric)
        if tolerance == PRIMARY_TOLERANCE:
            selected, linked = detail, matched
    baseline = next(m for m in tolerances if m["tolerance_minutes"] == PRIMARY_TOLERANCE)
    alerts = audit_alerts(rows, linked)
    grid = hyperparameter_experiments(events, series)
    output.mkdir(parents=True, exist_ok=True)
    write_csv(output / "official_attack_onset_matches_5min.csv", selected,
              list(selected[0]))
    write_csv(output / "alerts_start_proximity_audit.csv", alerts, list(alerts[0]))
    write_csv(output / "onset_tolerance.csv", tolerances, list(tolerances[0]))
    write_csv(output / "hyperparameter_grid.csv", grid, list(grid[0]))
    summary = {
        "scope": "attack onset proximity ONLY, not attack confirmation or validated classification",
        "official_label_url": OFFICIAL_URL,
        "labels_sha256": hashlib.sha256(labels.read_bytes()).hexdigest(),
        "detections_sha256": hashlib.sha256(detection_csv.read_bytes()).hexdigest(),
        "baseline": baseline,
        "onset_tolerances": tolerances,
        "experiments": len(grid),
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (output / "README.md").write_text(report(summary, grid), encoding="utf-8")
    charts(events, rows, grid, output)
    print(json.dumps({"baseline": baseline, "experiments": len(grid)}, indent=2))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate DARPA Week 2 onset proximity")
    parser.add_argument("--labels", type=Path,
                        default=Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"))
    parser.add_argument("--detections", type=Path,
                        default=Path("reports/week2-1999/results/detections.csv"))
    parser.add_argument("--series", type=Path,
                        default=Path("reports/week2-1999/data/traffic_60s.csv"))
    parser.add_argument("--output", type=Path,
                        default=Path("reports/week2-1999/stage3-4"))
    args = parser.parse_args()
    run(args.labels, args.detections, args.series, args.output)


if __name__ == "__main__":
    main()
