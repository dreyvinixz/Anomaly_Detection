"""Audit DARPA 1999 training Week 2 ground truth without inventing durations."""

import argparse
import csv
import hashlib
import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from .part_b import read_series, utc_instant

SOURCE = "https://archive.ll.mit.edu/ideval/docs/detections_1999.html"
EST = ZoneInfo("America/New_York")
MIN_DATE = datetime(1999, 3, 8, tzinfo=timezone.utc)
MAX_DATE = datetime(1999, 3, 14, tzinfo=timezone.utc)
INTERVAL_FIELDS = ("attack_id", "label", "start_utc", "end_utc",
                   "review_status", "evidence_url", "reviewer", "notes")
LABEL_FIELDS = ("source_day", "window_start_utc", "pps", "is_attack",
                "label_status", "official_onset_ids", "interval_ids", "evidence_urls")


def csv_rows(path):
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def write_csv(path, rows, fieldnames):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def events_from_csv(path):
    rows = csv_rows(path)
    if len(rows) != 43 or {int(row["id"]) for row in rows} != set(range(1, 44)):
        raise ValueError("A lista oficial exige 43 IDs distintos de 1 a 43")
    events = []
    for row in rows:
        local = datetime.strptime(
            row["date_local"] + " " + row["start_local"], "%Y-%m-%d %H:%M:%S"
        ).replace(tzinfo=EST)
        if local.utcoffset() != timedelta(hours=-5):
            raise ValueError("Data de evento fora de EST historico")
        onset = local.astimezone(timezone.utc)
        if not MIN_DATE <= onset < MAX_DATE:
            raise ValueError("Inicio de ataque fora da semana")
        events.append({
            "id": int(row["id"]), "onset": onset,
            "minute": onset.replace(second=0, microsecond=0),
            "attack": row["attack"], "destination": row["destination"],
            "date_local": row["date_local"], "start_local": row["start_local"],
        })
    return sorted(events, key=lambda item: item["id"])


def intervals_from_csv(path, events):
    with path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if not set(INTERVAL_FIELDS).issubset(reader.fieldnames or []):
            raise ValueError("Cabecalho de intervalos incompleto")
        rows = list(reader)
    known = {e["id"]: e for e in events}
    intervals = []
    for line, row in enumerate(rows, 2):
        if not any((v or "").strip() for v in row.values()):
            continue
        label = row["label"].strip()
        status = row["review_status"].strip()
        id_text = row["attack_id"].strip()
        url = row["evidence_url"].strip()
        reviewer = row["reviewer"].strip()
        notes = row["notes"].strip()
        if label not in {"attack", "benign"} or status not in {"verified", "candidate"}:
            raise ValueError(f"Linha {line}: label/review_status invalido")
        if label == "attack":
            if not id_text.isdigit() or int(id_text) not in known:
                raise ValueError(f"Linha {line}: ID de ataque invalido")
        elif id_text:
            raise ValueError(f"Linha {line}: periodo benigno nao usa attack_id")
        start, end = utc_instant(row["start_utc"]), utc_instant(row["end_utc"])
        if not (MIN_DATE <= start < end <= MAX_DATE) or end-start > timedelta(days=1):
            raise ValueError(f"Linha {line}: intervalo fora da semana ou invalido")
        if label == "attack":
            onset = known[int(id_text)]["onset"]
            if not onset - timedelta(hours=24) <= start <= onset + timedelta(hours=24):
                raise ValueError(f"Linha {line}: data incompativel com inicio oficial")
        if status == "verified" and not (url.startswith("https://") and reviewer):
            raise ValueError(f"Linha {line}: verificado exige fonte HTTPS e revisor")
        if status == "candidate" and not (url or notes):
            raise ValueError(f"Linha {line}: candidato exige fonte ou justificativa")
        intervals.append({
            "attack_id": int(id_text) if id_text else None,
            "label": label, "status": status,
            "start": start, "end": end,
            "url": url, "reviewer": reviewer, "notes": notes,
        })
    return intervals


def intersects(a, b, c, d):
    return a < d and c < b


def covers_whole_minute(start, end, intervals):
    cursor = start
    for interval in sorted(intervals, key=lambda item: item["start"]):
        if interval["end"] <= cursor:
            continue
        if interval["start"] > cursor:
            return False
        cursor = max(cursor, interval["end"])
        if cursor >= end:
            return True
    return False


def build_labels(series, events, intervals):
    """Return binary only where verified; all other minutes are unknown."""
    starts = defaultdict(list)
    for e in events:
        starts[e["minute"]].append(e["id"])
    result = []
    previous = None
    for raw in series:
        minute = utc_instant(raw["window_start_utc"])
        if minute.second or minute.microsecond:
            raise ValueError("Minuto de trafego desalinhado")
        if previous and minute <= previous:
            raise ValueError("Timestamps nao crescentes na serie")
        previous = minute
        end = minute + timedelta(minutes=1)
        active = [i for i in intervals if intersects(minute, end, i["start"], i["end"])]
        malicious = [i for i in active if i["label"] == "attack"]
        benign = [i for i in active if i["label"] == "benign" and i["status"] == "verified"]
        candidate_benign = any(i["label"] == "benign" for i in active)
        verified_attack = any(i["status"] == "verified" for i in malicious)
        start_ids = starts.get(minute, [])
        if benign and (malicious or start_ids):
            raise ValueError(f"Conflito entre benigno e ataque oficial: {minute}")
        if verified_attack:
            label, status = "1", "verified_attack"
        elif start_ids:
            label, status = "", "official_onset_only"
        elif malicious:
            label, status = "", "candidate_attack"
        elif benign and covers_whole_minute(minute, end, benign):
            label, status = "0", "verified_benign"
        elif candidate_benign:
            label, status = "", "incomplete_benign_evidence"
        else:
            label, status = "", "unknown"
        result.append({
            "source_day": raw.get("source_day", ""),
            "window_start_utc": minute.isoformat(),
            "pps": raw["pps"],
            "is_attack": label, "label_status": status,
            "official_onset_ids": ";".join(map(str, start_ids)),
            "interval_ids": ";".join(
                map(str, sorted({i["attack_id"] for i in active
                                 if i["attack_id"] is not None}))
            ),
            "evidence_urls": ";".join(sorted({i["url"] for i in active if i["url"]})),
        })
    return result


def packet_audit_ids(path):
    if path is None or not path.exists():
        return set()
    rows = csv_rows(path)
    for row in rows:
        if row["conclusion"] != "protocol_and_destination_evidence_only_not_attack_proof":
            raise ValueError("Dados de protocolo nao permitem afirmar ground truth")
    return {int(row["attack_id"]) for row in rows}


def build_event_queue(events, labels, intervals, packet_ids):
    captured = {utc_instant(row["window_start_utc"]) for row in labels}
    queue = []
    for e in events:
        reviewed = [i for i in intervals if i["attack_id"] == e["id"]]
        queue.append({
            "attack_id": e["id"], "date_local_est": e["date_local"],
            "start_local_est": e["start_local"],
            "onset_utc": e["onset"].isoformat(),
            "onset_minute_utc": e["minute"].isoformat(),
            "attack": e["attack"], "destination": e["destination"],
            "onset_minute_captured": int(e["minute"] in captured),
            "protocol_evidence_available": int(e["id"] in packet_ids),
            "verified_segments": sum(i["status"] == "verified" for i in reviewed),
            "candidate_segments": sum(i["status"] == "candidate" for i in reviewed),
            "duration_status": "segments_reviewed_not_full_duration" if any(
                i["status"] == "verified" for i in reviewed
            ) else "unknown",
            "official_source": SOURCE,
            "protocol_source": (
                "reports/week2-1999/stage5-packet-evidence/four_attack_event_evidence.csv"
                if e["id"] in packet_ids else ""
            ),
        })
    return queue


def audit(series_file, onsets_file, intervals_file, out_dir, packet_file=None):
    series = read_series(series_file)
    events = events_from_csv(onsets_file)
    intervals = intervals_from_csv(intervals_file, events)
    packet_ids = packet_audit_ids(packet_file)
    labels = build_labels(series, events, intervals)
    queue = build_event_queue(events, labels, intervals, packet_ids)
    counts = Counter(row["label_status"] for row in labels)
    positive = sum(row["is_attack"] == "1" for row in labels)
    negative = sum(row["is_attack"] == "0" for row in labels)
    complete = positive + negative == len(labels)
    summary = {
        "dataset": "DARPA_1999_training_week2_inside_60s",
        "official_source": SOURCE,
        "series_sha256": sha256(series_file),
        "onsets_sha256": sha256(onsets_file),
        "intervals_sha256": sha256(intervals_file),
        "total_windows": len(labels),
        "official_events": len(events),
        "captured_onsets": sum(i["onset_minute_captured"] for i in queue),
        "events_with_protocol_evidence": sum(i["protocol_evidence_available"] for i in queue),
        "verified_intervals": sum(i["status"] == "verified" for i in intervals),
        "candidate_intervals": sum(i["status"] == "candidate" for i in intervals),
        "verified_attack_windows": positive,
        "verified_benign_windows": negative,
        "unknown_windows": len(labels) - positive - negative,
        "label_status_counts": dict(sorted(counts.items())),
        "binary_labels_complete": complete,
        "confusion_matrix_ready": complete,
        "warning": "Start times and candidate packets are not attack durations. Missing labels are unknown, not benign.",
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    write_csv(out_dir / "minute_labels_tri_state.csv", labels, LABEL_FIELDS)
    write_csv(out_dir / "official_event_review_queue.csv", queue, list(queue[0]))
    binary = out_dir / "labels_complete_for_part_b.csv"
    if complete:
        write_csv(binary, [{"window_start_utc": row["window_start_utc"],
                            "is_attack": row["is_attack"]} for row in labels],
                  ["window_start_utc", "is_attack"])
    else:
        binary.unlink(missing_ok=True)
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description="Auditoria de ground truth DARPA 1999")
    parser.add_argument("--series", type=Path,
                        default=Path("reports/week2-1999/data/traffic_60s.csv"))
    parser.add_argument("--official", type=Path,
                        default=Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"))
    parser.add_argument("--intervals", type=Path,
                        default=Path("data/ground_truth/week2_intervals_review.csv"))
    parser.add_argument("--packet-evidence", type=Path,
                        default=Path("reports/week2-1999/stage5-packet-evidence/four_attack_event_evidence.csv"))
    parser.add_argument("--out-dir", type=Path, default=Path("results/ground-truth-week2"))
    args = parser.parse_args(argv)
    print(json.dumps(audit(args.series, args.official, args.intervals,
                           args.out_dir, args.packet_evidence), indent=2,
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
