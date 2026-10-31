"""Corroborate candidate time spans with original INSIDE PCAP metadata.

Never auto-promote candidates to verified ground truth. TCP SYN on an
expected source-target pair is evidence, not proof of an attack.
"""

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path

from .ground_truth_week2 import events_from_csv, intervals_from_csv, sha256
from .part_b import read_series
from .packet_evidence import frames

PAIRS = {
    17: ("wednesday", "204.97.153.43", "172.16.114.50"),
    26: ("thursday", "209.117.157.183", "172.16.114.207"),
    36: ("friday", "204.97.153.43", "172.16.114.50"),
}
SOURCE = ("https://www.researchgate.net/publication/"
          "221506722_An_Artificial_Immune_System-Inspired_Multiobjective_"
          "Evolutionary_Algorithm_with_Application_to_the_Detection_of_"
          "Distributed_Computer_Network_Intrusions")


def spec_from_registry(official, registry):
    candidates = intervals_from_csv(registry, events_from_csv(official))
    chosen = {}
    for row in candidates:
        event_id = row["attack_id"]
        if event_id not in PAIRS:
            continue
        if event_id in chosen or row["status"] != "candidate" or row["url"] != SOURCE:
            raise ValueError("Duplicate/non-candidate/non-literature input")
        day, src, dst = PAIRS[event_id]
        chosen[event_id] = dict(row, day=day, src=src, dst=dst)
    if set(chosen) != set(PAIRS):
        raise ValueError("Expected three independently documented candidates")
    return chosen


def zero_stats():
    return {"pair_packets": 0, "syn_no_ack": 0, "syn_inside": 0,
            "ports": set(), "first": None, "last": None}


def add(stats, spec, record):
    epoch, _, source, target, protocol, port, _, flags = record
    if protocol != "6" or source != spec["src"] or target != spec["dst"]:
        return
    t = datetime.fromtimestamp(float(epoch), timezone.utc)
    if not spec["start"]-timedelta(minutes=2) <= t < spec["end"]+timedelta(minutes=2):
        return
    stats["pair_packets"] += 1
    bits = int(flags, 0) if flags else 0
    if not (bits & 0x02) or (bits & 0x10):
        return
    stats["syn_no_ack"] += 1
    if spec["start"] <= t < spec["end"]:
        stats["syn_inside"] += 1
    if port:
        stats["ports"].add(int(port))
    stats["first"] = t if stats["first"] is None else min(stats["first"], t)
    stats["last"] = t if stats["last"] is None else max(stats["last"], t)


def run(pcaps, series, official, registry, out):
    specs = spec_from_registry(official, registry)
    expected = Counter()
    for row in read_series(series):
        expected[row["source_day"]] += int(row["packets"])
    stats = {event_id: zero_stats() for event_id in specs}
    provenance = []
    for day in ("wednesday", "thursday", "friday"):
        path = pcaps / day / "inside.tcpdump.gz"
        if not path.is_file():
            raise FileNotFoundError(path)
        count = 0
        for record in frames(path):
            count += 1
            for event_id, spec in specs.items():
                if spec["day"] == day:
                    add(stats[event_id], spec, record)
        if count != expected[day]:
            raise ValueError(f"Capture {day} has {count} frames, expected {expected[day]}")
        provenance.append({"day": day, "packets": count, "sha256": sha256(path)})
        print(f"[verified source integrity] {day}: {count} packets", flush=True)
    rows = []
    for event_id, spec in sorted(specs.items()):
        s = stats[event_id]
        rows.append({
            "attack_id": event_id, "day": spec["day"],
            "candidate_start": spec["start"].isoformat(),
            "candidate_end_exclusive": spec["end"].isoformat(),
            "source_ip_hypothesis": spec["src"], "target_ip_hypothesis": spec["dst"],
            "matched_pair_packets_near": s["pair_packets"],
            "matched_syn_no_ack_near": s["syn_no_ack"],
            "matched_syn_no_ack_in_candidate": s["syn_inside"],
            "unique_syn_destination_ports": len(s["ports"]),
            "first_syn_utc": s["first"].isoformat() if s["first"] else "",
            "last_syn_utc": s["last"].isoformat() if s["last"] else "",
            "observed_metadata": "yes" if s["syn_no_ack"] else "no",
            "ground_truth": "UNVERIFIED",
            "evidence_source": SOURCE,
        })
    out.mkdir(parents=True, exist_ok=True)
    with (out / "pcap_candidate_evidence.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = {
        "source_archives": provenance,
        "candidate_attack_ids": sorted(specs),
        "candidates_with_matching_syn_metadata": sum(r["observed_metadata"] == "yes" for r in rows),
        "automatically_verified_attack_intervals": 0,
        "automatically_verified_benign_intervals": 0,
        "methodology": "source/target TCP SYN metadata only; manual attribution still required",
    }
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pcaps", type=Path, default=Path("data/raw"))
    p.add_argument("--series", type=Path, default=Path("reports/week2-1999/data/traffic_60s.csv"))
    p.add_argument("--official", type=Path, default=Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"))
    p.add_argument("--intervals", type=Path, default=Path("data/ground_truth/week2_intervals_review.csv"))
    p.add_argument("--out", type=Path, default=Path("results/week2-pcap-validation"))
    a = p.parse_args()
    print(json.dumps(run(a.pcaps, a.series, a.official, a.intervals, a.out),
                     indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
