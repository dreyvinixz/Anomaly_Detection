"""Offline packet evidence for four MIT attack onsets and 115 PPS alerts.

Retains packet COUNTS and protocol/IP aggregates, never payloads. A flow
near an attack start is not automatically malicious. In particular, the
official 1999 internal host inventory omits marx.eyrie.af.mil.
"""

import argparse
import csv
import json
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from .download import DAYS, paths
from .evaluate_week2 import load_official, read_csv

TARGETS = {"pigeon.eyrie.af.mil": "172.16.114.207"}
EVENT_IDS = (17, 24, 26, 36)
FIELDS = ("frame.time_epoch", "frame.len", "ip.src", "ip.dst", "ip.proto",
          "tcp.dstport", "udp.dstport", "tcp.flags")


def frames(path):
    """Unzip into TShark stdin and yield TSV records with exit-code checks."""
    for command in ("gzip", "tshark"):
        if not shutil.which(command):
            raise RuntimeError("Missing executable: " + command)
    unzip = subprocess.Popen(["gzip", "-dc", str(path)],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert unzip.stdout
    try:
        cmd = (["tshark", "-r", "-", "-n", "-T", "fields"] +
               [item for field in FIELDS for item in ("-e", field)] +
               ["-E", "separator=/t", "-E", "quote=n", "-E", "occurrence=f"])
        shark = subprocess.Popen(cmd, stdin=unzip.stdout, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, text=True, errors="replace")
    except Exception:
        unzip.stdout.close()
        unzip.wait()
        raise
    unzip.stdout.close()
    assert shark.stdout
    try:
        for line in shark.stdout:
            record = line.rstrip("\r\n").split("\t")
            if len(record) != len(FIELDS):
                raise ValueError("Unexpected tshark TSV field count")
            yield record
    finally:
        shark.stdout.close()
        status_t, status_g = shark.wait(), unzip.wait()
        if status_t or status_g:
            raise RuntimeError(f"Invalid capture {path}: tshark={status_t}, gzip={status_g}")


class Evidence:
    def __init__(self):
        self.n = 0
        self.bytes = 0
        self.proto = Counter()
        self.src = Counter()
        self.dst = Counter()
        self.ports = Counter()
        self.syn_target = Counter()
        self.syn_ports = defaultdict(set)
        self.syn = self.synack = self.rst = self.fin = 0

    def add(self, record):
        _, length, src, dst, protocol, port, udp_port, flags = record
        bits = int(flags, 0) if flags else 0
        self.n += 1
        self.bytes += int(length)
        proto = {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(protocol, "OTHER")
        self.proto[proto] += 1
        if src:
            self.src[src] += 1
        if dst:
            self.dst[dst] += 1
        if proto == "TCP":
            if port:
                self.ports[port] += 1
            if bits & 0x02 and not bits & 0x10:
                self.syn += 1
                if dst:
                    self.syn_target[dst] += 1
                    if port:
                        self.syn_ports[dst].add(port)
            if bits & 0x02 and bits & 0x10:
                self.synack += 1
            if bits & 0x04:
                self.rst += 1
            if bits & 0x01:
                self.fin += 1
        elif proto == "UDP" and udp_port:
            self.ports["udp:" + udp_port] += 1

    def row(self, day, minute):
        best_ip, best_count = self.dst.most_common(1)[0] if self.dst else ("", 0)
        syn_ip, syn_count = self.syn_target.most_common(1)[0] if self.syn_target else ("", 0)
        return {
            "source_day": day,
            "window_start_utc": datetime.fromtimestamp(60 * minute, timezone.utc).isoformat(),
            "packets": self.n,
            "pps": round(self.n / 60, 6),
            "tcp_packets": self.proto["TCP"],
            "udp_packets": self.proto["UDP"],
            "icmp_packets": self.proto["ICMP"],
            "syn_no_ack_packets": self.syn,
            "syn_ack_packets": self.synack,
            "tcp_rst_packets": self.rst,
            "tcp_fin_packets": self.fin,
            "unique_source_ips": len(self.src),
            "unique_destination_ips": len(self.dst),
            "unique_ports": len(self.ports),
            "top_dst_ip": best_ip,
            "top_dst_packets": best_count,
            "top_syn_dst_ip": syn_ip,
            "top_syn_dst_packets": syn_count,
            "top_syn_dst_distinct_ports": len(self.syn_ports[syn_ip]),
            "top_ports": ";".join(k + ":" + str(v) for k, v in self.ports.most_common(5)),
        }


def save(path, rows):
    if not rows:
        raise ValueError("Empty export")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def phenotype(r):
    """Traffic descriptions, not ground-truth attack/benign labels."""
    n = int(r["packets"])
    tcp = int(r["tcp_packets"])
    syn = int(r["syn_no_ack_packets"])
    if n == 0:
        return "zero_packets"
    if syn >= 30 and syn / max(tcp, 1) >= 0.6:
        return "tcp_syn_scan_candidate" if int(r["top_syn_dst_distinct_ports"]) >= 20 else "tcp_syn_heavy"
    if int(r["icmp_packets"]) / n >= .6:
        return "icmp_dominated"
    if int(r["udp_packets"]) / n >= .6:
        return "udp_dominated"
    if float(r["pps"]) < 10:
        return "low_rate_deviation"
    return "mixed_unresolved"


def main_run(pcaps, series_path, detections_path, labels_path, output):
    series = read_csv(series_path)
    observed = {(r["source_day"], int(datetime.fromisoformat(r["window_start_utc"]).timestamp()) // 60): r
                for r in series}
    all_rows = read_csv(detections_path)
    flagged_rows = [r for r in all_rows if r["is_anomaly"] == "1"]
    if len(flagged_rows) != 115:
        raise AssertionError("Expected the 115 original baseline alerts")
    flagged = {(r["source_day"], int(datetime.fromisoformat(r["window_start_utc"]).timestamp()) // 60)
               for r in flagged_rows}
    official = {int(e["id"]): e for e in load_official(labels_path)
                if int(e["id"]) in EVENT_IDS}
    assert set(official) == set(EVENT_IDS)
    needed = set(flagged)
    for e in official.values():
        onset = int(e["onset_minute"].timestamp()) // 60
        needed.update((e["day"], onset + i) for i in range(-5, 6))
    if not needed.issubset(set(observed)):
        raise ValueError("Requested attack/alert windows absent from original 60s CSV")
    accum = {key: Evidence() for key in needed}
    counts = Counter()
    for day, path in zip(DAYS, paths(pcaps)):
        print("[pcap] reading", day, flush=True)
        for record in frames(path):
            counts[day] += 1
            key = (day, int(float(record[0]) // 60))
            if key in accum:
                accum[key].add(record)
        expected = sum(int(r["packets"]) for r in series if r["source_day"] == day)
        if counts[day] != expected:
            raise AssertionError(f"Full PCAP packet count inconsistent on {day}")
        print("[pcap]", day, counts[day], "packets verified", flush=True)
    windows = [value.row(*key) for key, value in sorted(accum.items())]
    for r in windows:
        key = (r["source_day"], int(datetime.fromisoformat(r["window_start_utc"]).timestamp()) // 60)
        if r["packets"] != int(observed[key]["packets"]):
            raise AssertionError("Window packets do not match Stage 2 " + str(key))
    idx = {(r["source_day"], int(datetime.fromisoformat(r["window_start_utc"]).timestamp()) // 60): r for r in windows}
    alerts = []
    for a in flagged_rows:
        key = (a["source_day"], int(datetime.fromisoformat(a["window_start_utc"]).timestamp()) // 60)
        r = dict(idx[key])
        near_any = any(e["day"] == key[0] and abs(key[1] - int(e["onset_minute"].timestamp()) // 60) <= 5
                       for e in official.values())
        r.update(robust_score=a["robust_score"], near_4_attack_onsets=int(near_any),
                 phenotype=phenotype(r), attack_truth="unresolved")
        alerts.append(r)

    event_rows = []
    for id in EVENT_IDS:
        e = official[id]
        base = int(e["onset_minute"].timestamp()) // 60
        prior = [accum[(e["day"], base + i)] for i in range(-5, 0)]
        later = [accum[(e["day"], base + i)] for i in range(0, 6)]
        target = TARGETS.get(e["destination"], "")
        syn_by_dst = Counter()
        dst_total = Counter()
        ports_by_dst = defaultdict(set)
        for v in later:
            syn_by_dst.update(v.syn_target)
            dst_total.update(v.dst)
            for ip, ps in v.syn_ports.items():
                ports_by_dst[ip].update(ps)
        candidate = syn_by_dst.most_common(1)[0][0] if syn_by_dst else ""
        event_rows.append({
            "attack_id": id, "attack": e["attack"], "onset_utc": e["onset_utc"].isoformat(),
            "official_target": e["destination"], "target_ipv4_official": target,
            "target_mapping_status": "official_host_inventory" if target else "unresolved",
            "pre_5min_syn_pps": round(sum(v.syn for v in prior) / 300, 6),
            "onset_plus_5min_syn_pps": round(sum(v.syn for v in later) / 360, 6),
            "onset_plus_5min_tcp_packets": sum(v.proto["TCP"] for v in later),
            "onset_plus_5min_rst_packets": sum(v.rst for v in later),
            "onset_plus_5min_target_packets": dst_total[target] if target else "",
            "onset_plus_5min_target_syn": syn_by_dst[target] if target else "",
            "observed_top_syn_dst": candidate,
            "observed_top_syn_dst_packets": syn_by_dst[candidate] if candidate else 0,
            "observed_top_syn_dst_unique_ports": len(ports_by_dst[candidate]),
            "observed_top_destinations": ";".join(ip + ":" + str(n) for ip, n in dst_total.most_common(7)),
            "conclusion": "protocol_and_destination_evidence_only_not_attack_proof",
        })
    if sum(v.syn + v.synack + v.rst + v.fin for v in accum.values()) == 0:
        raise AssertionError("All inspected TCP flags are zero; abort protocol evidence report")
    output.mkdir(parents=True, exist_ok=True)
    save(output / "packet_window_features.csv", windows)
    save(output / "all_115_alert_packet_audit.csv", alerts)
    save(output / "four_attack_event_evidence.csv", event_rows)
    categories = Counter(r["phenotype"] for r in alerts)
    summary = {
        "all_five_raw_pcaps_checked": True,
        "total_frames_validated": sum(counts.values()),
        "frames_by_day": dict(counts),
        "selected_windows": len(windows),
        "original_ewma_alerts_investigated": len(alerts),
        "official_event_ids": list(EVENT_IDS),
        "host_mapping_marx": "unresolved_not_in_official_inside_host_list",
        "host_mapping_pigeon": TARGETS["pigeon.eyrie.af.mil"],
        "alert_traffic_phenotypes": dict(sorted(categories.items())),
        "confirmed_true_positives": None,
        "confirmed_false_positives": None,
        "reason_no_tp_fp": "Attack intervals and packet attribution are not completely labeled",
    }
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    make_figures(output, event_rows, categories)
    write_report(output, event_rows, summary)
    print(json.dumps(summary, indent=2), flush=True)


def make_figures(output, event_rows, categories):
    figures = output / "figures"
    figures.mkdir(exist_ok=True)
    fig, ax = plt.subplots(figsize=(10, 5))
    xs = list(range(4))
    ax.bar([i - .18 for i in xs], [r["pre_5min_syn_pps"] for r in event_rows],
           width=.36, label="5 min before")
    ax.bar([i + .18 for i in xs], [r["onset_plus_5min_syn_pps"] for r in event_rows],
           width=.36, label="6 onset-inclusive minutes")
    ax.set_xticks(xs, [r["attack"] + " #" + str(r["attack_id"]) for r in event_rows])
    ax.set_ylabel("TCP SYN-only packets per second (PPS)")
    ax.set_title("SYN evidence near four MIT attack start times")
    ax.legend()
    ax.grid(axis="y", alpha=.25)
    fig.tight_layout()
    fig.savefig(figures / "four_event_syn_pps.png", dpi=170)
    plt.close(fig)
    fig, ax = plt.subplots(figsize=(11, 5))
    ax.barh(list(categories), list(categories.values()))
    ax.set_xlabel("Number of anomalous one-minute windows")
    ax.set_title("Network traffic phenotypes (not ground-truth attack labels)")
    ax.grid(axis="x", alpha=.2)
    fig.tight_layout()
    fig.savefig(figures / "alert_protocol_phenotypes.png", dpi=170)
    plt.close(fig)


def write_report(output, events, summary):
    text = [
        "# Etapa 5 — Investigação por destino e protocolo (PCAP INSIDE)",
        "",
        "Foram relidas as cinco capturas originais do MIT, com verificação de "
        "contagens globais e de cada minuto investigado contra a série da Etapa 2.",
        "",
        "| ID | Ataque | Destino oficial | IPv4 oficial | SYN PPS 5 min antes | SYN PPS 6 min a partir do início | Destino SYN mais frequente |",
        "|---:|---|---|---|---:|---:|---|",
    ]
    for e in events:
        text.append("| " + str(e["attack_id"]) + " | " + e["attack"] + " | " +
                    e["official_target"] + " | " + (e["target_ipv4_official"] or "não resolvido") +
                    " | " + str(e["pre_5min_syn_pps"]) + " | " +
                    str(e["onset_plus_5min_syn_pps"]) + " | " +
                    (e["observed_top_syn_dst"] or "-") + " |")
    text.extend([
        "",
        "**Interpretação:** a identificação do IP de pigeon (172.16.114.207) "
        "é sustentada pelo inventário oficial de hosts de 1999. O destino "
        "marx não aparece naquele inventário e permanece não resolvido; "
        "não atribuir ao marx o IP predominante sem provas adicionais.",
        "",
        "Os números acima mostram metadados de conexões TCP capturadas nos "
        "minutos próximos aos inícios, e não a atribuição de sessões a "
        "um ataque. Para saber as contagens relativas ao IP pigeon, consultar "
        "four_attack_event_evidence.csv.",
        "",
        "## Todos os 115 alertas",
        "",
        "Cada janela de alerta foi validada contra o PCAP original e possui "
        "contagem TCP/UDP/ICMP, flags SYN/ACK/RST/FIN, número de IPs/portas "
        "distintos, principais destinos e fenótipo de tráfego.",
        "",
        "| Fenótipo de tráfego | Quantidade de alertas |",
        "|---|---:|",
    ])
    for key, value in summary["alert_traffic_phenotypes"].items():
        text.append("| " + key + " | " + str(value) + " |")
    text.extend([
        "",
        "![Taxas SYN em PPS](figures/four_event_syn_pps.png)",
        "",
        "![Categorias de triagem](figures/alert_protocol_phenotypes.png)",
        "",
        "## Limitações e validade científica",
        "",
        "- Os quatro ataques são candidatos temporais, não quatro "
        "verdadeiros positivos confirmados.",
        "- Um pico de SYN para um alvo coincide com comportamento suspeito, "
        "mas tráfego de fundo também pode contribuir.",
        "- O período analisado (5 min antes, 6 min a partir do início) "
        "NÃO representa a duração verificada de cada ataque.",
        "- Os 106 alertas fora de ±5 min dos inícios oficiais não são "
        "falsos positivos automaticamente, pois ataques podem continuar.",
        "- Este estudo não identifica integralmente sessões maliciosas, "
        "não permite computar TP/FP/F1 definitivos e não deve alegá-los.",
        "",
        "## Fontes e reprodutibilidade",
        "",
        "- Hosts: https://archive.ll.mit.edu/ideval/docs/hosts_1999.html",
        "- Inícios: https://archive.ll.mit.edu/ideval/docs/detections_1999.html",
        "- Capturas: https://archive.ll.mit.edu/ideval/data/1999/training/week2/index.html",
        "- Código: src/anomaly_detection/packet_evidence.py",
        "- Workflow: .github/workflows/packet-evidence.yml",
        "- Arquivos: packet_window_features.csv, four_attack_event_evidence.csv, "
        "all_115_alert_packet_audit.csv, summary.json e dois PNGs.",
        "- Nenhum payload nem PCAP completo foi incluído no Git.",
        "",
    ])
    (output / "README.md").write_text("\n".join(text))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcaps", type=Path, default=Path("data/raw"))
    parser.add_argument("--output", type=Path,
                        default=Path("reports/week2-1999/stage5-packet-evidence"))
    args = parser.parse_args()
    main_run(args.pcaps,
             Path("reports/week2-1999/data/traffic_60s.csv"),
             Path("reports/week2-1999/results/detections.csv"),
             Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"),
             args.output)


if __name__ == "__main__":
    main()
