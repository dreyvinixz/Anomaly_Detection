"""User-facing command line interface."""

import argparse
from pathlib import Path
from .download import download
from .preprocess import preprocess
from .detect import detect
from .plots import plot


def main() -> None:
    parser = argparse.ArgumentParser(description="DARPA offline anomaly detection")
    sub = parser.add_subparsers(dest="command", required=True)

    cmd = sub.add_parser("download", help="Fetch Week 2 inside captures")
    cmd.add_argument("--data-dir", type=Path, default=Path("data/raw"))

    cmd = sub.add_parser("preprocess", help="Aggregate into exact 60-second windows")
    cmd.add_argument("--data-dir", type=Path, default=Path("data/raw"))
    cmd.add_argument("--series", type=Path, default=Path("data/processed/traffic_60s.csv"))
    cmd.add_argument("--max-gap-minutes", type=int, default=5)

    for name in ("detect", "run"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--series", type=Path, default=Path("data/processed/traffic_60s.csv"))
        cmd.add_argument("--out-dir", type=Path, default=Path("results"))
        cmd.add_argument("--alpha", type=float, default=0.2)
        cmd.add_argument("--threshold", type=float, default=4.5)
        cmd.add_argument("--warmup", type=int, default=30)
        cmd.add_argument("--history", type=int, default=120)
        if name == "run":
            cmd.add_argument("--data-dir", type=Path, default=Path("data/raw"))

    cmd = sub.add_parser("part-b", help="Entrega B: SMA(10), NMSE, MAPE, alarmes")
    cmd.add_argument("--series", type=Path, default=Path("reports/week2-1999/data/traffic_60s.csv"))
    cmd.add_argument("--out-dir", type=Path, default=Path("results/part-b"))
    cmd.add_argument("--labels", type=Path)
    cmd.add_argument("--threshold", type=float, default=4.5)
    cmd.add_argument("--residual-warmup", type=int, default=10)

    cmd = sub.add_parser("ground-truth-week2", help="Auditar rotulos DARPA Week 2")
    cmd.add_argument("--series", type=Path, default=Path("reports/week2-1999/data/traffic_60s.csv"))
    cmd.add_argument("--official", type=Path, default=Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"))
    cmd.add_argument("--intervals", type=Path, default=Path("data/ground_truth/week2_intervals_review.csv"))
    cmd.add_argument("--packet-evidence", type=Path, default=Path("reports/week2-1999/stage5-packet-evidence/four_attack_event_evidence.csv"))
    cmd.add_argument("--out-dir", type=Path, default=Path("results/ground-truth-week2"))

    cmd = sub.add_parser("evaluate-confusion-week2", help="Etapa 3: cobertura de rotulos e matriz validada")
    cmd.add_argument("--series", type=Path, default=Path("reports/week2-1999/data/traffic_60s.csv"))
    cmd.add_argument("--official", type=Path, default=Path("data/ground_truth/darpa1999_week2_official_attack_starts.csv"))
    cmd.add_argument("--intervals", type=Path, default=Path("data/ground_truth/week2_intervals_review.csv"))
    cmd.add_argument("--out-dir", type=Path, default=Path("results/stage3-confusion"))
    cmd.add_argument("--threshold", type=float, default=4.5)
    cmd.add_argument("--residual-warmup", type=int, default=10)

    cmd = sub.add_parser("plot", help="Generate PPS charts")
    cmd.add_argument("--detections", type=Path, default=Path("results/detections.csv"))
    cmd.add_argument("--out-dir", type=Path, default=Path("results/figures"))

    args = parser.parse_args()
    if args.command == "download":
        download(args.data_dir)
    elif args.command == "preprocess":
        preprocess(args.data_dir, args.series, args.max_gap_minutes)
    elif args.command == "evaluate-confusion-week2":
        from .evaluate_confusion_week2 import run_stage3
        import json
        print(json.dumps(run_stage3(args.series, args.official, args.intervals,
                                    args.out_dir, args.threshold, args.residual_warmup),
                         indent=2, ensure_ascii=False))
    elif args.command == "ground-truth-week2":
        from .ground_truth_week2 import audit
        import json
        print(json.dumps(audit(args.series, args.official, args.intervals,
                               args.out_dir, args.packet_evidence),
                         indent=2, ensure_ascii=False))
    elif args.command == "part-b":
        from .part_b import run_part_b
        import json
        print(json.dumps(run_part_b(args.series, args.out_dir, args.labels,
                                    args.threshold, args.residual_warmup), indent=2))
    elif args.command == "plot":
        print(plot(args.detections, args.out_dir))
    else:
        if args.command == "run":
            preprocess(args.data_dir, args.series)
        detect(args.series, args.out_dir,
               alpha=args.alpha, threshold=args.threshold,
               warmup=args.warmup, history=args.history)
        if args.command == "run":
            print(plot(args.out_dir / "detections.csv", args.out_dir / "figures"))


if __name__ == "__main__":
    main()
