#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (c) 2026 MikiMiku (MoreMorePwn)
"""Summarize run-overhead-bench.sh output: medians per state and workload,
overhead against the kernel without Antinomie, and recording losses."""
import json
import re
import statistics
import sys
from pathlib import Path

LINE = re.compile(r"BENCH (\{.*?\})")
STATES = ("off", "idle", "recording")


def bench_lines(text):
    return [json.loads(match) for match in LINE.findall(text.replace("\r", ""))]


def main():
    out = Path(sys.argv[1])
    rows = {}
    losses = []
    for state in STATES:
        for path in sorted(out.glob(f"{state}-*")):
            if state == "recording":
                if not path.name.endswith(".report.json"):
                    continue
                report = json.loads(path.read_text())
                run = report["runs"][0]
                text = run["terminal"]
                execution = run.get("execution") or {}
                stats = dict(re.findall(r"(calls|packets|failed) (\d+)", report["recorder"]))
                losses.append({"round": path.name.split("-")[1].split(".")[0],
                               "transport_dropped": report["health"].get("dropped"),
                               "packets_sent": int(stats.get("packets", 0)),
                               "packets_failed": int(stats.get("failed", 0)),
                               "syscalls_recorded": int(stats.get("calls", 0)),
                               "run_async_loss": execution.get("async_loss_count"),
                               "run_flags": execution.get("flags")})
            elif path.suffix == ".log":
                text = path.read_text(errors="replace")
            else:
                continue
            for line in bench_lines(text):
                rows.setdefault((state, line["workload"]), []).append(line)
    summary = []
    workloads = sorted({workload for _, workload in rows})
    for workload in workloads:
        base = rows.get(("off", workload))
        base_ops = statistics.median(r["ops_per_s"] for r in base) if base else None
        base_p50 = statistics.median(r["p50_ns"] for r in base) if base else None
        for state in STATES:
            samples = rows.get((state, workload), [])
            if not samples:
                continue
            ops = statistics.median(r["ops_per_s"] for r in samples)
            p50 = statistics.median(r["p50_ns"] for r in samples)
            p99 = statistics.median(r["p99_ns"] for r in samples)
            summary.append({
                "workload": workload, "state": state, "rounds": len(samples),
                "ops_per_s": round(ops), "p50_ns": p50, "p99_ns": p99,
                "throughput_vs_off": round(ops / base_ops, 3) if base_ops else None,
                "p50_vs_off": round(p50 / base_p50, 2) if base_p50 else None,
            })
    result = {"summary": summary, "recording_losses": losses}
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"{'workload':22} {'state':10} {'ops/s':>10} {'p50 ns':>8} {'p99 ns':>8} {'thr/off':>8} {'p50/off':>8}")
    for row in summary:
        print(f"{row['workload']:22} {row['state']:10} {row['ops_per_s']:>10} {row['p50_ns']:>8} "
              f"{row['p99_ns']:>8} {row['throughput_vs_off']!s:>8} {row['p50_vs_off']!s:>8}")
    for loss in losses:
        print(json.dumps(loss))


if __name__ == "__main__":
    main()
