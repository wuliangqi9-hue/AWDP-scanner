from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .analysis import analyze_python_project
from .io import atomic_write_json


def load_cases(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    cases = payload.get("cases", []) if isinstance(payload, dict) else []
    if not isinstance(cases, list):
        raise ValueError("benchmark corpus must contain a cases array")
    return [case for case in cases if isinstance(case, dict)]


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * percentile)))
    return ordered[index]


def evaluate_cases(cases: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    case_results = []
    true_positive = false_positive = false_negative = true_negative = 0
    family_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    durations = []
    total_lines = 0
    with tempfile.TemporaryDirectory(prefix="awdp-benchmark-") as temporary_directory:
        root = Path(temporary_directory)
        for index, case in enumerate(cases):
            case_id = str(case.get("id", f"case-{index}"))
            case_root = root / case_id
            records = []
            for relative_path, content in dict(case.get("files", {})).items():
                file_path = case_root / relative_path
                records.append((str(file_path), str(content)))
                total_lines += len(str(content).splitlines())
            started = time.perf_counter()
            analysis = analyze_python_project(records)
            duration = time.perf_counter() - started
            durations.append(duration)
            predicted = {str(flow.get("family", "")) for flow in analysis.get("flows", []) if flow.get("family")}
            expected = {str(family) for family in case.get("expected_families", []) if family}
            for family in predicted | expected:
                if family in predicted and family in expected:
                    family_counts[family]["tp"] += 1
                elif family in predicted:
                    family_counts[family]["fp"] += 1
                else:
                    family_counts[family]["fn"] += 1
            expected_risk = bool(expected)
            predicted_risk = bool(predicted)
            if expected_risk and predicted_risk:
                true_positive += 1
            elif expected_risk:
                false_negative += 1
            elif predicted_risk:
                false_positive += 1
            else:
                true_negative += 1
            case_results.append(
                {
                    "id": case_id,
                    "expected_families": sorted(expected),
                    "predicted_families": sorted(predicted),
                    "passed": predicted == expected,
                    "duration_ms": round(duration * 1000, 3),
                }
            )
    precision = true_positive / (true_positive + false_positive) if true_positive + false_positive else 1.0
    recall = true_positive / (true_positive + false_negative) if true_positive + false_negative else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    false_positive_rate = false_positive / (false_positive + true_negative) if false_positive + true_negative else 0.0
    elapsed = sum(durations)
    per_family = {}
    for family, counts in sorted(family_counts.items()):
        family_precision = counts["tp"] / (counts["tp"] + counts["fp"]) if counts["tp"] + counts["fp"] else 1.0
        family_recall = counts["tp"] / (counts["tp"] + counts["fn"]) if counts["tp"] + counts["fn"] else 1.0
        per_family[family] = {**counts, "precision": family_precision, "recall": family_recall}
    return {
        "schema_version": "awdp-benchmark-v1",
        "summary": {
            "cases": len(case_results),
            "passed": sum(result["passed"] for result in case_results),
            "tp": true_positive,
            "fp": false_positive,
            "fn": false_negative,
            "tn": true_negative,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "false_positive_rate": false_positive_rate,
        },
        "performance": {
            "elapsed_seconds": elapsed,
            "lines": total_lines,
            "lines_per_second": total_lines / elapsed if elapsed else 0.0,
            "case_latency_p50_ms": _percentile(durations, 0.50) * 1000,
            "case_latency_p95_ms": _percentile(durations, 0.95) * 1000,
            "case_latency_mean_ms": statistics.fmean(durations) * 1000 if durations else 0.0,
        },
        "per_family": per_family,
        "cases": case_results,
    }


def build_parser() -> argparse.ArgumentParser:
    default_corpus = Path(__file__).resolve().parent / "data" / "benchmark_corpus.json"
    parser = argparse.ArgumentParser(description="Run deterministic AWDP static-analysis benchmarks.")
    parser.add_argument("--corpus", default=str(default_corpus))
    parser.add_argument("--output", help="Optional JSON result path.")
    parser.add_argument("--min-recall", type=float, default=0.90)
    parser.add_argument("--max-fpr", type=float, default=0.10)
    parser.add_argument("--max-seconds", type=float, default=5.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = evaluate_cases(load_cases(args.corpus))
    if args.output:
        atomic_write_json(args.output, result)
    print(json.dumps(result["summary"], ensure_ascii=False, indent=2))
    print(json.dumps(result["performance"], ensure_ascii=False, indent=2))
    summary = result["summary"]
    performance = result["performance"]
    passed = (
        summary["recall"] >= args.min_recall
        and summary["false_positive_rate"] <= args.max_fpr
        and performance["elapsed_seconds"] <= args.max_seconds
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
