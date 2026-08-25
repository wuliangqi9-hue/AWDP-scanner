from pathlib import Path

from awdp_scanner.benchmark import evaluate_cases, load_cases


def test_reference_benchmark_meets_regression_thresholds():
    corpus = Path(__file__).resolve().parent.parent / "benchmarks" / "corpus.json"

    result = evaluate_cases(load_cases(corpus))

    assert result["summary"]["cases"] >= 8
    assert result["summary"]["recall"] >= 0.90
    assert result["summary"]["false_positive_rate"] <= 0.10
    assert result["performance"]["elapsed_seconds"] < 5.0
