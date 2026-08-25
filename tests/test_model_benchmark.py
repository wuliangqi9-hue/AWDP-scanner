import hashlib
import json
from pathlib import Path

from awdp_scanner.model_benchmark import (
    ACTIONABLE,
    CONFIRMED,
    _gate_score,
    _patch_score,
    _score_runs,
    _select_cases,
    load_corpus,
    normalize_family,
    prepare_corpus,
)


ROOT = Path(__file__).resolve().parent.parent


def test_real_model_corpus_packaged_copy_matches_source():
    source = json.loads((ROOT / "benchmarks" / "real_corpus.json").read_text(encoding="utf-8"))
    packaged = json.loads(
        (ROOT / "awdp_scanner" / "data" / "real_model_corpus.json").read_text(encoding="utf-8")
    )
    assert source == packaged
    assert source["dataset"]["commit"] == "4f5d17a20ac16eebda41144dc33f5f3b7c02cf68"
    assert len(source["cases"]) == 8


def test_family_scoring_separates_confirmed_and_actionable():
    cases = [
        {
            "id": "nosql",
            "expected_families": ["sqli"],
            "evidence_files": ["app.py"],
            "negative_files": ["safe.py"],
        }
    ]
    runs = {
        "nosql": {
            "findings": [
                {"file_path": "app.py", "suspected": "待人工复核", "vuln_type": "NoSQL injection"},
                {"file_path": "safe.py", "suspected": "否", "vuln_type": ""},
            ]
        }
    }

    actionable = _score_runs(cases, runs, accepted_statuses=ACTIONABLE)
    confirmed = _score_runs(cases, runs, accepted_statuses=CONFIRMED)

    assert actionable["summary"]["recall"] == 1.0
    assert actionable["summary"]["false_positive_rate"] == 0.0
    assert confirmed["summary"]["recall"] == 0.0
    assert normalize_family("MongoDB NoSQL injection") == "sqli"


def test_gate_score_requires_an_evidence_file_to_be_admitted():
    cases = [{"id": "case", "evidence_files": ["sink.py"]}]
    rejected = {"case": {"findings": [{"file_path": "sink.py", "suspected": "未命中候选"}]}}
    admitted = {"case": {"findings": [{"file_path": "sink.py", "suspected": "待人工复核"}]}}

    assert _gate_score(cases, rejected)["summary"]["recall"] == 0.0
    assert _gate_score(cases, admitted)["summary"]["recall"] == 1.0


def test_case_selection_preserves_requested_order_and_rejects_unknown():
    corpus = {"cases": [{"id": "first"}, {"id": "second"}]}

    assert [case["id"] for case in _select_cases(corpus, ["second", "first"])] == ["second", "first"]

    try:
        _select_cases(corpus, ["missing"])
    except ValueError as exc:
        assert "missing" in str(exc)
    else:
        raise AssertionError("unknown benchmark cases must be rejected")


def test_patch_score_does_not_label_static_validation_as_functional_success():
    cases = [{"id": "patch", "patch_benchmark": True, "evidence_files": ["app.py"]}]
    runs = {
        "patch": {
            "findings": [
                {
                    "file_path": "app.py",
                    "original_code_snippet": "dangerous(value)",
                    "fixed_code_snippet": "safe(value)",
                    "patch_verification": {
                        "status": "validated",
                        "syntax_check": {"status": "passed"},
                        "semantic_checks": [{"status": "passed"}],
                    },
                }
            ]
        }
    }

    summary = _patch_score(cases, runs)["summary"]

    assert summary["isolated_static_candidate_rate"] == 1.0
    assert summary["functional_or_poc_validation_rate"] is None
    assert "candidate_patch_success_rate" not in summary


def test_prepare_corpus_accepts_only_matching_pinned_content(tmp_path):
    content = b"print('pinned')\n"
    corpus = {
        "schema_version": "awdp-real-model-corpus-v1",
        "dataset": {
            "repository": "https://github.com/example/example",
            "commit": "a" * 40,
        },
        "cases": [
            {
                "id": "sample",
                "files": [
                    {
                        "remote_path": "src/app.py",
                        "local_path": "app.py",
                        "sha256": hashlib.sha256(content).hexdigest(),
                    }
                ],
            }
        ],
    }
    manifest = tmp_path / "corpus.json"
    manifest.write_text(json.dumps(corpus), encoding="utf-8")
    loaded = load_corpus(manifest)
    target = tmp_path / "sources" / "sample" / "app.py"
    target.parent.mkdir(parents=True)
    target.write_bytes(content)

    paths = prepare_corpus(loaded, tmp_path / "sources", allow_download=False)

    assert paths["sample"] == target.parent
