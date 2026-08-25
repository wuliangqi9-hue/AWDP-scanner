import json
from pathlib import Path

import awdp_pro_scanner as scanner


def test_report_separates_no_candidate_from_safe(tmp_path):
    entries = [
        scanner.make_report_entry(
            file_path="clean.py",
            suspected="否",
            prescreen="已完成分析",
            reason="未发现漏洞",
        ),
        scanner.make_report_entry(
            file_path="unmatched.py",
            suspected="未命中候选",
            prescreen="规则未命中",
            note="未触发深度分析",
        ),
    ]
    report_path = tmp_path / "report.md"

    scanner.render_report(str(tmp_path), entries, report_path=str(report_path))

    report = report_path.read_text(encoding="utf-8")
    assert "安全: `1` | 未命中候选: `1`" in report
    assert "不能作为代码安全证明" in report
    assert "## 未命中候选文件" in report
    assert "`unmatched.py`" in report


def test_scan_writes_reproducible_run_artifacts(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "math.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    report_path = run_dir / "report.md"
    findings_path = run_dir / "findings.json"
    manifest_path = run_dir / "manifest.json"

    scanner.scan_directory(
        str(target),
        vector_db=None,
        report_path=str(report_path),
        findings_path=str(findings_path),
        manifest_path=str(manifest_path),
        run_id="test-run",
    )

    findings = json.loads(findings_path.read_text(encoding="utf-8"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert report_path.is_file()
    assert findings["schema_version"] == "awdp-findings-v1"
    assert findings["summary"]["no_candidate"] == 1
    assert manifest["schema_version"] == "awdp-run-manifest-v1"
    assert manifest["run_id"] == "test-run"
    assert manifest["summary"]["safe"] == 0
    assert Path(manifest["artifacts"]["report"]) == report_path


def test_cli_rejects_missing_target_before_model_probe(tmp_path, monkeypatch):
    probed = False

    def fake_probe():
        nonlocal probed
        probed = True
        return True

    monkeypatch.setattr(scanner, "check_ollama_status", fake_probe)

    exit_code = scanner.main(["--target", str(tmp_path / "missing")])

    assert exit_code == 2
    assert probed is False


def test_second_identical_scan_uses_incremental_cache(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "math.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    cache = scanner.ScanCache(tmp_path / "cache")

    scanner.scan_directory(
        str(target),
        report_path=str(tmp_path / "first" / "report.md"),
        findings_path=str(tmp_path / "first" / "findings.json"),
        manifest_path=str(tmp_path / "first" / "manifest.json"),
        run_id="first",
        scan_cache=cache,
    )
    scanner.scan_directory(
        str(target),
        report_path=str(tmp_path / "second" / "report.md"),
        findings_path=str(tmp_path / "second" / "findings.json"),
        manifest_path=str(tmp_path / "second" / "manifest.json"),
        run_id="second",
        scan_cache=cache,
    )

    second_findings = json.loads((tmp_path / "second" / "findings.json").read_text(encoding="utf-8"))
    second_manifest = json.loads((tmp_path / "second" / "manifest.json").read_text(encoding="utf-8"))
    assert second_findings["findings"][0]["cache_hit"] is True
    assert second_manifest["cache"]["hits"] == 1


def test_static_only_cli_does_not_probe_or_call_model(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    (target / "math.py").write_text("def add(a, b):\n    return a + b\n", encoding="utf-8")
    output = tmp_path / "output"
    monkeypatch.setattr(scanner, "STATIC_ONLY", False)
    monkeypatch.setattr(
        scanner,
        "check_ollama_status",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("model probe is forbidden")),
    )
    monkeypatch.setattr(
        scanner,
        "call_ollama",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("model call is forbidden")),
    )

    exit_code = scanner.main(
        ["--target", str(target), "--output-dir", str(output), "--static-only", "--no-cache"]
    )

    assert exit_code == 0
    assert (output / "manifest.json").is_file()
    manifest = json.loads((output / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["configuration"]["static_only"] is True
