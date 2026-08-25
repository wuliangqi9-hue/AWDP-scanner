from awdp_scanner.cache import ScanCache, project_fingerprint
from awdp_scanner.reporters import build_sarif


def test_sarif_contains_only_actionable_results_with_regions():
    entries = [
        {
            "file_path": "src/app.py",
            "suspected": "是",
            "vuln_type": "Command Injection",
            "reason": "request reaches subprocess",
            "confidence": 0.9,
            "start_line": 12,
            "end_line": 14,
            "root_cause_family": "command_injection",
            "root_cause_fingerprint": "abc123",
        },
        {"file_path": "src/math.py", "suspected": "未命中候选", "confidence": 0.0},
    ]

    payload = build_sarif(entries, "0.2.0")

    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert len(run["results"]) == 1
    result = run["results"][0]
    assert result["ruleId"] == "AWDP.command_injection"
    assert result["locations"][0]["physicalLocation"]["region"] == {"startLine": 12, "endLine": 14}
    assert result["partialFingerprints"]["awdpRootCauseFingerprint"] == "abc123"


def test_scan_cache_is_content_and_context_addressed(tmp_path):
    cache = ScanCache(tmp_path / "cache")
    context = project_fingerprint([("app.py", "print('ok')")])
    base = {
        "file_path": "app.py",
        "content": "print('ok')",
        "project_digest": context,
        "configuration": {"model": "local"},
    }
    key = cache.make_key(**base)

    cache.put(key, {"file_path": "app.py", "suspected": "未命中候选"})

    assert cache.get(key)["file_path"] == "app.py"
    assert cache.make_key(**{**base, "content": "print('changed')"}) != key
    assert cache.make_key(**{**base, "configuration": {"model": "other"}}) != key


def test_corrupt_cache_entry_is_ignored(tmp_path):
    cache = ScanCache(tmp_path / "cache")
    key = "a" * 64
    cache_path = cache.directory / "aa" / f"{key}.json"
    cache_path.parent.mkdir(parents=True)
    cache_path.write_text("{broken", encoding="utf-8")

    assert cache.get(key) is None
