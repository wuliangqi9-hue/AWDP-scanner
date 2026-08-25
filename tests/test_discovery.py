import os

import pytest

from awdp_scanner.discovery import DiscoveryPolicy, discover_sources


def test_discovery_decodes_without_ignoring_bytes_and_reports_encoding(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "utf8.py").write_text("message = '你好'\n", encoding="utf-8")
    (target / "gb.py").write_bytes("message = '中文'\n".encode("gb18030"))

    sources, issues, stats = discover_sources(
        str(target),
        allowed_extensions={".py"},
        ignored_directories=set(),
        policy=DiscoveryPolicy(),
    )

    assert not issues
    by_name = {source.relative_path: source for source in sources}
    assert by_name["utf8.py"].encoding == "utf-8-sig"
    assert by_name["gb.py"].encoding == "gb18030"
    assert stats["analyzable_files"] == 2


def test_binary_and_oversized_sources_become_explicit_issues(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    (target / "binary.py").write_bytes(b"x\x00y")
    (target / "large.py").write_text("x" * 20, encoding="utf-8")

    sources, issues, _stats = discover_sources(
        str(target),
        allowed_extensions={".py"},
        ignored_directories=set(),
        policy=DiscoveryPolicy(max_file_bytes=10),
    )

    assert not sources
    reasons = {issue.relative_path: issue.reason for issue in issues}
    assert "NUL byte" in reasons["binary.py"]
    assert "per-file byte budget" in reasons["large.py"]


def test_symlink_source_is_not_followed(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("print('secret')\n", encoding="utf-8")
    link = target / "linked.py"
    try:
        os.symlink(outside, link)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    sources, issues, _stats = discover_sources(
        str(target),
        allowed_extensions={".py"},
        ignored_directories=set(),
        policy=DiscoveryPolicy(),
    )

    assert not sources
    assert issues[0].relative_path == "linked.py"
    assert "symlink" in issues[0].reason
