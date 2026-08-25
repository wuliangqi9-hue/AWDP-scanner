from pathlib import Path

from awdp_scanner.patching import verify_patch_in_isolated_copy


def test_valid_patch_is_checked_in_copy_and_source_is_unchanged(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    original = "def parse(user):\n    return eval(user)\n"
    source.write_text(original, encoding="utf-8")

    result = verify_patch_in_isolated_copy(
        str(target),
        "app.py",
        "return eval(user)",
        "return user",
    )

    assert result.status == "validated"
    assert result.syntax_check.status == "passed"
    assert result.source_unchanged is True
    assert source.read_text(encoding="utf-8") == original
    assert "-    return eval(user)" in result.diff
    assert "+    return user" in result.diff


def test_invalid_patch_fails_syntax_without_touching_source(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    original = "value = eval(user)\n"
    source.write_text(original, encoding="utf-8")

    result = verify_patch_in_isolated_copy(str(target), "app.py", "eval(user)", "safe(user")

    assert result.status == "failed"
    assert result.syntax_check.status == "failed"
    assert source.read_text(encoding="utf-8") == original


def test_patch_with_new_undefined_module_is_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    original = "def decode(user):\n    return pickle.loads(user)\n"
    source.write_text(original, encoding="utf-8")

    result = verify_patch_in_isolated_copy(
        str(target),
        "app.py",
        "return pickle.loads(user)",
        "return json.loads(user)",
    )

    assert result.status == "failed"
    assert result.syntax_check.status == "passed"
    assert result.semantic_checks[0].status == "failed"
    assert "json" in result.semantic_checks[0].detail
    assert source.read_text(encoding="utf-8") == original


def test_ambiguous_exact_match_is_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    source = target / "app.py"
    source.write_text("eval(user)\neval(user)\n", encoding="utf-8")

    result = verify_patch_in_isolated_copy(str(target), "app.py", "eval(user)", "user")

    assert result.status == "rejected"
    assert "observed 2" in result.reason


def test_path_escape_is_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_text("eval(user)\n", encoding="utf-8")

    result = verify_patch_in_isolated_copy(str(target), "../outside.py", "eval(user)", "user")

    assert result.status == "rejected"
    assert "escapes" in result.reason
    assert Path(outside).read_text(encoding="utf-8") == "eval(user)\n"
