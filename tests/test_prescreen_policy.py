import awdp_pro_scanner as scanner
import pytest


@pytest.mark.parametrize(
    ("path", "code"),
    [
        (
            "wrapper.py",
            "import subprocess\ndef run_command(user_cmd):\n    return subprocess.run(user_cmd, shell=True)",
        ),
        (
            "wrapper.php",
            "<?php function run_cmd($cmd) { system($cmd); } ?>",
        ),
        (
            "decode.py",
            "import pickle\ndef decode(payload):\n    return pickle.loads(payload)",
        ),
        (
            "proxy.js",
            "async function proxy(targetUrl) { return fetch(targetUrl); }",
        ),
    ],
)
def test_unknown_source_high_risk_sink_is_not_discarded(path, code):
    heuristic = scanner.run_heuristic_prescreen(code, file_path=path)
    plan = scanner.build_scan_plan(path, code, heuristic_meta=heuristic)

    assert plan["status"] == "candidate"
    assert plan["unknown_source_sink"] is True


def test_no_candidate_is_not_reported_as_safe():
    code = "def add(left, right):\n    return left + right\n"
    heuristic = scanner.run_heuristic_prescreen(code, file_path="math.py")
    plan = scanner.build_scan_plan("math.py", code, heuristic_meta=heuristic)

    assert plan["status"] == "no_candidate"
    assert scanner.evaluate_suspected({"verdict": "no_candidate"}) == "未命中候选"


@pytest.mark.parametrize(
    ("extension", "line"),
    [
        (".py", 'url = "https://example.test/path#fragment"  # comment'),
        (".js", 'const url = "https://example.test/a//b"; // comment'),
        (".php", '$url = "https://example.test/path#fragment"; # comment'),
    ],
)
def test_inline_comment_stripping_preserves_string_content(extension, line):
    stripped = scanner._strip_inline_comment(line, extension)

    assert "https://example.test" in stripped
    assert "fragment" in stripped or extension == ".js"
