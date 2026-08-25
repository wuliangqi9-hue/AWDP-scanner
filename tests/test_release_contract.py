import json
import re
from pathlib import Path

import awdp_pro_scanner
import awdp_scanner


ROOT = Path(__file__).resolve().parent.parent


def test_release_versions_are_synchronized():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, re.M).group(1)

    assert project_version == awdp_scanner.__version__ == awdp_pro_scanner.SCANNER_VERSION


def test_packaged_and_editable_benchmark_corpora_match():
    editable = json.loads((ROOT / "benchmarks" / "corpus.json").read_text(encoding="utf-8"))
    packaged = json.loads(
        (ROOT / "awdp_scanner" / "data" / "benchmark_corpus.json").read_text(encoding="utf-8")
    )

    assert packaged == editable


def test_source_distribution_prunes_local_benchmark_artifacts():
    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")

    assert "prune benchmarks/.external" in manifest
    assert "prune benchmarks/.results" in manifest
