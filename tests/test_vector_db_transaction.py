import os
from types import SimpleNamespace

import pytest

import build_vector_db


def test_knowledge_labels_are_materialized_as_metadata():
    content = """# SSRF 修复约束

## 机器可读标签
- 适用family: ssrf
- 适用语言: python, go
- 文档角色: 主文档
- 支持mitigation_only: 是
- 支持cross_file_risk: 否

## 内容
constraint
"""

    metadata = build_vector_db.parse_knowledge_metadata(content, "07_ssrf_fix.md")

    assert metadata["doc_id"] == "07_ssrf_fix.md"
    assert metadata["title"] == "SSRF 修复约束"
    assert metadata["families"] == "ssrf"
    assert metadata["languages"] == "python, go"
    assert metadata["supports_mitigation_only"] is True
    assert metadata["supports_cross_file_risk"] is False
    assert len(metadata["content_sha256"]) == 64


def test_corpus_digest_is_stable_across_loader_order():
    first = SimpleNamespace(page_content="a", metadata={"source": "a.md"})
    second = SimpleNamespace(page_content="b", metadata={"source": "b.md"})

    forward = build_vector_db.knowledge_corpus_digest([first, second])
    reverse = build_vector_db.knowledge_corpus_digest([second, first])

    assert forward == reverse


def test_staged_database_replaces_previous_only_after_build(tmp_path):
    destination = tmp_path / "db"
    destination.mkdir()
    (destination / "state.txt").write_text("old", encoding="utf-8")
    staging = tmp_path / "db.building"
    staging.mkdir()
    (staging / "state.txt").write_text("new", encoding="utf-8")

    replaced = build_vector_db._install_staged_database(str(staging), str(destination))

    assert replaced is True
    assert (destination / "state.txt").read_text(encoding="utf-8") == "new"
    assert not staging.exists()
    assert not list(tmp_path.glob("db.backup-*"))


def test_failed_swap_restores_previous_database(tmp_path, monkeypatch):
    destination = tmp_path / "db"
    destination.mkdir()
    (destination / "state.txt").write_text("old", encoding="utf-8")
    staging = tmp_path / "db.building"
    staging.mkdir()
    (staging / "state.txt").write_text("new", encoding="utf-8")
    real_replace = os.replace

    def fail_staging_install(source, target):
        if os.path.normcase(source) == os.path.normcase(str(staging)):
            raise OSError("simulated install failure")
        return real_replace(source, target)

    monkeypatch.setattr(build_vector_db.os, "replace", fail_staging_install)

    with pytest.raises(OSError, match="simulated"):
        build_vector_db._install_staged_database(str(staging), str(destination))

    assert (destination / "state.txt").read_text(encoding="utf-8") == "old"
    assert (staging / "state.txt").read_text(encoding="utf-8") == "new"
    assert not list(tmp_path.glob("db.backup-*"))


def test_build_failure_keeps_previous_database(tmp_path, monkeypatch):
    knowledge_dir = tmp_path / "knowledge"
    knowledge_dir.mkdir()
    destination = tmp_path / "db"
    destination.mkdir()
    (destination / "state.txt").write_text("old", encoding="utf-8")
    document = SimpleNamespace(
        page_content="# Rule\n\n## 机器可读标签\n- 适用family: sqli\n",
        metadata={"source": str(knowledge_dir / "rule.md")},
    )

    class FakeLoader:
        def __init__(self, *args, **kwargs):
            pass

        def load(self):
            return [document]

    class FakeSplitter:
        def __init__(self, *args, **kwargs):
            pass

        def split_documents(self, documents):
            return documents

    class FailingChroma:
        @staticmethod
        def from_documents(documents, embeddings, persist_directory):
            os.makedirs(persist_directory)
            (tmp_path / "observed-staging.txt").write_text(persist_directory, encoding="utf-8")
            raise RuntimeError("simulated vector write failure")

    monkeypatch.setattr(build_vector_db, "DirectoryLoader", FakeLoader)
    monkeypatch.setattr(build_vector_db, "MarkdownTextSplitter", FakeSplitter)
    monkeypatch.setattr(build_vector_db, "build_local_embeddings", lambda: object())
    monkeypatch.setattr(build_vector_db, "Chroma", FailingChroma)
    monkeypatch.setattr(build_vector_db, "BUILD_DEPENDENCY_ERROR", "")

    with pytest.raises(RuntimeError, match="simulated"):
        build_vector_db.build_database(str(knowledge_dir), str(destination))

    assert (destination / "state.txt").read_text(encoding="utf-8") == "old"
    assert not list(tmp_path.glob("db.building-*"))
