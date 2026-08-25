from __future__ import annotations

import hashlib
import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


@dataclass(frozen=True)
class RankedKnowledgeChunk:
    document: Any
    dense_distance: float
    hybrid_score: float
    components: Mapping[str, float]
    source: str


def directory_content_digest(directory: str | os.PathLike[str]) -> str:
    root = Path(directory).expanduser().resolve()
    if not root.is_dir():
        return ""
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
    for path in files:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as input_file:
            while chunk := input_file.read(1024 * 1024):
                digest.update(chunk)
        digest.update(b"\0")
    return digest.hexdigest()


def _tokens(text: str) -> set[str]:
    lowered = str(text or "").lower()
    latin = set(re.findall(r"[a-z0-9_./-]{2,}", lowered))
    chinese_sequences = re.findall(r"[\u3400-\u9fff]+", lowered)
    chinese_bigrams = {
        sequence[index : index + 2]
        for sequence in chinese_sequences
        for index in range(max(0, len(sequence) - 1))
    }
    return latin | chinese_bigrams


def _csv_values(value: Any) -> set[str]:
    return {item.strip().lower() for item in str(value or "").split(",") if item.strip()}


def _family_compatible(desired: str, available: set[str]) -> bool:
    desired = str(desired or "").lower()
    if not desired or not available:
        return False
    if desired in available:
        return True
    groups = (
        {"command_injection", "command_execution_rce_eval", "command_injection_php", "code_execution"},
        {"path_traversal", "path_traversal_lfi", "zip_slip_path_traversal", "dynamic_include"},
        {"deserialization", "yaml_deserialization", "jndi_fastjson_deserialization"},
        {"ssti", "ssti_python_jinja", "dynamic_include"},
    )
    return any(desired in group and bool(group.intersection(available)) for group in groups)


def _lexical_score(query_tokens: set[str], content: str) -> float:
    if not query_tokens:
        return 0.0
    content_tokens = _tokens(content)
    if not content_tokens:
        return 0.0
    overlap = len(query_tokens.intersection(content_tokens))
    return min(1.0, overlap / math.sqrt(len(query_tokens) * len(content_tokens)))


def rerank_knowledge_candidates(
    candidates: Iterable[tuple[Any, float]],
    *,
    query: str,
    desired_family: str = "",
    language: str = "",
    top_k: int = 3,
    distance_threshold: float = 1.2,
) -> list[RankedKnowledgeChunk]:
    query_tokens = _tokens(query)
    language = str(language or "").lower()
    ranked = []
    for document, raw_distance in candidates:
        try:
            distance = max(0.0, float(raw_distance))
        except (TypeError, ValueError):
            continue
        metadata = dict(getattr(document, "metadata", {}) or {})
        families = _csv_values(metadata.get("families", ""))
        languages = _csv_values(metadata.get("languages", ""))
        family_match = 1.0 if _family_compatible(desired_family, families) else 0.0
        language_match = 1.0 if language and language in languages else 0.0
        if distance > distance_threshold and not family_match:
            continue
        dense = 1.0 / (1.0 + distance)
        lexical = _lexical_score(query_tokens, getattr(document, "page_content", ""))
        role = str(metadata.get("document_role", "") or "")
        role_score = 1.0 if role in {"主文档", "专项文档", "项目级联动文档"} else 0.0
        metadata_quality = 1.0 if metadata.get("label_schema_version") else 0.0
        components = {
            "dense": dense,
            "family": family_match,
            "language": language_match,
            "lexical": lexical,
            "role": role_score,
            "metadata": metadata_quality,
        }
        hybrid = (
            0.42 * dense
            + 0.28 * family_match
            + 0.16 * lexical
            + 0.08 * language_match
            + 0.04 * role_score
            + 0.02 * metadata_quality
        )
        source = os.path.basename(str(metadata.get("source", "") or metadata.get("doc_id", "")))
        ranked.append(RankedKnowledgeChunk(document, distance, hybrid, components, source))
    ranked.sort(key=lambda item: (-item.hybrid_score, item.dense_distance, item.source))

    selected = []
    selected_sources = set()
    for item in ranked:
        source_key = item.source or str((getattr(item.document, "metadata", {}) or {}).get("chunk_id", ""))
        if source_key in selected_sources:
            continue
        selected.append(item)
        selected_sources.add(source_key)
        if len(selected) >= max(1, top_k):
            return selected
    for item in ranked:
        if item in selected:
            continue
        selected.append(item)
        if len(selected) >= max(1, top_k):
            break
    return selected


def enrich_knowledge_chunks(chunks: Sequence[Any]) -> list[Any]:
    per_source_index: dict[str, int] = {}
    enriched = []
    for chunk in chunks:
        metadata = dict(getattr(chunk, "metadata", {}) or {})
        source = str(metadata.get("source", "") or metadata.get("doc_id", ""))
        index = per_source_index.get(source, 0)
        per_source_index[source] = index + 1
        raw_content = str(getattr(chunk, "page_content", "") or "")
        context_prefix = (
            f"[title={metadata.get('title', '')}; families={metadata.get('families', '')}; "
            f"languages={metadata.get('languages', '')}; role={metadata.get('document_role', '')}]\n"
        )
        chunk.page_content = context_prefix + raw_content
        chunk_digest = hashlib.sha256(
            (source + "\0" + str(index) + "\0" + raw_content).encode("utf-8")
        ).hexdigest()
        metadata.update({"chunk_index": index, "chunk_id": chunk_digest})
        chunk.metadata = metadata
        enriched.append(chunk)
    return enriched
