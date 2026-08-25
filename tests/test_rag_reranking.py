from types import SimpleNamespace

from awdp_scanner.rag import directory_content_digest, enrich_knowledge_chunks, rerank_knowledge_candidates


def _document(source, family, language, content):
    return SimpleNamespace(
        page_content=content,
        metadata={
            "source": source,
            "families": family,
            "languages": language,
            "document_role": "主文档",
            "label_schema_version": "awdp-kb-labels-v1",
        },
    )


def test_family_metadata_can_outweigh_slightly_better_dense_distance():
    wrong = _document("xss.md", "xss", "python", "output encoding")
    right = _document("ssrf.md", "ssrf", "python", "scheme host resolved ip redirect")

    ranked = rerank_knowledge_candidates(
        [(wrong, 0.1), (right, 0.3)],
        query="python ssrf scheme host ip",
        desired_family="ssrf",
        language="python",
        top_k=2,
    )

    assert ranked[0].source == "ssrf.md"
    assert ranked[0].components["family"] == 1.0


def test_reranker_prefers_document_diversity_before_second_chunk():
    first = _document("ssrf.md", "ssrf", "python", "scheme host ip")
    duplicate = _document("ssrf.md", "ssrf", "python", "redirect dns")
    complementary = _document("cross-file.md", "cross_file_state_chain", "python", "shared wrapper policy")

    ranked = rerank_knowledge_candidates(
        [(first, 0.1), (duplicate, 0.11), (complementary, 0.2)],
        query="ssrf shared wrapper",
        desired_family="ssrf",
        language="python",
        top_k=2,
    )

    assert {item.source for item in ranked} == {"ssrf.md", "cross-file.md"}


def test_chunk_enrichment_adds_context_and_stable_identifier():
    chunk = _document("ssrf.md", "ssrf", "python", "disable redirects")
    chunk.metadata["title"] = "SSRF 修复约束"

    enriched = enrich_knowledge_chunks([chunk])

    assert enriched[0].page_content.startswith("[title=SSRF 修复约束")
    assert enriched[0].metadata["chunk_index"] == 0
    assert len(enriched[0].metadata["chunk_id"]) == 64


def test_model_directory_digest_changes_with_content(tmp_path):
    model = tmp_path / "model"
    model.mkdir()
    weight = model / "weights.bin"
    weight.write_bytes(b"one")
    first = directory_content_digest(model)
    weight.write_bytes(b"two")

    assert len(first) == 64
    assert directory_content_digest(model) != first
