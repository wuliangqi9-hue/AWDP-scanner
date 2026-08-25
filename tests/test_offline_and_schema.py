import json

import awdp_pro_scanner as scanner


class _FakeResponse:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def test_remote_endpoint_is_rejected_before_network(monkeypatch):
    class ExplodingSession:
        def get(self, *args, **kwargs):
            raise AssertionError("network must not be touched")

    monkeypatch.setattr(scanner, "OLLAMA_BASE_URL", "https://model.example.com")
    monkeypatch.setattr(scanner, "HTTP_SESSION", ExplodingSession())

    assert scanner.check_ollama_status(allow_remote_model=False) is False


def test_loopback_recognition_does_not_depend_on_dns():
    assert scanner._is_loopback_endpoint("http://localhost:11434")
    assert scanner._is_loopback_endpoint("http://127.0.0.1:11434")
    assert scanner._is_loopback_endpoint("http://[::1]:11434")
    assert not scanner._is_loopback_endpoint("http://model.internal:11434")
    assert not scanner._is_loopback_endpoint("file:///tmp/socket")


def test_ollama_receives_json_schema_and_disables_redirects(monkeypatch):
    calls = []

    class FakeSession:
        def post(self, url, **kwargs):
            calls.append((url, kwargs))
            response_text = json.dumps(
                {
                    "verdict": "safe",
                    "vuln_type": "",
                    "reason": "bounded input",
                    "code_evidence": "constant expression",
                    "confidence": 0.9,
                }
            )
            return _FakeResponse({"response": response_text})

    monkeypatch.setattr(scanner, "OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    monkeypatch.setattr(scanner, "HTTP_SESSION", FakeSession())

    result = scanner.call_ollama("audit", 64, retries=1, output_schema=scanner.DETECTION_OUTPUT_SCHEMA)

    assert result["ok"] is True
    assert calls[0][1]["json"]["format"] == scanner.DETECTION_OUTPUT_SCHEMA
    assert calls[0][1]["json"]["options"]["seed"] == scanner.MODEL_SEED
    assert calls[0][1]["json"]["keep_alive"] == scanner.MODEL_KEEP_ALIVE
    assert calls[0][1]["allow_redirects"] is False
    assert result["telemetry"]["ok"] is True


def test_invalid_safe_payload_fails_closed_to_manual_review():
    missing_evidence = json.dumps(
        {"verdict": "safe", "vuln_type": "", "reason": "looks fine", "confidence": 0.99}
    )

    result = scanner.parse_detection_output(missing_evidence)

    assert result["verdict"] == "needs_manual_review"
    assert result["confidence"] == 0.0
    assert "JSON Schema" in result["reason"]


def test_unsupported_model_api_claim_is_downgraded_for_review():
    result, grounding = scanner._ground_detection_evidence(
        "def update_user(changes):\n    return changes\n",
        {
            "verdict": "vulnerable",
            "vuln_type": "Command Injection",
            "reason": "subprocess executes attacker-controlled commands",
            "code_evidence": "subprocess.run(user_input, shell=True)",
            "confidence": 0.95,
        },
    )

    assert result["verdict"] == "needs_manual_review"
    assert result["vuln_type"] == ""
    assert result["confidence"] == 0.0
    assert result["ungrounded_claims"] == ["subprocess"]
    assert grounding["status"] == "failed"


def test_present_model_api_claim_passes_grounding():
    detection = {
        "verdict": "vulnerable",
        "vuln_type": "Unsafe deserialization",
        "reason": "pickle.loads consumes request data",
        "code_evidence": "pickle.loads(payload)",
        "confidence": 0.9,
    }

    result, grounding = scanner._ground_detection_evidence("return pickle.loads(payload)", detection)

    assert result == detection
    assert grounding["status"] == "passed"


def test_database_claim_without_any_query_api_is_downgraded():
    result, grounding = scanner._ground_detection_evidence(
        "def add(left, right):\n    return left + right\n",
        {
            "verdict": "vulnerable",
            "vuln_type": "SQL Injection",
            "reason": "An unparameterized SQL query accepts user data",
            "code_evidence": "The database query concatenates the request",
            "confidence": 0.8,
        },
    )

    assert result["verdict"] == "needs_manual_review"
    assert "database-query API" in result["ungrounded_claims"]
    assert grounding["status"] == "failed"


def test_embedding_loader_never_retries_without_local_only(tmp_path, monkeypatch):
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    calls = []

    def fake_embeddings(**kwargs):
        calls.append(kwargs)
        raise TypeError("unsupported option")

    monkeypatch.setattr(scanner, "HAS_RAG", True)
    monkeypatch.setattr(scanner, "EMBED_MODEL_PATH", str(model_dir))
    monkeypatch.setattr(scanner, "HuggingFaceEmbeddings", fake_embeddings)

    assert scanner.build_local_embeddings(required=False) is None
    assert calls == [{"model_name": str(model_dir), "model_kwargs": {"local_files_only": True}}]


def test_unversioned_vector_database_is_rejected_before_embedding_load(tmp_path, monkeypatch):
    db_dir = tmp_path / "db"
    db_dir.mkdir()

    def exploding_embeddings(*args, **kwargs):
        raise AssertionError("untrusted database must be rejected first")

    monkeypatch.setattr(scanner, "HAS_RAG", True)
    monkeypatch.setattr(scanner, "build_local_embeddings", exploding_embeddings)

    assert scanner.init_vector_db(str(db_dir)) is None
