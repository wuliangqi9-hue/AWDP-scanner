from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping

from .io import atomic_write_json, atomic_write_text


ROOT = Path(__file__).resolve().parent.parent
ACTIONABLE = {"是", "待人工复核"}
CONFIRMED = {"是"}
CANONICAL_FAMILIES = {
    "sqli",
    "upload",
    "file_write",
    "ssti",
    "command_exec",
    "auth",
    "proto_pollution",
    "ssrf",
    "xss",
    "deserialization",
    "xxe",
    "variable_overwrite",
    "jndi",
    "path_traversal",
    "dynamic_include",
}


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _ratio(numerator: int | float, denominator: int | float, *, empty: float = 0.0) -> float:
    return float(numerator) / float(denominator) if denominator else empty


def _percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_relative_path(value: str) -> Path:
    path = Path(str(value or "").replace("\\", "/"))
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"unsafe relative corpus path: {value!r}")
    return path


def load_corpus(path: str | Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if payload.get("schema_version") != "awdp-real-model-corpus-v1":
        raise ValueError("unsupported real-model corpus schema")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("real-model corpus must contain cases")
    seen_ids = set()
    for case in cases:
        case_id = str(case.get("id", ""))
        if not case_id or case_id in seen_ids:
            raise ValueError(f"invalid or duplicate case id: {case_id!r}")
        seen_ids.add(case_id)
        for source in case.get("files", []):
            _safe_relative_path(source.get("remote_path", ""))
            _safe_relative_path(source.get("local_path", ""))
            digest = str(source.get("sha256", ""))
            if len(digest) != 64:
                raise ValueError(f"missing SHA-256 for {case_id}")
    return payload


def _select_cases(corpus: Mapping[str, Any], selected_ids: Iterable[str] | None) -> list[Mapping[str, Any]]:
    cases = list(corpus.get("cases", []))
    requested = list(dict.fromkeys(str(case_id) for case_id in (selected_ids or []) if str(case_id)))
    if not requested:
        return cases
    by_id = {str(case["id"]): case for case in cases}
    unknown = [case_id for case_id in requested if case_id not in by_id]
    if unknown:
        raise ValueError("unknown benchmark case(s): " + ", ".join(unknown))
    return [by_id[case_id] for case_id in requested]


def _raw_base_url(dataset: Mapping[str, Any]) -> str:
    repository = str(dataset.get("repository", "")).rstrip("/")
    commit = str(dataset.get("commit", ""))
    parsed = urllib.parse.urlparse(repository)
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if parsed.hostname not in {"github.com", "www.github.com"} or len(parts) != 2 or len(commit) != 40:
        raise ValueError("corpus repository must be a pinned GitHub repository")
    return f"https://raw.githubusercontent.com/{parts[0]}/{parts[1]}/{commit}"


def _download_bytes(url: str, timeout: int = 60) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": "awdp-model-benchmark/0.2"})
    with opener.open(request, timeout=timeout) as response:
        return response.read()


def _atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(content)
    os.replace(temporary, path)


def prepare_corpus(
    corpus: Mapping[str, Any],
    destination: str | Path,
    *,
    allow_download: bool,
) -> dict[str, Path]:
    destination_path = Path(destination).expanduser().resolve()
    base_url = _raw_base_url(corpus.get("dataset", {}))
    case_paths: dict[str, Path] = {}
    for case in corpus.get("cases", []):
        case_id = str(case["id"])
        case_root = destination_path / case_id
        for source in case.get("files", []):
            relative = _safe_relative_path(source["local_path"])
            target = case_root / relative
            expected_digest = str(source["sha256"]).lower()
            content = target.read_bytes() if target.is_file() else b""
            if not content or _sha256(content) != expected_digest:
                if not allow_download:
                    raise FileNotFoundError(
                        f"missing or invalid pinned source {case_id}/{relative}; rerun with --prepare"
                    )
                remote_path = urllib.parse.quote(str(source["remote_path"]).replace("\\", "/"), safe="/")
                content = _download_bytes(f"{base_url}/{remote_path}")
                observed_digest = _sha256(content)
                if observed_digest != expected_digest:
                    raise ValueError(
                        f"SHA-256 mismatch for {source['remote_path']}: {observed_digest} != {expected_digest}"
                    )
                _atomic_write_bytes(target, content)
            case_paths[case_id] = case_root
    return case_paths


def _loopback_endpoint(endpoint: str) -> str:
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("model benchmark accepts loopback Ollama endpoints only")
    return endpoint.rstrip("/")


def _http_json(endpoint: str, path: str, payload: Mapping[str, Any] | None = None, timeout: int = 30) -> dict[str, Any]:
    url = f"{_loopback_endpoint(endpoint)}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    request = urllib.request.Request(
        url,
        data=data,
        method="POST" if payload is not None else "GET",
        headers={"Content-Type": "application/json", "User-Agent": "awdp-model-benchmark/0.2"},
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=timeout) as response:
        parsed = json.loads(response.read().decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


def _unload_model(endpoint: str, model: str) -> None:
    try:
        _http_json(
            endpoint,
            "/api/generate",
            {"model": model, "prompt": "", "stream": False, "keep_alive": 0},
            timeout=120,
        )
    except (OSError, ValueError, urllib.error.URLError):
        return


def _model_metadata(endpoint: str, model: str) -> dict[str, Any]:
    shown = _http_json(endpoint, "/api/show", {"model": model}, timeout=30)
    details = dict(shown.get("details", {}) or {})
    return {
        "name": model,
        "family": details.get("family", ""),
        "parameter_size": details.get("parameter_size", ""),
        "quantization_level": details.get("quantization_level", ""),
        "model_format": details.get("format", ""),
        "capabilities": list(shown.get("capabilities", []) or []),
    }


def _resident_model(endpoint: str, model: str) -> dict[str, Any]:
    try:
        payload = _http_json(endpoint, "/api/ps", timeout=10)
    except (OSError, ValueError, urllib.error.URLError):
        return {}
    for item in payload.get("models", []):
        if item.get("name") == model or item.get("model") == model:
            return {
                "size_bytes": int(item.get("size", 0) or 0),
                "size_vram_bytes": int(item.get("size_vram", 0) or 0),
                "context_length": int(item.get("context_length", 0) or 0),
                "digest": str(item.get("digest", "") or ""),
                "processor": "gpu" if int(item.get("size_vram", 0) or 0) else "cpu",
            }
    return {}


def _windows_hardware() -> dict[str, Any]:
    if os.name != "nt":
        return {}
    command = (
        "$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1 Name,NumberOfCores,NumberOfLogicalProcessors;"
        "$gpu=@(Get-CimInstance Win32_VideoController|Select-Object Name,DriverVersion,AdapterRAM,VideoProcessor);"
        "$cs=Get-CimInstance Win32_ComputerSystem|Select-Object -First 1 Manufacturer,Model,TotalPhysicalMemory;"
        "[pscustomobject]@{cpu=$cpu;gpu=$gpu;computer=$cs}|ConvertTo-Json -Depth 5 -Compress"
    )
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            shell=False,
        )
        return json.loads(completed.stdout) if completed.returncode == 0 else {}
    except (OSError, subprocess.SubprocessError, ValueError):
        return {}


def collect_host_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "processor": platform.processor(),
        "logical_cpus": os.cpu_count(),
    }
    info.update(_windows_hardware())
    try:
        completed = subprocess.run(
            ["ollama", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
            shell=False,
        )
        info["ollama_version"] = (completed.stdout or completed.stderr).strip()
    except (OSError, subprocess.SubprocessError):
        info["ollama_version"] = "unavailable"
    return info


class ResourceMonitor:
    def __init__(self, endpoint: str, model: str, interval: float = 0.5):
        self.endpoint = endpoint
        self.model = model
        self.interval = interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.samples = 0
        self.baseline_host_used_bytes = 0
        self.peak_host_used_bytes = 0
        self.peak_llama_rss_bytes = 0
        self.peak_vram_bytes = 0

    def _sample(self) -> None:
        try:
            import psutil

            host_used = int(psutil.virtual_memory().used)
            if not self.baseline_host_used_bytes:
                self.baseline_host_used_bytes = host_used
            self.peak_host_used_bytes = max(self.peak_host_used_bytes, host_used)
            llama_rss = 0
            for process in psutil.process_iter(["name", "memory_info"]):
                if str(process.info.get("name", "")).lower() == "llama-server.exe":
                    llama_rss += int(process.info["memory_info"].rss)
            self.peak_llama_rss_bytes = max(self.peak_llama_rss_bytes, llama_rss)
        except (ImportError, OSError):
            pass
        resident = _resident_model(self.endpoint, self.model)
        self.peak_vram_bytes = max(self.peak_vram_bytes, int(resident.get("size_vram_bytes", 0) or 0))
        self.samples += 1

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            self._sample()

    def start(self) -> None:
        self._sample()
        self._thread = threading.Thread(target=self._run, name="awdp-resource-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> dict[str, Any]:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._sample()
        return {
            "samples": self.samples,
            "baseline_host_used_bytes": self.baseline_host_used_bytes,
            "peak_host_used_bytes": self.peak_host_used_bytes,
            "peak_host_used_delta_bytes": max(0, self.peak_host_used_bytes - self.baseline_host_used_bytes),
            "peak_llama_server_rss_bytes": self.peak_llama_rss_bytes,
            "peak_ollama_size_vram_bytes": self.peak_vram_bytes,
        }


def _scanner_environment(
    endpoint: str,
    model: str,
    *,
    detection_tokens: int,
    repair_tokens: int,
    seed: int,
) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "OLLAMA_BASE_URL": endpoint,
            "AWDP_MODEL_NAME": model,
            "AWDP_STRICT_OFFLINE": "true",
            "AWDP_MODEL_RETRIES": "1",
            "AWDP_MODEL_SEED": str(seed),
            "AWDP_MODEL_KEEP_ALIVE": "20m",
            "AWDP_DETECTION_NUM_PREDICT": str(detection_tokens),
            "AWDP_REPAIR_NUM_PREDICT": str(repair_tokens),
            "AWDP_MAX_WORKERS": "1",
            "AWDP_FULL_FILE_MODEL_CHAR_LIMIT": "12000",
            "AWDP_MAX_MODEL_INPUT_CHARS": "12000",
            "PYTHONUTF8": "1",
        }
    )
    return environment


def _run_scanner(
    target: Path,
    output_directory: Path,
    *,
    endpoint: str,
    model: str,
    detection_tokens: int,
    repair_tokens: int,
    seed: int,
    static_only: bool,
    generate_repairs: bool,
    timeout: int,
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(ROOT / "awdp_pro_scanner.py"),
        "--target",
        str(target),
        "--output-dir",
        str(output_directory),
        "--no-rag",
        "--no-cache",
    ]
    if static_only:
        command.extend(["--static-only", "--no-verify-patches"])
    else:
        command.append("--deep-all")
        if not generate_repairs:
            command.extend(["--no-generate-repairs", "--no-verify-patches"])
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=_scanner_environment(
                endpoint,
                model,
                detection_tokens=detection_tokens,
                repair_tokens=repair_tokens,
                seed=seed,
            ),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
        return_code = completed.returncode
        output = (completed.stdout or "") + (completed.stderr or "")
    except subprocess.TimeoutExpired as exc:
        return_code = 124
        output = ((exc.stdout or "") if isinstance(exc.stdout, str) else "") + "\nbenchmark timeout"
    duration = time.perf_counter() - started
    atomic_write_text(output_directory / "scanner.log", output)
    findings_path = output_directory / "findings.json"
    manifest_path = output_directory / "manifest.json"
    findings = json.loads(findings_path.read_text(encoding="utf-8")) if findings_path.is_file() else {}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {}
    return {
        "return_code": return_code,
        "duration_seconds": round(duration, 3),
        "findings": list(findings.get("findings", []) or []),
        "manifest": manifest,
        "log": str(output_directory / "scanner.log"),
    }


def normalize_family(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in CANONICAL_FAMILIES:
        return text
    keywords = {
        "sqli": ("sql", "nosql", "injection", "注入", "mongo"),
        "upload": ("upload", "文件上传", "multipart"),
        "file_write": ("file write", "文件写入", "overwrite"),
        "ssti": ("ssti", "template injection", "jinja", "twig", "模板注入"),
        "command_exec": ("command", "rce", "exec", "shell", "eval", "命令执行", "代码执行"),
        "auth": ("jwt", "session", "auth", "token", "privilege", "authorization", "鉴权", "认证", "越权", "权限"),
        "proto_pollution": ("prototype", "proto", "污染"),
        "ssrf": ("ssrf", "server-side request", "内网请求"),
        "xss": ("xss", "cross site", "脚本"),
        "deserialization": ("deserialize", "pickle", "unserialize", "反序列化"),
        "xxe": ("xxe", "loadxml", "external entity", "外部实体"),
        "variable_overwrite": ("variable overwrite", "变量覆盖", "extract", "parse_str"),
        "jndi": ("jndi", "lookup", "fastjson", "autotype"),
        "path_traversal": ("path", "traversal", "lfi", "zip slip", "目录穿越", "文件读取"),
        "dynamic_include": ("dynamic include", "include path", "动态包含"),
    }
    for family, tokens in keywords.items():
        if any(token in text for token in tokens):
            return family
    return ""


def _entry_families(entry: Mapping[str, Any], accepted_statuses: set[str]) -> set[str]:
    if entry.get("suspected") not in accepted_statuses:
        return set()
    raw_values: list[Any] = [
        entry.get("root_cause_family"),
        entry.get("hard_override_family"),
        entry.get("vuln_type"),
    ]
    raw_values.extend(item.get("family") for item in entry.get("secondary_findings_data", []) if isinstance(item, dict))
    return {family for family in (normalize_family(value) for value in raw_values) if family}


def _score_runs(
    cases: Iterable[Mapping[str, Any]],
    runs: Mapping[str, Mapping[str, Any]],
    *,
    accepted_statuses: set[str],
) -> dict[str, Any]:
    tp = fp = fn = 0
    negative_total = negative_fp = 0
    manual_review_files = analyzed_files = schema_failures = 0
    family_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    case_results = []
    for case in cases:
        case_id = str(case["id"])
        entries = list(runs.get(case_id, {}).get("findings", []) or [])
        by_file = {str(entry.get("file_path", "")).replace("\\", "/"): entry for entry in entries}
        predicted = set()
        for entry in entries:
            predicted.update(_entry_families(entry, accepted_statuses))
            if entry.get("suspected") != "未分析":
                analyzed_files += 1
            if entry.get("suspected") == "待人工复核":
                manual_review_files += 1
            reason = str(entry.get("reason", ""))
            if "JSON Schema" in reason or entry.get("detection_model_telemetry", {}).get("ok") is False:
                schema_failures += 1
        expected = {str(item) for item in case.get("expected_families", [])}
        intersection = predicted & expected
        tp += len(intersection)
        fp += len(predicted - expected)
        fn += len(expected - predicted)
        for family in predicted | expected:
            if family in predicted and family in expected:
                family_counts[family]["tp"] += 1
            elif family in predicted:
                family_counts[family]["fp"] += 1
            else:
                family_counts[family]["fn"] += 1
        false_positive_files = []
        for relative in case.get("negative_files", []):
            negative_total += 1
            entry = by_file.get(str(relative).replace("\\", "/"), {})
            if entry.get("suspected") in accepted_statuses:
                negative_fp += 1
                false_positive_files.append(relative)
        case_results.append(
            {
                "id": case_id,
                "expected_families": sorted(expected),
                "predicted_families": sorted(predicted),
                "matched_families": sorted(intersection),
                "family_exact": predicted == expected,
                "detected": bool(intersection),
                "false_positive_files": false_positive_files,
                "duration_seconds": runs.get(case_id, {}).get("duration_seconds", 0.0),
                "return_code": runs.get(case_id, {}).get("return_code", -1),
            }
        )
    precision = _ratio(tp, tp + fp, empty=1.0)
    recall = _ratio(tp, tp + fn, empty=1.0)
    per_family = {}
    for family, counts in sorted(family_counts.items()):
        per_family[family] = {
            **counts,
            "precision": _ratio(counts["tp"], counts["tp"] + counts["fp"], empty=1.0),
            "recall": _ratio(counts["tp"], counts["tp"] + counts["fn"], empty=1.0),
        }
    return {
        "summary": {
            "case_family_tp": tp,
            "case_family_fp": fp,
            "case_family_fn": fn,
            "precision": precision,
            "recall": recall,
            "f1": _ratio(2 * precision * recall, precision + recall),
            "negative_control_files": negative_total,
            "negative_control_false_positives": negative_fp,
            "false_positive_rate": _ratio(negative_fp, negative_total),
            "manual_review_rate": _ratio(manual_review_files, analyzed_files),
            "schema_or_call_failure_rate": _ratio(schema_failures, analyzed_files),
        },
        "per_family": per_family,
        "cases": case_results,
    }


def _gate_score(cases: Iterable[Mapping[str, Any]], runs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    passed = 0
    results = []
    for case in cases:
        entries = list(runs.get(str(case["id"]), {}).get("findings", []) or [])
        by_file = {str(entry.get("file_path", "")).replace("\\", "/"): entry for entry in entries}
        evidence = [str(item).replace("\\", "/") for item in case.get("evidence_files", [])]
        admitted = [path for path in evidence if by_file.get(path, {}).get("suspected") != "未命中候选"]
        case_passed = bool(admitted)
        passed += int(case_passed)
        results.append({"id": case["id"], "passed": case_passed, "admitted_evidence_files": admitted})
    total = len(results)
    return {"summary": {"cases": total, "passed": passed, "recall": _ratio(passed, total)}, "cases": results}


def _aggregate_telemetry(runs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    telemetry = []
    for run in runs.values():
        for entry in run.get("findings", []):
            for stage in ("detection", "repair"):
                item = dict(entry.get(f"{stage}_model_telemetry", {}) or {})
                if item:
                    item["stage"] = stage
                    telemetry.append(item)
    wall_values = [_number(item.get("wall_duration_ms")) for item in telemetry]
    prompt_count = sum(int(item.get("prompt_eval_count", 0) or 0) for item in telemetry)
    prompt_ms = sum(_number(item.get("prompt_eval_duration_ms")) for item in telemetry)
    eval_count = sum(int(item.get("eval_count", 0) or 0) for item in telemetry)
    eval_ms = sum(_number(item.get("eval_duration_ms")) for item in telemetry)
    return {
        "calls": len(telemetry),
        "failed_calls": sum(1 for item in telemetry if item.get("ok") is False),
        "detection_calls": sum(1 for item in telemetry if item.get("stage") == "detection"),
        "repair_calls": sum(1 for item in telemetry if item.get("stage") == "repair"),
        "prompt_eval_count": prompt_count,
        "eval_count": eval_count,
        "prompt_tokens_per_second": _ratio(prompt_count, prompt_ms / 1000),
        "eval_tokens_per_second": _ratio(eval_count, eval_ms / 1000),
        "call_latency_p50_ms": _percentile(wall_values, 0.50),
        "call_latency_p95_ms": _percentile(wall_values, 0.95),
        "call_latency_max_ms": max(wall_values, default=0.0),
        "load_duration_ms": sum(_number(item.get("load_duration_ms")) for item in telemetry),
    }


def _patch_score(cases: Iterable[Mapping[str, Any]], runs: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    selected = [case for case in cases if case.get("patch_benchmark")]
    results = []
    for case in selected:
        entries = list(runs.get(str(case["id"]), {}).get("findings", []) or [])
        evidence_paths = {str(path).replace("\\", "/") for path in case.get("evidence_files", [])}
        evidence_entries = [entry for entry in entries if str(entry.get("file_path", "")).replace("\\", "/") in evidence_paths]
        generated = any(entry.get("original_code_snippet") and entry.get("fixed_code_snippet") for entry in evidence_entries)
        statuses = [str(entry.get("patch_verification", {}).get("status", "not_run")) for entry in evidence_entries]
        applicable = any(status in {"validated", "inconclusive", "failed"} for status in statuses)
        syntax_passed = any(
            entry.get("patch_verification", {}).get("syntax_check", {}).get("status") == "passed"
            for entry in evidence_entries
        )
        semantic_passed = any(
            checks
            and all(check.get("status") in {"passed", "not_available"} for check in checks)
            for entry in evidence_entries
            if (checks := entry.get("patch_verification", {}).get("semantic_checks", []))
        )
        validated = any(status == "validated" for status in statuses)
        results.append(
            {
                "id": case["id"],
                "generated": generated,
                "applicable": applicable,
                "syntax_passed": syntax_passed,
                "static_semantic_passed": semantic_passed,
                "isolated_static_validation_passed": validated,
                "verification_statuses": statuses,
            }
        )
    total = len(results)
    return {
        "summary": {
            "cases": total,
            "generated": sum(item["generated"] for item in results),
            "generation_rate": _ratio(sum(item["generated"] for item in results), total),
            "applicable": sum(item["applicable"] for item in results),
            "applicability_rate": _ratio(sum(item["applicable"] for item in results), total),
            "syntax_passed": sum(item["syntax_passed"] for item in results),
            "syntax_pass_rate": _ratio(sum(item["syntax_passed"] for item in results), total),
            "static_semantic_passed": sum(item["static_semantic_passed"] for item in results),
            "isolated_static_validation_passed": sum(item["isolated_static_validation_passed"] for item in results),
            "isolated_static_candidate_rate": _ratio(
                sum(item["isolated_static_validation_passed"] for item in results), total
            ),
            "functional_or_poc_validated": 0,
            "functional_or_poc_validation_rate": None,
        },
        "cases": results,
        "warning": "Static candidate rate is not patch success: it means exact application plus configured static checks only; no challenge code or PoC was executed.",
    }


def _format_pct(value: Any) -> str:
    return f"{_number(value) * 100:.1f}%"


def render_markdown(result: Mapping[str, Any]) -> str:
    lines = [
        "# AWDP 真实模型 / 硬件基准",
        "",
        f"> 生成时间（UTC）：`{result.get('generated_at_utc', '')}`",
        f"> 语料：`{result.get('corpus', {}).get('dataset', {}).get('name', '')}`",
        f"> 固定提交：`{result.get('corpus', {}).get('dataset', {}).get('commit', '')}`",
        "",
        "## 结果",
        "",
        "| 模型 | 后端 | 确认 F1 | 可操作 F1 | FPR | 输出 tok/s | P95 调用延迟 | 静态补丁候选率 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for model_result in result.get("models", []):
        confirmed = model_result.get("confirmed", {}).get("summary", {})
        actionable = model_result.get("actionable", {}).get("summary", {})
        telemetry = model_result.get("telemetry", {})
        patch = model_result.get("patches", {}).get("summary", {})
        resident = model_result.get("resident_model", {})
        lines.append(
            "| {model} | {backend} | {confirmed_f1} | {actionable_f1} | {fpr} | {tps:.2f} | {p95:.1f} s | {patch_rate} |".format(
                model=model_result.get("model", ""),
                backend=resident.get("processor", "unknown"),
                confirmed_f1=_format_pct(confirmed.get("f1", 0)),
                actionable_f1=_format_pct(actionable.get("f1", 0)),
                fpr=_format_pct(actionable.get("false_positive_rate", 0)),
                tps=_number(telemetry.get("eval_tokens_per_second")),
                p95=_number(telemetry.get("call_latency_p95_ms")) / 1000,
                patch_rate=_format_pct(patch.get("isolated_static_candidate_rate", 0)),
            )
        )
    gate = result.get("candidate_gate", {}).get("summary", {})
    lines.extend(
        [
            "",
            "## 候选门控",
            "",
            f"- 真实题目送入深度分析的召回率：`{_format_pct(gate.get('recall', 0))}`（{gate.get('passed', 0)}/{gate.get('cases', 0)}）。",
            "- 模型指标使用 `--deep-all` 测量模型条件能力；端到端部署效果还必须乘入候选门控损失。",
            "",
            "## 解释边界",
            "",
            "- `待人工复核` 在“可操作”指标中算召回，在“确认”指标中不算确认命中。",
            "- FPR 只使用清单中明确标注的负对照文件，不能外推为任意代码库误报率。",
            "- 静态补丁候选率只代表精确替换和静态/显式检查通过，不是补丁成功率；功能/PoC 成功率在本安全基准中记为未测量。",
            "- `size_vram` 来自 Ollama `/api/ps`；共享内存 iGPU 的该值不是独立物理显存容量。",
            "",
        ]
    )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    default_corpus = Path(__file__).resolve().parent / "data" / "real_model_corpus.json"
    parser = argparse.ArgumentParser(description="Run pinned real-CTF Ollama and hardware benchmarks without executing targets.")
    parser.add_argument("--corpus", default=str(default_corpus))
    parser.add_argument("--workspace", default=str(ROOT / "benchmarks" / ".external" / "real-corpus"))
    parser.add_argument("--output-dir", default=str(ROOT / "benchmarks" / ".results"))
    parser.add_argument("--prepare", action="store_true", help="Explicitly download the pinned public corpus and verify SHA-256.")
    parser.add_argument("--model", action="append", dest="models", help="Ollama model; repeat to compare models.")
    parser.add_argument("--case", action="append", dest="case_ids", help="Run one corpus case; repeat for a subset.")
    parser.add_argument("--endpoint", default="http://127.0.0.1:11434")
    parser.add_argument("--detection-tokens", type=int, default=256)
    parser.add_argument("--repair-tokens", type=int, default=384)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--case-timeout", type=int, default=600)
    parser.add_argument("--skip-patches", action="store_true")
    parser.add_argument("--patch-model", action="append", dest="patch_models")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    endpoint = _loopback_endpoint(args.endpoint)
    models = args.models or ["qwen2.5-coder:14b"]
    patch_models = set(args.patch_models or models[:1])
    corpus = load_corpus(args.corpus)
    try:
        cases = _select_cases(corpus, args.case_ids)
    except ValueError as exc:
        parser.error(str(exc))
    selected_corpus = {**corpus, "cases": cases}
    case_paths = prepare_corpus(selected_corpus, args.workspace, allow_download=args.prepare)
    output_root = Path(args.output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    gate_runs = {}
    for case in cases:
        case_id = str(case["id"])
        gate_runs[case_id] = _run_scanner(
            case_paths[case_id],
            output_root / "static-gate" / case_id,
            endpoint=endpoint,
            model=models[0],
            detection_tokens=max(32, args.detection_tokens),
            repair_tokens=max(32, args.repair_tokens),
            seed=max(0, args.seed),
            static_only=True,
            generate_repairs=False,
            timeout=max(30, args.case_timeout),
        )

    result: dict[str, Any] = {
        "schema_version": "awdp-real-model-benchmark-v1",
        "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "safety": {"target_code_executed": False, "poc_executed": False, "functional_tests_executed": False},
        "host": collect_host_info(),
        "corpus": {"dataset": corpus.get("dataset", {}), "cases": len(cases), "source_files": sum(len(case.get("files", [])) for case in cases)},
        "configuration": {
            "endpoint": endpoint,
            "models": models,
            "detection_tokens": max(32, args.detection_tokens),
            "repair_tokens": max(32, args.repair_tokens),
            "seed": max(0, args.seed),
            "deep_all": True,
            "case_ids": [str(case["id"]) for case in cases],
        },
        "candidate_gate": _gate_score(cases, gate_runs),
        "models": [],
    }

    for model in models:
        for loaded_model in models:
            _unload_model(endpoint, loaded_model)
        monitor = ResourceMonitor(endpoint, model)
        monitor.start()
        detection_runs = {}
        for case in cases:
            case_id = str(case["id"])
            detection_runs[case_id] = _run_scanner(
                case_paths[case_id],
                output_root / model.replace(":", "_") / "detection" / case_id,
                endpoint=endpoint,
                model=model,
                detection_tokens=max(32, args.detection_tokens),
                repair_tokens=max(32, args.repair_tokens),
                seed=max(0, args.seed),
                static_only=False,
                generate_repairs=False,
                timeout=max(30, args.case_timeout),
            )
        patch_runs = {}
        if not args.skip_patches and model in patch_models:
            for case in cases:
                if not case.get("patch_benchmark"):
                    continue
                case_id = str(case["id"])
                patch_runs[case_id] = _run_scanner(
                    case_paths[case_id],
                    output_root / model.replace(":", "_") / "patch" / case_id,
                    endpoint=endpoint,
                    model=model,
                    detection_tokens=max(32, args.detection_tokens),
                    repair_tokens=max(32, args.repair_tokens),
                    seed=max(0, args.seed),
                    static_only=False,
                    generate_repairs=True,
                    timeout=max(30, args.case_timeout),
                )
        resources = monitor.stop()
        resident = _resident_model(endpoint, model)
        metadata = _model_metadata(endpoint, model)
        combined_runs = {**detection_runs, **{f"patch:{key}": value for key, value in patch_runs.items()}}
        model_result = {
            "model": model,
            "metadata": metadata,
            "resident_model": resident,
            "resources": resources,
            "confirmed": _score_runs(cases, detection_runs, accepted_statuses=CONFIRMED),
            "actionable": _score_runs(cases, detection_runs, accepted_statuses=ACTIONABLE),
            "telemetry": _aggregate_telemetry(combined_runs),
            "patches": _patch_score(cases, patch_runs) if patch_runs else {"summary": {"cases": 0}},
        }
        result["models"].append(model_result)
        atomic_write_json(output_root / "benchmark-result.partial.json", result)
        _unload_model(endpoint, model)

    atomic_write_json(output_root / "benchmark-result.json", result)
    atomic_write_text(output_root / "benchmark-report.md", render_markdown(result))
    print(json.dumps({"candidate_gate": result["candidate_gate"]["summary"], "models": [{"model": item["model"], "confirmed": item["confirmed"]["summary"], "actionable": item["actionable"]["summary"], "patches": item["patches"]["summary"]} for item in result["models"]]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
