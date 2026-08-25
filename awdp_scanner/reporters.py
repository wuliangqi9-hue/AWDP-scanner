from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable, Mapping

from .io import atomic_write_json
from .models import FindingDisposition, FindingRecord, RunSummary


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def write_findings_json(
    path: str,
    *,
    run_id: str,
    target: str,
    entries: list[Mapping[str, Any]],
    root_cause_groups: list[Mapping[str, Any]],
) -> str:
    payload = {
        "schema_version": "awdp-findings-v1",
        "run_id": run_id,
        "target": str(Path(target).resolve()),
        "summary": RunSummary.from_entries(entries).to_dict(),
        "root_cause_groups": root_cause_groups,
        "findings": entries,
    }
    return atomic_write_json(path, payload)


def _rule_id(record: FindingRecord) -> str:
    raw = record.raw
    family = str(raw.get("root_cause_family", "") or record.vuln_type or "manual-review").lower()
    normalized = re.sub(r"[^a-z0-9._-]+", "-", family).strip("-")
    return f"AWDP.{normalized or 'manual-review'}"


def _sarif_rule(record: FindingRecord) -> dict[str, Any]:
    rule_id = _rule_id(record)
    title = record.vuln_type or "Manual security review"
    return {
        "id": rule_id,
        "name": re.sub(r"[^A-Za-z0-9_]+", "_", title).strip("_") or "ManualReview",
        "shortDescription": {"text": title},
        "help": {"text": "AWDP Scanner defensive source review finding."},
        "properties": {"security-severity": f"{max(0.0, min(10.0, record.confidence * 10)):.1f}"},
    }


def _sarif_result(record: FindingRecord) -> dict[str, Any]:
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": record.file_path.replace("\\", "/")},
        }
    }
    if record.region.start_line:
        location["physicalLocation"]["region"] = {
            "startLine": record.region.start_line,
            "endLine": record.region.end_line or record.region.start_line,
        }
    result = {
        "ruleId": _rule_id(record),
        "level": "error" if record.disposition is FindingDisposition.VULNERABLE else "warning",
        "message": {"text": record.reason or record.vuln_type or "Security review required."},
        "locations": [location],
        "properties": {
            "disposition": record.disposition.value,
            "confidence": record.confidence,
            "rootCauseGroup": str(record.raw.get("root_cause_group_id", "") or ""),
            "detectionBasis": str(record.raw.get("detection_basis", "") or ""),
        },
    }
    fingerprint = str(record.raw.get("root_cause_fingerprint", "") or "")
    if fingerprint:
        result["partialFingerprints"] = {"awdpRootCauseFingerprint": fingerprint}
    return result


def build_sarif(entries: Iterable[Mapping[str, Any]], scanner_version: str) -> dict[str, Any]:
    records = [FindingRecord.from_mapping(entry) for entry in entries]
    actionable = [
        record
        for record in records
        if record.disposition in {FindingDisposition.VULNERABLE, FindingDisposition.NEEDS_MANUAL_REVIEW}
    ]
    rules_by_id = {_rule_id(record): _sarif_rule(record) for record in actionable}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AWDP Scanner",
                        "version": scanner_version,
                        "informationUri": "https://github.com/wuliangqi9-hue/AWDP-scanner",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": [_sarif_result(record) for record in actionable],
            }
        ],
    }


def write_sarif(path: str, entries: Iterable[Mapping[str, Any]], scanner_version: str) -> str:
    return atomic_write_json(path, build_sarif(entries, scanner_version))
