from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


class FindingDisposition(str, Enum):
    VULNERABLE = "是"
    NEEDS_MANUAL_REVIEW = "待人工复核"
    SAFE = "否"
    NO_CANDIDATE = "未命中候选"
    NOT_ANALYZED = "未分析"

    @classmethod
    def parse(cls, value: Any) -> FindingDisposition:
        try:
            return cls(str(value or "未分析"))
        except ValueError:
            return cls.NOT_ANALYZED


@dataclass(frozen=True)
class SourceRegion:
    start_line: int = 0
    end_line: int = 0

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SourceRegion:
        start = max(0, int(value.get("start_line", 0) or 0))
        end = max(start, int(value.get("end_line", 0) or 0)) if start else 0
        return cls(start_line=start, end_line=end)


@dataclass(frozen=True)
class FindingRecord:
    file_path: str
    disposition: FindingDisposition
    vuln_type: str
    reason: str
    confidence: float
    region: SourceRegion
    raw: Mapping[str, Any]

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> FindingRecord:
        confidence = value.get("confidence", 0.0)
        try:
            confidence = max(0.0, min(1.0, float(confidence or 0.0)))
        except (TypeError, ValueError):
            confidence = 0.0
        return cls(
            file_path=str(value.get("file_path", "") or ""),
            disposition=FindingDisposition.parse(value.get("suspected")),
            vuln_type=str(value.get("vuln_type", "") or ""),
            reason=str(value.get("reason", "") or value.get("note", "") or ""),
            confidence=confidence,
            region=SourceRegion.from_mapping(value),
            raw=value,
        )


@dataclass(frozen=True)
class RunSummary:
    files_total: int
    vulnerable: int
    needs_manual_review: int
    safe: int
    no_candidate: int
    not_analyzed: int

    @classmethod
    def from_entries(cls, entries: Iterable[Mapping[str, Any]]) -> RunSummary:
        records = [FindingRecord.from_mapping(entry) for entry in entries]

        def count(status: FindingDisposition) -> int:
            return sum(record.disposition is status for record in records)

        return cls(
            files_total=len(records),
            vulnerable=count(FindingDisposition.VULNERABLE),
            needs_manual_review=count(FindingDisposition.NEEDS_MANUAL_REVIEW),
            safe=count(FindingDisposition.SAFE),
            no_candidate=count(FindingDisposition.NO_CANDIDATE),
            not_analyzed=count(FindingDisposition.NOT_ANALYZED),
        )

    def to_dict(self) -> dict[str, int]:
        return {
            "files_total": self.files_total,
            "vulnerable": self.vulnerable,
            "needs_manual_review": self.needs_manual_review,
            "safe": self.safe,
            "no_candidate": self.no_candidate,
            "not_analyzed": self.not_analyzed,
        }
