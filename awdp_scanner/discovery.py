from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class DiscoveryPolicy:
    max_files: int = 10_000
    max_file_bytes: int = 2 * 1024 * 1024
    max_total_bytes: int = 128 * 1024 * 1024
    encodings: tuple[str, ...] = ("utf-8-sig", "gb18030")


@dataclass(frozen=True)
class DiscoveredSource:
    path: str
    relative_path: str
    content: str
    encoding: str
    size_bytes: int


@dataclass(frozen=True)
class DiscoveryIssue:
    path: str
    relative_path: str
    reason: str
    size_bytes: int = 0


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _decode_source(payload: bytes, encodings: Iterable[str]) -> tuple[str, str, str]:
    if b"\x00" in payload:
        return "", "", "NUL byte indicates binary or unsupported source"
    errors = []
    for encoding in encodings:
        try:
            return payload.decode(encoding, errors="strict"), encoding, ""
        except (UnicodeDecodeError, LookupError) as exc:
            errors.append(f"{encoding}: {exc}")
    return "", "", "source decoding failed without byte loss; " + " | ".join(errors)


def discover_sources(
    target_root: str,
    *,
    allowed_extensions: Iterable[str],
    ignored_directories: Iterable[str],
    policy: DiscoveryPolicy,
) -> tuple[list[DiscoveredSource], list[DiscoveryIssue], dict[str, object]]:
    root = Path(target_root).expanduser().resolve()
    extensions = {extension.lower() for extension in allowed_extensions}
    ignored = {directory.lower() for directory in ignored_directories}
    sources: list[DiscoveredSource] = []
    issues: list[DiscoveryIssue] = []
    total_bytes = 0
    eligible_seen = 0
    if not root.is_dir():
        raise NotADirectoryError(str(root))

    for current_root, directories, files in os.walk(root, followlinks=False):
        current = Path(current_root)
        kept_directories = []
        for directory in sorted(directories):
            path = current / directory
            if directory.lower() in ignored:
                continue
            if path.is_symlink():
                relative = path.relative_to(root).as_posix()
                issues.append(DiscoveryIssue(str(path), relative, "symlink directory was not followed"))
                continue
            kept_directories.append(directory)
        directories[:] = kept_directories

        for filename in sorted(files):
            lexical_path = current / filename
            if lexical_path.suffix.lower() not in extensions:
                continue
            eligible_seen += 1
            relative = lexical_path.relative_to(root).as_posix()
            if eligible_seen > policy.max_files:
                issues.append(DiscoveryIssue(str(lexical_path), relative, "run file-count budget exceeded"))
                continue
            if lexical_path.is_symlink():
                issues.append(DiscoveryIssue(str(lexical_path), relative, "symlink source file was rejected"))
                continue
            resolved = lexical_path.resolve()
            if not _inside(root, resolved):
                issues.append(DiscoveryIssue(str(lexical_path), relative, "resolved path escapes target root"))
                continue
            try:
                size = resolved.stat().st_size
            except OSError as exc:
                issues.append(DiscoveryIssue(str(lexical_path), relative, f"stat failed: {exc}"))
                continue
            if size > policy.max_file_bytes:
                issues.append(DiscoveryIssue(str(resolved), relative, "per-file byte budget exceeded", size))
                continue
            if total_bytes + size > policy.max_total_bytes:
                issues.append(DiscoveryIssue(str(resolved), relative, "run byte budget exceeded", size))
                continue
            try:
                payload = resolved.read_bytes()
            except OSError as exc:
                issues.append(DiscoveryIssue(str(resolved), relative, f"read failed: {exc}", size))
                continue
            content, encoding, decode_error = _decode_source(payload, policy.encodings)
            if decode_error:
                issues.append(DiscoveryIssue(str(resolved), relative, decode_error, size))
                continue
            total_bytes += size
            sources.append(DiscoveredSource(str(resolved), relative, content, encoding, size))

    stats = {
        "policy": asdict(policy),
        "eligible_files_seen": eligible_seen,
        "analyzable_files": len(sources),
        "issues": len(issues),
        "analyzable_bytes": total_bytes,
    }
    return sources, issues, stats
