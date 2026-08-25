from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable, Mapping

from .io import atomic_write_json


CACHE_SCHEMA_VERSION = "awdp-scan-cache-v1"


def project_fingerprint(files: Iterable[tuple[str, str]]) -> str:
    digest = hashlib.sha256()
    for path, content in sorted(files, key=lambda item: os.path.normcase(item[0])):
        digest.update(os.path.normcase(path).encode("utf-8", errors="surrogatepass"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(content.encode("utf-8", errors="surrogatepass")).digest())
        digest.update(b"\0")
    return digest.hexdigest()


class ScanCache:
    def __init__(self, directory: str | os.PathLike[str]):
        self.directory = Path(directory).expanduser().resolve()

    @staticmethod
    def make_key(
        *,
        file_path: str,
        content: str,
        project_digest: str,
        configuration: Mapping[str, Any],
    ) -> str:
        material = {
            "schema": CACHE_SCHEMA_VERSION,
            "file_path": os.path.normcase(file_path),
            "content_sha256": hashlib.sha256(content.encode("utf-8", errors="surrogatepass")).hexdigest(),
            "project_sha256": project_digest,
            "configuration": configuration,
        }
        encoded = json.dumps(material, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _path_for_key(self, key: str) -> Path:
        if not re_full_sha256(key):
            raise ValueError("cache key must be a lowercase SHA-256 digest")
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        cache_path = self._path_for_key(key)
        try:
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return None
        if not isinstance(payload, dict) or payload.get("schema_version") != CACHE_SCHEMA_VERSION:
            return None
        entry = payload.get("entry")
        return dict(entry) if isinstance(entry, dict) else None

    def put(self, key: str, entry: Mapping[str, Any]) -> str:
        cache_path = self._path_for_key(key)
        return atomic_write_json(
            cache_path,
            {"schema_version": CACHE_SCHEMA_VERSION, "key": key, "entry": dict(entry)},
        )


def re_full_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)
