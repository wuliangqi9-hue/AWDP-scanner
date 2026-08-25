import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_text(path: str | os.PathLike[str], content: str) -> str:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=".awdp-",
        suffix=".tmp",
        dir=str(destination.parent),
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="\n") as output_file:
            output_file.write(content)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.replace(temporary_path, destination)
    except Exception:
        try:
            os.unlink(temporary_path)
        except OSError:
            pass
        raise
    return str(destination)


def atomic_write_json(path: str | os.PathLike[str], payload: Any) -> str:
    return atomic_write_text(path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
