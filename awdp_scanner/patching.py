from __future__ import annotations

import ast
import builtins
import difflib
import hashlib
import os
import shutil
import subprocess
import tempfile
import textwrap
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Sequence

from .io import atomic_write_text


@dataclass(frozen=True)
class CheckResult:
    status: str
    tool: str
    detail: str


@dataclass
class PatchVerificationResult:
    status: str
    reason: str
    relative_file: str
    syntax_check: CheckResult
    semantic_checks: list[CheckResult] = field(default_factory=list)
    test_checks: list[CheckResult] = field(default_factory=list)
    diff: str = ""
    diff_sha256: str = ""
    source_unchanged: bool = True

    def to_dict(self, include_diff: bool = False) -> dict[str, object]:
        payload = asdict(self)
        if not include_diff:
            payload.pop("diff", None)
        return payload


def _inside(root: Path, candidate: Path) -> bool:
    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _run_static_syntax_check(file_path: Path, timeout: int) -> CheckResult:
    suffix = file_path.suffix.lower()
    if suffix == ".py":
        try:
            ast.parse(file_path.read_text(encoding="utf-8"), filename=str(file_path))
        except (SyntaxError, UnicodeError, OSError) as exc:
            return CheckResult("failed", "python-ast", str(exc))
        return CheckResult("passed", "python-ast", "AST parse passed")

    command_by_suffix = {
        ".php": (["php", "-l", str(file_path)], "php-lint"),
        ".js": (["node", "--check", str(file_path)], "node-check"),
        ".go": (["gofmt", "-d", str(file_path)], "gofmt-parse"),
    }
    command_and_tool = command_by_suffix.get(suffix)
    if command_and_tool is None:
        return CheckResult("not_available", "", f"no static parser configured for {suffix or 'extensionless file'}")
    command, tool = command_and_tool
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError:
        return CheckResult("not_available", tool, f"{command[0]} is not installed")
    except subprocess.TimeoutExpired:
        return CheckResult("failed", tool, f"syntax check exceeded {timeout}s")
    output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()
    if completed.returncode != 0:
        return CheckResult("failed", tool, output[:1000] or f"exit code {completed.returncode}")
    return CheckResult("passed", tool, output[:1000] or "syntax check passed")


def _parse_python_fragment(fragment: str) -> ast.Module | None:
    try:
        return ast.parse(textwrap.dedent(fragment))
    except (SyntaxError, ValueError):
        return None


def _loaded_python_names(tree: ast.AST) -> set[str]:
    return {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
    }


def _bound_python_names(tree: ast.AST) -> set[str]:
    names = {
        node.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Param))
    }
    names.update(node.arg for node in ast.walk(tree) if isinstance(node, ast.arg))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Import):
            names.update(alias.asname or alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in node.names if alias.name != "*")
        elif isinstance(node, ast.ExceptHandler) and isinstance(node.name, str):
            names.add(node.name)
    return names


def _run_python_symbol_check(
    original_snippet: str,
    replacement_snippet: str,
    patched_content: str,
) -> CheckResult:
    original_tree = _parse_python_fragment(original_snippet)
    replacement_tree = _parse_python_fragment(replacement_snippet)
    try:
        patched_tree = ast.parse(patched_content)
    except (SyntaxError, ValueError):
        return CheckResult("not_run", "python-symbols", "syntax validation must pass first")
    if original_tree is None or replacement_tree is None:
        return CheckResult(
            "not_available",
            "python-symbols",
            "snippets are not independently parseable; undefined-symbol delta was not evaluated",
        )

    newly_loaded = _loaded_python_names(replacement_tree) - _loaded_python_names(original_tree)
    available = _bound_python_names(patched_tree) | set(dir(builtins))
    undefined = sorted(newly_loaded - available)
    if undefined:
        return CheckResult(
            "failed",
            "python-symbols",
            "replacement introduces names with no definition or import in the patched module: "
            + ", ".join(undefined),
        )
    return CheckResult(
        "passed",
        "python-symbols",
        "replacement introduces no statically undefined loaded names",
    )


def _sanitized_test_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for variable in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        environment.pop(variable, None)
    environment.update(
        {
            "NO_PROXY": "*",
            "no_proxy": "*",
            "HF_HUB_OFFLINE": "1",
            "TRANSFORMERS_OFFLINE": "1",
            "PIP_NO_INDEX": "1",
        }
    )
    return environment


def _run_explicit_tests(
    workspace: Path,
    commands: Sequence[Sequence[str]],
    timeout: int,
) -> list[CheckResult]:
    results = []
    for command in commands:
        normalized = [str(part) for part in command if str(part)]
        if not normalized:
            continue
        try:
            completed = subprocess.run(
                normalized,
                cwd=workspace,
                env=_sanitized_test_environment(),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
        except FileNotFoundError:
            results.append(CheckResult("not_available", normalized[0], "test executable is not installed"))
            continue
        except subprocess.TimeoutExpired:
            results.append(CheckResult("failed", normalized[0], f"test exceeded {timeout}s"))
            continue
        output = ((completed.stdout or "") + "\n" + (completed.stderr or "")).strip()[:2000]
        status = "passed" if completed.returncode == 0 else "failed"
        results.append(CheckResult(status, normalized[0], output or f"exit code {completed.returncode}"))
    return results


def verify_patch_in_isolated_copy(
    target_root: str,
    relative_file: str,
    original_snippet: str,
    replacement_snippet: str,
    *,
    test_commands: Sequence[Sequence[str]] = (),
    timeout: int = 30,
) -> PatchVerificationResult:
    root = Path(target_root).expanduser().resolve()
    lexical_source_file = root / relative_file
    source_file = lexical_source_file.resolve()
    unavailable = CheckResult("not_run", "", "patch was not installed")
    if not root.is_dir() or not _inside(root, source_file):
        return PatchVerificationResult("rejected", "target path escapes scan root", relative_file, unavailable)
    if lexical_source_file.is_symlink() or not source_file.is_file():
        return PatchVerificationResult("rejected", "target must be a regular non-symlink file", relative_file, unavailable)
    if not original_snippet or not replacement_snippet:
        return PatchVerificationResult("rejected", "both original and replacement snippets are required", relative_file, unavailable)

    try:
        original_content = source_file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        return PatchVerificationResult("rejected", f"cannot read target: {exc}", relative_file, unavailable)
    occurrence_count = original_content.count(original_snippet)
    if occurrence_count != 1:
        return PatchVerificationResult(
            "rejected",
            f"exact original snippet must occur once; observed {occurrence_count}",
            relative_file,
            unavailable,
        )
    source_digest = hashlib.sha256(source_file.read_bytes()).hexdigest()
    patched_content = original_content.replace(original_snippet, replacement_snippet, 1)
    diff = "".join(
        difflib.unified_diff(
            original_content.splitlines(keepends=True),
            patched_content.splitlines(keepends=True),
            fromfile=f"a/{relative_file.replace(os.sep, '/')}",
            tofile=f"b/{relative_file.replace(os.sep, '/')}",
        )
    )

    with tempfile.TemporaryDirectory(prefix="awdp-patch-") as temporary_directory:
        workspace = Path(temporary_directory) / "workspace"
        shutil.copytree(root, workspace, symlinks=True)
        cloned_file = workspace / source_file.relative_to(root)
        atomic_write_text(cloned_file, patched_content)
        syntax_check = _run_static_syntax_check(cloned_file, timeout)
        semantic_checks = []
        if syntax_check.status == "passed" and cloned_file.suffix.lower() == ".py":
            semantic_checks.append(
                _run_python_symbol_check(original_snippet, replacement_snippet, patched_content)
            )
        test_checks = []
        semantics_failed = any(check.status == "failed" for check in semantic_checks)
        if syntax_check.status in {"passed", "not_available"} and not semantics_failed and test_commands:
            test_checks = _run_explicit_tests(workspace, test_commands, timeout)

    source_unchanged = hashlib.sha256(source_file.read_bytes()).hexdigest() == source_digest
    semantics_failed = any(check.status == "failed" for check in semantic_checks)
    tests_failed = any(check.status == "failed" for check in test_checks)
    if not source_unchanged:
        status = "failed"
        reason = "source tree changed during isolated verification"
    elif syntax_check.status == "failed":
        status = "failed"
        reason = "patched file failed syntax validation"
    elif semantics_failed:
        status = "failed"
        reason = "patched file introduced a statically undefined Python symbol"
    elif tests_failed:
        status = "failed"
        reason = "explicit regression command failed"
    elif syntax_check.status == "not_available" and not test_checks:
        status = "inconclusive"
        reason = "patch applied in isolation, but no parser or explicit tests were available"
    else:
        status = "validated"
        reason = "patch applied only to an isolated copy and passed configured checks"
    return PatchVerificationResult(
        status=status,
        reason=reason,
        relative_file=relative_file,
        syntax_check=syntax_check,
        semantic_checks=semantic_checks,
        test_checks=test_checks,
        diff=diff,
        diff_sha256=hashlib.sha256(diff.encode("utf-8")).hexdigest(),
        source_unchanged=source_unchanged,
    )
