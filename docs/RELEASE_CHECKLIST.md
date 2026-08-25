# Release checklist

- [ ] Repository owner selects and adds an explicit software license. This is a legal decision and is intentionally not inferred by the refactor.
- [ ] Version in `pyproject.toml`, `awdp_pro_scanner.py`, and `awdp_scanner/__init__.py` matches the release tag.
- [ ] Ruff, pytest, deterministic benchmark, package build, CodeQL, and dependency audit pass.
- [ ] Benchmark changes include an explanation of corpus composition; small-fixture scores are not presented as real-world accuracy.
- [ ] Rebuild the vector database with the release embedding model and verify all recorded SHA-256 values.
- [ ] Inspect wheel and sdist contents for models, target code, reports, caches, credentials, and CTF artifacts.
- [ ] Review the generated CycloneDX SBOM and `SHA256SUMS`.
- [ ] Confirm the default model endpoint is loopback and remote access requires an explicit flag.
- [ ] Confirm no target test command is executed without explicit operator configuration.
- [ ] Create a signed `vX.Y.Z` tag only after all checks pass.
