# Contributing

Use Python 3.10 or newer. Install the core development environment with:

```bash
python -m pip install -e ".[dev]"
```

Before opening a pull request, run:

```bash
ruff check .
python -m pytest -q
awdp-benchmark --corpus benchmarks/corpus.json
python -m build
```

Every detector change must add at least one positive and one negative regression case. A finding must not be labelled safe merely because a parser, model, knowledge base, or external tool failed. Do not add attack automation, flag extraction, persistence, destructive actions, or remote model calls enabled by default.

Generated patches must remain suggestions until they pass isolated verification. Tests from an audited target are untrusted code and must never run implicitly.
