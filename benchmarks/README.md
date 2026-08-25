# Benchmark corpora

## Deterministic regression gate

`corpus.json` is a small deterministic regression set for the parser-backed Python analysis. It includes direct and cross-file vulnerable flows plus negative controls for parameterized SQL, argument-list subprocess execution and ordinary code.

Run it with:

```bash
awdp-benchmark --corpus benchmarks/corpus.json --output benchmark-result.json
```

Add both a positive and a semantically adjacent negative case for detector changes. Do not optimize production thresholds solely against this corpus, and do not describe its score as real-world accuracy.

## Pinned real-CTF model/hardware benchmark

`real_corpus.json` pins 8 challenges / 14 source files from Probely CTF Challenges at commit `4f5d17a20ac16eebda41144dc33f5f3b7c02cf68`. Every downloaded file has an expected SHA-256. Network access occurs only with the explicit `--prepare` flag, and the benchmark never executes challenge code, PoCs or target tests.

```bash
awdp-model-benchmark --prepare \
  --model qwen2.5-coder:14b \
  --model codellama:latest \
  --output-dir benchmarks/.results/comparison
```

For a targeted prompt or analyzer experiment:

```bash
awdp-model-benchmark \
  --model qwen2.5-coder:14b \
  --case probely-get-the-list \
  --skip-patches \
  --output-dir benchmarks/.results/nosql-experiment
```

The report separates confirmed from actionable/manual-review metrics and records native Ollama token/duration telemetry, host memory and `size_vram`. The patch metric is deliberately named a static candidate rate: exact application and static validation are not functional or security success.
