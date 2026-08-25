# Real Ollama model and hardware benchmark — 2026-08-25

This report records one machine, two locally installed model artifacts and a pinned public CTF subset. It is a reproducible engineering measurement, not a claim of general vulnerability-detection accuracy.

## Host and artifacts

| Item | Measured value |
|---|---|
| Computer | Lenovo 21RU0000CD |
| CPU | Intel Core Ultra 9 285H, 16 cores / 16 logical processors |
| Memory | 33,812,238,336 bytes (about 32 GiB installed) |
| GPU | Intel Arc 140T integrated GPU, driver 32.0.101.8826 |
| OS / Python | Windows 10.0.26200 / Python 3.11.9 |
| Ollama | 0.32.15 |
| Qwen artifact | `qwen2.5-coder:14b`, 14.8B, Q4_K_M, digest `9ec8897f747e…` |
| CodeLlama artifact | `codellama:latest`, 7B, Q4_0, digest `8fdf8f752f6e…` |

The Windows adapter label contains “16GB”, but this integrated GPU uses shared system memory. It must not be interpreted as 16 GiB of dedicated VRAM.

## CPU detection baseline

Corpus: 8 Probely CTF challenge projects, 14 source files, 4 explicit negative-control files, repository commit `4f5d17a20ac16eebda41144dc33f5f3b7c02cf68`. Seed 42, context 4096, detection budget 256 tokens, `--deep-all`, source/PoC/tests never executed.

| Model | Precision | Recall | F1 | Negative-control FPR | Output tok/s | P95 call latency |
|---|---:|---:|---:|---:|---:|---:|
| Qwen2.5-Coder 14B Q4_K_M | 83.3% | 55.6% | 66.7% | 0.0% (0/4) | 4.87 | 101.0 s |
| CodeLlama 7B Q4_0 | 30.0% | 66.7% | 41.4% | 100.0% (4/4) | 9.49 | 56.3 s |

Qwen was slower but substantially more precise. CodeLlama frequently labeled benign files and invented absent APIs such as `subprocess`; it is not suitable as the final confirmation model under this configuration. The Qwen baseline missed the Mongo object-injection case and three authorization/crypto-logic cases, which motivated the security-invariant prompt, evidence-grounding guard and Bottle→Mongo AST flow added after the baseline.

An offline replay of the saved CodeLlama outputs against the final evidence-grounding rules caught 8 unsupported high-signal API claims, including four invented `subprocess` claims and database/command claims in files with no corresponding API. This is a guard-coverage observation, not a rescored model benchmark: a clean post-change CodeLlama run would still be required for comparable final precision/recall.

Peak measurements are host-wide samples, not isolated energy or memory attribution. Qwen reached about 13.80 GB peak `llama-server` RSS and 13.80 GB host-used-memory delta; CodeLlama reached about 14.50 GB RSS and 14.85 GB host-used-memory delta. Both CPU runs reported `size_vram=0`.

## Post-refactor targeted validation

The four Qwen baseline misses were rerun with the security-invariant prompt and hybrid analyzer. The final static gate assigns the intended family to all four: Rolodex `auth`, Get The List `sqli`, From User To Admin `auth`, and Read Email `auth`.

The measured four-case Qwen run confirmed 2/4 families directly and recovered 4/4 in the actionable/manual-review view (confirmed precision 100%, recall 50%, F1 66.7%; actionable precision 80%, recall 100%, F1 88.9%). It also exposed two remaining costs: one delegated-auth source file was falsely confirmed, and a deployment-configuration file read appeared as an extra path family. The final `python-ast-v2` pass now separates `sys.argv`/environment configuration flows and suppresses that path-family cross-contamination; an isolated final Rolodex rerun measured actionable precision/recall/F1 of 100% for that case, while correctly retaining it as manual review rather than model-confirmed.

These targeted numbers are diagnostic and intentionally not merged into the original 8-case baseline. The improvement is mainly hybrid-system recall, not proof that Qwen itself became a better calibrated detector. A fresh full-corpus run is required before publishing a replacement headline score.

## Intel Arc Vulkan experiment

A separate Ollama server was started on loopback port 11435 with `OLLAMA_IGPU_ENABLE=1` and `OLLAMA_VULKAN=1`. Ollama discovered the Arc device and reported non-zero `size_vram`, so the original zero value was a CPU-backend result rather than a missing GPU driver.

| Model | CPU output tok/s | Vulkan output tok/s | Vulkan `size_vram` |
|---|---:|---:|---:|
| Qwen2.5-Coder 14B | 4.78 | 4.55 | 9,459,613,039 bytes |
| CodeLlama 7B | 13.38 | 8.43 | 5,987,494,788 bytes |

On this shared-memory iGPU, Vulkan was slower in both short generation probes. CPU is therefore the recommended competition baseline for these two artifacts on this laptop; non-zero `size_vram` is not itself evidence of better performance.

To reproduce without disturbing the default Ollama service, open a separate PowerShell session:

```powershell
$env:OLLAMA_HOST = "127.0.0.1:11435"
$env:OLLAMA_IGPU_ENABLE = "1"
$env:OLLAMA_VULKAN = "1"
ollama serve
```

Then point the benchmark at `--endpoint http://127.0.0.1:11435`. Ollama documents Vulkan as an experimental GPU path and documents GPU discovery/selection in its official [GPU guide](https://github.com/ollama/ollama/blob/main/docs/gpu.mdx). Ordinary sustained inference should not physically damage a correctly cooled computer, but it increases temperature, fan use and battery/power draw; stop if the system throttles, becomes unstable or exceeds the manufacturer’s thermal envelope.

## Patch metric correction

The baseline Qwen run generated replacement pairs for 3/4 selected cases and only one applied exactly and passed syntax. That one changed `pickle.loads` to `json.loads` without adding `import json` or preserving the application protocol, so even “25%” was not a functional success rate. The benchmark now reports an isolated static candidate rate, includes a newly introduced Python-symbol check, and records functional/PoC validation as not measured.

## Reproduction

```bash
awdp-model-benchmark --prepare \
  --model qwen2.5-coder:14b \
  --output-dir benchmarks/.results/cpu-qwen14b

awdp-model-benchmark \
  --model codellama:latest \
  --skip-patches \
  --output-dir benchmarks/.results/cpu-codellama7b
```

Raw JSON and Markdown artifacts are written under the chosen output directory. For a defensible comparison, retain the model digest, quantization, prompt/strategy versions, seed, corpus commit, hardware/driver and Ollama version together.
