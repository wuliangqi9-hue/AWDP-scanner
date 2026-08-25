# Research foundations and design consequences

This refactor follows a neuro-symbolic direction: program analysis owns facts and paths; an LLM may infer missing specifications, judge contextual evidence or propose repairs; verification determines whether a repair is trustworthy.

## Detection and repository reasoning

- [IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities](https://arxiv.org/abs/2405.17238) combines LLM-inferred source/sink specifications and path classification with CodeQL repository taint analysis. Design consequence: do not ask an LLM to invent a path that a static engine can establish.
- [RepoAudit](https://arxiv.org/abs/2501.18160) explores repositories along call/data flow and emphasizes validation and caching. Design consequence: preserve call-chain evidence and use content-addressed reuse.
- [LLMxCPG](https://arxiv.org/abs/2507.16585) uses code-property-graph slicing to reduce context while retaining vulnerability-relevant structure. Design consequence: graph/semantic slices should replace arbitrary head/tail truncation.
- [SemTaint](https://arxiv.org/abs/2601.10865) is a 2026 preprint on LLM-assisted JavaScript source/sink/call-edge specification combined with static analysis. Its early status warrants caution, but it reinforces the separation between specification inference and path execution.
- [BugLens](https://arxiv.org/abs/2504.11711) reports that structured LLM post-refinement raised precision from 0.10 to 0.72 over its static-analysis inputs and helped find four previously unknown vulnerabilities. Design consequence: validate model evidence against concrete code identifiers and downgrade invented APIs instead of accepting fluent explanations.
- [QLPro](https://arxiv.org/abs/2506.23644) combines static analysis with LLM reasoning and reports 41/62 JavaTest vulnerabilities versus 24/62 for its CodeQL comparison. The arXiv record also carries an author warning about experimental-data errors. Design consequence: use the architecture as a hypothesis, but reproduce locally and preserve caveats rather than importing headline numbers as guarantees.
- [A Survey on Large Language Models for Code Analysis](https://arxiv.org/abs/2502.07049) highlights repository context, language diversity and evaluation limitations. Design consequence: a Python AST front end plus regexes is not a cross-language CPG; language parity needs explicit front ends and per-language evaluation.

## Evaluation discipline

- [PrimeVul](https://arxiv.org/abs/2403.18624) shows how duplication, leakage and noisy labels can inflate vulnerability-detection results. Design consequence: use time-aware, deduplicated vulnerable/fixed pairs and never present a small fixture suite as real-world accuracy.
- The bundled `benchmarks/corpus.json` is only a deterministic regression gate. It reports precision, recall, F1, false-positive rate, per-family metrics and latency, but does not claim external validity.
- The pinned `benchmarks/real_corpus.json` adds 8 public CTF cases and explicit negative files. It is still a small convenience sample, not a statistically representative benchmark; scores must always name the model digest, quantization, prompt version, backend and hardware.

## Repair verification

- [PatchEval](https://arxiv.org/abs/2511.11019) evaluates security and functionality because a patch can close a vulnerability while breaking behavior. Design consequence: syntax-only results remain limited evidence.
- [VulnRepairEval](https://arxiv.org/abs/2509.03331) uses real proof-of-concept differential validation and reports that successful vulnerability repair remains difficult. Design consequence: label model output as a candidate until isolated security and functional regressions pass.
- [PVBench](https://arxiv.org/abs/2603.06858) reports that more than 40% of patches passing basic tests fail its stricter PoC+ validation. Design consequence: never rename syntax/static applicability as “patch success”; require exploit-regression and intended-behavior checks in an OS-level sandbox before promotion.

## RAG and structured output

- Ollama's [structured outputs documentation](https://docs.ollama.com/capabilities/structured-outputs) supports JSON Schema in the `format` field. Design consequence: reject missing, extra or ill-typed output instead of regex-recovering a confident result.
- OWASP's [SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html) recommends layered application/network controls and careful redirect/DNS handling. Design consequence: repair knowledge must include redirect, all-address and egress controls rather than string blacklists.

Preprints and reported benchmark values evolve. The repository therefore records the design implication, not a promise that reproducing a paper architecture automatically reproduces its result.
