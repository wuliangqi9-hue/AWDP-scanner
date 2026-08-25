# Architecture

## Pipeline

```text
Discovery
  -> lexical candidates and language policy
  -> Python project AST / symbols / imports / call graph
  -> fixed-point interprocedural taint summaries
  -> source-to-sink slices
  -> local LLM evidence decision (strict JSON Schema)
  -> claimed-API grounding and semantic-family reconciliation
  -> local hybrid RAG repair constraints
  -> candidate patch
  -> isolated exact-apply / syntax / Python symbol-delta / explicit regression checks
  -> Markdown + JSON + SARIF + run manifest
```

## Module boundaries

- `awdp_pro_scanner.py`: compatibility façade and orchestration while legacy language rules are progressively migrated.
- `awdp_scanner.analysis`: parser-backed repository analysis. The Python backend resolves imports, builds call edges, computes function summaries to a fixed point, substitutes actual arguments for formal parameters, and emits traceable slices.
- `awdp_scanner.models`: typed finding disposition, source region, finding record, and run summary contracts.
- `awdp_scanner.reporters`: versioned JSON and SARIF 2.1.0 serialization.
- `awdp_scanner.cache`: project-aware, content-addressed cache. Any project file, prompt, model, RAG corpus, or relevant policy change invalidates cached entries conservatively.
- `awdp_scanner.patching`: exact one-match edits in a temporary project copy, including Python syntax and newly introduced undefined-symbol checks; no in-place application API exists.
- `awdp_scanner.rag`: metadata parsing support, contextual chunks, hybrid reranking, diversity, and model/corpus hashing.
- `awdp_scanner.benchmark`: deterministic accuracy and latency regression gates.
- `awdp_scanner.model_benchmark`: pinned real-CTF Ollama/hardware measurements with native token timing, resource sampling and explicit non-execution boundaries.

## Required invariants

1. `no_candidate`, `not_analyzed`, and `safe` are distinct states.
2. Parser, model, schema, network, RAG, cache, or verification failure never becomes `safe`.
3. RAG text cannot create a vulnerability finding; it is repair-only by default.
4. A model `safe` response cannot suppress a confirmed static source-to-sink path.
5. A model cannot confirm a high-signal API claim when that API is absent from the target file; static/model family conflicts become manual review.
6. Remote model access requires an explicit CLI flag.
7. Embedding loading never falls back from local-only to download-capable behavior.
8. Vector database replacement occurs only after a complete staged build and metadata write.
9. Candidate patches never mutate the target tree during verification.
10. Target tests execute only when the operator provides an explicit command, with `shell=False`.
11. Every run has non-overwriting, atomically written evidence artifacts.

## Static-analysis model

The Python backend is flow-sensitive within a simplified function body and context-insensitive across calls. It tracks request/process sources through variables, receiver methods, returns and formal/actual parameter substitution. It models selected high-value sinks: shell execution, dynamic code execution, unsafe deserialization, SQL/NoSQL execution, outbound requests, template-string rendering, file paths, dynamic privilege-field assignment and authentication-boundary comparisons.

Branch environments are unioned conservatively. Top-level, class and nested decorator functions plus imported symbols are resolved when unambiguous. Summaries iterate to a fixed point, enabling wrapper chains and cross-file propagation. Bottle/Flask route parameters are explicit request sources. Deployment-only `sys.argv`/environment flows are retained separately and do not outrank remote AWD inputs. Each flow retains sources, source scope, sink, call chain, trace locations and slice lines.

This is not a complete code property graph. Dynamic imports, reflection, descriptor/metaclass behavior, framework dependency injection, native extensions and path feasibility remain future work and require human review.

## Evidence and confidence

Evidence is stronger than model confidence. Current confidence values are retained for compatibility but are not calibrated probabilities. Reports should be interpreted in this order:

1. exact source/sink spans and static path;
2. deterministic hard rules and syntax results;
3. model evidence judgment;
4. RAG repair guidance;
5. isolated patch checks.
