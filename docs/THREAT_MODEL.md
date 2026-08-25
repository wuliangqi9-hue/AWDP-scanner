# Threat model

## Protected assets

- Audited source code, credentials, CTF flags and challenge artifacts.
- Integrity and availability of the target service tree.
- Integrity of findings, cache entries, vector data and patch evidence.
- Operator workstation credentials, network access and execution privileges.

## Untrusted inputs

- Every file, filename, symlink, archive, build script and test in the target tree.
- LLM responses, including structured output and generated code.
- Knowledge documents and persisted vector database contents.
- Environment variables, proxy configuration and remote HTTP responses.
- Cache files and previously generated reports.

## Primary threats and controls

| Threat | Control |
|---|---|
| Source exfiltration to a remote model | Loopback-only default, explicit remote flag, proxy-disabled session, no redirects |
| Runtime embedding download | Existing local directory plus `local_files_only`; no compatibility fallback |
| Model output injection or malformed JSON | JSON Schema request and strict field/type/enum validation |
| Fluent but invented model evidence | Claimed high-signal APIs must exist in the target file; unsupported claims are cleared and downgraded |
| False-safe caused by tool failure | Separate `not_analyzed`/`no_candidate`; fail-closed manual review |
| Cross-function false negative | Python call graph, fixed-point summaries, taint propagation and safe override |
| Patch corrupts service | Exact single match, temporary copy, syntax/new-symbol/regression ladder, no in-place mutation |
| Path escape during patching | Resolved root containment and symlink rejection |
| Old vector database loss | Staged build and rollback-capable directory swap |
| Stale or mismatched RAG | Strategy, label schema, corpus and embedding SHA-256 checks |
| Cache poisoning/staleness | SHA-256 key validation, schema version, project/config/model/prompt/RAG inputs |
| Target test executes malicious code | Never automatic; explicit operator command; `shell=False`; external sandbox required |

## Residual risk

The scanner itself is not an OS sandbox. Static language tools may contain parser vulnerabilities, and explicitly requested target tests execute code. Run untrusted targets inside a disposable low-privilege VM/container with no secrets, mounted read-only where possible, and with network egress blocked externally.

Loopback restriction protects against accidental remote exfiltration, not a malicious local service. A compromised local Ollama, embedding model, Python environment or dependency can still access inputs. Verify packages, model files, SBOM and host integrity before an offline competition.

The analysis is incomplete by design. Unsupported semantics must remain reviewable rather than silently safe.
