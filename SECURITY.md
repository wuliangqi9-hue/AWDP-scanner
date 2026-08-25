# Security policy

## Supported versions

Security fixes are applied to the latest release and the `main` branch.

## Reporting a vulnerability

Do not include exploit payloads, CTF flags, credentials, or vulnerable target archives in a public issue. Use GitHub's private vulnerability reporting for this repository. Include the affected revision, a minimal defensive reproducer, impact, and a proposed mitigation when available.

The project is a defensive scanner, not a sandbox. Source trees under review are treated as untrusted: patch tests are never executed unless the operator explicitly supplies `--patch-test-command`. Even then, run the scanner inside an OS-level sandbox with network and secret access removed.

## Scope

In scope: path escape, unintended network access, command execution not explicitly requested by the operator, unsafe patch application, report corruption, cache poisoning, and dependency compromise affecting the scanner.

Out of scope: vulnerabilities intentionally present in CTF targets and accuracy disagreements without a reproducible corpus case.
