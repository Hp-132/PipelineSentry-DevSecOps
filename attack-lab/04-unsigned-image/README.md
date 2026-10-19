# 04 — Unsigned or tampered image

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-9 Improper Artifact Integrity Validation.

A release pipeline is about to deploy three images: one with no signature and a mutable `latest`
tag, one whose signature fails verification (subject digest mismatch), and one correctly signed
control image.

**Simulation:** each file is signature *evidence* in the shape of `cosign verify --output json`
results. No registry is contacted and no signing happens here; real signing and verification is
Member 2's `supply-chain/` module. Detection only judges the evidence it is given.

**Run:** `make attack ID=04` or `.\scripts\make.ps1 attack 04`

| Expected rule | Layer | Source file |
|---|---|---|
| IMG-001 (no signature) | static | `unsigned.json` |
| IMG-003 (tag without digest) | static | `unsigned.json` |
| IMG-002 (critical, failed verification) | static | `tampered.json` |
| none | — | `signed-ok.json` (false-positive control) |
