# 07 — Correlated multi-layer incident

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-4 PPE + CICD-SEC-6 Credential Hygiene + CICD-SEC-8 Runtime.

Three independent signals arrive for the same pipeline run, each from a different detection layer:

1. **Static** — the workflow file uses `pull_request_target` and checks out untrusted PR code (PPE-001).
2. **Behaviour** — run telemetry shows a new outbound domain and sensitive-file access (BEH-001).
3. **Runtime** — Falco detects a reverse-shell pattern inside the runner container (RT-SHELL).

Individually each alert would be actionable, but together they confirm an active pipeline compromise.
The correlation engine links them by `run_id`, computes a score across three layers and produces a
roll-up incident alert with `critical` severity.

**How correlation works in this project:**

The `correlate_run` function in `detection/correlation/engine.py` queries all non-correlation alerts
for a given `run_id`, deduplicates by `(layer, rule_id)`, weights each signal by severity and layer
confidence, and fires a correlation roll-up when:

- at least 2 independent layers contribute signals, OR
- the weighted score is >= 70.

The key field is `run_id`. Events sharing the same `run_id` are correlated; events with different
`run_id` values are never combined.

**Simulation:** all three events are synthetic. The workflow YAML is only parsed, no run is executed,
no network traffic leaves the host and no Falco agent is required. `attacker.example.test` uses the
reserved `.test` TLD and does not resolve.

**Run:** `make attack ID=07` or `.\scripts\make.ps1 attack 07`

| Expected rule | Layer | Source |
|---|---|---|
| PPE-001 (critical) | static | `workflow.yml` — `pull_request_target` + PR head checkout |
| BEH-001 (high) | behaviour | `workflow_run.json` — new outbound domain + sensitive file |
| RT-SHELL (critical) | runtime | `falco_events.jsonl` — reverse-shell pattern |

Correlation roll-up expected with `critical` severity and score >= 90 (three independent layers +
diversity bonus).

**Negative case:** submitting any single event on its own should still produce a child alert but not
trigger the multi-layer roll-up unless it crosses the score threshold alone.
