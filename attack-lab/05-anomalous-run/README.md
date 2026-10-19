# 05 — Anomalous run behaviour

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-4 / CICD-SEC-6 — Compromised runner exfiltrating data via anomalous behaviour.

A CI run deviates significantly from the known baseline: the duration triples, CPU spikes, a new
outbound domain that has never appeared in clean runs (`exfil.attacker.test`) is contacted, and a
sensitive file (`/home/runner/.aws/credentials`) is touched. Individually these signals are weak;
combined they raise the behavioural risk score above the alert threshold.

**Simulation:** a synthetic `workflow_run` webhook carrying run telemetry is sent to
`POST /webhooks/github`. No code is executed and no network traffic leaves the host.

**Run:** `make attack ID=05` or `.\scripts\make.ps1 attack 05`

| Expected rule | Layer | Why |
|---|---|---|
| BEH-001 `duration_drift` | behaviour | run took 3× the baseline mean |
| BEH-001 `cpu_drift` | behaviour | CPU 95 % vs baseline ~55 % |
| BEH-001 `new_outbound_domain` | behaviour | `exfil.attacker.test` not in baseline |
| BEH-001 `sensitive_file_touched` | behaviour | `.aws/credentials` in files_touched |

A single behaviour-layer alert with `high` or `critical` severity is expected.
