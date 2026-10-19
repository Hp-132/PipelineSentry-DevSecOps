# 06 — Runtime compromise

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-8 Ungoverned Usage of 3rd Party Services, CICD-SEC-9 Improper Artifact Integrity Validation.

A malicious dependency installs a backdoor that opens a reverse shell to an attacker's host, then
launches a crypto miner. Falco detects both events inside the runner container.

**Simulation:** two synthetic Falco-format JSON events are submitted to `POST /events/falco`.
No process is spawned, no network traffic leaves the host, and no mining occurs.
`attacker.example.test` uses the reserved `.test` TLD and does not resolve.

**Run:** `make attack ID=06` or `.\scripts\make.ps1 attack 06`

| Expected rule | Layer | Why |
|---|---|---|
| RT-SHELL (critical) | runtime | `/dev/tcp/attacker.example.test/4444` in proc.cmdline |
| RT-MINER (critical) | runtime | `xmrig` binary spawned with `stratum+tcp://` pool |

Both signals are from the runtime layer; the correlation engine is expected to produce a roll-up
with score >= 90 (single layer but both signals are critical).
