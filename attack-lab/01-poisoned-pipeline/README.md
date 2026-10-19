# 01 — Poisoned pipeline execution

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-4 Poisoned Pipeline Execution (PPE).

A contributor pushes a workflow change that runs `pull_request_target` (which has secrets and a
write token) but checks out and builds the untrusted PR head. It also interpolates the PR title into
a shell, echoes a secret, grants `write-all`, and uses unpinned actions.

**Simulation:** a synthetic GitHub `push` webhook carrying `workflow.yml` is sent to
`POST /webhooks/github`. Nothing is executed; the YAML is only parsed.

**Run:** `make attack ID=01` or `.\scripts\make.ps1 attack 01`

| Expected rule | Layer | Why |
|---|---|---|
| PPE-001 (critical) | static | `pull_request_target` + checkout of `pull_request.head.sha` |
| INJ-001 | static | `${{ github.event.pull_request.title }}` inside `run:` |
| PERM-001 | static | `permissions: write-all` |
| SEC-003 | static | `echo "token is $NPM_TOKEN"` |
| PIN-001 | static | `actions/checkout@v4`, `tj-actions/changed-files@v44` not SHA-pinned |

A correlation roll-up with score >= 80 is expected (static layer only).
