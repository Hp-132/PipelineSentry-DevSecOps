# response/ — automated incident response (Member 2)

Consumes Member 1's alerts, chooses response actions from a playbook, executes them in a safe mode and
records every decision in the `response_actions` table.

| File | Purpose |
|---|---|
| `playbook.py` | Maps alert rule families + evidence to actions and targets |
| `actions.py` | Executors: simulated containment, live GitHub Actions run cancellation |
| `engine.py` | `respond()`: plan → authorise → execute → audit → mark `handled` |
| `worker.py` | `responder` service: polls new correlated incidents |
| `routes.py` | `/incidents`, `/alerts/{id}/respond`, `/responses`, `/containments`, `/defence/status` |

## How alerts are consumed

The `responder` service (docker-compose) polls exactly what this README originally proposed:
`alerts WHERE layer='correlation' AND status='new' AND risk_score >= RESPONSE_MIN_SCORE`.
A correlation roll-up is planned from its child alerts (`evidence.child_alert_ids`), so targets come
from Member 1's evidence. Any single alert can also be handled through `POST /alerts/{id}/respond`.

| Rule family (high/critical only) | Action(s) | Target |
|---|---|---|
| `PPE-*`, `INJ-*`, `PERM-*`, `REPO-*`, `BEH-*` | `cancel_pipeline` | run id |
| `SEC-*`, `GL-*` (gitleaks), `RT-CRED` | `revoke_credential` (+ cancel for SEC-001/002, + quarantine for RT-CRED) | secret names from the evidence |
| `RT-SHELL`, `RT-NET`, `RT-MINER`, `RT-OTHER` | `quarantine_runner`, `cancel_pipeline` | Falco hostname / container |
| `DEP-*` | `block_dependency` | package / index URL |
| `IMG-001`, `IMG-002` | `block_image` | image reference |
| critical roll-up | `cancel_pipeline` in addition | run id |

Medium/low alerts and rules without a mapping (e.g. `PIN-001`) get **no** automated action and stay `new` for triage.

## Modes — what is real and what is simulated

| Mode | What happens | Alert status |
|---|---|---|
| `dry_run` (default) | Plan recorded with status `planned`. **Nothing executes.** | unchanged (`new`) |
| `simulated` | PipelineSentry's own `containments` table is updated (pipeline `cancelled`, runner `quarantined`, …). **No external system is touched**; every result says so. | `handled` when every action succeeded |
| `live` | Only `cancel_pipeline` has a real integration (`POST /repos/{repo}/actions/runs/{id}/cancel`). Other actions are recorded as `rejected` with "no live integration". | `handled` when every action succeeded |

Live mode requires **all** of: `RESPONSE_LIVE_ENABLED=true`, the action listed in `RESPONSE_LIVE_ACTIONS`,
`GITHUB_TOKEN` + `GITHUB_REPOSITORY`, and — for API requests — the header `X-Response-Token: $RESPONSE_API_TOKEN`.
Rejected attempts are still written to the audit trail (HTTP 403).

## Safety properties

- **Idempotent:** unique key `(alert_id, action, target, mode)`; re-processing returns the existing record (`duplicate: true`).
- **Retries:** transient failures (timeouts, 5xx, 429) are retried up to `RESPONSE_MAX_ATTEMPTS` only for retry-safe
  actions. `revoke_credential` is never retried automatically. Permanent failures (4xx, bad run id) are not retried.
- **Transactions:** action records, containment and the alert's `handled` status commit together.

## Configuration

`RESPONSE_MODE` (dry_run), `RESPONSE_MIN_SCORE` (70), `RESPONSE_MAX_ATTEMPTS` (3), `RESPONSE_POLL_SECONDS` (5),
`RESPONSE_LIVE_ENABLED` (false), `RESPONSE_LIVE_ACTIONS` (cancel_pipeline), `RESPONSE_API_TOKEN`, `GITHUB_TOKEN`,
`GITHUB_REPOSITORY`, `GITHUB_API_URL`. Use placeholders in `.env`; never commit real tokens.

## Run

```bash
make up && make attack ID=07                       # creates a critical correlated incident
curl -s localhost:8000/incidents | jq '.[0].id'
curl -s -XPOST localhost:8000/alerts/<id>/respond -H 'Content-Type: application/json' -d '{"mode":"dry_run"}'
curl -s -XPOST localhost:8000/alerts/<id>/respond -H 'Content-Type: application/json' -d '{"mode":"simulated"}'
docker compose logs responder
```

Tests: `tests/test_response.py`, `tests/test_member2_api.py`.

## Limitations

- Credential revocation, runner quarantine and image/dependency blocking are simulated; there is no cloud/IdP/registry integration.
- Live cancellation needs a numeric GitHub Actions run id; attack-lab run ids are synthetic, so they fail cleanly in live mode.
