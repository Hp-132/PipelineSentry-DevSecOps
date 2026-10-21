# PipelineSentry — Member 2 integration guide

Member 2 adds **response**, **recovery**, **supply-chain** and **policy** on top of Member 1's detection
engine. It uses the same PostgreSQL database, the same alert contract (`shared/schema.py`, unchanged), the
same RabbitMQ pipeline and the same FastAPI app.

```
attack / webhook / scan ─► API ─► RabbitMQ ─► worker (Member 1 detectors) ─► alerts ─► correlation roll-up
                                     ▲                                                     │
   supply_chain: cosign verify ──────┤ image events (IMG-001/002)                          ▼
   supply_chain: SBOM ───────────────┘ dependency events (DEP-*)          responder / POST /alerts/{id}/respond
   policy: OPA evaluate ─► POL-* alerts via save_alert + correlate_run          │  response_actions, containments
                                                                                ▼
                                                                  POST /incidents/{id}/recover ─► recovery_runs
                                     dashboard: Incidents · Response · Recovery · Supply Chain · Policy · Events
```

## Contract with Member 1

| Item | How Member 2 uses it | Changed? |
|---|---|---|
| `alerts` table / `Alert` schema | read; `status` set to `handled` after a successful non-dry-run response (as the original `response/README.md` proposed) | no |
| correlation roll-ups (`layer='correlation'`, `evidence.child_alert_ids`) | the incident unit for response/recovery | no |
| `correlate_run` resetting a handled roll-up to `new` when new children arrive | re-triggers response for the new evidence; existing actions are de-duplicated | no |
| `image` / `dependency` event kinds and IMG/DEP rules | supply-chain results are submitted as these events | no |
| `save_alert`, `alert_id` | policy violations are stored as `static` alerts with deterministic ids | no |

**Additive changes to shared code** (please review, Member 1):

- `shared/models.py`: new tables `response_actions`, `containments`, `recovery_runs`, `supply_chain_results`,
  `policy_results` (created by the existing `init_db()`; no migration tool is used in this project).
- `shared/config.py`: new settings (below) and `CORS_ORIGINS`, `SELF_URL`.
- `detection/api/main.py`: CORS middleware for the dashboard, `GET /events` (list), `POST /attack-lab/{id}/run`
  (the dashboard's Attack Lab button sent an invalid `workflow` event and always got 422), and `include_router` for
  the four Member 2 routers.
- `tests/test_correlation.py`, `tests/test_deduplication.py`: fixed 9 failing tests (missing `MagicMock` import;
  `diversity_bonus` lives under `components`; a single `high` alert scores 70, which meets `CORRELATION_MIN_SCORE`).
  The assertions still check the original intent; no test was removed.
- `supply-chain/` renamed to `supply_chain/` (Python packages cannot contain `-`).

## New API endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/incidents`, `/incidents/{id}` | roll-ups with children, planned/recorded actions, containment, recovery |
| POST | `/alerts/{id}/respond` | `{"mode": "dry_run" \| "simulated" \| "live"}`; live needs `X-Response-Token` |
| GET | `/responses`, `/containments` | response audit trail, current containment state |
| GET/POST | `/incidents/{id}/recovery-plan`, `/incidents/{id}/recover` | preview / run recovery |
| GET | `/recovery` | recovery runs and steps |
| POST | `/supply-chain/verify`, `/supply-chain/sbom` | cosign verification, CycloneDX SBOM |
| GET | `/supply-chain/results[/{id}[/sbom]]` | results; raw SBOM download |
| POST/GET | `/policy/evaluate`, `/policy/results`, `/policy/samples` | OPA evaluation |
| GET | `/defence/status` | tool availability and response configuration |
| GET | `/events` | event list (Events page) |
| POST | `/attack-lab/{id}/run` | queue a scenario from the dashboard |

## Configuration (placeholders only; see `.env.example`)

| Variable | Default | Notes |
|---|---|---|
| `RESPONSE_MODE` | `dry_run` | responder mode: `dry_run`, `simulated`, `live` |
| `RESPONSE_MIN_SCORE` | `70` | roll-ups at or above this score are handled automatically |
| `RESPONSE_LIVE_ENABLED` | `false` | master switch for live actions |
| `RESPONSE_LIVE_ACTIONS` | `cancel_pipeline` | allow-list; only this action has a live integration |
| `RESPONSE_API_TOKEN` | — | required header value for live requests through the API |
| `GITHUB_TOKEN`, `GITHUB_REPOSITORY` | — | for live run cancellation (`actions: write` scope) |
| `COSIGN_PASSWORD` | `change-me-cosign` | encrypts the demo key pair in the `cosignkeys` volume |
| `ALLOWED_REGISTRIES` | `registry:5000,ghcr.io/pipelinesentry` | used by POL-K8S-006 |
| `CORS_ORIGINS` | `http://localhost:5173,…` | dashboard origins |

## Run the complete demonstration

```bash
cp .env.example .env            # Windows: .\scripts\make.ps1 up creates it
make up                          # postgres, rabbitmq, redis, registry, api, worker, responder
make demo-m2                     # Windows: .\scripts\make.ps1 demo-m2
cd dashboard && npm install && npm run dev     # http://localhost:5173
```

`scripts/demo_member2.py` checks every expected outcome and ends with `RESULT: PASS` or a list of failures:

1. **Suspicious event:** attack scenario 07 (static PPE-001 + behaviour BEH-001 + runtime RT-SHELL).
2. **Member 1 alert:** a critical correlated incident (score ≥ 90).
3. **Response:** a dry run (planned only), a live attempt (rejected with 403 and audited), then a simulated response
   (pipeline cancelled, runner quarantined, alerts `handled`). A repeat run executes nothing.
4. **Record:** every action is in `/responses` with its mode, status, attempts and outcome.
5. **Recovery:** pipeline rolled back to the last known-good run, runner restored (simulated).
6. **Supply chain:** three demo images pushed to the local registry. One is signed with the trusted key, one is left
   unsigned and one is signed with an untrusted key. Verifying them gives `verified`, `unsigned` and
   `verification_failed`, and raises IMG-001/IMG-002 alerts. CycloneDX SBOMs are generated for `requirements.txt`
   and the typosquat scenario; the latter raises DEP-001.
7. **Policy:** all five samples are evaluated; only the two `compliant*` files are allowed.
8. **Dashboard:** Incidents, Response, Recovery, Supply Chain, Policy and Events pages show the stored results.

## Tests

```bash
make test-unit       # pytest -m "not integration" in the image (opa, cosign, cyclonedx installed)
make test            # + integration tests against the running stack (real cosign + registry)
make test-policy     # opa test policy/opa
make test-kyverno    # kyverno test policy/kyverno (offline)
```

## What is simulated

| Capability | Real | Simulated / not implemented |
|---|---|---|
| Pipeline cancellation | GitHub API, live mode only, when fully configured | simulated mode marks containment only |
| Credential revocation and rotation | — | simulated; adapter interface in `recovery/identity.py` |
| Runner quarantine and restore | — | simulated |
| Image and dependency blocking | enforced by POL-K8S-007 when policies are evaluated | no registry or package-index integration |
| SBOM generation and validation | real (cyclonedx-py, schema validation) | — |
| Signing and verification | real cosign against the local registry | no Rekor or keyless signing (offline) |
| Policy evaluation | real OPA | — |
| Admission enforcement | Kyverno policies, tested offline | not applied to a cluster (none available) |

## Needs Member 1's review

- The five new tables and the `main.py` additions listed above.
- A dedicated `policy` or `supply_chain` alert layer would need a schema change (`Layer` enum + DB check constraint).
  This implementation avoids that by using `layer='static'` with `evidence.observation`/`source`.
- When response marks a roll-up `handled`, it also marks its child alerts `handled`. If Member 1 prefers child
  statuses to stay independent, remove the loop in `response/engine.py`.
