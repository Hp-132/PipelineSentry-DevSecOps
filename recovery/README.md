# recovery/ — recovery and remediation (Member 2)

Restores resources contained by `response/`. Every active containment of an incident has one recovery
plan; each run and each step is stored in `recovery_runs` against the originating incident (alert id).

**All recovery is simulated.** It updates PipelineSentry's containment state and audit trail; it does not
rebuild real runners or issue real credentials.

| Containment | Plan | Steps | Automatic? |
|---|---|---|---|
| pipeline `cancelled` | `resume_pipeline` | find the last run of the same workflow with no high/critical alerts (from the `events` table) → roll back and release | yes, or `manual_required` if no known-good run exists |
| runner `quarantined` | `restore_runner` | rebuild from clean image → release quarantine | yes |
| credential `revoked` | `rotate_credential` | resolve the named secret → rotate via the identity-provider adapter | yes for named secrets; `manual_required` for "all secrets" |
| image `blocked` | `unblock_image` | require the latest `supply_chain_results` signature check to be `verified` → release | only after a passing cosign verification |
| dependency `blocked` | `review_dependency` | a person confirms the package | always `manual_required` |

## Prerequisites and conflict rules

- The incident must be `handled` (contained by a simulated or live response). A dry run contains nothing, so recovery is `blocked`.
- There must be at least one active containment.
- Only one recovery can run per incident (row lock + `running` check → HTTP 409).
- Restored/rotated/released resources no longer have a plan, so recovery is never repeated.
- Blocked attempts are recorded too (`status: blocked`, with the reasons).

## Identity provider adapter

`recovery/identity.py` defines `IdentityProvider.rotate(credential) -> dict` (non-secret metadata only).
`SimulatedIdentityProvider` ships; `RECOVERY_IDENTITY_PROVIDER` selects an implementation. A real adapter
(Vault, AWS IAM, GitHub App) implements the same method — none is included.

## API

- `GET /incidents/{id}/recovery-plan` — preview: ready?, blocking reasons, plans
- `POST /incidents/{id}/recover` `{"plans": ["restore_runner"]}` (omit for all)
- `GET /recovery?incident_id=...`

Tests: `tests/test_recovery.py`, `tests/test_member2_api.py`.
