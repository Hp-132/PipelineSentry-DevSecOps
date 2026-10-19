# response/ — Member 2 (not implemented)

Planned:
- Pipeline cancellation (e.g. GitHub Actions "cancel workflow run" API)
- Credential revocation
- Workload quarantine

## Integration with detection

Detection writes alerts to the PostgreSQL `alerts` table using the fixed contract in
[`shared/schema.py`](../shared/schema.py) / [`shared/models.py`](../shared/models.py).

Suggested loop for this module:

1. Poll for work: `SELECT * FROM alerts WHERE status = 'new' AND layer = 'correlation' AND risk_score >= <threshold>`
   (or read via `GET /alerts?status=new&layer=correlation`).
2. Validate rows with `shared.schema.Alert.model_validate(row)`.
3. Act, then set `status = 'handled'` in the same transaction that records the action.

Use `shared.database.session_scope()` for sessions. Do not change or remove contract fields
without agreeing it with Member 1.
