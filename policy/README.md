# policy/ — policy evaluation and enforcement (Member 2)

| Path | Purpose |
|---|---|
| `opa/kubernetes.rego` | Workload policies `POL-K8S-001…010` |
| `opa/workflow.rego` | GitHub Actions policies `POL-WF-001…004` |
| `opa/*_test.rego` | 25 Rego unit tests (`opa test policy/opa`) |
| `kyverno/*.yaml` | Admission policies (the enforcement side) + offline `kyverno-test.yaml` |
| `samples/` | Allowed and denied manifests/workflows used by tests, demo and dashboard |
| `evaluator.py`, `service.py`, `routes.py` | `opa eval` wrapper, alert creation, `/policy/*` API |

## Policies

| Id | Severity | Denies |
|---|---|---|
| POL-K8S-001 | critical | `privileged: true` (incl. init/ephemeral containers) |
| POL-K8S-002 | high | `allowPrivilegeEscalation` not set to `false` |
| POL-K8S-003 | high | `hostNetwork` / `hostPID` / `hostIPC` |
| POL-K8S-004 | high | `hostPath` volumes |
| POL-K8S-005 | high | image not pinned by `@sha256:` digest |
| POL-K8S-006 | high | image not from `ALLOWED_REGISTRIES` |
| POL-K8S-007 | critical | image **blocked by an incident response** (live from the `containments` table) |
| POL-K8S-008 | med | may run as root (`runAsNonRoot` not true) |
| POL-K8S-009 | high | added capabilities `ALL`, `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`, `SYS_MODULE` |
| POL-K8S-010 | low | no resource limits |
| POL-WF-001 | med | action / reusable workflow not pinned to a 40-char commit SHA |
| POL-WF-002 | high/med | `permissions: write-all` / no permissions block |
| POL-WF-003 | high | self-hosted runner for `pull_request(_target)`, `issue_comment`, `workflow_run` |
| POL-WF-004 | med | job container image not pinned by digest |

## Evaluation vs enforcement

- **Evaluation (implemented, tested):** `POST /policy/evaluate` runs OPA and reports allowed/denied. Violations
  become `static`-layer alerts (`rule_id` POL-*, `evidence.observation = "policy_evaluation"`) saved with Member 1's
  `save_alert`, and the run is re-correlated. Nothing is blocked; this is a CI / pre-deploy gate.
- **Enforcement (policies provided, cluster required):** the Kyverno `ClusterPolicy` files use
  `validationFailureAction: Enforce` and would reject non-compliant Pods at admission. They are verified offline with
  `kyverno test`. They have **not** been applied to a cluster here, since none was available.
  `verify-image-signatures.yaml` needs the demo cosign public key pasted in and a cluster that can reach the registry,
  so it is excluded from the offline tests.

## Run

```bash
make test-policy                        # opa test (inside the image)
make test-kyverno                       # kyverno test, offline via the kyverno-cli container
curl -s localhost:8000/policy/samples
curl -s -XPOST localhost:8000/policy/evaluate -H 'Content-Type: application/json' \
     -d '{"kind":"kubernetes","path":"policy/samples/kubernetes/privileged-pod.yaml"}'
```

To enforce in a local cluster (e.g. kind): install Kyverno, then `kubectl apply -f policy/kyverno/` and try
`kubectl apply -f policy/samples/kubernetes/privileged-pod.yaml` (expected: denied).

Tests: `tests/test_policy.py`, `opa test policy/opa`, `policy/kyverno/kyverno-test.yaml`.
