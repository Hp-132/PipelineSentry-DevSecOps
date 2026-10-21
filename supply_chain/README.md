# supply_chain/ — SBOMs and image signatures (Member 2)

> Renamed from `supply-chain/` so it can be imported as a Python package.

| File | Purpose |
|---|---|
| `sbom.py` | CycloneDX 1.6 JSON SBOMs with `cyclonedx-py`, validated with `cyclonedx-python-lib`'s strict JSON-schema validator |
| `cosign.py` | Key generation, signing and verification with the `cosign` CLI |
| `registry.py` | Minimal OCI distribution client: digest resolution, signature-tag lookup, pushing a tiny demo image |
| `service.py` | Stores results in `supply_chain_results` and feeds Member 1's pipeline |
| `routes.py` | `/supply-chain/sbom`, `/supply-chain/verify`, `/supply-chain/results[/{id}[/sbom]]` |

## How results become alerts

No second detection engine: results are sent through Member 1's queue as normal events.

- `POST /supply-chain/verify` → an `image` event with the real signature evidence → Member 1's `IMG-001`
  (no signature) / `IMG-002` (signature fails verification) rules → alerts → correlation.
- `POST /supply-chain/sbom` for a requirements file → a `dependency` event → `DEP-*` rules (typosquats, unsafe indexes).
- Only **conclusive** cosign answers produce events. A missing tool, unreachable registry or invalid image is
  stored as `tool_unavailable` / `error` / `invalid_input` and raises no alert.

## Verification statuses

| Status | Meaning |
|---|---|
| `verified` | `cosign verify` exited 0 **and** a returned payload covers this exact digest |
| `unsigned` | verification failed and no `sha256-<digest>.sig` signature tag exists |
| `verification_failed` | a signature exists but does not verify with the trusted key (or covers another digest) |
| `invalid_input` / `error` / `tool_unavailable` | bad reference or missing image / registry or key problem / cosign not installed |

An image is never marked verified because a signing command ran; only the verify result counts.

## Local, offline demo

The Compose stack runs `registry:2.8.3` on `registry:5000` (host: `127.0.0.1:5000`, plain HTTP).
`registry.push_demo_image()` pushes a one-file OCI image without needing Docker inside the container.
Signing uses an encrypted key pair in the `cosignkeys` volume (`COSIGN_PASSWORD`) and runs **without** the public
Rekor transparency log (`--tlog-upload=false`, `--insecure-ignore-tlog`). Signing is only allowed for
`SIGNING_ALLOWED_REGISTRIES` (default: the local registry).

```bash
make up
make demo-m2      # signs one image, leaves one unsigned, signs one with an untrusted key, verifies all three
curl -s -XPOST localhost:8000/supply-chain/sbom -H 'Content-Type: application/json' -d '{"path":"requirements.txt"}'
```

## Limitations

- SBOMs cover Python requirements files and the running Python environment. `package.json` and container-image
  SBOMs would need `cyclonedx-npm` or Syft/Trivy, which are not installed (reported as `unsupported`).
- Keyless (Fulcio/OIDC) signing and Rekor are not used, to keep the demo offline.
- Registries that need credentials are not supported (anonymous token auth only).
