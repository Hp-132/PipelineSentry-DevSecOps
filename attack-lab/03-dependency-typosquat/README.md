# 03 — Dependency typosquatting

**OWASP Top 10 CI/CD Security Risks:** CICD-SEC-3 Dependency Chain Abuse.

The manifests pull look-alike packages (`reqeusts`, `colourama`, `expresss`, `axois`), add an
extra package index over plain HTTP (dependency confusion), and run a `postinstall` script that
downloads and executes a shell script.

**Simulation:** the manifests are sent as text to `POST /events` and only parsed. Nothing is installed
and the `.test` hosts do not resolve. Do not run `pip install` or `npm install` on these files.

**Run:** `make attack ID=03` or `.\scripts\make.ps1 attack 03`

| Expected rule | Layer | Why |
|---|---|---|
| DEP-001 | static | name within edit distance 1–2 of a popular package |
| DEP-002 | static | `--extra-index-url http://...` |
| DEP-004 | static | `postinstall: curl ... \| sh` |

`numpy`, `flask` and `lodash` are correct names and must not be flagged.
