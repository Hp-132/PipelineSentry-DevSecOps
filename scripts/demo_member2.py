"""End-to-end Member 2 demonstration against the running Docker Compose stack.

    make demo-m2                  (or .\\scripts\\make.ps1 demo-m2)
    docker compose exec -T api python scripts/demo_member2.py

1. attack scenario 07 -> Member 1 alerts + correlated incident
2. dry-run, unauthorised live and simulated responses (all recorded)
3. simulated recovery of the contained incident
4. cosign: sign / leave unsigned / sign with an untrusted key, then verify each through the API
5. CycloneDX SBOMs for the project and the typosquat scenario
6. OPA policy evaluation of the bundled samples
Exits non-zero if any expected outcome is not observed.
"""

import importlib.util
import os
import sys
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from shared import config  # noqa: E402
from supply_chain import cosign, registry  # noqa: E402

API = os.getenv("API_URL", "http://localhost:8000")
problems: list[str] = []


def load_attack_lab():
    spec = importlib.util.spec_from_file_location("attack_lab_run", ROOT / "attack-lab" / "run.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def step(title: str) -> None:
    print(f"\n=== {title}")


def expect(condition: bool, message: str) -> None:
    print(f"  [{'ok' if condition else 'FAIL'}] {message}")
    if not condition:
        problems.append(message)


def call(client: httpx.Client, method: str, url: str, ok=(200, 202), **kwargs) -> dict:
    response = client.request(method, url, **kwargs)
    if response.status_code not in ok:
        raise SystemExit(f"{method} {url} -> {response.status_code}: {response.text[:500]}")
    return response.json()


def wait_events(client, lab, event_ids):
    statuses = lab.wait_for_events(client, event_ids, timeout=60)
    return all(s.get("status") == "done" for s in statuses.values())


def main() -> int:
    lab = load_attack_lab()
    with httpx.Client(base_url=API, timeout=90) as client:
        status = call(client, "GET", "/defence/status")
        print(f"tools: cosign={status['supply_chain']['cosign']} opa={status['policy']['opa']} "
              f"cyclonedx={status['supply_chain']['cyclonedx']} responder mode={status['response']['default_mode']}")

        # 1 -- detection (Member 1)
        step("1. Attack scenario 07 -> Member 1 detection and correlation")
        report = lab.run_scenario(client, "07")
        lab.print_report(report)
        expect(report["passed"], "scenario 07 detected by static, behaviour and runtime layers")
        rollup = report["rollup"]
        if not rollup:
            return 1
        incident_id = rollup["id"]

        # A clean run of the same workflow gives recovery a last known-good rollback point
        good = (ROOT / "policy" / "samples" / "workflows" / "compliant.yml").read_text(encoding="utf-8")
        queued = call(client, "POST", "/scan/workflow", json={
            "content": good, "filename": "release.yml", "workflow": rollup["workflow"],
            "run_id": f"known-good-{uuid.uuid4().hex[:8]}"})
        wait_events(client, lab, queued["event_ids"])

        # 2 -- response
        step("2. Response")
        dry = call(client, "POST", f"/alerts/{incident_id}/respond", json={"mode": "dry_run"})
        for action in dry["actions"]:
            print(f"  DRY RUN   {action['action']:<18} -> {action['target']}  ({action['status']})")
        expect(dry["outcome"] == "planned" and dry["alert_status"] == "new", "dry run planned actions and changed nothing")

        live = client.post(f"/alerts/{incident_id}/respond", json={"mode": "live"})
        expect(live.status_code == 403, f"live response without authorisation rejected (HTTP {live.status_code}: "
                                        f"{live.json().get('detail')})")

        sim = call(client, "POST", f"/alerts/{incident_id}/respond", json={"mode": "simulated"})
        for action in sim["actions"]:
            print(f"  SIMULATED {action['action']:<18} -> {action['target']}  ({action['status']})")
        expect(sim["outcome"] == "contained" and sim["alert_status"] == "handled", "simulated response contained the incident")
        again = call(client, "POST", f"/alerts/{incident_id}/respond", json={"mode": "simulated"})
        expect(all(a["duplicate"] for a in again["actions"]), "re-processing the incident executed nothing twice")

        # 3 -- recovery
        step("3. Recovery")
        recovered = call(client, "POST", f"/incidents/{incident_id}/recover", json={})
        for run in recovered["runs"]:
            print(f"  {run['plan']:<18} {run['status']:<16} {run['target']}")
            for s in run["steps"]:
                print(f"      - {s['name']}: {s['status']} - {s['detail']}")
        expect(recovered["outcome"] == "recovered", "simulated recovery restored the pipeline, runner and leaked credential")

        # 4 -- signatures
        step("4. Image signing and verification (cosign, local registry)")
        tag = uuid.uuid4().hex[:8]
        images = {name: f"registry:5000/demo/app:{name}-{tag}" for name in ("signed", "unsigned", "forged")}
        attacker_dir = Path(config.COSIGN_KEY_DIR) / "untrusted"
        cosign.generate_key_pair()
        cosign.generate_key_pair(attacker_dir)
        with registry.RegistryClient() as client_registry:
            for name, image in images.items():
                client_registry.push_demo_image(registry.parse(image), f"PipelineSentry demo {name} {tag}")
        cosign.sign(images["signed"])
        cosign.sign(images["forged"], attacker_dir)

        sc_run = f"supply-chain-demo-{tag}"
        expected_status = {"signed": "verified", "unsigned": "unsigned", "forged": "verification_failed"}
        event_ids = []
        for name, image in images.items():
            result = call(client, "POST", "/supply-chain/verify", json={"image": image, "run_id": sc_run})
            event_ids += result["event_ids"]
            print(f"  {image:<45} {result['status']:<20} {result['summary']['detail']}")
            expect(result["status"] == expected_status[name], f"{name} image reported as {expected_status[name]}")
        wait_events(client, lab, event_ids)
        rules = {a["evidence"].get("rule_id") for a in call(client, "GET", "/alerts", params={"run_id": sc_run})}
        expect({"IMG-001", "IMG-002"} <= rules, f"verification results raised Member 1 image alerts {sorted(rules - {None})}")

        # 5 -- SBOM
        step("5. CycloneDX SBOMs")
        project = call(client, "POST", "/supply-chain/sbom", json={"path": "requirements.txt"})
        print(f"  requirements.txt: {project['status']}, {project['summary'].get('component_count')} components, "
              f"download /supply-chain/results/{project['id']}/sbom")
        expect(project["status"] == "generated" and project["summary"]["schema_valid"], "project SBOM is valid CycloneDX 1.6")
        sbom_run = f"sbom-demo-{tag}"
        typo = call(client, "POST", "/supply-chain/sbom", json={
            "path": "attack-lab/03-dependency-typosquat/requirements.txt", "run_id": sbom_run})
        wait_events(client, lab, typo["event_ids"])
        dep_rules = {a["evidence"].get("rule_id") for a in call(client, "GET", "/alerts", params={"run_id": sbom_run})}
        expect("DEP-001" in dep_rules, f"typosquat SBOM linked to dependency alerts {sorted(dep_rules - {None})}")

        # 6 -- policy
        step("6. Policy evaluation (OPA)")
        for sample in call(client, "GET", "/policy/samples"):
            result = call(client, "POST", "/policy/evaluate", json={"kind": sample["kind"], "path": sample["path"]})
            verdict = "ALLOW" if result["allowed"] else "DENY "
            print(f"  {verdict} {sample['kind']:<10} {sample['name']:<26} "
                  f"{', '.join(sorted({v['rule_id'] for v in result['violations']}))}")
            expect(result["allowed"] == sample["name"].startswith("compliant"),
                   f"{sample['name']} {'allowed' if sample['name'].startswith('compliant') else 'denied'}")

        step("Inspect the results")
        print("  Dashboard: http://localhost:5173  (Incidents, Response, Recovery, Supply Chain, Policy)")
        print(f"  Incident:  {API}/incidents/{incident_id}")
    print("\nRESULT:", "PASS" if not problems else "FAIL - " + "; ".join(problems))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
