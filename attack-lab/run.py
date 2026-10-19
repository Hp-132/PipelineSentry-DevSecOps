"""Run a safe attack scenario through the detection API and check the expected detections.

    python attack-lab/run.py 01            (inside the api container: make attack ID=01)
"""

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent
FINAL_STATUSES = {"done", "failed", "dead_lettered", "publish_failed"}


def scenario_dir(attack_id: str) -> Path:
    matches = sorted(LAB.glob(f"{attack_id}-*"))
    if not matches:
        raise SystemExit(f"no scenario folder for attack {attack_id}")
    return matches[0]


def load_scenario(attack_id: str) -> tuple[Path, dict]:
    folder = scenario_dir(attack_id)
    return folder, json.loads((folder / "scenario.json").read_text(encoding="utf-8"))


def _relative(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def _check(response: httpx.Response) -> list[str]:
    if response.status_code not in (200, 202):
        raise RuntimeError(f"{response.request.method} {response.request.url} -> {response.status_code}: {response.text}")
    return response.json().get("event_ids", [])


def send_step(client, step: dict, folder: Path, run_id: str, attack_id: str) -> list[str]:
    kind = step["type"]
    common = {"run_id": run_id, "attack_id": attack_id}

    if kind == "github_webhook":
        payload = json.loads((folder / step["payload"]).read_text(encoding="utf-8"))
        ext = payload.setdefault("pipelinesentry", {})
        ext.update(common)
        if step.get("workflow_files"):
            ext["workflow_files"] = [
                {"path": f["path"], "content": (folder / f["file"]).read_text(encoding="utf-8")}
                for f in step["workflow_files"]
            ]
        headers = {"X-GitHub-Event": step["event"], "X-GitHub-Delivery": str(uuid.uuid4())}
        return _check(client.post("/webhooks/github", json=payload, headers=headers))

    if kind == "scan_workflow":
        body = {"path": _relative(folder / step["file"]), "workflow": step.get("workflow"), **common}
        return _check(client.post("/scan/workflow", json=body))

    if kind == "scan_secrets":
        body = {"path": _relative(folder / step["dir"]), "workflow": step.get("workflow"), **common}
        return _check(client.post("/scan/secrets", json=body))

    if kind == "event":
        if "manifest_file" in step:
            payload = {"manifest": step["manifest_file"],
                       "content": (folder / step["manifest_file"]).read_text(encoding="utf-8")}
        else:
            payload = json.loads((folder / step["payload"]).read_text(encoding="utf-8"))
        body = {"kind": step["kind"], "workflow": step["workflow"], "payload": payload, **common}
        return _check(client.post("/events", json=body))

    if kind == "falco":
        ids = []
        start = datetime.now(timezone.utc)
        lines = (folder / step["file"]).read_text(encoding="utf-8").splitlines()
        for offset, line in enumerate(l for l in lines if l.strip()):
            event = json.loads(line)
            event.update(common, workflow=step["workflow"], simulated=True,
                         time=(start + timedelta(seconds=offset)).isoformat())
            ids += _check(client.post("/events/falco", json=event))
        return ids

    raise ValueError(f"unknown step type {kind}")


def wait_for_events(client, event_ids: list[str], timeout: float = 60) -> dict[str, dict]:
    deadline = time.monotonic() + timeout
    statuses = {}
    while time.monotonic() < deadline:
        statuses = {i: client.get(f"/events/{i}").json() for i in event_ids}
        if all(s.get("status") in FINAL_STATUSES for s in statuses.values()):
            break
        time.sleep(0.5)
    return statuses


def check_expectations(client, run_id: str, expected: dict) -> dict:
    alerts = client.get("/alerts", params={"run_id": run_id, "limit": 500}).json()
    children = [a for a in alerts if a["layer"] != "correlation"]
    rules = {a["evidence"].get("rule_id") for a in children}
    behaviour_rules = {r["rule"] for a in children if a["layer"] == "behaviour"
                       for r in a["evidence"].get("triggered_rules", [])}
    layers = {a["layer"] for a in children}

    correlation = client.post(f"/runs/{run_id}/correlate").json() if children else {}
    timeline = client.get(f"/runs/{run_id}/timeline").json() if children else {}
    rollup = correlation.get("rollup")

    def has_rule(wanted):
        return any(r and r.startswith(wanted[:-1]) for r in rules) if wanted.endswith("*") else wanted in rules

    problems = [f"missing rule {r}" for r in expected.get("rules", []) if not has_rule(r)]
    problems += [f"missing behaviour rule {r}" for r in expected.get("behaviour_rules", []) if r not in behaviour_rules]
    problems += [f"missing layer {l}" for l in expected.get("layers", []) if l not in layers]
    if expected.get("rollup") and not rollup:
        problems.append("expected a correlation roll-up alert")
    if rollup and rollup["risk_score"] < expected.get("min_rollup_score", 0):
        problems.append(f"roll-up score {rollup['risk_score']} below {expected['min_rollup_score']}")

    return {
        "run_id": run_id,
        "passed": not problems,
        "problems": problems,
        "alert_count": len(children),
        "rules": sorted(r for r in rules if r),
        "behaviour_rules": sorted(behaviour_rules),
        "layers": sorted(layers),
        "rollup": rollup,
        "timeline": timeline,
    }


def run_scenario(client, attack_id: str, run_id: str | None = None, after_send=None, timeout: float = 60) -> dict:
    folder, scenario = load_scenario(attack_id)
    run_id = run_id or f"attack-{attack_id}-{uuid.uuid4().hex[:8]}"
    event_ids = []
    for step in scenario["steps"]:
        event_ids += send_step(client, step, folder, run_id, attack_id)
    if after_send:
        after_send()
    statuses = wait_for_events(client, event_ids, timeout)
    report = check_expectations(client, run_id, scenario["expected"])
    unfinished = [i for i, s in statuses.items() if s.get("status") != "done"]
    if unfinished:
        report["passed"] = False
        report["problems"].append(f"events not processed: { {i: statuses[i].get('status') for i in unfinished} }")
    report.update(name=scenario["name"], event_ids=event_ids)
    return report


def print_report(report: dict) -> None:
    print(f"\n== {report['name']}  (run_id={report['run_id']})")
    print(f"events queued: {len(report['event_ids'])}, alerts stored: {report['alert_count']}, layers: {report['layers']}")
    for entry in report["timeline"].get("entries", []):
        print(f"  {entry['timestamp'][11:19]}  {entry['layer']:<9} {entry['severity']:<8} "
              f"{entry['rule_id'] or '':<22} {entry['title']}")
    if report["rollup"]:
        r = report["rollup"]
        print(f"roll-up: {r['severity']} score={r['risk_score']}  ({r['title']})")
        for reason in r["evidence"]["reasons"]:
            print(f"  - {reason}")
    print("RESULT:", "PASS" if report["passed"] else "FAIL " + "; ".join(report["problems"]))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("attack_id", choices=[f"0{i}" for i in range(1, 8)])
    parser.add_argument("--api", default=os.getenv("API_URL", "http://localhost:8000"))
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args(argv)
    with httpx.Client(base_url=args.api, timeout=30) as client:
        report = run_scenario(client, args.attack_id, timeout=args.timeout)
    print_report(report)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
