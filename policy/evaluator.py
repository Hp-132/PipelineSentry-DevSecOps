"""Evaluates Kubernetes manifests and GitHub workflows against the OPA/Rego policies in policy/opa.

This is policy *evaluation* (a CI/pre-deploy gate): it reports whether a configuration would be allowed.
Admission *enforcement* in a cluster is done by the Kyverno policies in policy/kyverno.
"""

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from shared import config

POLICY_DIR = Path(__file__).resolve().parent / "opa"
PACKAGES = {"kubernetes": "pipelinesentry.kubernetes", "workflow": "pipelinesentry.workflow"}
SEVERITY_ORDER = ["low", "med", "high", "critical"]


class PolicyError(Exception):
    pass


class OpaUnavailable(PolicyError):
    pass


class InvalidDocument(PolicyError):
    pass


@dataclass
class Evaluation:
    target: str
    target_kind: str
    allowed: bool
    violations: list[dict] = field(default_factory=list)
    engine: str = "opa"
    engine_version: str | None = None
    resources: int = 0


def opa_path() -> str:
    path = shutil.which("opa")
    if not path:
        raise OpaUnavailable("opa binary not found on PATH; it ships in the PipelineSentry Docker image "
                             "(or install it from https://www.openpolicyagent.org/docs/latest/#running-opa)")
    return path


def opa_version() -> str | None:
    try:
        out = subprocess.run([opa_path(), "version"], capture_output=True, text=True, timeout=10)
    except (PolicyError, OSError, subprocess.TimeoutExpired):
        return None
    first = out.stdout.splitlines()[0] if out.stdout else ""
    return first.split(":", 1)[1].strip() if ":" in first else None


def build_input(kind: str, content: str, target: str) -> dict:
    try:
        if kind == "kubernetes":
            resources = [d for d in yaml.safe_load_all(content) if d]
            if not resources or not all(isinstance(d, dict) and "kind" in d for d in resources):
                raise InvalidDocument("expected one or more Kubernetes resources with a 'kind'")
            return {"resources": resources}
        if kind == "workflow":
            workflow = yaml.safe_load(content)
            if not isinstance(workflow, dict) or "jobs" not in workflow:
                raise InvalidDocument("expected a GitHub Actions workflow with a 'jobs' mapping")
            # YAML 1.1 parses the bare key `on` as boolean True
            triggers = workflow.pop(True, None) if True in workflow else workflow.get("on")
            workflow["on"] = triggers
            if isinstance(triggers, str):
                names = [triggers]
            elif isinstance(triggers, dict):
                names = list(triggers)
            else:
                names = list(triggers or [])
            return {"path": target, "triggers": [str(n) for n in names], "workflow": workflow}
    except yaml.YAMLError as exc:
        raise InvalidDocument(f"invalid YAML: {exc}") from exc
    raise InvalidDocument(f"unknown target kind '{kind}' (expected one of {sorted(PACKAGES)})")


def evaluate(kind: str, content: str, target: str, blocked_images: list[str] = ()) -> Evaluation:
    document = build_input(kind, content, target)
    data = {"config": {"allowed_registries": config.ALLOWED_REGISTRIES, "blocked_images": sorted(blocked_images)}}
    binary = opa_path()
    with tempfile.TemporaryDirectory() as tmp:
        data_file = Path(tmp) / "data.json"
        data_file.write_text(json.dumps(data), encoding="utf-8")
        # Only the policy files are loaded; *_test.rego files are skipped so tests cannot shadow data
        policies = [str(p) for p in sorted(POLICY_DIR.glob("*.rego")) if not p.name.endswith("_test.rego")]
        cmd = [binary, "eval", "--format", "json", "--stdin-input", "--data", str(data_file)]
        for policy in policies:
            cmd += ["--data", policy]
        cmd.append(f"data.{PACKAGES[kind]}.violations")
        try:
            result = subprocess.run(cmd, input=json.dumps(document, default=str), capture_output=True, text=True,
                                    timeout=config.OPA_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise PolicyError(f"opa timed out after {config.OPA_TIMEOUT_SECONDS}s") from exc
    if result.returncode != 0:
        raise PolicyError(f"opa eval failed ({result.returncode}): {(result.stderr or result.stdout).strip()[:500]}")
    try:
        output = json.loads(result.stdout)
        violations = output["result"][0]["expressions"][0]["value"] if output.get("result") else []
    except (ValueError, KeyError, IndexError) as exc:
        raise PolicyError(f"unexpected opa output: {exc}") from exc

    violations = sorted(violations, key=lambda v: (-SEVERITY_ORDER.index(v["severity"]), v["rule_id"], v["resource"]))
    resources = len(document["resources"]) if kind == "kubernetes" else 1
    return Evaluation(target=target, target_kind=kind, allowed=not violations, violations=violations,
                      engine_version=opa_version(), resources=resources)
