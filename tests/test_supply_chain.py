"""Member 2 — supply chain: CycloneDX SBOMs, cosign verification outcomes and alert association."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest

from detection.payloads import ImagePayload
from detection.static.image_rules import scan_image
from shared import config
from supply_chain import cosign, registry, sbom, service
from tests.m2_factories import memory_session_factory

ROOT = Path(__file__).resolve().parents[1]
TYPOSQUAT_REQUIREMENTS = ROOT / "attack-lab" / "03-dependency-typosquat" / "requirements.txt"
DIGEST = "sha256:" + "b" * 64


@pytest.fixture
def session():
    s = memory_session_factory()()
    yield s
    s.close()


class Emitter:
    def __init__(self):
        self.events = []

    def __call__(self, events):
        self.events += events
        return [e.event_id for e in events]


# --- image references ---------------------------------------------------------------------------


class TestImageReferences:

    @pytest.mark.parametrize("image,expected", [
        ("registry:5000/demo/app:1", ("registry:5000", "demo/app", "1", None)),
        (f"ghcr.io/org/app@{DIGEST}", ("ghcr.io", "org/app", None, DIGEST)),
        ("alpine", ("registry-1.docker.io", "library/alpine", None, None)),
        ("localhost:5000/app:dev", ("localhost:5000", "app", "dev", None)),
    ])
    def test_parse(self, image, expected):
        ref = registry.parse(image)
        assert (ref.registry, ref.repository, ref.tag, ref.digest) == expected

    @pytest.mark.parametrize("image", ["", "has space/app", "ghcr.io/org/app@sha256:short", "ghcr.io/Org/App:1"])
    def test_invalid_references(self, image):
        with pytest.raises(registry.RegistryError):
            registry.parse(image)


# --- SBOM ---------------------------------------------------------------------------------------


class TestSbom:

    def test_generates_valid_cyclonedx(self):
        result = sbom.generate(TYPOSQUAT_REQUIREMENTS)
        assert result.valid, result.validation_error
        assert result.document["bomFormat"] == "CycloneDX"
        assert result.document["specVersion"] == sbom.SPEC_VERSION
        names = {c["name"] for c in result.components}
        assert {"colourama", "flask"} <= names
        assert all(c["purl"].startswith("pkg:pypi/") for c in result.components)

    def test_output_is_reproducible(self):
        assert sbom.generate(TYPOSQUAT_REQUIREMENTS).document == sbom.generate(TYPOSQUAT_REQUIREMENTS).document

    def test_validator_rejects_broken_documents(self):
        good = json.dumps(sbom.generate(TYPOSQUAT_REQUIREMENTS).document)
        assert sbom.validate(good) is None
        broken = json.loads(good)
        broken["components"][0]["type"] = "not-a-component-type"
        assert sbom.validate(json.dumps(broken)) is not None

    def test_missing_and_unsupported_inputs(self, tmp_path):
        with pytest.raises(sbom.SbomError, match="not found"):
            sbom.generate(tmp_path / "requirements.txt")
        package_json = tmp_path / "package.json"
        package_json.write_text("{}")
        with pytest.raises(sbom.UnsupportedManifest):
            sbom.generate(package_json)

    def test_service_records_sbom_and_feeds_dependency_rules(self, session):
        emit = Emitter()
        result = service.generate_sbom(session, TYPOSQUAT_REQUIREMENTS, "attack-lab/03/requirements.txt",
                                       emit=emit, run_id="sc-run-1")
        assert result["status"] == "generated" and result["has_document"]
        assert result["summary"]["schema_valid"] and result["summary"]["component_count"] >= 2
        [event] = emit.events
        assert event.kind == "dependency" and event.run_id == "sc-run-1" and event.source == "supply-chain"
        assert "colourama" in event.payload["content"]
        assert result["event_ids"] == [event.event_id]

    def test_tool_unavailable_is_reported_not_faked(self, session):
        with patch.object(sbom, "_command", side_effect=sbom.SbomToolUnavailable("cyclonedx-bom is not installed")):
            result = service.generate_sbom(session, TYPOSQUAT_REQUIREMENTS, "req.txt", emit=Emitter())
        assert result["status"] == "tool_unavailable" and not result["has_document"] and result["event_ids"] == []


# --- cosign verification outcomes (cosign and registry replaced by fakes) -------------------------


class FakeRegistry:
    def __init__(self, digest=DIGEST, signed=False, error=None):
        self.digest, self.signed, self.error = digest, signed, error
        self.client = httpx.Client()

    def manifest_digest(self, ref, reference=None):
        if self.error:
            raise registry.RegistryError(self.error)
        return self.digest

    def has_signature_tag(self, ref, digest):
        return self.signed


def fake_cosign(returncode, stdout="", stderr=""):
    return patch.object(cosign, "_run", return_value=subprocess.CompletedProcess([], returncode, stdout, stderr))


@pytest.fixture
def public_key(tmp_path):
    key = tmp_path / "cosign.pub"
    key.write_text("-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----\n")
    with patch.object(cosign, "cosign_path", return_value="cosign"), patch.object(cosign, "tool_version", return_value="v-test"):
        yield key


IMAGE = "registry:5000/demo/app:1"


class TestVerification:

    def test_verified_only_when_cosign_confirms_this_digest(self, public_key):
        payload = json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}, "type": "cosign container image signature"}}])
        with fake_cosign(0, stdout=payload):
            result = cosign.verify(IMAGE, public_key, FakeRegistry(signed=True))
        assert result.status == cosign.VERIFIED
        assert result.signatures[0]["verified"] and result.signatures[0]["subject_digest"] == DIGEST
        assert result.pinned_image == f"registry:5000/demo/app@{DIGEST}"

    def test_success_exit_without_matching_digest_is_a_failure(self, public_key):
        payload = json.dumps([{"critical": {"image": {"docker-manifest-digest": "sha256:" + "c" * 64}}}])
        with fake_cosign(0, stdout=payload):
            result = cosign.verify(IMAGE, public_key, FakeRegistry(signed=True))
        assert result.status == cosign.FAILED

    def test_unsigned_image(self, public_key):
        with fake_cosign(1, stderr="Error: no signatures found"):
            result = cosign.verify(IMAGE, public_key, FakeRegistry(signed=False))
        assert result.status == cosign.UNSIGNED and result.signatures == []

    def test_signature_from_another_key_fails_verification(self, public_key):
        with fake_cosign(1, stderr="Error: no matching signatures: invalid signature"):
            result = cosign.verify(IMAGE, public_key, FakeRegistry(signed=True))
        assert result.status == cosign.FAILED
        assert result.signatures == [{"verified": False, "keyid": cosign.fingerprint(public_key), "subject_digest": None}]
        assert "invalid signature" in result.tool_output

    def test_unreachable_registry_and_missing_image(self, public_key):
        assert cosign.verify(IMAGE, public_key, FakeRegistry(error="unreachable")).status == cosign.ERROR
        assert cosign.verify(IMAGE, public_key, FakeRegistry(digest=None)).status == cosign.INVALID

    def test_invalid_reference_missing_key_and_missing_tool(self, tmp_path, public_key):
        assert cosign.verify("not a valid ref", public_key).status == cosign.INVALID
        assert cosign.verify(IMAGE, tmp_path / "missing.pub").status == cosign.ERROR
        with patch.object(cosign, "cosign_path", side_effect=cosign.CosignUnavailable("no cosign")):
            assert cosign.verify(IMAGE, public_key).status == cosign.TOOL_UNAVAILABLE

    def test_signing_refuses_unapproved_registries(self):
        with pytest.raises(cosign.CosignError, match="only allowed"):
            cosign.sign("ghcr.io/someone/else:latest")


# --- association with Member 1's image rules -----------------------------------------------------


class TestAlertAssociation:

    @pytest.mark.parametrize("returncode,signed,stdout,rules", [
        (1, False, "", {"IMG-001"}),
        (1, True, "", {"IMG-002"}),
        (0, True, json.dumps([{"critical": {"image": {"docker-manifest-digest": DIGEST}}}]), set()),
    ])
    def test_verification_becomes_image_event_for_existing_rules(self, session, public_key, returncode, signed,
                                                                 stdout, rules):
        emit = Emitter()
        with fake_cosign(returncode, stdout=stdout), \
             patch.object(cosign, "RegistryClient", return_value=FakeRegistry(signed=signed)):
            result = service.verify_image(session, IMAGE, emit=emit, run_id="sc-run-2", public_key=str(public_key))
        [event] = emit.events
        assert event.kind == "image" and event.run_id == "sc-run-2"
        findings = scan_image(ImagePayload.model_validate(event.payload).model_dump())
        assert {f.rule_id for f in findings} == rules
        assert result["event_ids"] == [event.event_id]

    def test_inconclusive_results_raise_no_alert(self, session):
        emit = Emitter()
        with patch.object(cosign, "cosign_path", side_effect=cosign.CosignUnavailable("no cosign")):
            result = service.verify_image(session, IMAGE, emit=emit)
        assert result["status"] == "tool_unavailable" and emit.events == []


# --- registry client (HTTP mocked) ----------------------------------------------------------------


class TestRegistryClient:

    def test_push_demo_image_is_deterministic_and_resolvable(self):
        blobs, manifests = {}, {}

        def handler(request):
            path = request.url.path
            if request.method == "POST" and path.endswith("/blobs/uploads/"):
                return httpx.Response(202, headers={"Location": "/v2/demo/app/blobs/uploads/u1"})
            if request.method == "PUT" and "/blobs/uploads/" in path:
                blobs[request.url.params["digest"]] = request.content
                return httpx.Response(201)
            if request.method == "PUT" and "/manifests/" in path:
                manifests[path.rsplit("/", 1)[1]] = request.content
                return httpx.Response(201)
            if request.method == "HEAD" and "/manifests/" in path:
                tag = path.rsplit("/", 1)[1]
                if tag not in manifests:
                    return httpx.Response(404)
                import hashlib
                return httpx.Response(200, headers={"Docker-Content-Digest": "sha256:" + hashlib.sha256(manifests[tag]).hexdigest()})
            return httpx.Response(400)

        ref = registry.parse("registry:5000/demo/app:v1")
        with registry.RegistryClient(transport=httpx.MockTransport(handler)) as client:
            first = client.push_demo_image(ref, "hello")
            second = client.push_demo_image(ref, "hello")
            assert first == second == client.manifest_digest(ref)
            assert client.push_demo_image(registry.parse("registry:5000/demo/app:v2"), "tampered") != first
            assert not client.has_signature_tag(ref, first)
        assert len(blobs) == 4


# --- real cosign + registry (Docker Compose stack) ------------------------------------------------


@pytest.mark.integration
class TestRealCosign:
    """Runs inside the api container: `make test` (needs cosign and the local registry)."""

    @pytest.fixture
    def keys(self, tmp_path):
        if not shutil.which("cosign"):
            pytest.skip("cosign not installed")
        try:
            httpx.get("http://registry:5000/v2/", timeout=3)
        except httpx.HTTPError:
            pytest.skip("local registry not reachable")
        with patch.object(config, "COSIGN_PASSWORD", "test-password"):
            trusted = cosign.generate_key_pair(tmp_path / "trusted")
            other = cosign.generate_key_pair(tmp_path / "other")
            yield trusted, other, tmp_path

    def test_sign_verify_and_reject(self, keys):
        trusted, other, tmp_path = keys
        tag = uuid4().hex[:8]
        with patch.object(config, "COSIGN_PASSWORD", "test-password"), registry.RegistryClient() as client:
            signed_digest = client.push_demo_image(registry.parse(f"registry:5000/test/signed:{tag}"), f"signed {tag}")
            client.push_demo_image(registry.parse(f"registry:5000/test/unsigned:{tag}"), f"unsigned {tag}")
            client.push_demo_image(registry.parse(f"registry:5000/test/forged:{tag}"), f"forged {tag}")
            cosign.sign(f"registry:5000/test/signed:{tag}", tmp_path / "trusted")
            cosign.sign(f"registry:5000/test/forged:{tag}", tmp_path / "other")

        verified = cosign.verify(f"registry:5000/test/signed:{tag}", trusted)
        assert verified.status == cosign.VERIFIED and verified.digest == signed_digest
        assert cosign.verify(f"registry:5000/test/unsigned:{tag}", trusted).status == cosign.UNSIGNED
        assert cosign.verify(f"registry:5000/test/forged:{tag}", trusted).status == cosign.FAILED
        assert cosign.verify(f"registry:5000/test/forged:{tag}", other).status == cosign.VERIFIED
        assert os.path.exists(tmp_path / "trusted" / "cosign.key")
