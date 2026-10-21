"""Cosign key-pair signing and verification.

Runs offline against the local registry: signatures are not uploaded to the Rekor transparency log
(--tlog-upload=false) and verification skips the log (--insecure-ignore-tlog). Verification status comes
only from `cosign verify`'s exit code and its JSON output, never from a sign command having been run.
"""

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from shared import config
from supply_chain.registry import ImageRef, RegistryClient, RegistryError, parse

VERIFIED, UNSIGNED, FAILED = "verified", "unsigned", "verification_failed"
TOOL_UNAVAILABLE, ERROR, INVALID = "tool_unavailable", "error", "invalid_input"


class CosignError(Exception):
    pass


class CosignUnavailable(CosignError):
    pass


@dataclass
class Verification:
    image: str
    status: str
    digest: str | None = None
    pinned_image: str | None = None
    key_fingerprint: str | None = None
    signatures: list[dict] = field(default_factory=list)
    detail: str = ""
    tool_version: str | None = None
    tool_output: str = ""

    @property
    def conclusive(self) -> bool:
        """True when cosign actually answered the signed/unsigned question."""
        return self.status in (VERIFIED, UNSIGNED, FAILED)


def cosign_path() -> str:
    path = shutil.which("cosign")
    if not path:
        raise CosignUnavailable("cosign binary not found on PATH; it ships in the PipelineSentry Docker image "
                                "(or install it from https://github.com/sigstore/cosign/releases)")
    return path


def tool_version() -> str | None:
    try:
        out = subprocess.run([cosign_path(), "version", "--json"], capture_output=True, text=True, timeout=10)
        return json.loads(out.stdout).get("gitVersion")
    except (CosignError, ValueError, OSError, subprocess.TimeoutExpired):
        return None


def key_paths(key_dir: str | Path | None = None) -> tuple[Path, Path]:
    directory = Path(key_dir or config.COSIGN_KEY_DIR)
    return directory / "cosign.key", directory / "cosign.pub"


def fingerprint(public_key: Path) -> str:
    return "sha256:" + hashlib.sha256(public_key.read_bytes()).hexdigest()[:16]


def _env() -> dict:
    return {**os.environ, "COSIGN_PASSWORD": config.COSIGN_PASSWORD, "COSIGN_YES": "true"}


def _registry_flags(ref: ImageRef) -> list[str]:
    return ["--allow-insecure-registry", "--allow-http-registry"] if ref.insecure else []


def _run(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run([cosign_path(), *args], capture_output=True, text=True, env=_env(), cwd=cwd,
                              timeout=config.COSIGN_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise CosignError(f"cosign timed out after {config.COSIGN_TIMEOUT_SECONDS}s") from exc


def generate_key_pair(key_dir: str | Path | None = None) -> Path:
    """Create cosign.key/cosign.pub if missing; returns the public key path."""
    private, public = key_paths(key_dir)
    if private.exists() and public.exists():
        return public
    if not config.COSIGN_PASSWORD:
        raise CosignError("COSIGN_PASSWORD must be set to create an encrypted demo key pair")
    private.parent.mkdir(parents=True, exist_ok=True)
    result = _run(["generate-key-pair"], cwd=private.parent)
    if result.returncode != 0:
        raise CosignError(f"cosign generate-key-pair failed: {result.stderr.strip()[:500]}")
    return public


def sign(image: str, key_dir: str | Path | None = None) -> dict:
    """Sign an image by digest. Only registries in SIGNING_ALLOWED_REGISTRIES may be written to."""
    ref = parse(image)
    if ref.registry not in config.SIGNING_ALLOWED_REGISTRIES:
        raise CosignError(f"signing is only allowed for {config.SIGNING_ALLOWED_REGISTRIES}, not {ref.registry}")
    private, public = key_paths(key_dir)
    if not private.exists():
        raise CosignError(f"no private key at {private}; run key generation first")
    with RegistryClient() as registry:
        digest = ref.digest or registry.manifest_digest(ref)
    if digest is None:
        raise CosignError(f"image {image} not found in registry")
    pinned = ref.pinned(digest)
    result = _run(["sign", "--key", str(private), "--tlog-upload=false", *_registry_flags(ref), pinned])
    if result.returncode != 0:
        raise CosignError(f"cosign sign failed: {result.stderr.strip()[:500]}")
    return {"image": pinned, "digest": digest, "key_fingerprint": fingerprint(public)}


def _signatures_from_output(stdout: str, keyid: str) -> list[dict]:
    try:
        payloads = json.loads(stdout)
    except json.JSONDecodeError:
        return []
    signatures = []
    for item in payloads if isinstance(payloads, list) else []:
        critical = item.get("critical", {})
        signatures.append({"verified": True, "keyid": keyid,
                           "subject_digest": critical.get("image", {}).get("docker-manifest-digest"),
                           "issuer": (item.get("optional") or {}).get("Issuer")})
    return signatures


def verify(image: str, public_key: str | Path | None = None, registry: RegistryClient | None = None) -> Verification:
    try:
        ref = parse(image)
    except RegistryError as exc:
        return Verification(image, INVALID, detail=str(exc))
    public = Path(public_key) if public_key else key_paths()[1]
    try:
        cosign_path()
    except CosignUnavailable as exc:
        return Verification(image, TOOL_UNAVAILABLE, detail=str(exc))
    if not public.exists():
        return Verification(image, ERROR, detail=f"public key not found at {public}")
    keyid = fingerprint(public)

    own_client = registry is None
    registry = registry or RegistryClient()
    try:
        digest = ref.digest or registry.manifest_digest(ref)
        if digest is None:
            return Verification(image, INVALID, key_fingerprint=keyid, detail="image not found in registry")
        has_signature = registry.has_signature_tag(ref, digest)
    except RegistryError as exc:
        return Verification(image, ERROR, key_fingerprint=keyid, detail=str(exc))
    finally:
        if own_client:
            registry.client.close()

    pinned = ref.pinned(digest)
    result = _run(["verify", "--key", str(public), "--insecure-ignore-tlog=true", "--output", "json",
                   *_registry_flags(ref), pinned])
    output = (result.stderr or "").strip()[-1500:]
    base = dict(image=image, digest=digest, pinned_image=pinned, key_fingerprint=keyid,
                tool_version=tool_version(), tool_output=output)

    if result.returncode == 0:
        signatures = _signatures_from_output(result.stdout, keyid)
        matching = [s for s in signatures if s["subject_digest"] == digest]
        if matching:
            return Verification(status=VERIFIED, signatures=matching,
                                detail=f"{len(matching)} signature(s) verified with key {keyid}", **base)
        return Verification(status=FAILED, signatures=[{**s, "verified": False} for s in signatures],
                            detail="cosign succeeded but no signature covers this digest", **base)
    if not has_signature:
        return Verification(status=UNSIGNED, detail="no cosign signature exists for this digest", **base)
    return Verification(status=FAILED, signatures=[{"verified": False, "keyid": keyid, "subject_digest": None}],
                        detail="a signature exists but does not verify with the trusted key", **base)
