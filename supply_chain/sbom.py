"""CycloneDX SBOM generation (cyclonedx-py) and schema validation (cyclonedx-python-lib)."""

import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

SPEC_VERSION = "1.6"
ENVIRONMENT = "python-environment"


class SbomError(Exception):
    pass


class SbomToolUnavailable(SbomError):
    pass


class UnsupportedManifest(SbomError):
    pass


@dataclass
class SbomResult:
    subject: str
    document: dict
    valid: bool
    validation_error: str | None
    tool_version: str | None
    components: list[dict] = field(default_factory=list)


def _command() -> list[str]:
    exe = shutil.which("cyclonedx-py")
    if exe:
        return [exe]
    try:
        import cyclonedx_py  # noqa: F401
    except ImportError as exc:
        raise SbomToolUnavailable("cyclonedx-bom is not installed (pip install cyclonedx-bom)") from exc
    return [sys.executable, "-m", "cyclonedx_py"]


def tool_version() -> str | None:
    try:
        from importlib.metadata import version
        return version("cyclonedx-bom")
    except Exception:
        return None


def validate(document_text: str) -> str | None:
    """Return None if the text is a valid CycloneDX 1.6 JSON document, else the validation error."""
    try:
        from cyclonedx.schema import SchemaVersion
        from cyclonedx.validation.json import JsonStrictValidator
    except ImportError as exc:
        raise SbomToolUnavailable("cyclonedx-python-lib[json-validation] is not installed") from exc
    error = JsonStrictValidator(SchemaVersion.V1_6).validate_str(document_text)
    return None if error is None else str(error)[:1000]


def _subcommand(target: Path | str) -> list[str]:
    if target == ENVIRONMENT:
        return ["environment", sys.executable]
    path = Path(target)
    if not path.is_file():
        raise SbomError(f"manifest not found: {path}")
    name = path.name.lower()
    if name.endswith(".txt") and "requirements" in name:
        return ["requirements", str(path)]
    if name == "pyproject.toml":
        raise UnsupportedManifest("pyproject.toml needs an installed environment; use the environment SBOM")
    raise UnsupportedManifest(f"no CycloneDX generator configured for '{path.name}' "
                              "(supported: requirements*.txt and the running Python environment)")


def generate(target: Path | str, subject: str | None = None, timeout: int = 120) -> SbomResult:
    cmd = _command() + _subcommand(target) + ["--sv", SPEC_VERSION, "--of", "JSON", "--output-reproducible",
                                              "--no-validate", "-o", "-"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise SbomError(f"cyclonedx-py timed out after {timeout}s") from exc
    if result.returncode != 0:
        raise SbomError(f"cyclonedx-py failed ({result.returncode}): {result.stderr.strip()[:500]}")
    try:
        document = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise SbomError(f"cyclonedx-py did not produce JSON: {exc}") from exc

    error = validate(result.stdout)
    components = [{"name": c.get("name"), "version": c.get("version"), "purl": c.get("purl"),
                   "type": c.get("type")} for c in document.get("components", [])]
    return SbomResult(subject=subject or str(target), document=document, valid=error is None,
                      validation_error=error, tool_version=tool_version(), components=components)
