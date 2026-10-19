import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from detection.alerts import Finding, PermanentError


class GitleaksUnavailable(PermanentError):
    pass


class GitleaksError(PermanentError):
    pass


def gitleaks_path() -> str:
    path = shutil.which("gitleaks")
    if not path:
        raise GitleaksUnavailable(
            "gitleaks binary not found on PATH. Run scans inside the Docker image "
            "(it ships gitleaks) or install it from https://github.com/gitleaks/gitleaks/releases"
        )
    return path


def run_gitleaks(target: Path, timeout: int = 120) -> list[dict]:
    if not target.exists():
        raise GitleaksError(f"scan target does not exist: {target}")
    binary = gitleaks_path()
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        # --exit-code 0 means leaks do not fail the command, so a non-zero code is a real error
        cmd = [binary, "dir", str(target), "--no-banner", "--redact", "--exit-code", "0",
               "--report-format", "json", "--report-path", str(report)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise GitleaksError(f"gitleaks timed out after {timeout}s") from exc
        if result.returncode != 0:
            raise GitleaksError(f"gitleaks failed ({result.returncode}): {result.stderr.strip()[:500]}")
        if not report.exists():
            raise GitleaksError("gitleaks produced no report")
        return json.loads(report.read_text() or "[]")


def scan_secrets(target: Path, display_root: Path | None = None) -> list[Finding]:
    findings = []
    for leak in run_gitleaks(target):
        file = Path(leak.get("File", ""))
        if display_root is not None:
            try:
                file = file.relative_to(display_root)
            except ValueError:
                pass
        rule = leak.get("RuleID", "unknown")
        findings.append(Finding(
            rule_id=f"GL-{rule}",
            title=f"Committed secret detected by gitleaks ({rule})",
            severity="high",
            recommendation="Remove the secret from the repository and history, then rotate it.",
            evidence={
                "file": str(file),
                "line": leak.get("StartLine"),
                "gitleaks_rule": rule,
                "description": leak.get("Description"),
                "redacted_match": leak.get("Match"),
                "fingerprint": leak.get("Fingerprint"),
            },
            key=leak.get("Fingerprint") or f"{file}:{leak.get('StartLine')}:{rule}",
        ))
    return findings
