import json
import re

from detection.alerts import Finding, PermanentError

POPULAR_PYPI = {
    "requests", "urllib3", "numpy", "pandas", "django", "flask", "fastapi", "boto3", "botocore",
    "setuptools", "pyyaml", "cryptography", "pytest", "scipy", "matplotlib", "pillow", "jinja2",
    "sqlalchemy", "psycopg2", "colorama", "python-dateutil", "certifi", "idna", "charset-normalizer",
    "click", "attrs", "packaging", "beautifulsoup4", "selenium", "tensorflow", "torch", "scikit-learn",
    "pydantic", "uvicorn", "httpx", "aiohttp", "redis", "paramiko", "openpyxl", "virtualenv",
}
POPULAR_NPM = {
    "express", "react", "react-dom", "lodash", "axios", "moment", "chalk", "commander", "debug",
    "request", "vue", "webpack", "typescript", "eslint", "jest", "next", "dotenv", "uuid",
    "cross-env", "colors", "async", "body-parser", "mongoose", "jsonwebtoken", "bcrypt", "cors",
    "nodemon", "socket.io", "electron", "yargs", "minimist", "underscore", "jquery", "babel-core",
}
LOOKALIKE = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "_": "-", ".": "-"})
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "prepare")
DOWNLOAD_EXEC = re.compile(r"\b(curl|wget|bash|sh\s+-c|node\s+-e|powershell|iwr|invoke-webrequest)\b", re.I)
REQUIREMENT_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")


def edit_distance(a: str, b: str) -> int:
    """Optimal string alignment distance (Levenshtein plus adjacent swaps)."""
    rows = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        rows[i][0] = i
    for j in range(len(b) + 1):
        rows[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            rows[i][j] = min(rows[i - 1][j] + 1, rows[i][j - 1] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                rows[i][j] = min(rows[i][j], rows[i - 2][j - 2] + 1)
    return rows[-1][-1]


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def typosquat_target(name: str, popular: set[str]) -> str | None:
    name = normalise(name)
    if name in popular:
        return None
    for target in sorted(popular):
        if len(target) < 4 or abs(len(target) - len(name)) > 2:
            continue
        allowed = 1 if len(target) <= 6 else 2
        if edit_distance(name, target) <= allowed or name.translate(LOOKALIKE) == target:
            return target
    return None


def _typosquat(name: str, manifest: str, line: int | None, popular: set[str]) -> Finding | None:
    target = typosquat_target(name, popular)
    if not target:
        return None
    return Finding(
        "DEP-001", f"Possible typosquatted dependency '{name}' (looks like '{target}')", "high",
        f"Confirm the package name; the intended package is probably '{target}'.",
        {"manifest": manifest, "package": name, "similar_to": target, "line": line},
        key=f"{manifest}:{name}",
    )


def scan_requirements(content: str, manifest: str) -> list[Finding]:
    findings = []
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.split(" #")[0].strip()
        if not line or line.startswith("#"):
            continue
        option = re.match(r"^(--index-url|-i|--extra-index-url)\s*=?\s*(\S+)", line)
        if option:
            url = option.group(2)
            extra = option.group(1) == "--extra-index-url"
            insecure = url.startswith("http://")
            findings.append(Finding(
                "DEP-002", "Non-default package index configured" + (" over plain HTTP" if insecure else ""),
                "high" if insecure or extra else "med",
                "Use a single trusted index; --extra-index-url enables dependency-confusion attacks.",
                {"manifest": manifest, "option": option.group(1), "url": url, "line": number},
                key=f"{manifest}:{number}",
            ))
            continue
        if line.startswith("-"):
            continue
        if "://" in line or line.startswith("git+"):
            findings.append(Finding(
                "DEP-003", "Dependency installed from a direct URL", "med",
                "Install from the package index with a pinned version and hash.",
                {"manifest": manifest, "requirement": line, "line": number}, key=f"{manifest}:{number}",
            ))
        name = REQUIREMENT_NAME.match(line)
        if name:
            finding = _typosquat(name.group(1), manifest, number, POPULAR_PYPI)
            if finding:
                findings.append(finding)
    return findings


def scan_package_json(content: str, manifest: str) -> list[Finding]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PermanentError(f"invalid package.json: {exc}") from exc
    findings = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            finding = _typosquat(name, manifest, None, POPULAR_NPM)
            if finding:
                finding.evidence["section"] = section
                findings.append(finding)
            if re.match(r"^(https?://|git\+|github:)", str(spec)):
                findings.append(Finding(
                    "DEP-003", f"Dependency '{name}' installed from a direct URL", "med",
                    "Install from the registry with a pinned version and lockfile integrity hash.",
                    {"manifest": manifest, "package": name, "spec": spec}, key=f"{manifest}:{name}:url",
                ))
    for hook in INSTALL_HOOKS:
        script = (data.get("scripts") or {}).get(hook)
        if script and DOWNLOAD_EXEC.search(script):
            findings.append(Finding(
                "DEP-004", f"npm '{hook}' script downloads or executes code", "high",
                "Remove the install hook or run installs with --ignore-scripts.",
                {"manifest": manifest, "hook": hook, "script": script[:200]}, key=f"{manifest}:{hook}",
            ))
    return findings


def scan_manifest(manifest: str, content: str) -> list[Finding]:
    filename = manifest.replace("\\", "/").rsplit("/", 1)[-1].lower()
    if filename.endswith(".txt") and "requirements" in filename:
        return scan_requirements(content, manifest)
    if filename == "package.json":
        return scan_package_json(content, manifest)
    raise PermanentError(f"unsupported manifest '{manifest}' (expected requirements*.txt or package.json)")
