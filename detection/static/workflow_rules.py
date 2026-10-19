import re

import yaml

from detection.alerts import Finding, PermanentError


class WorkflowParseError(PermanentError):
    pass


SHA_PIN = re.compile(r"^[0-9a-f]{40}$")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
TO_JSON_SECRETS = re.compile(r"toJSON\(\s*secrets\s*\)", re.I)
NETWORK_COMMAND = re.compile(r"\b(curl|wget|nc|ncat|netcat|scp|invoke-webrequest|invoke-restmethod|iwr|irm)\b", re.I)
PRINT_COMMAND = re.compile(r"\b(echo|printf|write-host|write-output)\b", re.I)
ENV_DUMP = re.compile(r"^\s*(env|printenv|export -p|set)\s*($|\||>)")
URL_HOST = re.compile(r"(?:https?|ftp)://([^/\s:\"'`]+)", re.I)
FORCE_PUSH = re.compile(r"\bgit\s+push\b.*(--force|\s-f\b|--mirror|--delete|\s\+\S+)")
REPO_API_CALL = re.compile(r"\bgh\s+api\b|api\.github\.com")
SENSITIVE_API_PATH = re.compile(r"branches/[^/\s]+/protection|/keys\b|/hooks\b|/collaborators\b|/actions/secrets|/actions/permissions|/rulesets")
GH_ADMIN_COMMAND = re.compile(r"\bgh\s+(secret\s+(set|delete)|repo\s+(edit|delete)|release\s+delete)\b")

PRIVILEGED_TRIGGERS = {"pull_request_target", "workflow_run"}
UNTRUSTED_INPUTS = (
    "github.head_ref",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.workflow_run.head_branch",
)
PR_CODE_REFS = (
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.merge_commit_sha",
    "github.head_ref",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "refs/pull/",
)
TRUSTED_HOSTS = {"api.github.com", "uploads.github.com", "github.com", "ghcr.io", "registry.npmjs.org", "upload.pypi.org"}


def parse_workflow(content: str) -> dict:
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}" if mark else ""
        raise WorkflowParseError(f"invalid YAML{where}: {getattr(exc, 'problem', exc)}") from exc
    if not isinstance(data, dict):
        raise WorkflowParseError("workflow must be a YAML mapping")
    if not isinstance(data.get("jobs"), dict) or not data["jobs"]:
        raise WorkflowParseError("not a GitHub Actions workflow: missing 'jobs' mapping")
    return data


def triggers_of(workflow: dict) -> set[str]:
    # PyYAML (YAML 1.1) reads the bare key `on` as boolean True
    on = workflow.get("on", workflow.get(True))
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


def _secret_env_names(env) -> set[str]:
    if not isinstance(env, dict):
        return set()
    return {name for name, value in env.items() if "secrets." in str(value) or "github.token" in str(value)}


def _references_env(line: str, names: set[str]) -> bool:
    return any(re.search(rf"\$\{{?{re.escape(n)}\b|\$env:{re.escape(n)}\b|%{re.escape(n)}%", line) for n in names)


class _Scanner:
    def __init__(self, content: str, path: str):
        self.content = content
        self.path = path
        self.lines = content.splitlines()
        self.workflow = parse_workflow(content)
        self.triggers = triggers_of(self.workflow)
        self.findings: list[Finding] = []

    def line_of(self, needle: str) -> int | None:
        needle = needle.strip()
        if not needle:
            return None
        for number, line in enumerate(self.lines, start=1):
            if needle in line:
                return number
        return None

    def add(self, rule_id, title, severity, recommendation, key="", **evidence):
        evidence = {"file": self.path, **evidence}
        if "snippet" in evidence:
            evidence["snippet"] = str(evidence["snippet"])[:200]
        self.findings.append(Finding(rule_id, title, severity, recommendation, evidence, key))

    def jobs(self):
        for job_id, job in self.workflow["jobs"].items():
            if isinstance(job, dict):
                yield str(job_id), job

    def steps(self, job):
        steps = job.get("steps") or []
        for index, step in enumerate(steps if isinstance(steps, list) else []):
            if isinstance(step, dict):
                yield index, step, str(step.get("name") or step.get("uses") or f"step {index + 1}")

    def has_write_permissions(self) -> bool:
        levels = [self.workflow.get("permissions")] + [job.get("permissions") for _, job in self.jobs()]
        for perms in levels:
            if perms == "write-all":
                return True
            if isinstance(perms, dict) and "write" in perms.values():
                return True
        return False

    def run(self) -> list[Finding]:
        self.check_untrusted_checkout()
        self.check_unpinned_actions()
        self.check_permissions()
        self.check_run_steps()
        self.check_workflow_env()
        self.check_to_json_secrets()
        return self.findings

    def check_untrusted_checkout(self):
        privileged = self.triggers & PRIVILEGED_TRIGGERS
        if not privileged:
            return
        exposes_secrets = "secrets." in self.content or self.has_write_permissions()
        for job_id, job in self.jobs():
            for index, step, name in self.steps(job):
                uses = str(step.get("uses", ""))
                ref = str((step.get("with") or {}).get("ref", ""))
                if uses.startswith("actions/checkout") and any(r in ref for r in PR_CODE_REFS):
                    self.add(
                        "PPE-001",
                        f"{sorted(privileged)[0]} workflow checks out untrusted pull-request code",
                        "critical" if exposes_secrets else "high",
                        "Use the pull_request trigger for untrusted code, or never check out the PR head in a privileged workflow.",
                        key=f"{job_id}:{index}",
                        job=job_id, step=name, line=self.line_of(ref), triggers=sorted(self.triggers),
                        checkout_ref=ref, secrets_or_write_token_available=exposes_secrets,
                    )

    def check_unpinned_actions(self):
        unpinned = []
        for job_id, job in self.jobs():
            refs = [("job", str(job["uses"]))] if job.get("uses") else []
            refs += [(name, str(step["uses"])) for _, step, name in self.steps(job) if step.get("uses")]
            for step_name, uses in refs:
                if uses.startswith("./") or (uses.startswith("docker://") and "@sha256:" in uses):
                    continue
                version = uses.rsplit("@", 1)[1] if "@" in uses else ""
                if not SHA_PIN.match(version):
                    unpinned.append({"job": job_id, "step": step_name, "uses": uses, "line": self.line_of(uses)})
        if unpinned:
            first_party = all(u["uses"].split("/")[0] in {"actions", "github"} for u in unpinned)
            self.add(
                "PIN-001",
                f"{len(unpinned)} action reference(s) not pinned to a commit SHA",
                "low" if first_party else "med",
                "Pin every third-party action to a full 40-character commit SHA.",
                actions=unpinned,
            )

    def check_permissions(self):
        levels = [("workflow", self.workflow.get("permissions"))]
        levels += [(f"job:{job_id}", job.get("permissions")) for job_id, job in self.jobs()]
        declared = False
        for scope, perms in levels:
            if perms is None:
                continue
            declared = True
            if perms == "write-all":
                self.add(
                    "PERM-001", f"GITHUB_TOKEN granted write-all at {scope} level", "high",
                    "Declare least-privilege permissions, e.g. `permissions: contents: read`.",
                    key=scope, scope=scope, permissions=perms, line=self.line_of("write-all"),
                )
            elif isinstance(perms, dict):
                writes = sorted(k for k, v in perms.items() if v == "write")
                if len(writes) >= 3:
                    self.add(
                        "PERM-002", f"Broad write permissions at {scope} level", "med",
                        "Remove write scopes the workflow does not need.",
                        key=scope, scope=scope, write_scopes=writes,
                    )
        if not declared:
            privileged = bool(self.triggers & PRIVILEGED_TRIGGERS)
            self.add(
                "PERM-003", "Workflow does not declare GITHUB_TOKEN permissions",
                "med" if privileged else "low",
                "Add an explicit top-level `permissions:` block so the default token scope is not used.",
                triggers=sorted(self.triggers),
            )

    def check_workflow_env(self):
        names = _secret_env_names(self.workflow.get("env"))
        if names:
            self.add(
                "ENV-001", "Secrets exposed to every job through workflow-level env", "low",
                "Move secrets to the env of the single step that needs them.",
                variables=sorted(names),
            )

    def check_to_json_secrets(self):
        match = TO_JSON_SECRETS.search(self.content)
        if match:
            self.add(
                "SEC-001", "Entire secrets context serialised with toJSON(secrets)", "critical",
                "Reference only the individual secrets a step needs.",
                line=self.content[: match.start()].count("\n") + 1, snippet=match.group(0),
            )

    def check_run_steps(self):
        workflow_secret_env = _secret_env_names(self.workflow.get("env"))
        privileged = bool(self.triggers & PRIVILEGED_TRIGGERS)
        for job_id, job in self.jobs():
            job_secret_env = workflow_secret_env | _secret_env_names(job.get("env"))
            for index, step, name in self.steps(job):
                script = step.get("run")
                if not isinstance(script, str):
                    continue
                secret_env = job_secret_env | _secret_env_names(step.get("env"))
                where = {"job": job_id, "step": name}

                for expr in EXPRESSION.findall(script):
                    hit = next((ctx for ctx in UNTRUSTED_INPUTS if ctx in expr), None)
                    if hit:
                        self.add(
                            "INJ-001", f"Untrusted input `{hit}` interpolated into a shell script",
                            "critical" if privileged else "high",
                            "Pass the value through an env variable and quote it instead of using ${{ }} in run.",
                            key=f"{job_id}:{index}:{hit}", context=hit, line=self.line_of(expr), **where,
                        )

                for line in script.splitlines():
                    self.check_script_line(line, secret_env, job_id, index, where)

    def check_script_line(self, line, secret_env, job_id, index, where):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            return
        key = f"{job_id}:{index}:{stripped[:60]}"
        location = {**where, "line": self.line_of(stripped), "snippet": stripped}
        uses_secret = any("secrets." in e for e in EXPRESSION.findall(stripped)) or _references_env(stripped, secret_env)

        if uses_secret and NETWORK_COMMAND.search(stripped):
            hosts = URL_HOST.findall(stripped)
            untrusted = [h for h in hosts if h.lower() not in TRUSTED_HOSTS]
            if untrusted or not hosts:
                self.add(
                    "SEC-002", "Secret sent to an external host by a network command",
                    "critical" if untrusted else "high",
                    "Remove the command, rotate the exposed secret and restrict runner egress.",
                    key=key, destination_hosts=untrusted or hosts, **location,
                )
        elif uses_secret and PRINT_COMMAND.search(stripped):
            piped_to_login = "--password-stdin" in stripped or "GITHUB_ENV" in stripped
            if not piped_to_login:
                self.add(
                    "SEC-003", "Secret printed to the build log", "high",
                    "Never echo secrets; base64 or other encoding also bypasses log masking.",
                    key=key, encoded="base64" in stripped, **location,
                )

        if ENV_DUMP.match(stripped) and secret_env:
            self.add(
                "SEC-004", "Environment dumped in a job that holds secrets", "med",
                "Remove env/printenv debugging from jobs with secret environment variables.",
                key=key, secret_variables=sorted(secret_env), **location,
            )

        sensitive_api = REPO_API_CALL.search(stripped) and SENSITIVE_API_PATH.search(stripped)
        if FORCE_PUSH.search(stripped) or sensitive_api or GH_ADMIN_COMMAND.search(stripped):
            self.add(
                "REPO-001", "Workflow performs a sensitive repository operation", "high",
                "Review why CI needs this; use a scoped token and branch protection that CI cannot change.",
                key=key, **location,
            )


def scan_workflow(content: str, path: str = "workflow.yml") -> list[Finding]:
    return _Scanner(content, path).run()
