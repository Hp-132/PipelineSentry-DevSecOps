"""Synthetic clean-run baselines. This data is generated, not collected from real pipelines."""

import logging
import random

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from shared import config
from shared.models import BaselineRun

log = logging.getLogger(__name__)

PROFILES = {
    ".github/workflows/ci.yml": {
        "duration": (300, 30), "steps": (12, 1), "cpu": (55, 8),
        "domains": ["github.com", "api.github.com", "pypi.org", "files.pythonhosted.org", "registry.npmjs.org"],
        "files": ["src/app/main.py", "src/app/models.py", "src/app/utils.py", "tests/test_main.py",
                  "tests/test_models.py", "requirements.txt", "package-lock.json", "build/report.xml"],
        "operations": ["checkout", "status.create", "artifact.upload"],
    },
    ".github/workflows/release.yml": {
        "duration": (540, 45), "steps": (16, 1), "cpu": (65, 8),
        "domains": ["github.com", "api.github.com", "ghcr.io", "pypi.org", "files.pythonhosted.org"],
        "files": ["src/app/main.py", "Dockerfile", "dist/app.whl", "CHANGELOG.md", "pyproject.toml"],
        "operations": ["checkout", "status.create", "artifact.upload", "release.create", "package.publish"],
    },
    ".github/workflows/pr-check.yml": {
        "duration": (180, 20), "steps": (8, 1), "cpu": (45, 8),
        "domains": ["github.com", "api.github.com", "registry.npmjs.org"],
        "files": ["src/app/main.py", "src/app/utils.py", "tests/test_main.py", "package.json"],
        "operations": ["checkout", "status.create", "pr.comment"],
    },
}


def generate_clean_runs(workflow: str, count: int, seed: int = 42) -> list[dict]:
    profile = PROFILES[workflow]
    rng = random.Random(f"{seed}:{workflow}")
    runs = []
    for _ in range(count):
        domains = ["github.com"] + [d for d in profile["domains"][1:] if rng.random() < 0.8]
        files = [f for f in profile["files"] if rng.random() < 0.7] or profile["files"][:1]
        runs.append({
            "duration_seconds": round(max(30.0, rng.gauss(*profile["duration"])), 1),
            "step_count": max(1, round(rng.gauss(*profile["steps"]))),
            "outbound_domains": domains,
            "files_touched": files,
            "max_cpu_percent": round(min(100.0, max(5.0, rng.gauss(*profile["cpu"]))), 1),
            "repo_operations": [op for op in profile["operations"] if op == "checkout" or rng.random() < 0.7],
        })
    return runs


def seed_baselines(session: Session, count: int | None = None) -> dict[str, int]:
    count = count or config.BASELINE_RUNS_PER_WORKFLOW
    session.execute(delete(BaselineRun).where(BaselineRun.synthetic.is_(True)))
    seeded = {}
    for workflow in PROFILES:
        runs = generate_clean_runs(workflow, count)
        session.add_all(BaselineRun(workflow=workflow, features=r, synthetic=True) for r in runs)
        seeded[workflow] = len(runs)
    session.flush()
    log.info("seeded synthetic baselines: %s", seeded)
    return seeded


def seed_if_empty(session: Session) -> bool:
    if session.scalar(select(func.count()).select_from(BaselineRun)):
        return False
    seed_baselines(session)
    return True


def load_baseline(session: Session, workflow: str) -> list[dict]:
    rows = session.scalars(select(BaselineRun.features).where(BaselineRun.workflow == workflow).order_by(BaselineRun.id))
    return list(rows)


if __name__ == "__main__":
    from shared.database import init_db, session_scope

    logging.basicConfig(level=logging.INFO)
    init_db()
    with session_scope() as session:
        print(seed_baselines(session))
