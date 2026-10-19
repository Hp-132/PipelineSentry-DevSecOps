import hashlib
import statistics

import numpy as np
from sklearn.ensemble import IsolationForest

from detection.alerts import Finding

MODEL_FEATURES = [
    "duration_seconds", "step_count", "max_cpu_percent",
    "domain_count", "files_touched_count", "repo_operation_count",
]
DRIFT_CHECKS = {
    "duration_seconds": ("duration_drift", "up"),
    "step_count": ("step_count_drift", "both"),
    "max_cpu_percent": ("cpu_drift", "up"),
    "files_touched_count": ("files_touched_drift", "up"),
}
RULE_WEIGHTS = {
    "sensitive_repo_operation": 55,
    "sensitive_file_touched": 45,
    "new_outbound_domain": 35,
    "cpu_drift": 30,
    "duration_drift": 20,
    "isolation_forest_anomaly": 20,
    "step_count_drift": 15,
    "new_repo_operation": 15,
    "files_touched_drift": 10,
}
SENSITIVE_FILES = (".ssh/", "id_rsa", "id_ed25519", ".aws/credentials", ".git-credentials",
                   ".docker/config.json", "/etc/shadow", "/etc/passwd", ".npmrc", ".pypirc", ".github/workflows/")
SENSITIVE_OPERATIONS = ("branch_protection.", "push.force", "deploy_key.", "secret.", "webhook.",
                        "collaborator.", "workflow.modify", "repo.visibility", "release.delete")
MIN_RULE_BASELINE = 5
MIN_MODEL_BASELINE = 20
Z_THRESHOLD = 3.0

_model_cache: dict[str, tuple[IsolationForest, float]] = {}


def derived_features(run: dict) -> dict[str, float | None]:
    def count(key):
        value = run.get(key)
        return float(len(value)) if isinstance(value, list) else None

    def number(key):
        value = run.get(key)
        return float(value) if isinstance(value, (int, float)) else None

    return {
        "duration_seconds": number("duration_seconds"),
        "step_count": number("step_count"),
        "max_cpu_percent": number("max_cpu_percent"),
        "domain_count": count("outbound_domains"),
        "files_touched_count": count("files_touched"),
        "repo_operation_count": count("repo_operations"),
    }


def severity_for(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 55:
        return "high"
    if score >= 30:
        return "med"
    return "low"


def _drift_rules(observed: dict, baseline_rows: list[dict]) -> tuple[list[dict], dict]:
    rules, comparison = [], {}
    for feature, (rule, direction) in DRIFT_CHECKS.items():
        value = observed[feature]
        history = [row[feature] for row in baseline_rows if row[feature] is not None]
        if value is None or len(history) < MIN_RULE_BASELINE:
            continue
        mean = statistics.fmean(history)
        # floor the spread so a near-constant baseline does not flag tiny changes
        std = max(statistics.pstdev(history), 0.05 * abs(mean), 1.0)
        upper, lower = mean + Z_THRESHOLD * std, mean - Z_THRESHOLD * std
        comparison[feature] = {"observed": value, "baseline_mean": round(mean, 2), "baseline_std": round(std, 2),
                               "upper_limit": round(upper, 2)}
        if value > upper or (direction == "both" and value < lower):
            rules.append({"rule": rule, **comparison[feature]})
    return rules, comparison


def _set_rules(run: dict, baseline: list[dict]) -> list[dict]:
    rules = []
    domains = set(run.get("outbound_domains") or [])
    files = run.get("files_touched") or []
    operations = set(run.get("repo_operations") or [])

    if baseline and "outbound_domains" in run:
        known = {d for row in baseline for d in row.get("outbound_domains", [])}
        new = sorted(domains - known)
        if new:
            rules.append({"rule": "new_outbound_domain", "new_domains": new, "known_domains": sorted(known)})

    sensitive_files = [f for f in files if any(p in f for p in SENSITIVE_FILES)]
    if sensitive_files:
        rules.append({"rule": "sensitive_file_touched", "files": sensitive_files})

    sensitive_ops = sorted(op for op in operations if op.startswith(SENSITIVE_OPERATIONS))
    if sensitive_ops:
        rules.append({"rule": "sensitive_repo_operation", "operations": sensitive_ops})
    elif baseline and "repo_operations" in run:
        known_ops = {op for row in baseline for op in row.get("repo_operations", [])}
        new_ops = sorted(operations - known_ops)
        if new_ops:
            rules.append({"rule": "new_repo_operation", "operations": new_ops})
    return rules


def _model_for(matrix: np.ndarray) -> tuple[IsolationForest, float]:
    key = hashlib.sha1(matrix.tobytes()).hexdigest()
    if key not in _model_cache:
        model = IsolationForest(n_estimators=100, random_state=42).fit(matrix)
        # anything scoring below the least-normal 1% of clean runs counts as anomalous
        threshold = float(np.percentile(model.score_samples(matrix), 1))
        _model_cache[key] = (model, threshold)
    return _model_cache[key]


def _isolation_forest(observed: dict, baseline_rows: list[dict]) -> dict:
    if len(baseline_rows) < MIN_MODEL_BASELINE:
        return {"status": "skipped", "reason": f"{len(baseline_rows)} baseline runs, need {MIN_MODEL_BASELINE}"}
    medians = {}
    for f in MODEL_FEATURES:
        values = [row[f] for row in baseline_rows if row[f] is not None]
        medians[f] = statistics.median(values) if values else 0.0
    matrix = np.array([[row[f] if row[f] is not None else medians[f] for f in MODEL_FEATURES] for row in baseline_rows])
    sample = np.array([[observed[f] if observed[f] is not None else medians[f] for f in MODEL_FEATURES]])
    model, threshold = _model_for(matrix)
    score = float(model.score_samples(sample)[0])
    return {"status": "ok", "score": round(score, 4), "threshold": round(threshold, 4),
            "anomalous": score < threshold, "features": MODEL_FEATURES}


def analyse_run(run: dict, baseline: list[dict]) -> dict:
    observed = derived_features(run)
    baseline_rows = [derived_features(row) for row in baseline]
    drift, comparison = _drift_rules(observed, baseline_rows)
    rules = drift + _set_rules(run, baseline)
    anomaly = _isolation_forest(observed, baseline_rows)
    if anomaly.get("anomalous"):
        rules.append({"rule": "isolation_forest_anomaly", "score": anomaly["score"], "threshold": anomaly["threshold"]})

    for rule in rules:
        rule["weight"] = RULE_WEIGHTS[rule["rule"]]
    score = min(100, sum(rule["weight"] for rule in rules))
    return {
        "observed": run,
        "baseline_size": len(baseline),
        "baseline_comparison": comparison,
        "missing_features": [f for f, v in observed.items() if v is None],
        "triggered_rules": rules,
        "isolation_forest": anomaly,
        "risk_score": score,
        "severity": severity_for(score),
        "baseline_note": "baseline is synthetic clean-run data" if baseline else "no baseline for this workflow",
    }


def detect(run: dict, baseline: list[dict]) -> list[Finding]:
    result = analyse_run(run, baseline)
    if not result["triggered_rules"]:
        return []
    names = ", ".join(r["rule"] for r in result["triggered_rules"])
    return [Finding(
        rule_id="BEH-001",
        title=f"Run behaviour deviates from baseline: {names}",
        severity=result["severity"],
        recommendation="Compare this run with recent clean runs; investigate new domains, operations and resource use.",
        evidence=result,
        risk_score=result["risk_score"],
    )]
