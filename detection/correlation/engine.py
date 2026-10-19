"""Groups alerts by run_id and computes a weighted, explainable 0-100 risk score.

The score is a rule-based priority indicator, not a calibrated probability.

    signal points  = SEVERITY_POINTS[severity] * LAYER_CONFIDENCE[layer]
    layer points   = min(LAYER_CAP, sum of that layer's signal points)
    diversity      = DIVERSITY_BONUS * (number of independent layers - 1)
    score          = min(100, max(sum(layer points) + diversity, highest child risk_score))

Repeated alerts with the same (layer, rule_id) count once, so duplicates cannot inflate the score.
"""

from collections import Counter

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from detection.alerts import alert_id
from detection.behaviour.detector import severity_for
from shared import config
from shared.database import as_utc, record_to_alert
from shared.models import AlertRecord
from shared.schema import Alert

SEVERITY_POINTS = {"low": 5, "med": 12, "high": 22, "critical": 35}
LAYER_CONFIDENCE = {"static": 0.8, "behaviour": 0.7, "runtime": 1.0}
LAYER_CAP = 40
DIVERSITY_BONUS = 15
SEVERITY_ORDER = ["low", "med", "high", "critical"]

RECOMMENDATIONS = {
    "critical": "Treat as an active pipeline compromise: cancel the run, revoke exposed credentials, quarantine the runner.",
    "high": "Pause deployments from this run and investigate the linked alerts before releasing.",
    "med": "Review the linked alerts and fix the flagged configuration.",
    "low": "Review when convenient.",
}


def _signature(alert) -> tuple[str, str]:
    return alert.layer, (alert.evidence or {}).get("rule_id") or alert.title


def score_alerts(alerts) -> dict:
    children = [a for a in alerts if a.layer != "correlation"]
    strongest = {}
    for alert in children:
        sig = _signature(alert)
        current = strongest.get(sig)
        if current is None or (SEVERITY_ORDER.index(alert.severity), alert.risk_score) > (
            SEVERITY_ORDER.index(current.severity), current.risk_score
        ):
            strongest[sig] = alert

    layers: dict[str, dict] = {}
    for (layer, rule), alert in sorted(strongest.items()):
        points = round(SEVERITY_POINTS[alert.severity] * LAYER_CONFIDENCE[layer], 1)
        entry = layers.setdefault(layer, {"signals": [], "raw_points": 0.0})
        entry["signals"].append({"rule_id": rule, "severity": alert.severity, "points": points, "alert_id": alert.id})
        entry["raw_points"] += points
    for entry in layers.values():
        entry["points"] = min(LAYER_CAP, round(entry["raw_points"], 1))

    layer_total = sum(entry["points"] for entry in layers.values())
    diversity = DIVERSITY_BONUS * max(0, len(layers) - 1)
    highest = max((a.risk_score for a in children), default=0)
    computed = round(layer_total + diversity)
    score = min(100, max(computed, highest))

    reasons = [f"{layer}: {len(e['signals'])} distinct signal(s) worth {e['points']} points"
               + (f" (capped from {round(e['raw_points'], 1)})" if e["raw_points"] > LAYER_CAP else "")
               for layer, e in layers.items()]
    if diversity:
        reasons.append(f"{len(layers)} independent layers flagged this run: +{diversity}")
    if highest > computed:
        reasons.append(f"score raised to the highest single alert score ({highest})")
    duplicates = len(children) - len(strongest)
    if duplicates:
        reasons.append(f"{duplicates} repeated alert(s) ignored")

    return {
        "risk_score": score,
        "severity": severity_for(score),
        "components": {
            "layers": layers,
            "layer_total": round(layer_total, 1),
            "diversity_bonus": diversity,
            "highest_child_score": highest,
            "computed_score": computed,
        },
        "layer_count": len(layers),
        "distinct_signals": len(strongest),
        "duplicates_ignored": duplicates,
        "reasons": reasons,
        "weights": {"severity_points": SEVERITY_POINTS, "layer_confidence": LAYER_CONFIDENCE,
                    "layer_cap": LAYER_CAP, "diversity_bonus": DIVERSITY_BONUS},
    }


def criteria_met(result: dict) -> bool:
    return result["layer_count"] >= config.CORRELATION_MIN_LAYERS or result["risk_score"] >= config.CORRELATION_MIN_SCORE


def rollup_id(run_id: str) -> str:
    return alert_id("correlation", run_id)


def correlate_run(session: Session, run_id: str) -> dict:
    """Create or refresh the single roll-up alert for a run. Safe to call repeatedly."""
    if session.get_bind().dialect.name == "postgresql":
        session.execute(text("SELECT pg_advisory_xact_lock(hashtext(:run_id))"), {"run_id": run_id})

    records = session.scalars(
        select(AlertRecord).where(AlertRecord.run_id == run_id).order_by(AlertRecord.timestamp, AlertRecord.id)
    ).all()
    children = [r for r in records if r.layer != "correlation"]
    if not children:
        return {"run_id": run_id, "rollup": None, "criteria_met": False, "reason": "no alerts for this run"}

    result = score_alerts(children)
    if not criteria_met(result):
        return {"run_id": run_id, "rollup": None, "criteria_met": False, "score": result,
                "reason": f"needs {config.CORRELATION_MIN_LAYERS} layers or score >= {config.CORRELATION_MIN_SCORE}"}

    attack_ids = {c.attack_id for c in children}
    child_ids = sorted(c.id for c in children)
    layer_names = ", ".join(sorted(result["components"]["layers"]))
    rollup = Alert(
        id=rollup_id(run_id),
        run_id=run_id,
        workflow=Counter(c.workflow for c in children).most_common(1)[0][0],
        timestamp=max(as_utc(c.timestamp) for c in children),
        layer="correlation",
        attack_id=attack_ids.pop() if len(attack_ids) == 1 else None,
        severity=result["severity"],
        risk_score=result["risk_score"],
        title=f"Correlated incident: {result['distinct_signals']} signal(s) across {layer_names}",
        evidence={**result, "child_alert_ids": child_ids},
        recommended_action=RECOMMENDATIONS[result["severity"]],
    )

    existing = session.get(AlertRecord, rollup.id)
    if existing is None:
        session.add(AlertRecord(**rollup.model_dump()))
        session.flush()
    else:
        new_children = existing.evidence.get("child_alert_ids") != child_ids
        for field in ("workflow", "timestamp", "attack_id", "severity", "risk_score", "title", "evidence",
                      "recommended_action"):
            setattr(existing, field, getattr(rollup, field))
        if new_children and existing.status == "handled":
            existing.status = "new"
    for child in children:
        if child.parent_alert_id != rollup.id:
            child.parent_alert_id = rollup.id
    session.flush()
    return {"run_id": run_id, "rollup": rollup, "criteria_met": True, "score": result}


def build_timeline(session: Session, run_id: str) -> dict:
    records = session.scalars(
        select(AlertRecord).where(AlertRecord.run_id == run_id).order_by(AlertRecord.timestamp, AlertRecord.created_at)
    ).all()
    rollup = next((r for r in records if r.layer == "correlation"), None)
    entries = [
        {
            "timestamp": as_utc(r.timestamp).isoformat(),
            "alert_id": r.id,
            "layer": r.layer,
            "severity": r.severity,
            "risk_score": r.risk_score,
            "rule_id": (r.evidence or {}).get("rule_id"),
            "title": r.title,
            "attack_id": r.attack_id,
            "observation": (r.evidence or {}).get("observation"),
        }
        for r in records if r.layer != "correlation"
    ]
    return {
        "run_id": run_id,
        "alert_count": len(entries),
        "layers": sorted({e["layer"] for e in entries}),
        "rollup": record_to_alert(rollup).model_dump(mode="json") if rollup else None,
        "entries": entries,
    }
