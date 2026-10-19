import re

from detection.alerts import Finding
from detection.payloads import FalcoEvent

KNOWN_RULES = {
    "PipelineSentry Reverse Shell in Runner": ("RT-SHELL", "critical"),
    "PipelineSentry Unexpected Shell in Runner": ("RT-SHELL", "high"),
    "PipelineSentry Suspicious Outbound Connection": ("RT-NET", "high"),
    "PipelineSentry Credential File Read": ("RT-CRED", "high"),
    "PipelineSentry Crypto Miner Activity": ("RT-MINER", "critical"),
}
PRIORITY_SEVERITY = {
    "Emergency": "critical", "Alert": "critical", "Critical": "critical", "Error": "high",
    "Warning": "med", "Notice": "low", "Informational": "low", "Info": "low", "Debug": "low",
}
SEVERITY_ORDER = ["low", "med", "high", "critical"]

INDICATORS = [
    ("reverse_shell_redirect", re.compile(r"/dev/(tcp|udp)/|\bnc\b.*\s-e\s|bash -i"), "critical"),
    ("mining_pool_protocol", re.compile(r"stratum\+(tcp|ssl)://"), "critical"),
    ("miner_binary", re.compile(r"\b(xmrig|minerd|cpuminer|ethminer)\b"), "critical"),
    ("credential_file", re.compile(r"\.aws/credentials|\.git-credentials|\.ssh/id_|/etc/shadow|\.docker/config\.json"), "high"),
]
SUSPICIOUS_PORTS = {3333, 4444, 5555, 6666, 7777, 14444, 45700}

RECOMMENDATIONS = {
    "RT-SHELL": "Stop the job, isolate the runner and review the step that spawned the shell.",
    "RT-NET": "Block the destination, check what data left the runner and restrict runner egress.",
    "RT-CRED": "Rotate the credentials in that file and remove them from the runner image.",
    "RT-MINER": "Kill the job, rebuild the runner and audit how the binary entered the pipeline.",
    "RT-OTHER": "Review the Falco event and the job that triggered it.",
}


def detect(event: FalcoEvent) -> list[Finding]:
    rule_id, severity = KNOWN_RULES.get(event.rule, ("RT-OTHER", PRIORITY_SEVERITY[event.priority]))
    fields = event.output_fields
    text = " ".join(str(fields.get(k, "")) for k in ("proc.cmdline", "proc.name", "fd.name")) + " " + event.output

    indicators = []
    for name, pattern, indicator_severity in INDICATORS:
        if pattern.search(text):
            indicators.append(name)
            severity = max(severity, indicator_severity, key=SEVERITY_ORDER.index)
    port = fields.get("fd.sport") or fields.get("fd.rport")
    if str(port).isdigit() and int(port) in SUSPICIOUS_PORTS:
        indicators.append(f"suspicious_port_{port}")
        severity = max(severity, "high", key=SEVERITY_ORDER.index)

    observation = "simulated" if event.simulated else "falco"
    title = f"Runtime: {event.rule}" + (" (simulated)" if event.simulated else "")
    return [Finding(
        rule_id=rule_id,
        title=title[:255],
        severity=severity,
        recommendation=RECOMMENDATIONS[rule_id],
        evidence={
            "observation": observation,
            "falco_rule": event.rule,
            "falco_priority": event.priority,
            "falco_time": event.time.isoformat(),
            "falco_source": event.source,
            "output": event.output,
            "output_fields": fields,
            "indicators": indicators,
            "hostname": event.hostname,
        },
        key=f"{event.rule}:{event.time.isoformat()}",
    )]
