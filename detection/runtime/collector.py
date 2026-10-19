"""Forward Falco JSON events (one per line) to the detection API.

Real Falco:      falco -o json_output=true ... | python -m detection.runtime.collector
Simulated demo:  python -m detection.runtime.collector --file events.jsonl --simulated --run-id demo-1
"""

import argparse
import json
import logging
import sys

import httpx
from pydantic import ValidationError

from detection.payloads import FalcoEvent

log = logging.getLogger("collector")


def forward(lines, client: httpx.Client, overrides: dict) -> dict:
    counts = {"sent": 0, "invalid": 0, "rejected": 0}
    for number, line in enumerate(lines, start=1):
        line = line.strip()
        if not line:
            continue
        try:
            event = FalcoEvent.model_validate({**json.loads(line), **overrides})
        except (json.JSONDecodeError, ValidationError) as exc:
            log.warning("line %d is not a valid Falco event: %s", number, exc)
            counts["invalid"] += 1
            continue
        response = client.post("/events/falco", json=event.model_dump(mode="json"))
        if response.status_code in (200, 202):
            counts["sent"] += 1
            log.info("line %d -> %s", number, response.json().get("event_id"))
        else:
            counts["rejected"] += 1
            log.warning("line %d rejected (%d): %s", number, response.status_code, response.text[:200])
    return counts


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument("--file", help="JSON-lines file; reads stdin if omitted")
    parser.add_argument("--simulated", action="store_true", help="mark events as simulated, not real Falco")
    parser.add_argument("--run-id")
    parser.add_argument("--workflow")
    parser.add_argument("--attack-id")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    overrides = {k: v for k, v in {"run_id": args.run_id, "workflow": args.workflow,
                                   "attack_id": args.attack_id}.items() if v}
    if args.simulated:
        overrides["simulated"] = True
    with httpx.Client(base_url=args.api, timeout=10) as client:
        if args.file:
            with open(args.file, encoding="utf-8") as handle:
                counts = forward(handle, client, overrides)
        else:
            counts = forward(sys.stdin, client, overrides)
    print(json.dumps(counts))
    return 0 if counts["invalid"] == 0 and counts["rejected"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
