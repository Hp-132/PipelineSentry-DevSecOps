"""Responder loop: polls for new correlated incidents and responds in RESPONSE_MODE.

    python -m response.worker            (the `responder` service in docker-compose.yml)
"""

import logging
import time

from response.engine import LiveNotAuthorized, eligible_alert_ids, respond
from shared import config
from shared.database import SessionLocal, init_db

log = logging.getLogger("responder")


def run_once(session_factory=SessionLocal, mode: str | None = None) -> list[dict]:
    with session_factory() as session:
        ids = eligible_alert_ids(session)
    results = []
    for alert_id in ids:
        try:
            # one transaction per alert, so one failure cannot roll back another alert's audit records
            with session_factory() as session, session.begin():
                results.append(respond(session, alert_id, mode=mode, requested_by="responder"))
        except LiveNotAuthorized as exc:
            log.error("live response not authorised: %s", exc)
        except Exception:
            log.exception("response for alert %s failed", alert_id)
    return results


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    init_db()
    log.info("responder started: mode=%s, min score=%d, poll every %ss", config.RESPONSE_MODE,
             config.RESPONSE_MIN_SCORE, config.RESPONSE_POLL_SECONDS)
    while True:
        try:
            run_once()
        except Exception:
            log.exception("responder poll failed")
        time.sleep(config.RESPONSE_POLL_SECONDS)


if __name__ == "__main__":
    main()
