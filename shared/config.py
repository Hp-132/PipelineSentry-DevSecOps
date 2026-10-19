import os


def _bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./pipelinesentry.db")
RABBITMQ_URL = os.getenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/%2F")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

EVENT_QUEUE = os.getenv("EVENT_QUEUE", "events")
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
DEDUP_TTL_SECONDS = int(os.getenv("DEDUP_TTL_SECONDS", "86400"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "30"))

CORRELATION_MIN_LAYERS = int(os.getenv("CORRELATION_MIN_LAYERS", "2"))
CORRELATION_MIN_SCORE = int(os.getenv("CORRELATION_MIN_SCORE", "70"))
BASELINE_RUNS_PER_WORKFLOW = int(os.getenv("BASELINE_RUNS_PER_WORKFLOW", "60"))

SCAN_ROOT = os.getenv("SCAN_ROOT", "/app")
ALLOW_UNSIGNED_WEBHOOKS = _bool("ALLOW_UNSIGNED_WEBHOOKS")
GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "")
