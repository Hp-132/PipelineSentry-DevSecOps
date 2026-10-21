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



def _list(name: str, default: str = "") -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


CORS_ORIGINS = _list("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
# How the API reaches itself (attack-lab runs triggered from the dashboard)
SELF_URL = os.getenv("SELF_URL", "http://127.0.0.1:8000")


# --- Member 2: response ---
# dry_run records the plan only; simulated changes PipelineSentry's own containment state; live calls real APIs
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "dry_run")
RESPONSE_MIN_SCORE = int(os.getenv("RESPONSE_MIN_SCORE", "70"))
RESPONSE_MAX_ATTEMPTS = int(os.getenv("RESPONSE_MAX_ATTEMPTS", "3"))
RESPONSE_POLL_SECONDS = float(os.getenv("RESPONSE_POLL_SECONDS", "5"))
RESPONSE_LIVE_ENABLED = _bool("RESPONSE_LIVE_ENABLED")
RESPONSE_LIVE_ACTIONS = _list("RESPONSE_LIVE_ACTIONS", "cancel_pipeline")
RESPONSE_API_TOKEN = os.getenv("RESPONSE_API_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "")
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com")

# --- Member 2: supply chain ---
COSIGN_KEY_DIR = os.getenv("COSIGN_KEY_DIR", "./.cosign")
COSIGN_PASSWORD = os.getenv("COSIGN_PASSWORD", "")
COSIGN_TIMEOUT_SECONDS = int(os.getenv("COSIGN_TIMEOUT_SECONDS", "60"))
# Registries reached over plain HTTP (local demo registry only)
INSECURE_REGISTRIES = _list("INSECURE_REGISTRIES", "registry:5000,localhost:5000")
SIGNING_ALLOWED_REGISTRIES = _list("SIGNING_ALLOWED_REGISTRIES", "registry:5000,localhost:5000")

# --- Member 2: policy ---
OPA_TIMEOUT_SECONDS = int(os.getenv("OPA_TIMEOUT_SECONDS", "30"))
ALLOWED_REGISTRIES = _list("ALLOWED_REGISTRIES", "registry:5000,ghcr.io/pipelinesentry")
