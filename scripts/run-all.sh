#!/usr/bin/env bash
# Runs the whole PipelineSentry stack end to end and prints a PASS/FAIL summary (Linux / macOS).
#
#   ./scripts/run-all.sh                   start everything, run demos and all checks, keep it running
#   ./scripts/run-all.sh --skip-tests      start everything and run the demos only (quicker, lighter)
#   ./scripts/run-all.sh --skip-dashboard  backend, demos and checks only (no Node.js needed)
#   ./scripts/run-all.sh --stop            tear the stack down at the end
#   ./scripts/run-all.sh --down            just stop a running stack and the dashboard
set -u

cd "$(dirname "$0")/.."
API_URL="http://localhost:8000"
DASHBOARD_URL="http://localhost:5173"
PID_FILE="${TMPDIR:-/tmp}/pipelinesentry-dashboard.pid"
# Docker Desktop's Bake integration can fail with "DeadlineExceeded" / "no such job"
export COMPOSE_BAKE=false

# npm starts vite as a child process, so stop the children first
stop_dashboard() {
  if [ -f "$PID_FILE" ]; then
    pid=$(cat "$PID_FILE"); pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; rm -f "$PID_FILE"
    echo "Dashboard stopped."
  fi
}

SKIP_TESTS=false SKIP_DASHBOARD=false STOP=false
for arg in "$@"; do
  case "$arg" in
    --skip-tests) SKIP_TESTS=true ;;
    --skip-dashboard) SKIP_DASHBOARD=true ;;
    --stop) STOP=true ;;
    --down)
      stop_dashboard; exec docker compose down ;;
    -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (see --help)"; exit 2 ;;
  esac
done

if [ -t 1 ]; then C='\033[36m' G='\033[32m' R='\033[31m' Y='\033[33m' N='\033[0m'; else C='' G='' R='' Y='' N=''; fi
STEPS=() RESULTS=()

section() { printf "\n${C}%s\n  %s\n%s${N}\n" "$(printf '=%.0s' {1..72})" "$1" "$(printf '=%.0s' {1..72})"; }
record() {
  STEPS+=("$1"); RESULTS+=("$2")
  if [ "$2" = PASS ]; then printf "  ${G}-> PASS${N}\n"; else printf "  ${R}-> FAIL %s${N}\n" "${3:-}"; fi
}
# run "<name>" cmd args...  -- live output, recorded as PASS when the command exits 0
run() {
  local name="$1"; shift
  printf "\n${Y}> %s${N}\n" "$name"
  if "$@"; then record "$name" PASS; return 0; else local code=$?; record "$name" FAIL "(exit code $code)"; return 1; fi
}
url_ok() { curl -fsS -o /dev/null --max-time 5 "$1" 2>/dev/null; }

summary() {
  section "Summary"
  local failed=0 i
  for i in "${!STEPS[@]}"; do
    if [ "${RESULTS[$i]}" = PASS ]; then printf "  ${G}PASS${N}  %s\n" "${STEPS[$i]}"
    else printf "  ${R}FAIL${N}  %s\n" "${STEPS[$i]}"; failed=$((failed + 1)); fi
  done
  echo
  if [ "$failed" -eq 0 ]; then printf "  ${G}ALL %d STEPS PASSED${N}\n" "${#STEPS[@]}"
  else printf "  ${R}%d OF %d STEPS FAILED - scroll up for the output of each failed step${N}\n" "$failed" "${#STEPS[@]}"; fi
  return "$failed"
}

# ---------------------------------------------------------------------------
section "1/6  Prerequisites"
command -v docker >/dev/null || { echo "Docker is not installed: https://docs.docker.com/get-docker/"; exit 1; }
docker info --format 'Docker engine {{.ServerVersion}}, {{.NCPU}} CPUs, memory for containers: {{.MemTotal}} bytes' \
  || { printf "${R}The Docker engine is not running. Start it and re-run.${N}\n"; exit 1; }
command -v curl >/dev/null || { echo "curl is required"; exit 1; }
if ! $SKIP_DASHBOARD && ! command -v npm >/dev/null; then
  printf "${Y}Node.js/npm not found: skipping the dashboard (install Node 18+ to include it).${N}\n"; SKIP_DASHBOARD=true
fi
[ -f .env ] || { cp .env.example .env && echo "Created .env from .env.example"; }
record "Prerequisites" PASS

# ---------------------------------------------------------------------------
section "2/6  Backend (Postgres, RabbitMQ, Redis, registry, API, worker, responder)"
echo "Building and starting containers. The first run takes several minutes."
if ! run "docker compose up" docker compose up -d --build --wait; then
  # The API can report unhealthy if it came up before RabbitMQ; it reconnects by itself, so retry once
  printf "${Y}Retrying once (a service may have started before its dependency was ready)...${N}\n"
  last=$((${#STEPS[@]} - 1)); unset "STEPS[$last]" "RESULTS[$last]"  # bash 3.2 (macOS): no negative indices
  run "docker compose up" docker compose up -d --wait
fi
docker compose ps

printf "\nWaiting for %s/health ...\n" "$API_URL"
healthy=false
for _ in $(seq 1 40); do
  body=$(curl -fsS --max-time 5 "$API_URL/health" 2>/dev/null) && echo "$body" | grep -q '"status":"ok"' && { healthy=true; break; }
  sleep 3
done
if $healthy; then echo "$body"; record "API health" PASS
else
  record "API health" FAIL "see: docker compose logs api rabbitmq"
  printf "${R}The backend is not healthy, so the demos cannot run. Troubleshooting: README.md > Quick Start.${N}\n"
  summary; exit 1
fi

# ---------------------------------------------------------------------------
section "3/6  Dashboard"
if $SKIP_DASHBOARD; then echo "Skipped."
elif url_ok "$DASHBOARD_URL"; then echo "Already running at $DASHBOARD_URL"; record "Dashboard" PASS
else
  if [ ! -d dashboard/node_modules ]; then
    cd dashboard; run "npm ci" npm ci --no-audit --no-fund; cd ..
  fi
  (cd dashboard && nohup npm run dev > ../dashboard-dev.log 2>&1 & echo $! > "$PID_FILE")
  echo "Starting the dev server (log: dashboard-dev.log) ..."
  up=false
  for _ in $(seq 1 30); do url_ok "$DASHBOARD_URL" && { up=true; break; }; sleep 2; done
  if $up; then record "Dashboard" PASS; else record "Dashboard" FAIL "see dashboard-dev.log"; fi
fi

# ---------------------------------------------------------------------------
section "4/6  Attack scenarios (detection layers)"
for id in 01 02 03 04 05 06 07; do
  run "Attack scenario $id" docker compose exec -T api python attack-lab/run.py "$id"
done

# ---------------------------------------------------------------------------
section "5/6  End-to-end demo: detection -> response -> recovery -> signing -> SBOM -> policy"
run "End-to-end demo" docker compose exec -T api python scripts/demo_member2.py

# ---------------------------------------------------------------------------
section "6/6  Checks"
if $SKIP_TESTS; then echo "Skipped (--skip-tests)."
else
  run "Python test suite (unit + integration)" docker compose exec -T api pytest -q -p no:cacheprovider
  run "OPA policy tests" docker compose exec -T api opa test policy/opa -v
  run "Kyverno policy tests" docker run --rm -v "$PWD/policy:/policy" ghcr.io/kyverno/kyverno-cli:v1.13.2 test /policy/kyverno
  if ! $SKIP_DASHBOARD; then
    (cd dashboard && npm run type-check) && record "Dashboard type-check" PASS || record "Dashboard type-check" FAIL
  fi
fi

# ---------------------------------------------------------------------------
summary; failed=$?
echo
if $STOP; then
  stop_dashboard; docker compose down; echo "Stack stopped."
else
  printf "${C}Still running - look around:${N}\n"
  $SKIP_DASHBOARD || echo "  Dashboard        $DASHBOARD_URL"
  echo "  API docs         $API_URL/docs"
  echo "  Incidents (JSON) $API_URL/incidents"
  echo "  RabbitMQ UI      http://localhost:15672   (user/password from .env)"
  echo
  echo "Stop everything:   ./scripts/run-all.sh --down"
fi
exit "$failed"
