COMPOSE = docker compose
# Attack scenario ID: 01-07
ID ?= 01

.PHONY: env up down reset test test-unit logs ps baseline attack demo demo-m2 test-policy test-kyverno

env:
	@test -f .env || (cp .env.example .env && echo "Created .env from .env.example")

up: env
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

reset:
	@echo "WARNING: this deletes all stored alerts, events, baselines and queued messages."
	@read -p "Type 'yes' to continue: " answer && [ "$$answer" = "yes" ]
	$(COMPOSE) down -v

test: up
	$(COMPOSE) run --rm api pytest -q

test-unit: env
	$(COMPOSE) build api
	$(COMPOSE) run --rm --no-deps api pytest -q -m "not integration"

logs:
	$(COMPOSE) logs -f --tail=100 api worker responder

ps:
	$(COMPOSE) ps

baseline:
	$(COMPOSE) exec -T worker python -m detection.behaviour.baseline

attack:
	$(COMPOSE) exec -T api python attack-lab/run.py $(ID)

demo:
	@echo "=== PipelineSentry end-to-end demo ==="
	@echo "1. Running scenario 01 (poisoned pipeline — static layer)"
	$(COMPOSE) exec -T api python attack-lab/run.py 01
	@echo ""
	@echo "2. Running scenario 04 (unsigned/tampered image — static layer)"
	$(COMPOSE) exec -T api python attack-lab/run.py 04
	@echo ""
	@echo "3. Running scenario 05 (anomalous run behaviour — behaviour layer)"
	$(COMPOSE) exec -T api python attack-lab/run.py 05
	@echo ""
	@echo "4. Running scenario 06 (runtime compromise — runtime layer)"
	$(COMPOSE) exec -T api python attack-lab/run.py 06
	@echo ""
	@echo "5. Running scenario 07 (correlated multi-layer incident)"
	$(COMPOSE) exec -T api python attack-lab/run.py 07
	@echo ""
	@echo "=== Demo complete. Check /alerts and /health above. ==="

# Member 2: detection -> response -> recovery -> signatures -> SBOM -> policy
demo-m2:
	$(COMPOSE) exec -T api python scripts/demo_member2.py

# OPA/Rego unit tests (opa ships in the image)
test-policy: env
	$(COMPOSE) run --rm --no-deps api opa test policy/opa -v

# Kyverno policy tests, offline (no cluster needed)
test-kyverno:
	docker run --rm -v "$(CURDIR)/policy:/policy" ghcr.io/kyverno/kyverno-cli:v1.13.2 test /policy/kyverno
