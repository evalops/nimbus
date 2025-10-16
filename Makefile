.PHONY: bootstrap compose-up compose-down compose-logs test test-integration smoke build-web lint-web build-docker-cache

bootstrap:
	uv run python scripts/bootstrap_compose.py --output .env --secrets-output bootstrap-tokens.json

compose-up:
	docker compose up --build

compose-down:
	docker compose down

compose-logs:
	docker compose logs --follow

test:
	uv run pytest

test-integration:
	uv run pytest tests/integration

smoke:
	uv run python scripts/run_smoke.py

build-web:
	cd web && npm install && npm run build

lint-web:
	cd web && npm install && npm run lint

build-docker-cache:
	uv run python -m compileall src/nimbus/docker_cache

audit:
	./scripts/dependency_audit.sh

coverage:
	uv run --with pytest-cov pytest --cov=src --cov-report=term-missing --cov-fail-under=85

scan-images:
	docker build -t nimbus-control-plane:ci .
	trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed --no-progress nimbus-control-plane:ci
	docker build -t nimbus-ai-runner:ci containers/ai-eval-runner
	trivy image --exit-code 1 --severity HIGH,CRITICAL --ignore-unfixed --no-progress nimbus-ai-runner:ci
	docker image rm -f nimbus-control-plane:ci nimbus-ai-runner:ci >/dev/null 2>&1 || true
