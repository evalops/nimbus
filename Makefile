.PHONY: bootstrap compose-up compose-down compose-logs test test-integration smoke build-web lint-web build-docker-cache scan-images clean-images

SBOM_OUTPUT ?= 0
SBOM_DIR ?= sbom
TRIVY_SEVERITY ?= HIGH,CRITICAL

bootstrap:
	uv run python scripts/bootstrap_compose.py --output .env --secrets-output bootstrap-tokens.json

compose-up:
	docker compose up --build

compose-down:
	docker compose down

compose-logs:
	docker compose logs --follow

test:
	uv pip install pytest pytest-asyncio
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
	uv pip install pytest pytest-asyncio pytest-cov
	uv run --no-sync python -m pytest --cov=src --cov-report=term-missing --cov-fail-under=66

scan-images:
	@if [ "$(SBOM_OUTPUT)" = "1" ]; then mkdir -p $(SBOM_DIR); fi
	@if docker buildx version >/dev/null 2>&1; then \
		CONTROL_PLANE_SBOM_ARGS=""; \
		if [ "$(SBOM_OUTPUT)" = "1" ]; then CONTROL_PLANE_SBOM_ARGS="--attest type=sbom,dest=$(SBOM_DIR)/nimbus-control-plane.spdx.json"; fi; \
		docker buildx build --load -t nimbus-control-plane:ci $$CONTROL_PLANE_SBOM_ARGS .; \
	else \
		echo "docker buildx not available; falling back to docker build (SBOM disabled)"; \
		docker build -t nimbus-control-plane:ci .; \
	fi
	trivy image --exit-code 1 --severity $(TRIVY_SEVERITY) --ignore-unfixed --no-progress nimbus-control-plane:ci
	@if docker buildx version >/dev/null 2>&1; then \
		AI_RUNNER_SBOM_ARGS=""; \
		if [ "$(SBOM_OUTPUT)" = "1" ]; then AI_RUNNER_SBOM_ARGS="--attest type=sbom,dest=$(SBOM_DIR)/nimbus-ai-runner.spdx.json"; fi; \
		docker buildx build --load -t nimbus-ai-runner:ci $$AI_RUNNER_SBOM_ARGS containers/ai-eval-runner; \
	else \
		echo "docker buildx not available; falling back to docker build (SBOM disabled)"; \
		docker build -t nimbus-ai-runner:ci containers/ai-eval-runner; \
	fi
	trivy image --exit-code 1 --severity $(TRIVY_SEVERITY) --ignore-unfixed --no-progress nimbus-ai-runner:ci
	docker image rm -f nimbus-control-plane:ci nimbus-ai-runner:ci >/dev/null 2>&1 || true
