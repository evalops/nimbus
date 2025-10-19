.PHONY: bootstrap compose-up compose-down compose-logs test test-integration smoke build-web lint-web build-docker-cache scan-images clean-images

SBOM_OUTPUT ?= 0
SBOM_DIR ?= sbom
TRIVY_SEVERITY ?= HIGH,CRITICAL
KEEP_IMAGES ?= 0

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
	uv sync --extra dev
	uv run python -m pytest --cov=src --cov-report=term-missing --cov-fail-under=66

scan-images:
	@if [ "$(SBOM_OUTPUT)" = "1" ]; then mkdir -p $(SBOM_DIR); fi
	@if docker buildx version >/dev/null 2>&1; then \
		docker buildx build --load --platform=linux/amd64 -t nimbus-control-plane:ci --provenance=false .; \
	else \
		echo "docker buildx not available; falling back to docker build (SBOM disabled)"; \
		docker build -t nimbus-control-plane:ci .; \
	fi
	@if [ "$(SBOM_OUTPUT)" = "1" ]; then \
		trivy image --format cyclonedx --output $(SBOM_DIR)/nimbus-control-plane.cdx.json nimbus-control-plane:ci || echo "trivy sbom generation failed; skipping SBOM" >&2; \
	fi
	trivy image --exit-code 1 --severity $(TRIVY_SEVERITY) --ignore-unfixed --no-progress nimbus-control-plane:ci
	@if docker buildx version >/dev/null 2>&1; then \
		docker buildx build --load --platform=linux/amd64 -t nimbus-ai-runner:ci --provenance=false containers/ai-eval-runner; \
	else \
		echo "docker buildx not available; falling back to docker build (SBOM disabled)"; \
		docker build -t nimbus-ai-runner:ci containers/ai-eval-runner; \
	fi
	@if [ "$(SBOM_OUTPUT)" = "1" ]; then \
		trivy image --format cyclonedx --output $(SBOM_DIR)/nimbus-ai-runner.cdx.json nimbus-ai-runner:ci || echo "trivy sbom generation failed; skipping SBOM" >&2; \
	fi
	trivy image --exit-code 1 --severity $(TRIVY_SEVERITY) --ignore-unfixed --no-progress nimbus-ai-runner:ci
	if [ "$(KEEP_IMAGES)" != "1" ]; then \
		docker image rm -f nimbus-control-plane:ci nimbus-ai-runner:ci >/dev/null 2>&1 || true; \
	fi
