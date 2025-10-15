.PHONY: bootstrap bootstrap-agent compose-up compose-down compose-logs test test-integration smoke

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
