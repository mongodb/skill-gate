.PHONY: all fmt lint test build tidy install-hooks e2e-live

# golangci-lint is the single source of truth for both formatting and linting,
# shared by the pre-commit hook (.pre-commit-config.yaml) and CI (ci.yml).

all: fmt lint test build

# Apply gofumpt formatting (the formatter configured in .golangci.yml).
fmt:
	golangci-lint fmt

# Run static analysis.
lint:
	golangci-lint run

# Run the test suite with the race detector.
test:
	go test -race ./... -count=1

# Build the CLI binary.
build:
	go build -o skill-gate ./cmd/skill-gate

# Run the live LLM-as-judge E2E against the configured provider. Loads .env if
# present (ANTHROPIC_API_KEY / ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_HEADER); the
# test self-skips when no key is set. Makes real API calls.
e2e-live:
	@set -a; if [ -f .env ]; then . ./.env; fi; set +a; \
		go test ./e2e -run LiveJudgeFixtures -count=1 -v

# Tidy module dependencies.
tidy:
	go mod tidy

# Wire up the local pre-commit hooks (requires the pre-commit framework).
install-hooks:
	pre-commit install
