.PHONY: all fmt lint test build tidy install-hooks

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

# Tidy module dependencies.
tidy:
	go mod tidy

# Wire up the local pre-commit hooks (requires the pre-commit framework).
install-hooks:
	pre-commit install
