.PHONY: all build clean test fuzz coverage lint verify-architecture package ci

# Output directories and binary targets
BIN_DIR := bin
BIN_CORE := $(BIN_DIR)/fplogin
BIN_PLATFORM := $(BIN_DIR)/fplogin-platform-arch
BIN_ADAPTER := $(BIN_DIR)/fplogin-adapter-sddm

all: build

# Full CI target (lint, test, fuzz, package verification, binary compilation)
ci: lint test fuzz package build


# Build all three executables (Core CLI, Arch Platform Provider, SDDM Adapter)
build: $(BIN_CORE) $(BIN_PLATFORM) $(BIN_ADAPTER)

$(BIN_CORE): cmd/fplogin/main.go
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_CORE) ./cmd/fplogin

$(BIN_PLATFORM): cmd/fplogin-platform-arch/main.go
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_PLATFORM) ./cmd/fplogin-platform-arch

$(BIN_ADAPTER): cmd/fplogin-adapter-sddm/main.go
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_ADAPTER) ./cmd/fplogin-adapter-sddm

# Run all automated tests (unit, contract, core integration)
test:
	go test -v ./internal/... ./cmd/... ./tests/contract/... ./tests/integration/core/...

# Run architecture contract boundary AST validation
verify-architecture:
	go test -v ./tests/contract/ -run TestCoreArchitectureBoundary

# Run Go static vetting and architecture check
lint: verify-architecture
	go vet ./internal/... ./cmd/... ./tests/contract/... ./tests/integration/core/...

# Run short native fuzz tests on parsers and transaction journal
fuzz:
	go test -fuzz=FuzzDecodeTransactionJournal -fuzztime=2s ./internal/core/transaction/...
	go test -fuzz=FuzzPAMParser -fuzztime=2s ./internal/core/analyze/...

# Generate test coverage report
coverage:
	@mkdir -p target/coverage
	go test -coverprofile=target/coverage/coverage.out ./internal/... ./tests/contract/... ./tests/integration/core/...
	go tool cover -html=target/coverage/coverage.out -o target/coverage/coverage.html
	@echo "Coverage HTML generated at target/coverage/coverage.html"

# Package verification and staging validation
package: build
	@bash scripts/verify_package.sh

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) target/

