.PHONY: all build clean test fuzz coverage lint verify-architecture package ci dashboard-screenshot

# Output directories and binary targets
BIN_DIR := bin
GO_SOURCES := $(shell find cmd internal -name '*.go') go.mod
BIN_CORE := $(BIN_DIR)/fplogin
BIN_PLATFORM := $(BIN_DIR)/fplogin-platform-arch
BIN_ADAPTER := $(BIN_DIR)/fplogin-adapter-sddm

all: build

# Portable CI target; the Arch package is verified separately.
ci: lint test fuzz build


# Build all three executables (Core CLI, Arch Platform Provider, SDDM Adapter)
build: $(BIN_CORE) $(BIN_PLATFORM) $(BIN_ADAPTER)

$(BIN_CORE): $(GO_SOURCES)
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_CORE) ./cmd/fplogin

$(BIN_PLATFORM): $(GO_SOURCES)
	@mkdir -p $(BIN_DIR)
	go build -o $(BIN_PLATFORM) ./cmd/fplogin-platform-arch

$(BIN_ADAPTER): $(GO_SOURCES)
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

# Real Arch tools package build (run in an isolated Arch build environment)
package:
	@bash scripts/verify_package.sh

# Clean build artifacts
clean:
	rm -rf $(BIN_DIR) target/

# Generate dashboard screenshot for documentation and README
dashboard-screenshot:
	@mkdir -p docs/assets
	@google-chrome-stable --headless --disable-gpu --no-sandbox --window-size=1440,1100 --screenshot=docs/assets/dashboard.png file://$(CURDIR)/dashboard.html
	@echo "Dashboard screenshot saved to docs/assets/dashboard.png"

