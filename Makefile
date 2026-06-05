# agent-sudo build/test targets.
#
# The production binary contains only the user-facing CLI. The development
# harness (root-smoke / launchd-dev) is compiled in only with -tags devtools.

GOCACHE ?= $(CURDIR)/.gocache
export GOCACHE

BIN := agent-sudo

.PHONY: build dev test test-dev vet fmt clean

build: ## Build the production binary (no dev harness)
	go build -o $(BIN) ./cmd/agent-sudo

dev: ## Build the development binary (includes root-smoke / launchd-dev)
	go build -tags devtools -o $(BIN) ./cmd/agent-sudo

test: ## Run the rootless test gate against the production build
	go test ./...

test-dev: ## Run the full test gate including the devtools harness tests
	go test -tags devtools ./...

vet: ## Vet both build configurations
	go vet ./...
	go vet -tags devtools ./...

fmt: ## Format all sources
	gofmt -w cmd internal

clean: ## Remove the built binary
	rm -f $(BIN)
