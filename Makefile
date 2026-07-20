GO ?= go

.PHONY: build test lint vuln ci

# CGO_ENABLED=0 is a property of the RELEASE BUILD (static binary); tests
# run with cgo enabled because `go test -race` requires it (ADR-G14).
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/heimdall-detect ./cmd/heimdall-detect
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/heimdall-analyst ./cmd/heimdall-analyst
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/heimdall-bridge ./cmd/heimdall-bridge
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/heimdall-notifier ./cmd/heimdall-notifier

test:
	CGO_ENABLED=1 $(GO) test -race ./...

lint:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	@if grep -rn --include='*.go' 'time\.Now()' internal/ | grep -v '//.*time\.Now()'; then \
		echo "time.Now() in internal/ is banned: inject now (ADR-G10)"; exit 1; fi
	@if grep -rn --include='*.go' 'contract\.Finding{' cmd/ internal/ | grep -v '^internal/contract/' \
		| sed 's/\[\]contract\.Finding{//g' | grep 'contract\.Finding{'; then \
		echo "contract.Finding literals outside internal/contract are banned: use NewFinding (ADR-G09)"; exit 1; fi
	# Scope: the shipped CODE + deploy + CI surface. Prose records (design/,
	# docs/, README.md) legitimately QUOTE these patterns (redaction rules,
	# this very gate) and are kept full-detail on the private GitLab remote,
	# sanitized separately for the public GitHub mirror (two-repo model) — so
	# they are excluded here, exactly as the Makefile and redact.go are. The
	# gate still guarantees no real infra string reaches code/deploy/CI.
	@if git grep -nE '192\.168\.|lazarev\.cloud|pbsHGST' -- ':!Makefile' ':!design/' ':!docs/' ':!README.md'; then \
		echo "real-infrastructure string leaked into shipped code/deploy/CI"; exit 1; fi
	@if git grep -nE 'glpat-[A-Za-z0-9_-]{20,}' -- ':!Makefile' ':!design/' ':!docs/' ':!README.md' ':!internal/contract/redact.go' ':!*_test.go'; then \
		echo "secret-shaped token outside the defanged test fixtures"; exit 1; fi
	@if grep -rn --include='*.go' 'internal/llm' cmd/heimdall-detect/ internal/detect/ internal/tier2/ internal/digest/ internal/emit/ 2>/dev/null; then \
		echo "internal/llm imported by the trusted detection/emission path: Tier-3 must stay off it (G1)"; exit 1; fi
	$(GO) mod verify

# pinned: bump deliberately, never @latest (reproducible CI)
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@v1.6.0 ./...

ci: lint test build vuln
