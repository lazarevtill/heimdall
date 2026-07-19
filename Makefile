# Heimdall build — static binaries, one per cmd/. See design/repo-layout.md.
BINS := heimdall-detect heimdall-bridge heimdall-notifier heimdall-analyst
GOFLAGS := -trimpath -ldflags "-s -w"

.PHONY: build test lint vet $(BINS)
build: $(BINS)
$(BINS):
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/$@ ./cmd/$@
test:
	go test ./...
vet:
	go vet ./...
lint:
	gofmt -l . ; go vet ./...
