package emit

import (
	"bytes"
	"testing"
)

// The redaction HELP/TYPE block must be byte-identical to every other file
// exposing heimdall_redaction_failures_total, or node_exporter's merged
// scrape is poisoned: the bridge renderer must reuse the one definition.
func TestRenderBridgePromReusesTheSharedRedactionHELP(t *testing.T) {
	if !bytes.Contains(RenderBridgeProm(BridgeStats{}), []byte(helpRedaction)) {
		t.Errorf("RenderBridgeProm does not carry helpRedaction verbatim:\n%s", RenderBridgeProm(BridgeStats{}))
	}
}
