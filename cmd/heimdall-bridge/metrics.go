package main

import (
	"log"
	"sync"

	"github.com/lazarevtill/heimdall/internal/contract"
	"github.com/lazarevtill/heimdall/internal/emit"
)

// heartbeatFilename is the bridge's node_exporter textfile, written into
// HEIMDALL_TEXTFILE_DIR beside heimdall.prom / heimdall-analyst.prom /
// heimdall-notifier.prom.
const heartbeatFilename = "heimdall-bridge.prom"

// bridgeMetrics holds heimdall-bridge's cumulative counters and sweep
// heartbeat, and rewrites the textfile (atomically, whole-file) after every
// change so a scrape always sees the current values. Writes are serialised
// under mu, so a slower writer can never land an older snapshot over a newer
// one.
//
// A write failure is logged, not fatal: the bridge's job is tickets, and a
// textfile that stops updating is exactly what the staleness rule on
// heimdall_bridge_sweep_last_success_timestamp_seconds exists to page on.
type bridgeMetrics struct {
	mu    sync.Mutex
	path  string // "" disables the file (tests that do not assert on it)
	stats emit.BridgeStats
}

func newBridgeMetrics(path string) *bridgeMetrics {
	return &bridgeMetrics{path: path}
}

// update applies f to the stats and rewrites the textfile.
func (m *bridgeMetrics) update(f func(*emit.BridgeStats)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(&m.stats)
	m.writeLocked()
}

// flush rewrites the textfile unchanged — used once at startup so every
// series exists (explicit zeros) before the first request or sweep.
func (m *bridgeMetrics) flush() { m.update(func(*emit.BridgeStats) {}) }

// snapshot returns a copy of the current stats.
func (m *bridgeMetrics) snapshot() emit.BridgeStats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stats
}

func (m *bridgeMetrics) writeLocked() {
	if m.path == "" {
		return
	}
	if err := emit.WriteFileAtomic(m.path, emit.RenderBridgeProm(m.stats)); err != nil {
		log.Printf("WARNING: metrics textfile not updated: %v", contract.Safe(err))
	}
}
