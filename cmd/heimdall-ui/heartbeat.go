package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Heartbeat sources. Three of the four binaries publish their liveness as a
// Prometheus textfile gauge; the console reads those files directly rather
// than querying Prometheus, so it keeps working when Prometheus is the thing
// that is broken.
//
// The BRIDGE is deliberately absent from this list: it renders no .prom at
// all, its liveness surface is its own /healthz endpoint. main probes that
// separately when a URL is configured. It is reported as "absent" rather
// than quietly omitted — a component with no evidence of life must never
// render as healthy.
var heartbeatMetrics = map[string]string{
	"detect":   "heimdall_last_run_timestamp_seconds",
	"analyst":  "heimdall_analyst_last_success_timestamp_seconds",
	"notifier": "heimdall_notifier_last_success_timestamp_seconds",
}

// ReadHeartbeats scans every .prom file in dir and returns the newest
// timestamp found for each known heartbeat metric.
//
// Fail-soft by design: an unreadable directory or a malformed file yields an
// EMPTY entry for the affected component, which BuildComponents renders as
// "absent". It never yields a fabricated timestamp — the failure mode of a
// liveness display must be "I cannot see it", never "it looks fine".
func ReadHeartbeats(dir string) (map[string]time.Time, error) {
	out := make(map[string]time.Time, len(heartbeatMetrics))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out, fmt.Errorf("heartbeats: read dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".prom") {
			continue
		}
		found, err := scanPromFile(filepath.Join(dir, e.Name()))
		if err != nil {
			// One bad file must not blind the whole strip.
			continue
		}
		for name, ts := range found {
			if cur, ok := out[name]; !ok || ts.After(cur) {
				out[name] = ts
			}
		}
	}
	return out, nil
}

// scanPromFile extracts any known heartbeat gauge from one textfile.
func scanPromFile(path string) (map[string]time.Time, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	out := map[string]time.Time{}
	sc := bufio.NewScanner(f)
	// A .prom line is short; a very long line means this is not a textfile
	// we understand, and the default 64KB budget is ample.
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := parsePromSample(line)
		if !ok {
			continue
		}
		for component, metric := range heartbeatMetrics {
			if name != metric {
				continue
			}
			secs, err := strconv.ParseFloat(value, 64)
			if err != nil {
				continue
			}
			ts := time.Unix(int64(secs), 0).UTC()
			if cur, exists := out[component]; !exists || ts.After(cur) {
				out[component] = ts
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// parsePromSample splits one Prometheus text-format sample into its metric
// name and value, discarding any label set. The detector's heartbeat carries
// a plane="tier1" label while the notifier's carries none, so a parser that
// only handled bare names would silently miss the detector — the single most
// important row on the strip.
func parsePromSample(line string) (name, value string, ok bool) {
	// Trailing value is whatever follows the last space.
	sp := strings.LastIndex(line, " ")
	if sp <= 0 {
		return "", "", false
	}
	head, value := strings.TrimSpace(line[:sp]), strings.TrimSpace(line[sp+1:])
	if value == "" {
		return "", "", false
	}
	if brace := strings.IndexByte(head, '{'); brace >= 0 {
		head = head[:brace]
	}
	head = strings.TrimSpace(head)
	if head == "" {
		return "", "", false
	}
	return head, value, true
}
