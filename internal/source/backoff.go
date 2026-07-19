package source

import (
	"context"
	"net/http"
	"time"
)

const maxAttempts = 3

// retryDelay: exponential backoff with FULL jitter, capped at 8s.
// delay = rand() * min(cap, base * 2^attempt). Note: base<=0 hits the
// ceiling BEFORE jitter — tests that want zero delay must zero the jitter
// func, not just baseDelay.
func retryDelay(attempt int, base time.Duration, jitter func() float64) time.Duration {
	d := base << attempt
	const ceiling = 8 * time.Second
	if d > ceiling || d <= 0 {
		d = ceiling
	}
	return time.Duration(jitter() * float64(d))
}

// retryableStatus: only transient classes are retried. Transport errors
// (status 0) are always retryable; 4xx and malformed 200s fail fast.
// Retrying is safe ONLY because the detector issues idempotent GETs — a
// future write-capable source must not inherit this policy blindly.
func retryableStatus(status int) bool {
	return status == 0 || status >= 500 || status == http.StatusTooManyRequests
}

// sleepCtx honors cancellation during backoff waits (no leaked timers).
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
