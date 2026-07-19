package source

import (
	"testing"
	"time"
)

func TestRetryDelayCapAndJitter(t *testing.T) {
	one := func() float64 { return 1.0 }
	zero := func() float64 { return 0.0 }
	if d := retryDelay(0, 250*time.Millisecond, one); d != 250*time.Millisecond {
		t.Errorf("attempt 0 = %v, want 250ms", d)
	}
	if d := retryDelay(1, 250*time.Millisecond, one); d != 500*time.Millisecond {
		t.Errorf("attempt 1 = %v, want 500ms", d)
	}
	if d := retryDelay(10, 250*time.Millisecond, one); d != 8*time.Second {
		t.Errorf("attempt 10 = %v, want capped 8s", d)
	}
	if d := retryDelay(3, 250*time.Millisecond, zero); d != 0 {
		t.Errorf("full jitter with r=0 should give 0, got %v", d)
	}
}

func TestRetryableStatus(t *testing.T) {
	for status, want := range map[int]bool{500: true, 503: true, 429: true, 404: false, 400: false, 200: false} {
		if got := retryableStatus(status); got != want {
			t.Errorf("retryableStatus(%d) = %v, want %v", status, got, want)
		}
	}
}
