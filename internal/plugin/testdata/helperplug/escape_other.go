//go:build !unix

package main

import "errors"

// startEscapee is unix-only: there is no setsid here, so the escape modes
// report themselves unavailable and the test that uses them skips.
func startEscapee() (int, error) {
	return 0, errors.New("setsid is not available on this platform")
}
