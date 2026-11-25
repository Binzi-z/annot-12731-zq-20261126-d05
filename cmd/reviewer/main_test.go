package main

import (
	"os"
	"testing"
)

// TestMainSelftestDispatch drives the real command entrypoint with the
// "selftest" subcommand. On success main returns; a failed check would route
// through fatal -> os.Exit and fail the test process.
func TestMainSelftestDispatch(t *testing.T) {
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{"reviewer", "selftest"}
	main()
}
