package reviewer12731

import (
	"io"
	"testing"

	"reviewer12731/internal/verify"
)

// TestSelfTestHarness runs the same in-binary acceptance suite exposed by
// `reviewer selftest`, so the runnable verifier path is covered by `go test`.
func TestSelfTestHarness(t *testing.T) {
	if err := verify.RunAll(io.Discard); err != nil {
		t.Fatal(err)
	}
}
