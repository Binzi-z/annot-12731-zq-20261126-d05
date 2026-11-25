package demo_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reviewer12731/internal/demo"
)

// TestDemoEndToEnd runs the full demo into a temp directory and then verifies
// the written certificate from disk using only cert + trust bundle.
func TestDemoEndToEnd(t *testing.T) {
	dir := t.TempDir()
	var buf bytes.Buffer
	if err := demo.Run(dir, &buf); err != nil {
		t.Fatalf("demo.Run: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"REACHED_WATERMARK", "BLOCKED_BY_UNPROVEN_GAP",
		"PREDECESSOR_MISMATCH", "已检出互相矛盾的两个边界",
		"大数据三空档局部扫描度量",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("demo output missing %q", want)
		}
	}

	cert := filepath.Join(dir, "conflict-cert-wm7.json")
	trust := filepath.Join(dir, "trust-bundle.json")
	if _, err := os.Stat(cert); err != nil {
		t.Fatalf("cert not written: %v", err)
	}

	var vbuf bytes.Buffer
	if err := demo.VerifyCertFiles(cert, trust, &vbuf); err != nil {
		t.Fatalf("third-party verify from disk failed: %v\n%s", err, vbuf.String())
	}
	if !strings.Contains(vbuf.String(), `"pairDetected": true`) {
		t.Fatalf("verdict did not detect pair:\n%s", vbuf.String())
	}

	// Structural-only verification with no trust file must still detect it.
	var sbuf bytes.Buffer
	if err := demo.VerifyCertFiles(cert, "", &sbuf); err != nil {
		t.Fatalf("structural verify should not hard-fail: %v", err)
	}
	if !strings.Contains(sbuf.String(), `"pairDetected": true`) {
		t.Fatalf("structural verdict missing pairDetected:\n%s", sbuf.String())
	}
}

// TestLargeMeasurementRuns ensures the measurement report is produced.
func TestLargeMeasurementRuns(t *testing.T) {
	var buf bytes.Buffer
	if err := demo.Large(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "局部/全局") {
		t.Fatalf("missing ratio report:\n%s", buf.String())
	}
}
