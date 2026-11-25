package synth

import (
	"testing"

	"reviewer12731/internal/reconcile"
)

// TestCanonicalWorld_ExpectedConclusions pins the worked example:
//   - watermark 3/4: clean prefix (copy-level missing segment recovered);
//   - watermark 6: unproven gap [5,6], no conflict yet;
//   - watermark 7+: the leading gap [5,6] is kept distinct from the earliest
//     proven predecessor conflict at seq 7.
func TestCanonicalWorld_ExpectedConclusions(t *testing.T) {
	w, err := NewCanonicalWorld()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[int64]struct {
		status   reconcile.Status
		trusted  int64
		conflict int64 // 0 => none
	}{
		3:  {reconcile.StatusWatermark, 3, 0},
		4:  {reconcile.StatusWatermark, 4, 0},
		6:  {reconcile.StatusGap, 4, 0},
		7:  {reconcile.StatusGap, 4, 7},
		8:  {reconcile.StatusGap, 4, 7},
		10: {reconcile.StatusGap, 4, 7},
	}

	for _, wm := range Watermarks {
		rep := w.Reviewer.Review(wm)
		want := cases[wm]
		if rep.Status != want.status {
			t.Fatalf("wm=%d status=%s want %s", wm, rep.Status, want.status)
		}
		if rep.TrustedThroughSeq != want.trusted {
			t.Fatalf("wm=%d trusted=%d want %d", wm, rep.TrustedThroughSeq, want.trusted)
		}
		var cs int64
		if rep.EarliestConflict != nil {
			cs = rep.EarliestConflict.Seq
		}
		if cs != want.conflict {
			t.Fatalf("wm=%d conflictSeq=%d want %d", wm, cs, want.conflict)
		}
		if !rep.VerifyHash() {
			t.Fatalf("wm=%d hash invalid", wm)
		}
	}

	rep7 := w.Reviewer.Review(7)
	if rep7.BlockingInterval == nil ||
		rep7.BlockingInterval.From != GapFrom || rep7.BlockingInterval.To != GapToBefore {
		t.Fatalf("wm=7 blocking interval=%+v want [%d,%d]",
			rep7.BlockingInterval, GapFrom, GapToBefore)
	}
	if rep7.EarliestConflict.Kind != reconcile.PairPrevMismatch {
		t.Fatalf("seq7 conflict should be predecessor mismatch, got %s",
			rep7.EarliestConflict.Kind)
	}

	// Effective + rejected revocations are classified.
	rep10 := w.Reviewer.Review(10)
	if !contains(rep10.RevokedHandoffs, HandoffRevoked) {
		t.Fatalf("h9 should be revoked: %v", rep10.RevokedHandoffs)
	}
	if !contains(rep10.EffectiveHandoffs, HandoffActive) {
		t.Fatalf("h10 should remain effective (bad revocation rejected): %v",
			rep10.EffectiveHandoffs)
	}
	if len(rep10.RejectedRevocations) == 0 {
		t.Fatalf("expected the unauthorized revocation to be rejected")
	}
}

// TestCanonicalWorld_SealedCertificateRoundTrip builds the minimal sealed
// conflict certificate and verifies it standalone with the key ring (no DB).
func TestCanonicalWorld_SealedCertificateRoundTrip(t *testing.T) {
	w, err := NewCanonicalWorld()
	if err != nil {
		t.Fatal(err)
	}
	rep := w.Reviewer.Review(7)
	cert, err := reconcile.BuildSealedConflictCert(rep, w.Source)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.Handoffs) != 0 {
		t.Fatalf("headline ordinary pair needs no handoff context, got %d", len(cert.Handoffs))
	}
	v, err := reconcile.VerifyConflictCert(cert, w.Ring)
	if err != nil {
		t.Fatalf("standalone sealed verification failed: %v", err)
	}
	if !v.PairDetected || !v.StrongContradiction || !v.SignaturesValid {
		t.Fatalf("unexpected verdict: %+v", v)
	}
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
