// Package verify is a runnable, black-box acceptance harness. It duplicates a
// small amount of oracle logic so that a native reviewer.exe "selftest" can
// exercise the same guarantees without the Go test runner present. The
// exhaustive white-box enumeration lives in the *_test.go files.
package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"reviewer12731/internal/model"
	"reviewer12731/internal/reconcile"
	"reviewer12731/internal/segment"
	"reviewer12731/internal/synth"
)

// Failure aggregates one or more failed checks.
type Failure struct{ Checks []string }

func (f *Failure) Error() string {
	return "self-check failed:\n  - " + strings.Join(f.Checks, "\n  - ")
}

// RunAll executes every acceptance check, writing progress to out. It returns
// a non-nil error if any property is violated.
func RunAll(out io.Writer) error {
	var fails []string
	check := func(name string, err error) {
		if err != nil {
			fails = append(fails, name+": "+err.Error())
			fmt.Fprintf(out, "FAIL  %s: %v\n", name, err)
			return
		}
		fmt.Fprintf(out, "PASS  %s\n", name)
	}

	w, err := synth.NewCanonicalWorld()
	if err != nil {
		return fmt.Errorf("build canonical world: %w", err)
	}

	check("canonical watermark conclusions", checkCanonical(w))
	check("sealed conflict certificate standalone", checkSealedCert(w))
	check("certificate tamper detection", checkTamper(w))
	check("historical watermark hash reproducibility", checkHistory(w))
	check("fact input-order independence", checkOrderIndependence(w))
	locLines, err := checkLocality()
	check("large three-gap partition locality", err)
	for _, ln := range locLines {
		fmt.Fprintln(out, "      "+ln)
	}
	permRuns, err := checkExhaustivePermutations()
	check(fmt.Sprintf("exhaustive small-graph insert/withdraw/order (%d permutation runs)", permRuns), err)

	if len(fails) > 0 {
		return &Failure{Checks: fails}
	}
	fmt.Fprintln(out, "\nALL CHECKS PASSED")
	return nil
}

func checkCanonical(w *synth.World) error {
	want := map[int64]struct {
		st reconcile.Status
		tr int64
		cs int64
	}{
		3:  {reconcile.StatusWatermark, 3, 0},
		4:  {reconcile.StatusWatermark, 4, 0},
		6:  {reconcile.StatusGap, 4, 0},
		7:  {reconcile.StatusGap, 4, 7},
		8:  {reconcile.StatusGap, 4, 7},
		10: {reconcile.StatusGap, 4, 7},
	}
	for wm, x := range want {
		r := w.Reviewer.Review(wm)
		if r.Status != x.st || r.TrustedThroughSeq != x.tr {
			return fmt.Errorf("wm=%d got %s trusted=%d", wm, r.Status, r.TrustedThroughSeq)
		}
		var cs int64
		if r.EarliestConflict != nil {
			cs = r.EarliestConflict.Seq
		}
		if cs != x.cs {
			return fmt.Errorf("wm=%d conflict=%d want %d", wm, cs, x.cs)
		}
		if !r.VerifyHash() {
			return fmt.Errorf("wm=%d bad hash", wm)
		}
	}
	r7 := w.Reviewer.Review(7)
	if r7.BlockingInterval == nil || *r7.BlockingInterval != (model.Interval{
		Partition: synth.Partition, From: synth.GapFrom, To: synth.GapToBefore,
	}) {
		return fmt.Errorf("blocking interval wrong: %+v", r7.BlockingInterval)
	}
	if !contains(r7.RevokedHandoffs, synth.HandoffRevoked) ||
		!contains(r7.EffectiveHandoffs, synth.HandoffActive) ||
		len(r7.RejectedRevocations) == 0 {
		return errors.New("handoff revocation classification wrong")
	}
	return nil
}

func checkSealedCert(w *synth.World) error {
	rep := w.Reviewer.Review(7)
	cert, err := reconcile.BuildSealedConflictCert(rep, w.Source)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(cert)
	var reloaded reconcile.ConflictCert
	if err := json.Unmarshal(raw, &reloaded); err != nil {
		return err
	}
	v, err := reconcile.VerifyConflictCert(&reloaded, w.Ring)
	if err != nil {
		return err
	}
	if !v.PairDetected || !v.StrongContradiction || !v.SignaturesValid {
		return fmt.Errorf("bad verdict %+v", v)
	}
	// Structural-only verification needs no ring at all.
	v2, err := reconcile.VerifyConflictCert(&reloaded, nil)
	if err != nil || !v2.PairDetected {
		return fmt.Errorf("structural verify failed: %v %v", v2, err)
	}
	return nil
}

func checkTamper(w *synth.World) error {
	rep := w.Reviewer.Review(7)
	cert, err := reconcile.BuildSealedConflictCert(rep, w.Source)
	if err != nil {
		return err
	}
	tam := *cert
	tam.B.Nonce += "-tampered"
	if _, err := reconcile.VerifyConflictCert(&tam, w.Ring); err == nil {
		return errors.New("tampered cert unexpectedly verified")
	}
	return nil
}

func checkHistory(w *synth.World) error {
	// The rejected-revocation list is an authenticated-pipeline output, not a
	// Facts field, so attach the same deterministic list to rebuilt reviewers.
	rejected := w.Reviewer.RejectedRevocations
	base := reconcile.NewReviewer(w.Facts)
	base.RejectedRevocations = rejected
	hashes := map[int64]model.Digest{}
	for _, wm := range synth.Watermarks {
		hashes[wm] = base.Review(wm).ConclusionHash
	}
	raw, err := json.Marshal(w.Facts)
	if err != nil {
		return err
	}
	var f2 reconcile.Facts
	if err := json.Unmarshal(raw, &f2); err != nil {
		return err
	}
	for _, wm := range synth.Watermarks {
		r := reconcile.NewReviewer(f2)
		r.RejectedRevocations = rejected
		if r.Review(wm).ConclusionHash != hashes[wm] {
			return fmt.Errorf("wm=%d not reproducible after JSON rebuild", wm)
		}
	}
	return nil
}

func checkOrderIndependence(w *synth.World) error {
	rejected := w.Reviewer.RejectedRevocations
	wantRV := reconcile.NewReviewer(w.Facts)
	wantRV.RejectedRevocations = rejected
	want := wantRV.Review(10).ConclusionHash
	f := w.Facts
	// Deterministically reverse and rotate each slice; maps/sorts must absorb it.
	revBounds := append([]model.Boundary(nil), f.Boundaries...)
	reverseBounds(revBounds)
	rotBounds := append([]model.Boundary(nil), f.Boundaries...)
	if len(rotBounds) > 1 {
		rotBounds = append(rotBounds[len(rotBounds)/2:], rotBounds[:len(rotBounds)/2]...)
	}
	for _, variant := range [][]model.Boundary{revBounds, rotBounds} {
		g := f
		g.Boundaries = variant
		rv := reconcile.NewReviewer(g)
		rv.RejectedRevocations = rejected
		if got := rv.Review(10).ConclusionHash; got != want {
			return errors.New("report hash changed when boundary slice order changed")
		}
	}
	return nil
}

func checkLocality() ([]string, error) {
	fx, err := synth.NewDefaultLarge()
	if err != nil {
		return nil, err
	}
	var lines []string
	for i, gf := range fx.Fills {
		fx.Meter.Reset()
		if _, err := fx.Store.VerifyFill(gf.GapLo, gf.GapHi, gf.Segment); err != nil {
			return lines, err
		}
		ps := fx.Meter.PartitionSet()
		if len(ps) != 1 || ps[0] != gf.Partition {
			return lines, fmt.Errorf("gap %d touched %v", i, ps)
		}
		if n := len(fx.Meter.ScannedSegmentIDs()); n > 3 {
			return lines, fmt.Errorf("gap %d scanned %d segments", i, n)
		}
		bound := int64(2*math.Ceil(math.Log2(float64(fx.BlocksPer+1))) + 4)
		if fx.Meter.SegmentProbeCompares > bound {
			return lines, fmt.Errorf("gap %d probes %d > %d", i, fx.Meter.SegmentProbeCompares, bound)
		}
		local := fx.Meter.TotalComparisons()
		global := fx.Store.NaiveGlobalScanComparisons(segment.Key{Partition: gf.Partition, Seq: gf.GapLo})
		if local >= global/5 {
			return lines, fmt.Errorf("locality ratio weak: %d vs %d", local, global)
		}
		lines = append(lines, fmt.Sprintf("gap[%d] %s [%d..%d] comparisons=%d (probes=%d item=%d link=%d) globalBaseline=%d ratio=%.3f scanned=%v",
			i, gf.Partition, gf.GapLo, gf.GapHi, local,
			fx.Meter.SegmentProbeCompares, fx.Meter.ItemKeyCompares, fx.Meter.LinkCompares,
			global, float64(local)/float64(global), fx.Meter.ScannedSegmentIDs()))
	}
	return lines, nil
}

// checkExhaustivePermutations runs a compact but truly exhaustive enumeration
// over a four-op insert/withdraw micro-world: every subset and every
// permutation of each subset must settle to the same conclusion hash.
func checkExhaustivePermutations() (int, error) {
	const part = "self"
	gen := model.Boundary{Partition: part, Seq: 0, Prev: model.NilDigest, Nonce: "g"}
	anchor := model.Anchor{Partition: part, Seq: 0, Digest: gen.ID()}
	b1 := model.Boundary{Partition: part, Seq: 1, Prev: anchor.Digest, Nonce: "b1"}
	b2 := model.Boundary{Partition: part, Seq: 2, Prev: b1.ID(), Nonce: "b2"}
	H := model.Handoff{ID: "H", Partition: part, Seq: 2, FromDigest: b1.ID(), Owner: "o"}
	gated := model.Boundary{Partition: part, Seq: 2, Prev: b1.ID(), Nonce: "g", HandoffID: "H"}
	rival := model.Boundary{Partition: part, Seq: 2, Prev: model.HashBytes("alt"), Nonce: "r"}

	ops := []reconcile.Op{
		reconcile.AddBoundary(b1),
		reconcile.AddBoundary(b2),
		reconcile.AddHandoff(H),
		reconcile.AddBoundary(gated),
		reconcile.AddBoundary(rival),
		reconcile.WithdrawHandoff("H"),
	}

	runs := 0
	for mask := 0; mask < 1<<len(ops); mask++ {
		var chosen []reconcile.Op
		for i := range ops {
			if mask&(1<<i) != 0 {
				chosen = append(chosen, ops[i])
			}
		}
		wantHash := reconcile.NewReviewer(reconcile.Settle(anchor, chosen...)).Review(2).ConclusionHash

		// Heap's algorithm over every permutation of this subset.
		arr := append([]reconcile.Op(nil), chosen...)
		var heap func(k int) bool
		heap = func(k int) bool {
			if k == 1 {
				runs++
				got := reconcile.NewReviewer(reconcile.Settle(anchor, arr...)).Review(2).ConclusionHash
				return got == wantHash
			}
			for i := 0; i < k; i++ {
				if !heap(k - 1) {
					return false
				}
				if k%2 == 0 {
					arr[0], arr[k-1] = arr[k-1], arr[0]
				} else {
					arr[i], arr[k-1] = arr[k-1], arr[i]
				}
			}
			return true
		}
		if !heap(len(arr)) {
			return runs, fmt.Errorf("mask %06b order-dependent conclusion", mask)
		}
	}
	return runs, nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func reverseBounds(bs []model.Boundary) {
	for i, j := 0, len(bs)-1; i < j; i, j = i+1, j-1 {
		bs[i], bs[j] = bs[j], bs[i]
	}
}
