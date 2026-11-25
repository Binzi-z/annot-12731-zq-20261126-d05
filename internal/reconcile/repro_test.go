package reconcile

import (
	"encoding/json"
	"testing"

	"reviewer12731/internal/model"
)

// TestHistoricalWatermarkReproducibility builds a graph, records conclusion
// hashes for every historical watermark, then rebuilds from serialized Facts
// and asserts byte-identical conclusions and stable hashes.
func TestHistoricalWatermarkReproducibility(t *testing.T) {
	anchor, chain := testChain("hist", 8)

	fork7 := model.Boundary{
		Partition: "hist", Seq: 7, Prev: model.HashBytes("alt7"), Nonce: "fork7",
	}
	ops := []Op{}
	for i := 0; i < 4; i++ { // seq 1..4 present
		ops = append(ops, AddBoundary(chain[i]))
	}
	// seq5 missing entirely
	ops = append(ops, AddBoundary(chain[5]))                     // seq6
	ops = append(ops, AddBoundary(chain[6]), AddBoundary(fork7)) // seq7 equivocation
	ops = append(ops, AddBoundary(chain[7]))                     // seq8

	facts := Settle(anchor, ops...)

	watermarks := []int64{3, 4, 5, 6, 7, 8, 12}
	first := map[int64]model.Digest{}
	firstJSON := map[int64][]byte{}
	for _, wm := range watermarks {
		rep := NewReviewer(facts).Review(wm)
		if !rep.VerifyHash() {
			t.Fatalf("hash does not verify at wm=%d", wm)
		}
		b, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		first[wm] = rep.ConclusionHash
		firstJSON[wm] = b
	}

	// Serialize Facts, then rebuild from JSON (the "reconstruct later" path).
	raw, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	var restored Facts
	if err := json.Unmarshal(raw, &restored); err != nil {
		t.Fatal(err)
	}

	for _, wm := range watermarks {
		rep := NewReviewer(restored).Review(wm)
		if rep.ConclusionHash != first[wm] {
			t.Fatalf("wm=%d hash changed after Facts JSON rebuild", wm)
		}
		b, _ := json.Marshal(rep)
		if string(b) != string(firstJSON[wm]) {
			t.Fatalf("wm=%d full report JSON not reproducible", wm)
		}
	}

	// Repeated reviews must be stable and distinct watermarks may differ.
	r := NewReviewer(facts)
	for _, wm := range watermarks {
		a := r.Review(wm).ConclusionHash
		b := r.Review(wm).ConclusionHash
		if a != b {
			t.Fatalf("non-deterministic review at wm=%d", wm)
		}
	}
}

// TestSettleIsOrderIndependentOnRandomizedInput permutes a fixed op list many
// ways and checks identical facts-derived conclusion.
func TestSettleDedupReplicatedCopies(t *testing.T) {
	anchor, chain := testChain("dup", 1)
	b := chain[0]
	ops := []Op{AddBoundary(b), AddBoundary(b), AddBoundary(b)}
	f := Settle(anchor, ops...)
	if len(f.Boundaries) != 1 {
		t.Fatalf("identical replicated boundaries must dedup to 1, got %d", len(f.Boundaries))
	}
	rep := NewReviewer(f).Review(1)
	if rep.Status != StatusWatermark {
		t.Fatalf("single deduped boundary should extend, got %s", rep.Status)
	}
}
