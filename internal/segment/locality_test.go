package segment_test

import (
	"math"
	"testing"

	"reviewer12731/internal/segment"
	"reviewer12731/internal/synth"
)

// TestThreeSpacedGaps_LocalizedFill is the headline large-data check:
// with three separated gaps in three partitions, verifying the fill for one
// gap (a) succeeds, (b) touches ONLY that partition, (c) scans only the fill
// plus its two bracket segments, and (d) uses O(log segments) index probes and
// comparisons far below a global scan.
func TestThreeSpacedGaps_LocalizedFill(t *testing.T) {
	fx, err := synth.NewDefaultLarge()
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.Fills) != 3 {
		t.Fatalf("expected exactly 3 separated gaps, got %d", len(fx.Fills))
	}

	partSeen := map[string]bool{}
	for i, gf := range fx.Fills {
		partSeen[gf.Partition] = true
		fx.Meter.Reset()

		rep, err := fx.Store.VerifyFill(gf.GapLo, gf.GapHi, gf.Segment)
		if err != nil {
			t.Fatalf("fill %d (%s) verification failed: %v", i, gf.Partition, err)
		}

		// (b) partition locality.
		if ps := fx.Meter.PartitionSet(); len(ps) != 1 || ps[0] != gf.Partition {
			t.Fatalf("fill %s touched partitions %v, want only %s",
				gf.Partition, ps, gf.Partition)
		}

		// (c) only fill + brackets have items scanned (<=3).
		scanned := fx.Meter.ScannedSegmentIDs()
		if len(scanned) > 3 {
			t.Fatalf("fill %s scanned too many segments: %v", gf.Partition, scanned)
		}
		wantScanned := map[string]bool{gf.Segment.ID: true}
		if rep.LeftID != "" {
			wantScanned[rep.LeftID] = true
		}
		if rep.RightID != "" {
			wantScanned[rep.RightID] = true
		}
		if len(scanned) != len(wantScanned) {
			t.Fatalf("fill %s scanned %v, want exactly %v", gf.Partition, scanned, wantScanned)
		}
		for _, id := range scanned {
			if !wantScanned[id] {
				t.Fatalf("fill %s unexpectedly scanned %s", gf.Partition, id)
			}
		}

		// (d) logarithmic index probes over BlocksPer segments.
		bound := int64(2*math.Ceil(math.Log2(float64(fx.BlocksPer+1))) + 4)
		if fx.Meter.SegmentProbeCompares > bound {
			t.Fatalf("fill %s used %d segment probes > bound %d",
				gf.Partition, fx.Meter.SegmentProbeCompares, bound)
		}

		localized := fx.Meter.TotalComparisons()
		naive := fx.Store.NaiveGlobalScanComparisons(segment.Key{
			Partition: gf.Partition, Seq: gf.GapLo,
		})
		if localized >= naive/5 {
			t.Fatalf("fill %s localized comparisons %d not << global baseline %d",
				gf.Partition, localized, naive)
		}
		t.Logf("gap[%d] %s [%d..%d] %s | globalBaseline=%d | ratio=%.3f",
			i, gf.Partition, gf.GapLo, gf.GapHi, fx.Meter.Report(),
			naive, float64(localized)/float64(naive))
	}

	if len(partSeen) != 3 {
		t.Fatalf("three gaps should lie in distinct partitions, saw %v", partSeen)
	}
}

// TestFillOnePartition_ReconstructOnlyThatPartition proves that completing one
// partition removes its gap and a full reconstruction touches only that
// partition's segments, never the other gapped partitions.
func TestFillOnePartition_ReconstructOnlyThatPartition(t *testing.T) {
	fx, err := synth.NewDefaultLarge()
	if err != nil {
		t.Fatal(err)
	}
	target := fx.Fills[1] // middle gap / middle partition

	// Before fill: reconstruction reports exactly the one missing interval.
	fx.Meter.Reset()
	rec, err := fx.Store.ReconstructPartition(target.Partition)
	if err != nil {
		t.Fatal(err)
	}
	if ps := fx.Meter.PartitionSet(); len(ps) != 1 || ps[0] != target.Partition {
		t.Fatalf("reconstruct touched %v", ps)
	}
	if len(rec.Gaps) != 1 || rec.Gaps[0].From != target.GapLo || rec.Gaps[0].To != target.GapHi {
		t.Fatalf("pre-fill gaps = %+v, want [%d,%d]", rec.Gaps, target.GapLo, target.GapHi)
	}
	storedSegs := len(fx.Store.Segments(target.Partition))
	if len(fx.Meter.ScannedSegmentIDs()) != storedSegs {
		t.Fatalf("scanned %d segments, want all %d stored for partition",
			len(fx.Meter.ScannedSegmentIDs()), storedSegs)
	}

	// Fill it ("补齐") and reconstruct again: no gaps, full record count.
	if err := fx.AddFill(target); err != nil {
		t.Fatal(err)
	}
	fx.Meter.Reset()
	rec2, err := fx.Store.ReconstructPartition(target.Partition)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec2.Gaps) != 0 {
		t.Fatalf("post-fill expected no gaps, got %+v", rec2.Gaps)
	}
	wantItems := fx.BlocksPer * fx.ItemsPerBlock
	if len(rec2.Items) != wantItems {
		t.Fatalf("post-fill items=%d want %d", len(rec2.Items), wantItems)
	}
	if ps := fx.Meter.PartitionSet(); len(ps) != 1 || ps[0] != target.Partition {
		t.Fatalf("post-fill reconstruction touched %v", ps)
	}
	if len(fx.Meter.ScannedSegmentIDs()) != fx.BlocksPer {
		t.Fatalf("post-fill scanned %d segments want %d",
			len(fx.Meter.ScannedSegmentIDs()), fx.BlocksPer)
	}
	t.Logf("reconstruct filled partition %s: items=%d %s",
		target.Partition, len(rec2.Items), fx.Meter.Report())

	// The OTHER two gaps must remain untouched and still be reported.
	for _, gf := range []synth.GapFill{fx.Fills[0], fx.Fills[2]} {
		fx.Meter.Reset()
		other, err := fx.Store.ReconstructPartition(gf.Partition)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, in := range other.Gaps {
			if in.From == gf.GapLo && in.To == gf.GapHi {
				found = true
			}
		}
		if !found {
			t.Fatalf("other partition %s gap was inadvertently resolved: %+v",
				gf.Partition, other.Gaps)
		}
	}
}

// BenchmarkLocalizedFill measures the comparison count / latency of a fill.
func BenchmarkLocalizedFill(b *testing.B) {
	fx, err := synth.NewDefaultLarge()
	if err != nil {
		b.Fatal(err)
	}
	gf := fx.Fills[0]
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fx.Meter.Reset()
		if _, err := fx.Store.VerifyFill(gf.GapLo, gf.GapHi, gf.Segment); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportMetric(float64(fx.Meter.TotalComparisons()), "comparisons/fill")
}
