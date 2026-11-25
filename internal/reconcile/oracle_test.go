package reconcile

import (
	"fmt"
	"sort"
	"testing"

	"reviewer12731/internal/model"
)

// ---- tiny canonical chain builder -----------------------------------------

func testChain(part string, length int) (model.Anchor, []model.Boundary) {
	gen := model.Boundary{Partition: part, Seq: 0, Prev: model.NilDigest, Nonce: "genesis-" + part}
	anchor := model.Anchor{Partition: part, Seq: 0, Digest: gen.ID()}
	chain := make([]model.Boundary, length+1)
	chain[0] = gen
	prev := anchor.Digest
	for i := 1; i <= length; i++ {
		chain[i] = model.Boundary{
			Partition: part, Seq: int64(i), Prev: prev,
			Nonce: fmt.Sprintf("%s-n%d", part, i),
		}
		prev = chain[i].ID()
	}
	return anchor, chain[1:]
}

// ---- independent oracle ----------------------------------------------------

type oracleResult struct {
	trusted     int64
	status      Status
	conflictSeq int64 // 0 => no conflict in window
	intervals   []model.Interval
}

// oracleReview is a deliberately separate, simple reference implementation.
// It takes the already-admissible boundaries and recomputes everything from
// scratch; it does not call Reviewer.Review.
func oracleReview(anchor model.Anchor, admissible []model.Boundary, wm int64) oracleResult {
	bySeq := map[int64][]model.Boundary{}
	seen := map[model.Digest]bool{}
	for _, b := range admissible {
		if b.Partition != anchor.Partition || b.Seq <= anchor.Seq || b.Seq > wm {
			continue
		}
		if seen[b.ID()] {
			continue
		}
		seen[b.ID()] = true
		bySeq[b.Seq] = append(bySeq[b.Seq], b)
	}
	for s := range bySeq {
		sort.Slice(bySeq[s], func(i, j int) bool { return bySeq[s][i].ID() < bySeq[s][j].ID() })
	}

	var conflictSeq int64 = -1
	seqs := make([]int64, 0, len(bySeq))
	for s := range bySeq {
		seqs = append(seqs, s)
		if len(bySeq[s]) >= 2 && (conflictSeq == -1 || s < conflictSeq) {
			conflictSeq = s
		}
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	tip := anchor.Digest
	trusted := anchor.Seq
	status := StatusWatermark
	for s := anchor.Seq + 1; s <= wm; s++ {
		g := bySeq[s]
		if len(g) >= 2 {
			status = StatusConflict
			break
		}
		var ext int
		for _, b := range g {
			if b.Prev == tip {
				ext++
				if ext == 1 {
					tip = b.ID()
				}
			}
		}
		if ext == 1 {
			trusted = s
			continue
		}
		status = StatusGap
		break
	}

	// Independently build unproven runs by walking every sequence point.
	var intervals []model.Interval
	runFrom := int64(-1)
	closeRun := func(to int64) {
		if runFrom != -1 && runFrom <= to {
			intervals = append(intervals, model.Interval{
				Partition: anchor.Partition, From: runFrom, To: to,
			})
		}
		runFrom = -1
	}
	for s := trusted + 1; s <= wm; s++ {
		isConflict := len(bySeq[s]) >= 2
		if isConflict {
			closeRun(s - 1)
			continue
		}
		if runFrom == -1 {
			runFrom = s
		}
	}
	closeRun(wm)
	if intervals == nil {
		intervals = []model.Interval{}
	}

	cs := conflictSeq
	if cs == -1 {
		cs = 0
	}
	return oracleResult{
		trusted: trusted, status: status, conflictSeq: cs, intervals: intervals,
	}
}

// ---- invariants ------------------------------------------------------------

func checkInvariants(t *testing.T, rep *Report, rv *Reviewer, wm int64) {
	t.Helper()
	a := rv.facts.Anchor

	if !rep.VerifyHash() {
		t.Fatalf("conclusion hash does not verify")
	}
	if rep.TrustedThroughSeq != a.Seq+int64(len(rep.PrefixSeqs)-1) {
		t.Fatalf("trustedThrough=%d inconsistent with contiguous prefix length %d",
			rep.TrustedThroughSeq, len(rep.PrefixSeqs))
	}
	if len(rep.Prefix) != len(rep.PrefixSeqs) {
		t.Fatalf("prefix/id seq length mismatch")
	}
	if rep.Prefix[0] != a.Digest || rep.PrefixSeqs[0] != a.Seq {
		t.Fatalf("prefix must start at trusted anchor")
	}

	// Prefix is a valid unique hash chain.
	for i := 1; i < len(rep.Prefix); i++ {
		s := rep.PrefixSeqs[i]
		if s != rep.PrefixSeqs[i-1]+1 {
			t.Fatalf("prefix seqs not contiguous at %d", i)
		}
		b, ok := rv.byID[rep.Prefix[i]]
		if !ok {
			t.Fatalf("prefix boundary %s missing from index", rep.Prefix[i])
		}
		if b.Prev != rep.Prefix[i-1] {
			t.Fatalf("prefix link %d does not match prior prefix id", s)
		}
		if !rv.admissible(b) {
			t.Fatalf("prefix boundary %d is inadmissible", s)
		}
	}
	if rep.Tip != rep.Prefix[len(rep.Prefix)-1] {
		t.Fatalf("tip must equal last prefix id")
	}

	trusted := rep.TrustedThroughSeq

	// Status consistency / maximality of the safe prefix.
	switch rep.Status {
	case StatusWatermark:
		if trusted != wm {
			t.Fatalf("WATERMARK but trusted=%d != wm=%d", trusted, wm)
		}
	case StatusConflict:
		if rep.EarliestConflict == nil {
			t.Fatalf("status CONFLICT without earliest conflict")
		}
		if rep.EarliestConflict.Seq != trusted+1 {
			t.Fatalf("conflict blocker seq %d should be trusted+1=%d",
				rep.EarliestConflict.Seq, trusted+1)
		}
		g := rv.byCoord[model.Coord{Partition: a.Partition, Seq: trusted + 1}]
		if pairAt(g) == nil {
			t.Fatalf("status CONFLICT but no equivocal pair at blocker")
		}
	case StatusGap:
		if rep.BlockingInterval == nil {
			t.Fatalf("status GAP requires a blocking interval")
		}
		if rep.BlockingInterval.From != trusted+1 {
			t.Fatalf("blocking interval must start at trusted+1")
		}
		g := rv.byCoord[model.Coord{Partition: a.Partition, Seq: trusted + 1}]
		if pairAt(g) != nil {
			t.Fatalf("status GAP but coordinate is equivocal")
		}
		uniqueExt := 0
		for _, b := range g {
			if b.Prev == rep.Tip {
				uniqueExt++
			}
		}
		if uniqueExt == 1 {
			t.Fatalf("status GAP but a unique extension exists")
		}
	}

	// EarliestConflict must equal a direct pairwise scan.
	var direct *Conflict
	var directSeqs []int64
	for c, g := range rv.byCoord {
		if c.Partition != a.Partition || c.Seq <= a.Seq || c.Seq > wm {
			continue
		}
		if p := pairAt(g); p != nil {
			directSeqs = append(directSeqs, c.Seq)
			if direct == nil || c.Seq < direct.Seq ||
				(c.Seq == direct.Seq && pairKey(p) < pairKey(direct)) {
				pp := *p
				direct = &pp
			}
		}
	}
	sort.Slice(directSeqs, func(i, j int) bool { return directSeqs[i] < directSeqs[j] })
	if direct == nil && rep.EarliestConflict != nil {
		t.Fatalf("report conflict but direct scan found none")
	}
	if direct != nil {
		if rep.EarliestConflict == nil {
			t.Fatalf("direct scan found conflict seq %d but report has none", direct.Seq)
		} else if pairKey(rep.EarliestConflict) != pairKey(direct) {
			t.Fatalf("earliest conflict mismatch report=%s direct=%s",
				pairKey(rep.EarliestConflict), pairKey(direct))
		}
	}
	if len(rep.Conflicts) != len(directSeqs) {
		t.Fatalf("allConflicts count %d != direct %d", len(rep.Conflicts), len(directSeqs))
	}

	// Coverage: every seq in (anchor,wm] is exactly one of trusted / conflict / unproven.
	conflictSet := map[int64]bool{}
	for _, c := range rep.Conflicts {
		conflictSet[c.Seq] = true
	}
	unprovenSet := map[int64]int{}
	for ii, in := range rep.UnprovenIntervals {
		if in.Partition != a.Partition {
			t.Fatalf("interval wrong partition")
		}
		if in.From > in.To {
			t.Fatalf("bad interval range")
		}
		for s := in.From; s <= in.To; s++ {
			if _, dup := unprovenSet[s]; dup {
				t.Fatalf("seq %d in overlapping unproven intervals", s)
			}
			unprovenSet[s] = ii
		}
	}
	for s := a.Seq + 1; s <= wm; s++ {
		isTrusted := s <= trusted
		isConflict := conflictSet[s]
		_, isUnproven := unprovenSet[s]
		count := 0
		if isTrusted {
			count++
		}
		if isConflict {
			count++
		}
		if isUnproven {
			count++
		}
		if count != 1 {
			t.Fatalf("seq %d classification count=%d (trusted=%v conflict=%v unproven=%v)",
				s, count, isTrusted, isConflict, isUnproven)
		}
	}
}

func pairKey(c *Conflict) string {
	ia, ib := c.A.ID(), c.B.ID()
	if ia > ib {
		ia, ib = ib, ia
	}
	return fmt.Sprintf("%d|%s|%s", c.Seq, ia, ib)
}

func compareOracle(t *testing.T, rep *Report, o oracleResult) {
	t.Helper()
	if rep.TrustedThroughSeq != o.trusted {
		t.Fatalf("trusted=%d oracle=%d", rep.TrustedThroughSeq, o.trusted)
	}
	if rep.Status != o.status {
		t.Fatalf("status=%s oracle=%s", rep.Status, o.status)
	}
	var repCS int64
	if rep.EarliestConflict != nil {
		repCS = rep.EarliestConflict.Seq
	}
	if repCS != o.conflictSeq {
		t.Fatalf("conflictSeq=%d oracle=%d", repCS, o.conflictSeq)
	}
	if len(rep.UnprovenIntervals) != len(o.intervals) {
		t.Fatalf("intervals %v != oracle %v", rep.UnprovenIntervals, o.intervals)
	}
	for i := range o.intervals {
		if rep.UnprovenIntervals[i] != o.intervals[i] {
			t.Fatalf("interval[%d]=%v oracle=%v", i, rep.UnprovenIntervals[i], o.intervals[i])
		}
	}
}
