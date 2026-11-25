package reconcile

import (
	"fmt"
	"testing"

	"reviewer12731/internal/model"
)

type coordState int

const (
	stAbsent coordState = iota
	stOK
	stWrong
	stEquiv
)

func statesForLength(L int) [][]coordState {
	total := 1
	for i := 0; i < L; i++ {
		total *= 4
	}
	out := make([][]coordState, 0, total)
	for mask := 0; mask < total; mask++ {
		st := make([]coordState, L)
		m := mask
		for i := 0; i < L; i++ {
			st[i] = coordState(m % 4)
			m /= 4
		}
		out = append(out, st)
	}
	return out
}

func configOps(t *testing.T, anchor model.Anchor, chain []model.Boundary, states []coordState) []Op {
	t.Helper()
	var ops []Op
	for i, st := range states {
		good := chain[i] // seq i+1
		switch st {
		case stAbsent:
			// nothing
		case stOK:
			ops = append(ops, AddBoundary(good))
		case stWrong:
			wrong := model.Boundary{
				Partition: good.Partition, Seq: good.Seq,
				Prev:  model.HashBytes("wrong-prev", fmt.Sprintf("%d", good.Seq)),
				Nonce: fmt.Sprintf("wrong-%d", good.Seq),
			}
			ops = append(ops, AddBoundary(wrong))
		case stEquiv:
			fork := model.Boundary{
				Partition: good.Partition, Seq: good.Seq,
				Prev:  model.HashBytes("fork-prev", fmt.Sprintf("%d", good.Seq)),
				Nonce: fmt.Sprintf("fork-%d", good.Seq),
			}
			ops = append(ops, AddBoundary(good), AddBoundary(fork))
		}
	}
	return ops
}

func eachPermutation(n int, fn func(order []int)) {
	if n == 0 {
		fn(nil)
		return
	}
	used := make([]bool, n)
	cur := make([]int, 0, n)
	var dfs func()
	dfs = func() {
		if len(cur) == n {
			order := append([]int(nil), cur...)
			fn(order)
			return
		}
		for i := 0; i < n; i++ {
			if used[i] {
				continue
			}
			used[i] = true
			cur = append(cur, i)
			dfs()
			cur = cur[:len(cur)-1]
			used[i] = false
		}
	}
	dfs()
}

func permutedOps(ops []Op, order []int) []Op {
	out := make([]Op, len(order))
	for i, idx := range order {
		out[i] = ops[idx]
	}
	return out
}

// TestExhaustiveCoordinateStates enumerates every per-sequence state tuple for
// small chains, checks the report against an independent oracle + invariants,
// and (for op counts <= 6) tries EVERY input permutation.
func TestExhaustiveCoordinateStates(t *testing.T) {
	const part = "p"
	configs := 0
	orderRuns := 0

	for L := 1; L <= 4; L++ {
		anchor, chain := testChain(part, L)
		for _, states := range statesForLength(L) {
			configs++
			ops := configOps(t, anchor, chain, states)

			canon := Settle(anchor, ops...)
			rv := NewReviewer(canon)
			rep := rv.Review(int64(L))
			checkInvariants(t, rep, rv, int64(L))

			adm := admissibleList(rv, canon.Boundaries)
			o := oracleReview(anchor, adm, int64(L))
			compareOracle(t, rep, o)
			checkStructuralCert(t, anchor, int64(L), rep)

			wantHash := rep.ConclusionHash

			if len(ops) <= 6 {
				eachPermutation(len(ops), func(order []int) {
					orderRuns++
					f := Settle(anchor, permutedOps(ops, order)...)
					r2 := NewReviewer(f)
					rep2 := r2.Review(int64(L))
					if rep2.ConclusionHash != wantHash {
						t.Fatalf("L=%d states=%v order=%v: hash differs under permutation",
							L, states, order)
					}
				})
			} else {
				// L=4 worst case (up to 8 ops): deterministic order sweep.
				sweeps := deterministicSweeps(len(ops))
				for _, order := range sweeps {
					orderRuns++
					f := Settle(anchor, permutedOps(ops, order)...)
					rep2 := NewReviewer(f).Review(int64(L))
					if rep2.ConclusionHash != wantHash {
						t.Fatalf("L=%d states=%v sweep=%v hash differs", L, states, order)
					}
				}
			}
		}
	}
	t.Logf("coordinate configs=%d order-runs=%d", configs, orderRuns)
}

func deterministicSweeps(n int) [][]int {
	base := make([]int, n)
	for i := range base {
		base[i] = i
	}
	var out [][]int
	// identity, reverse
	out = append(out, append([]int(nil), base...))
	rev := append([]int(nil), base...)
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	out = append(out, rev)
	// all rotations
	for r := 1; r < n; r++ {
		rot := make([]int, n)
		for i := 0; i < n; i++ {
			rot[i] = (i + r) % n
		}
		out = append(out, rot)
	}
	// fixed-LCG pseudo shuffles
	seed := uint32(0x12345678)
	for k := 0; k < 12 && n > 1; k++ {
		o := append([]int(nil), base...)
		seed = seed*1664525 + 1013904223
		start := int(seed) % n
		for i := 0; i < n; i++ {
			j := (start + i*7) % n
			o[i], o[j] = o[j], o[i]
		}
		out = append(out, o)
	}
	return out
}

func admissibleList(rv *Reviewer, all []model.Boundary) []model.Boundary {
	out := make([]model.Boundary, 0, len(all))
	for _, b := range all {
		if rv.admissible(b) {
			out = append(out, b)
		}
	}
	return out
}

func checkStructuralCert(t *testing.T, anchor model.Anchor, wm int64, rep *Report) {
	t.Helper()
	if rep.EarliestConflict == nil {
		return
	}
	cert := NewStructuralConflictCert(anchor, wm, *rep.EarliestConflict)
	v, err := VerifyConflictCert(cert, nil)
	if err != nil {
		t.Fatalf("structural cert verify error: %v", err)
	}
	if !v.PairDetected {
		t.Fatalf("cert did not detect pair")
	}
	if !v.HashIntact {
		t.Fatalf("fresh cert hash not intact")
	}
	if rep.EarliestConflict.Kind == PairPrevMismatch && !v.StrongContradiction {
		t.Fatalf("expected strong predecessor contradiction")
	}
	// DetectPair must agree with the predicate.
	if _, err := DetectPair(rep.EarliestConflict.A, rep.EarliestConflict.B); err != nil {
		t.Fatalf("DetectPair rejected report pair: %v", err)
	}
}

// TestInsertWithdrawAllOrders enumerates EVERY subset of a six-op handoff
// micro-world and EVERY permutation of each subset, proving settle conclusions
// are independent of insertion/withdrawal input order.
func TestInsertWithdrawAllOrders(t *testing.T) {
	const part = "hw"
	anchor, chain := testChain(part, 2)
	b1, b2 := chain[0], chain[1]

	H := model.Handoff{ID: "H", Partition: part, Seq: 2, FromDigest: b1.ID(), Owner: "o"}
	g := model.Boundary{
		Partition: part, Seq: 2, Prev: b1.ID(), Nonce: "gated2", HandoffID: "H",
	}
	rival := model.Boundary{
		Partition: part, Seq: 2,
		Prev: model.HashBytes("rival", "other-history"), Nonce: "rival2",
	}

	ops := []Op{
		AddBoundary(b1),      // 0
		AddBoundary(b2),      // 1 ordinary correct seq2
		AddHandoff(H),        // 2
		AddBoundary(g),       // 3 handoff-gated seq2
		AddBoundary(rival),   // 4 contradictory claim
		WithdrawHandoff("H"), // 5 effective revocation
	}

	subsets, totalOrders := 0, 0
	for mask := 0; mask < (1 << len(ops)); mask++ {
		var chosen []Op
		var idx []int
		for i := range ops {
			if mask&(1<<i) != 0 {
				chosen = append(chosen, ops[i])
				idx = append(idx, i)
			}
		}
		subsets++

		canonFacts := Settle(anchor, chosen...)
		canonRV := NewReviewer(canonFacts)
		canon := canonRV.Review(2)
		checkInvariants(t, canon, canonRV, 2)
		o := oracleReview(anchor, admissibleList(canonRV, canonFacts.Boundaries), 2)
		compareOracle(t, canon, o)

		k := len(chosen)
		eachPermutation(k, func(order []int) {
			totalOrders++
			reordered := make([]Op, k)
			for pos, srcPos := range order {
				reordered[pos] = chosen[srcPos]
			}
			f := Settle(anchor, reordered...)
			rep := NewReviewer(f).Review(2)
			if rep.ConclusionHash != canon.ConclusionHash {
				t.Fatalf("mask=%06b subsetIdx=%v order=%v hash differs", mask, idx, order)
			}
		})
	}
	t.Logf("subsets=%d all-order-runs=%d", subsets, totalOrders)
}

// TestRevocationSemantics pins the specific insert/withdraw outcomes, including
// an effective revocation dissolving an otherwise-proven conflict.
func TestRevocationSemantics(t *testing.T) {
	const part = "rv"
	anchor, chain := testChain(part, 2)
	b1 := chain[0]
	H := model.Handoff{ID: "H", Partition: part, Seq: 2, FromDigest: b1.ID(), Owner: "o"}
	g := model.Boundary{Partition: part, Seq: 2, Prev: b1.ID(), Nonce: "g", HandoffID: "H"}
	rival := model.Boundary{
		Partition: part, Seq: 2, Prev: model.HashBytes("x", "y"), Nonce: "r",
	}

	review := func(ops ...Op) *Report {
		f := Settle(anchor, ops...)
		rv := NewReviewer(f)
		rep := rv.Review(2)
		checkInvariants(t, rep, rv, 2)
		return rep
	}

	// H active: gated boundary uniquely extends -> watermark.
	rep := review(AddBoundary(b1), AddHandoff(H), AddBoundary(g))
	if rep.Status != StatusWatermark || rep.TrustedThroughSeq != 2 {
		t.Fatalf("active handoff should allow extension, got %s trusted=%d", rep.Status, rep.TrustedThroughSeq)
	}

	// H missing: gated boundary inadmissible -> gap.
	rep = review(AddBoundary(b1), AddBoundary(g))
	if rep.Status != StatusGap || rep.TrustedThroughSeq != 1 {
		t.Fatalf("missing handoff should gap at 2, got %s", rep.Status)
	}

	// H effectively revoked: gated boundary inadmissible -> gap.
	rep = review(AddBoundary(b1), AddHandoff(H), AddBoundary(g), WithdrawHandoff("H"))
	if rep.Status != StatusGap || rep.TrustedThroughSeq != 1 {
		t.Fatalf("revoked handoff should gap at 2, got %s", rep.Status)
	}
	if len(rep.RevokedHandoffs) != 1 || rep.RevokedHandoffs[0] != "H" {
		t.Fatalf("expected H in revoked list, got %v", rep.RevokedHandoffs)
	}

	// Active H + gated g + rival => proven predecessor conflict at 2.
	rep = review(AddBoundary(b1), AddHandoff(H), AddBoundary(g), AddBoundary(rival))
	if rep.Status != StatusConflict || rep.EarliestConflict == nil ||
		rep.EarliestConflict.Kind != PairPrevMismatch {
		t.Fatalf("expected prev-mismatch conflict at 2, got status=%s conflict=%+v",
			rep.Status, rep.EarliestConflict)
	}

	// Revoking H removes g; only rival (wrong prev) remains => conflict
	// dissolved into an unproven gap. This is the key withdrawal effect.
	rep = review(AddBoundary(b1), AddHandoff(H), AddBoundary(g), AddBoundary(rival), WithdrawHandoff("H"))
	if rep.Status != StatusGap {
		t.Fatalf("after revoking gated side, expected GAP (conflict dissolved), got %s", rep.Status)
	}
	if rep.EarliestConflict != nil {
		t.Fatalf("revocation should dissolve the admissible conflict, got %+v", rep.EarliestConflict)
	}
	if rep.BlockingInterval == nil || rep.BlockingInterval.From != 2 {
		t.Fatalf("expected blocking unproven interval from 2")
	}
}
