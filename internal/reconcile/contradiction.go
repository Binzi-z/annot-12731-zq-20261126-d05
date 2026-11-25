package reconcile

import "reviewer12731/internal/model"

// Equivocates reports whether two boundaries are distinct claims at the same
// coordinate. Identical boundaries (same own digest, e.g. replicated copies)
// are NOT an equivocation.
func Equivocates(a, b model.Boundary) bool {
	return a.Partition == b.Partition &&
		a.Seq == b.Seq &&
		a.ID() != b.ID()
}

// Contradictory is the canonical "互相矛盾的两个边界" predicate: same
// partition+sequence but different predecessor summaries. This check is purely
// structural and needs only the two boundaries — no database.
func Contradictory(a, b model.Boundary) bool {
	return Equivocates(a, b) && a.Prev != b.Prev
}

// pairAt deterministically selects the canonical equivocating pair from a
// non-empty coordinate group that may contain 0, 1 or many distinct boundaries.
// The group must already be de-duplicated by id. It returns nil when the group
// has fewer than two distinct boundaries.
//
// Selection is lexicographic by boundary id:
//   - prefer a predecessor mismatch; return the lexicographically smallest
//     index pair whose Prev differs (the strong contradiction);
//   - otherwise return the two smallest-id boundaries (same-prev body diverge).
func pairAt(group []model.Boundary) *Conflict {
	if len(group) < 2 {
		return nil
	}
	// group is expected sorted by ID; enforce canonical order defensively.
	sorted := make([]model.Boundary, len(group))
	copy(sorted, group)
	sortBoundariesByID(sorted)

	coord := sorted[0].Coord()

	// Prefer a predecessor mismatch with the smallest lexicographic id pair.
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i].Prev != sorted[j].Prev {
				a, b := sorted[i], sorted[j]
				return &Conflict{
					Partition: coord.Partition,
					Seq:       coord.Seq,
					Kind:      PairPrevMismatch,
					PrevA:     a.Prev,
					PrevB:     b.Prev,
					A:         a,
					B:         b,
				}
			}
		}
	}

	// All predecessor summaries agree, yet bodies/ids differ.
	a, b := sorted[0], sorted[1]
	return &Conflict{
		Partition: coord.Partition,
		Seq:       coord.Seq,
		Kind:      PairBodyDiverge,
		PrevA:     a.Prev,
		PrevB:     b.Prev,
		A:         a,
		B:         b,
	}
}

func sortBoundariesByID(bs []model.Boundary) {
	// local insertion sort keeps this file free of sort import churn; callers
	// also sort with sort.Slice in the index. n is tiny per coordinate.
	for i := 1; i < len(bs); i++ {
		for j := i; j > 0 && string(bs[j-1].ID()) > string(bs[j].ID()); j-- {
			bs[j-1], bs[j] = bs[j], bs[j-1]
		}
	}
}
