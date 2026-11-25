// Package reconcile is the pure, deterministic reconciliation kernel.
//
// It turns an order-independent set of boundaries, handoffs and effective
// revocations into a Report for a recovery watermark: the longest uniquely
// connected prefix from the trusted anchor, the earliest proven equivocation,
// and the unproven intervals.
package reconcile

import (
	"sort"

	"reviewer12731/internal/model"
	"reviewer12731/internal/stable"
)

// OpKind enumerates insertion / withdrawal facts for exhaustive small graphs.
type OpKind int

const (
	// OpBoundary inserts a (already authenticated) boundary.
	OpBoundary OpKind = iota
	// OpHandoff inserts a partition handoff record.
	OpHandoff
	// OpRevoke inserts an EFFECTIVE revocation withdrawing Target handoff.
	// Authentication / authorization of revocations is handled by the model
	// sealing layer before ops reach the pure kernel.
	OpRevoke
)

// Op is one insertion or withdrawal. Ops may be handed to Settle in any order.
type Op struct {
	Kind   OpKind
	B      model.Boundary
	H      model.Handoff
	Target string
	R      model.Revocation
}

// AddBoundary is an insertion op for a boundary.
func AddBoundary(b model.Boundary) Op { return Op{Kind: OpBoundary, B: b} }

// AddHandoff is an insertion op for a handoff.
func AddHandoff(h model.Handoff) Op { return Op{Kind: OpHandoff, H: h} }

// RevokeHandoff withdraws a handoff by id (effective revocation).
func RevokeHandoff(r model.Revocation) Op {
	return Op{Kind: OpRevoke, Target: r.RevokesID, R: r}
}

// WithdrawHandoff is a compact constructor for an effective withdrawal.
func WithdrawHandoff(handoffID string) Op {
	return Op{Kind: OpRevoke, Target: handoffID, R: model.Revocation{
		ID: "rev-" + handoffID, RevokesID: handoffID,
	}}
}

// Facts is the settled, serializable, order-independent dataset. Revocations
// must already have been authenticated as effective.
type Facts struct {
	Anchor      model.Anchor       `json:"anchor"`
	Boundaries  []model.Boundary   `json:"boundaries"`
	Handoffs    []model.Handoff    `json:"handoffs"`
	Revocations []model.Revocation `json:"effectiveRevocations"`
}

// Settle collapses ops (in ANY order) into canonical Facts. De-duplication is
// by content id, so replicating the same boundary from three copies is a no-op.
func Settle(anchor model.Anchor, ops ...Op) Facts {
	bounds := map[model.Digest]model.Boundary{}
	hands := map[string]model.Handoff{}
	revs := map[string]model.Revocation{}

	for _, op := range ops {
		switch op.Kind {
		case OpBoundary:
			bounds[op.B.ID()] = op.B
		case OpHandoff:
			hands[op.H.ID] = op.H
		case OpRevoke:
			r := op.R
			if r.RevokesID == "" {
				r.RevokesID = op.Target
			}
			if r.ID == "" {
				r.ID = "rev-" + r.RevokesID
			}
			revs[r.RevokesID] = r
		}
	}

	f := Facts{Anchor: anchor}
	for _, b := range bounds {
		f.Boundaries = append(f.Boundaries, b)
	}
	for _, h := range hands {
		f.Handoffs = append(f.Handoffs, h)
	}
	for _, r := range revs {
		f.Revocations = append(f.Revocations, r)
	}
	sortFacts(&f)
	return f
}

func sortFacts(f *Facts) {
	sort.Slice(f.Boundaries, func(i, j int) bool { return f.Boundaries[i].ID() < f.Boundaries[j].ID() })
	sort.Slice(f.Handoffs, func(i, j int) bool { return f.Handoffs[i].ID < f.Handoffs[j].ID })
	sort.Slice(f.Revocations, func(i, j int) bool { return f.Revocations[i].ID < f.Revocations[j].ID })
}

// Reviewer is a settled Facts with prebuilt indexes. Review is a pure read and
// may be called repeatedly for different historical watermarks.
type Reviewer struct {
	facts    Facts
	byID     map[model.Digest]model.Boundary
	handoffs map[string]model.Handoff
	revoked  map[string]model.Revocation
	byCoord  map[model.Coord][]model.Boundary

	// RejectedRevocations is optional authenticated-layer detail echoed into
	// reports; it never changes kernel conclusions.
	RejectedRevocations []model.RejectedRevocation
}

// NewReviewer builds indexes and computes admissibility once.
func NewReviewer(f Facts) *Reviewer {
	sortFacts(&f)
	r := &Reviewer{
		facts:    f,
		byID:     map[model.Digest]model.Boundary{},
		handoffs: map[string]model.Handoff{},
		revoked:  map[string]model.Revocation{},
		byCoord:  map[model.Coord][]model.Boundary{},
	}
	for _, h := range f.Handoffs {
		r.handoffs[h.ID] = h
	}
	for _, rv := range f.Revocations {
		r.revoked[rv.RevokesID] = rv
	}
	for _, b := range f.Boundaries {
		r.byID[b.ID()] = b
		if r.admissible(b) {
			c := b.Coord()
			r.byCoord[c] = append(r.byCoord[c], b)
		}
	}
	for c := range r.byCoord {
		g := r.byCoord[c]
		sort.Slice(g, func(i, j int) bool { return g[i].ID() < g[j].ID() })
		r.byCoord[c] = g
	}
	return r
}

// admissible applies the handoff gate via the shared exported predicate.
func (r *Reviewer) admissible(b model.Boundary) bool {
	return Admissible(b, r.handoffs, r.revoked)
}

// Review computes the deterministic conclusion for the given recovery
// watermark (inclusive sequence upper bound) in the anchor's partition.
func (r *Reviewer) Review(watermark int64) *Report {
	a := r.facts.Anchor
	rep := &Report{
		Schema:              "reviewer12731/report/v1",
		Partition:           a.Partition,
		Anchor:              a,
		Watermark:           watermark,
		Status:              StatusWatermark,
		Prefix:              []model.Digest{a.Digest},
		PrefixSeqs:          []int64{a.Seq},
		TrustedThroughSeq:   a.Seq,
		Tip:                 a.Digest,
		UnprovenIntervals:   []model.Interval{},
		Conflicts:           []Conflict{},
		Coordinates:         []CoordInfo{},
		RejectedRevocations: r.RejectedRevocations,
	}

	// Sorted evidence coordinates inside the reviewed window.
	var seqs []int64
	groups := map[int64][]model.Boundary{}
	for c, g := range r.byCoord {
		if c.Partition != a.Partition {
			continue
		}
		if c.Seq <= a.Seq || c.Seq > watermark {
			continue
		}
		seqs = append(seqs, c.Seq)
		groups[c.Seq] = g
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })

	// Every proven conflict up to W (needed to separate conflict points from
	// unproven ranges even when a gap precedes a later conflict).
	conflictBySeq := map[int64]Conflict{}
	for _, s := range seqs {
		if c := pairAt(groups[s]); c != nil {
			rep.Conflicts = append(rep.Conflicts, *c)
			conflictBySeq[s] = *c
		}
	}
	if len(rep.Conflicts) > 0 {
		c := rep.Conflicts[0]
		rep.EarliestConflict = &c
	}

	// Longest uniquely-connected prefix: walk consecutive sequence numbers.
	tip := a.Digest
	trusted := a.Seq
	for s := a.Seq + 1; s <= watermark; s++ {
		g := groups[s] // nil if no admissible boundary at this seq

		if c, isConflict := conflictBySeq[s]; isConflict {
			rep.Status = StatusConflict
			_ = c
			break
		}

		var ext []model.Boundary
		for _, b := range g {
			if b.Prev == tip {
				ext = append(ext, b)
			}
		}

		if len(ext) == 1 {
			b := ext[0]
			rep.Prefix = append(rep.Prefix, b.ID())
			rep.PrefixSeqs = append(rep.PrefixSeqs, b.Seq)
			trusted = b.Seq
			tip = b.ID()
			continue
		}

		// len(ext)==0 with no equivocation => missing/unconnected link.
		// len(ext)>=2 cannot happen here: two same-coord ext are an
		// equivocation and would have been classified as a conflict above.
		rep.Status = StatusGap
		break
	}

	rep.TrustedThroughSeq = trusted
	rep.ConnectedCount = len(rep.Prefix) - 1
	rep.Tip = tip

	// Build unproven intervals over (trusted .. W], removing conflict points.
	rep.UnprovenIntervals = buildUnproven(a.Partition, trusted, watermark, rep.Conflicts)
	if rep.Status == StatusGap && len(rep.UnprovenIntervals) > 0 {
		first := rep.UnprovenIntervals[0]
		rep.BlockingInterval = &first
	}

	rep.Coordinates = r.coordInfos(seqs, groups, conflictBySeq, rep.PrefixSeqs, trusted, tip)
	rep.EffectiveHandoffs, rep.RevokedHandoffs = r.handoffLists()

	rep.ConclusionHash = computeHash(rep)
	return rep
}

// buildUnproven constructs maximal non-conflict runs in (trusted, W].
func buildUnproven(partition string, trusted, watermark int64, conflicts []Conflict) []model.Interval {
	if watermark <= trusted {
		return []model.Interval{}
	}
	var conflictSeqs []int64
	for _, c := range conflicts {
		if c.Seq > trusted && c.Seq <= watermark {
			conflictSeqs = append(conflictSeqs, c.Seq)
		}
	}
	sort.Slice(conflictSeqs, func(i, j int) bool { return conflictSeqs[i] < conflictSeqs[j] })

	var out []model.Interval
	cur := trusted + 1
	flush := func(to int64) {
		if cur <= to {
			out = append(out, model.Interval{Partition: partition, From: cur, To: to})
		}
	}
	for _, cs := range conflictSeqs {
		if cs < cur {
			continue
		}
		flush(cs - 1)
		cur = cs + 1
	}
	flush(watermark)
	if out == nil {
		out = []model.Interval{}
	}
	return out
}

func (r *Reviewer) coordInfos(
	seqs []int64,
	groups map[int64][]model.Boundary,
	conflictBySeq map[int64]Conflict,
	prefixSeqs []int64,
	trusted int64,
	tip model.Digest,
) []CoordInfo {
	trustedSet := map[int64]bool{}
	for _, s := range prefixSeqs {
		trustedSet[s] = true
	}
	out := []CoordInfo{}
	for _, s := range seqs {
		g := groups[s]
		info := CoordInfo{Seq: s, AdmissibleCount: len(g), Region: "unproven"}
		prevSet := map[model.Digest]bool{}
		for _, b := range g {
			info.BoundaryIDs = append(info.BoundaryIDs, b.ID())
			prevSet[b.Prev] = true
		}
		for p := range prevSet {
			info.DistinctPrevs = append(info.DistinctPrevs, p)
		}
		sort.Slice(info.BoundaryIDs, func(i, j int) bool { return info.BoundaryIDs[i] < info.BoundaryIDs[j] })
		sort.Slice(info.DistinctPrevs, func(i, j int) bool {
			return info.DistinctPrevs[i] < info.DistinctPrevs[j]
		})
		if _, isConflict := conflictBySeq[s]; isConflict {
			info.Region = "conflict"
		} else if trustedSet[s] {
			info.Region = "trusted"
		}
		// For the unique coordinate directly after the trusted tip, report
		// whether any claim points at that tip.
		if s == trusted+1 {
			for _, b := range g {
				if b.Prev == tip {
					info.ConnectsFromTip = true
					break
				}
			}
		}
		out = append(out, info)
	}
	return out
}

func (r *Reviewer) handoffLists() (effective, revoked []string) {
	revSet := map[string]bool{}
	for id := range r.revoked {
		if _, ok := r.handoffs[id]; ok {
			revSet[id] = true
			revoked = append(revoked, id)
		}
	}
	for id := range r.handoffs {
		if !revSet[id] {
			effective = append(effective, id)
		}
	}
	sort.Strings(effective)
	sort.Strings(revoked)
	if effective == nil {
		effective = []string{}
	}
	if revoked == nil {
		revoked = []string{}
	}
	return effective, revoked
}

func computeHash(rep *Report) model.Digest {
	rep.ConclusionHash = ""
	payload, err := stable.Compact(rep)
	if err != nil {
		// All report fields are JSON-safe by construction.
		panic(err)
	}
	return model.SumCanonical("Conclusion", payload)
}

// VerifyHash re-derives the conclusion hash and reports whether it matches.
func (rep Report) VerifyHash() bool {
	want := rep.ConclusionHash
	rep.ConclusionHash = ""
	payload, err := stable.Compact(&rep)
	if err != nil {
		return false
	}
	return model.SumCanonical("Conclusion", payload) == want
}
