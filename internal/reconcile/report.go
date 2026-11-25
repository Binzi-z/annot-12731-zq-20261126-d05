package reconcile

import (
	"reviewer12731/internal/model"
)

// Status is the outcome of extending from the trusted anchor to a watermark.
type Status string

const (
	// StatusWatermark means the chain was uniquely extended all the way to W.
	StatusWatermark Status = "REACHED_WATERMARK"
	// StatusConflict means extension stopped at an earliest proven equivocation.
	StatusConflict Status = "BLOCKED_BY_PROVEN_CONFLICT"
	// StatusGap means extension stopped because the next link cannot be proven;
	// the corresponding range is unproven, not contradictory.
	StatusGap Status = "BLOCKED_BY_UNPROVEN_GAP"
)

// PairKind classifies a same-coordinate pair of distinct admissible boundaries.
type PairKind string

const (
	// PairPrevMismatch is the canonical contradiction: same coordinate,
	// different predecessor summary ("同一序号下给出不同前序摘要").
	PairPrevMismatch PairKind = "PREDECESSOR_MISMATCH"
	// PairBodyDiverge: same coordinate and same predecessor but two distinct
	// bodies/digests. Still an equivocation a safe prefix cannot pass.
	PairBodyDiverge PairKind = "SAME_PREV_DISTINCT_BODY"
)

// Conflict is a proven equivocating pair at one coordinate.
type Conflict struct {
	Partition string         `json:"partition"`
	Seq       int64          `json:"seq"`
	Kind      PairKind       `json:"kind"`
	PrevA     model.Digest   `json:"prevA"`
	PrevB     model.Digest   `json:"prevB"`
	A         model.Boundary `json:"a"`
	B         model.Boundary `json:"b"`
}

// CoordInfo summarizes evidence at one coordinate inside the reviewed window.
type CoordInfo struct {
	Seq             int64          `json:"seq"`
	BoundaryIDs     []model.Digest `json:"boundaryIds"`
	DistinctPrevs   []model.Digest `json:"distinctPrevs"`
	AdmissibleCount int            `json:"admissibleCount"`
	Region          string         `json:"region"` // trusted | conflict | unproven
	ConnectsFromTip bool           `json:"connectsFromTip,omitempty"`
}

// Report is the deterministic conclusion for one (dataset, watermark).
type Report struct {
	Schema    string       `json:"schema"`
	Partition string       `json:"partition"`
	Anchor    model.Anchor `json:"anchor"`
	Watermark int64        `json:"watermark"`
	Status    Status       `json:"status"`
	// Prefix contains boundary ids from the anchor (inclusive) through the tip.
	Prefix     []model.Digest `json:"prefix"`
	PrefixSeqs []int64        `json:"prefixSeqs"`
	// ConnectedCount is the number of non-anchor boundaries uniquely extended.
	ConnectedCount    int          `json:"connectedCount"`
	TrustedThroughSeq int64        `json:"trustedThroughSeq"`
	Tip               model.Digest `json:"tip"`
	EarliestConflict  *Conflict    `json:"earliestProvenConflict,omitempty"`
	// BlockingInterval is the leading unproven interval directly after the
	// prefix when Status == StatusGap; nil when blocked by conflict/WM.
	BlockingInterval    *model.Interval            `json:"blockingInterval,omitempty"`
	UnprovenIntervals   []model.Interval           `json:"unprovenIntervals"`
	Conflicts           []Conflict                 `json:"allConflictsUpToWatermark"`
	Coordinates         []CoordInfo                `json:"coordinates"`
	EffectiveHandoffs   []string                   `json:"effectiveHandoffs"`
	RevokedHandoffs     []string                   `json:"revokedHandoffs"`
	RejectedRevocations []model.RejectedRevocation `json:"rejectedRevocations,omitempty"`
	// ConclusionHash is the reproducible hash of all fields above with this
	// field blank. It pins the conclusion for a historical watermark.
	ConclusionHash model.Digest `json:"conclusionHash"`
}
