package model

// Coord is the unique logical coordinate of a boundary: partition + sequence.
// Within one partition a correct log has exactly one admissible boundary per Seq.
type Coord struct {
	Partition string `json:"partition"`
	Seq       int64  `json:"seq"`
}

// Boundary is one hash-chained log boundary ("边界"). Two distinct boundaries
// sharing a Coord but carrying different Prev summaries are a provable
// equivocation once both are admissible.
type Boundary struct {
	Partition string `json:"partition"`
	Seq       int64  `json:"seq"`
	// Prev is the summary of the immediately preceding boundary ("前序摘要").
	Prev Digest `json:"prev"`
	// Nonce stands in for the arbitrary record payload. It guarantees distinct
	// own digests for distinct bodies and is covered by the seal.
	Nonce string `json:"nonce"`
	// HandoffID, when non-empty, names the partition handoff authority under
	// which this boundary was accepted. The boundary is admissible only while
	// that handoff exists and has not been effectively revoked.
	HandoffID string `json:"handoffId,omitempty"`
}

// Coord returns the boundary coordinate.
func (b Boundary) Coord() Coord { return Coord{Partition: b.Partition, Seq: b.Seq} }

// ID is the boundary's own content digest, used as the next boundary's Prev.
func (b Boundary) ID() Digest {
	e := newEncoder("Boundary")
	e.string(b.Partition)
	e.int64(b.Seq)
	e.digest(b.Prev)
	e.string(b.Nonce)
	e.string(b.HandoffID)
	return e.sum()
}

// Handoff is a sealed partition hand-off record ("分区交接记录"). It authorizes
// boundaries that name HandoffID and whose predecessor equals FromDigest.
type Handoff struct {
	ID            string `json:"id"`
	Partition     string `json:"partition"`
	Seq           int64  `json:"seq"`
	FromPartition string `json:"fromPartition,omitempty"`
	FromDigest    Digest `json:"fromDigest"`
	ToPartition   string `json:"toPartition,omitempty"`
	IssuedSeq     int64  `json:"issuedSeq"`
	Owner         string `json:"owner"`
}

// HandoffID computes the canonical content id of a handoff when callers do not
// pin a human-readable id. Synthetic data pins readable ids for certificates.
func (h Handoff) ContentID() Digest {
	e := newEncoder("Handoff")
	e.string(h.ID)
	e.string(h.Partition)
	e.int64(h.Seq)
	e.string(h.FromPartition)
	e.digest(h.FromDigest)
	e.string(h.ToPartition)
	e.int64(h.IssuedSeq)
	e.string(h.Owner)
	return e.sum()
}

// Revocation is a sealed, later withdrawal of one handoff ("有效撤销").
// Effective() additionally requires a valid seal and authorization, checked by
// the sealing layer; the reconcile kernel only sees already-effective ones.
type Revocation struct {
	ID        string `json:"id"`
	RevokesID string `json:"revokesHandoffId"`
	IssuedSeq int64  `json:"issuedSeq"`
	Revoker   string `json:"revoker"`
	Reason    string `json:"reason,omitempty"`
}

// ContentID returns the canonical content digest of the revocation.
func (r Revocation) ContentID() Digest {
	e := newEncoder("Revocation")
	e.string(r.ID)
	e.string(r.RevokesID)
	e.int64(r.IssuedSeq)
	e.string(r.Revoker)
	e.string(r.Reason)
	return e.sum()
}

// Anchor is the pinned trusted start ("受信起点"). Its digest is trusted out of
// band; the reviewer extends the chain forward from it.
type Anchor struct {
	Partition string `json:"partition"`
	Seq       int64  `json:"seq"`
	Digest    Digest `json:"digest"`
	Label     string `json:"label,omitempty"`
}

// Interval is an inclusive sequence-number range inside one partition.
type Interval struct {
	Partition string `json:"partition"`
	From      int64  `json:"from"`
	To        int64  `json:"to"`
}

// Contains reports whether seq lies in the inclusive interval.
func (in Interval) Contains(seq int64) bool { return in.From <= seq && seq <= in.To }
