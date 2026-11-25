package reconcile

import (
	"errors"
	"fmt"
	"sort"

	"reviewer12731/internal/model"
	"reviewer12731/internal/stable"
)

// ErrNoContradiction is returned when a certificate does not actually contain
// an equivocating pair at one coordinate.
var ErrNoContradiction = errors.New("boundaries do not contradict at one coordinate")

// EnvelopeSource supplies sealed envelopes when building a certificate from a
// report. Implementations may be an in-memory index or a thin lookup over the
// sealed copies; certificate construction only reads the tiny referenced set.
type EnvelopeSource interface {
	SealedBoundaryByID(id model.Digest) (model.SealedBoundary, bool)
	SealedHandoffByID(id string) (model.SealedHandoff, bool)
	SealedRevocationsForHandoff(id string) []model.SealedRevocation
}

// MemEnvelopes is a map-backed EnvelopeSource.
type MemEnvelopes struct {
	Bounds        map[model.Digest]model.SealedBoundary
	Hands         map[string]model.SealedHandoff
	RevsByHandoff map[string][]model.SealedRevocation
}

// NewMemEnvelopes indexes sealed copies for certificate construction.
func NewMemEnvelopes(bs []model.SealedBoundary, hs []model.SealedHandoff, rs []model.SealedRevocation) *MemEnvelopes {
	m := &MemEnvelopes{
		Bounds:        map[model.Digest]model.SealedBoundary{},
		Hands:         map[string]model.SealedHandoff{},
		RevsByHandoff: map[string][]model.SealedRevocation{},
	}
	for _, b := range bs {
		m.Bounds[b.Boundary.ID()] = b
	}
	for _, h := range hs {
		m.Hands[h.ID] = h
	}
	for _, r := range rs {
		m.RevsByHandoff[r.RevokesID] = append(m.RevsByHandoff[r.RevokesID], r)
	}
	for k := range m.RevsByHandoff {
		rr := m.RevsByHandoff[k]
		sort.Slice(rr, func(i, j int) bool { return rr[i].ID < rr[j].ID })
		m.RevsByHandoff[k] = rr
	}
	return m
}

// SealedBoundaryByID implements EnvelopeSource.
func (m *MemEnvelopes) SealedBoundaryByID(id model.Digest) (model.SealedBoundary, bool) {
	b, ok := m.Bounds[id]
	return b, ok
}

// SealedHandoffByID implements EnvelopeSource.
func (m *MemEnvelopes) SealedHandoffByID(id string) (model.SealedHandoff, bool) {
	h, ok := m.Hands[id]
	return h, ok
}

// SealedRevocationsForHandoff implements EnvelopeSource.
func (m *MemEnvelopes) SealedRevocationsForHandoff(id string) []model.SealedRevocation {
	return m.RevsByHandoff[id]
}

// ConflictCert is the minimal boundary certificate ("最小边界证书"). It carries
// the contradictory pair and only the handoff/revocation context directly
// referenced by that pair. A third party verifies it with a constant-size
// trusted KeyRing and Anchor — never the whole original database.
type ConflictCert struct {
	Schema    string                `json:"schema"`
	CertKind  string                `json:"certKind"` // "conflict-boundary-pair/v1"
	PairKind  PairKind              `json:"pairKind"`
	Partition string                `json:"partition"`
	Seq       int64                 `json:"seq"`
	Watermark int64                 `json:"watermark"`
	Anchor    model.Anchor          `json:"anchor"`
	A         model.SealedBoundary  `json:"a"`
	B         model.SealedBoundary  `json:"b"`
	Handoffs  []model.SealedHandoff `json:"handoffs,omitempty"`
	// Revocations contains any revocations targeting the included handoffs, so
	// the verifier can independently decide whether a handoff is effective.
	Revocations []model.SealedRevocation `json:"revocations,omitempty"`
	CertHash    model.Digest             `json:"certHash"`
}

// NewStructuralConflictCert builds a certificate around the raw pair. The
// embedded boundaries may be unsigned when no EnvelopeSource is available
// (pure kernel tests); structural contradiction detection still works.
func NewStructuralConflictCert(anchor model.Anchor, watermark int64, c Conflict) *ConflictCert {
	cert := &ConflictCert{
		Schema:    "reviewer12731/cert/v1",
		CertKind:  "conflict-boundary-pair/v1",
		PairKind:  c.Kind,
		Partition: c.Partition,
		Seq:       c.Seq,
		Watermark: watermark,
		Anchor:    anchor,
		A:         model.SealedBoundary{Boundary: c.A},
		B:         model.SealedBoundary{Boundary: c.B},
	}
	cert.CertHash = hashCert(cert)
	return cert
}

// BuildSealedConflictCert constructs the minimal sealed certificate for the
// report's earliest proven conflict, attaching seals and the referenced
// handoff/revocation context from src.
func BuildSealedConflictCert(rep *Report, src EnvelopeSource) (*ConflictCert, error) {
	if rep.EarliestConflict == nil {
		return nil, fmt.Errorf("report has no proven conflict to certify")
	}
	return BuildCertForConflict(rep.Anchor, rep.Watermark, rep.EarliestConflict, src)
}

// BuildCertForConflict builds a sealed certificate for any chosen conflict.
func BuildCertForConflict(anchor model.Anchor, watermark int64, c *Conflict, src EnvelopeSource) (*ConflictCert, error) {
	cert := NewStructuralConflictCert(anchor, watermark, *c)

	if src != nil {
		sa, ok := src.SealedBoundaryByID(c.A.ID())
		if !ok {
			return nil, fmt.Errorf("sealed envelope missing for boundary A %s", c.A.ID())
		}
		sb, ok := src.SealedBoundaryByID(c.B.ID())
		if !ok {
			return nil, fmt.Errorf("sealed envelope missing for boundary B %s", c.B.ID())
		}
		cert.A = sa
		cert.B = sb

		needed := map[string]bool{}
		if id := sa.HandoffID; id != "" {
			needed[id] = true
		}
		if id := sb.HandoffID; id != "" {
			needed[id] = true
		}
		ids := make([]string, 0, len(needed))
		for id := range needed {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if h, ok := src.SealedHandoffByID(id); ok {
				cert.Handoffs = append(cert.Handoffs, h)
			}
			cert.Revocations = append(cert.Revocations, src.SealedRevocationsForHandoff(id)...)
		}
	}

	cert.CertHash = hashCert(cert)
	return cert, nil
}

func hashCert(c *ConflictCert) model.Digest {
	saved := c.CertHash
	c.CertHash = ""
	payload, err := stable.Compact(c)
	c.CertHash = saved
	if err != nil {
		panic(err)
	}
	return model.SumCanonical("ConflictCert", payload)
}

// VerifyCertHash checks the certificate's self-hash (corruption/tamper clue).
func (c *ConflictCert) VerifyCertHash() bool {
	return hashCert(c) == c.CertHash
}

// DetectPair returns the pair kind when a and b equivocate, or an error
// describing why they do not. This is the database-free contradiction check.
func DetectPair(a, b model.Boundary) (PairKind, error) {
	if a.Partition != b.Partition {
		return "", fmt.Errorf("different partitions %q vs %q", a.Partition, b.Partition)
	}
	if a.Seq != b.Seq {
		return "", fmt.Errorf("different sequence numbers %d vs %d", a.Seq, b.Seq)
	}
	if a.ID() == b.ID() {
		return "", fmt.Errorf("identical replicated boundary %s (not a conflict)", a.ID())
	}
	if a.Prev != b.Prev {
		return PairPrevMismatch, nil
	}
	return PairBodyDiverge, nil
}

// CertVerdict is the result of standalone certificate verification.
type CertVerdict struct {
	// PairDetected is true iff the two embedded boundaries equivocate.
	PairDetected bool `json:"pairDetected"`
	// StrongContradiction is true iff predecessor summaries differ.
	StrongContradiction bool     `json:"strongContradiction"`
	Kind                PairKind `json:"kind"`
	Partition           string   `json:"partition"`
	Seq                 int64    `json:"seq"`
	// HashIntact reports the certificate self-hash.
	HashIntact bool `json:"hashIntact"`
	// AuthenticityChecked is false when no KeyRing was supplied.
	AuthenticityChecked bool `json:"authenticityChecked"`
	// SignaturesValid is meaningful only when AuthenticityChecked is true.
	SignaturesValid bool `json:"signaturesValid"`
	// ContextAdmissible reports both boundaries are admissible under the
	// embedded handoff/revocation context (re-derived, not trusted).
	ContextAdmissible bool     `json:"contextAdmissible"`
	EffectiveHandoffs []string `json:"effectiveHandoffs"`
	RevokedHandoffs   []string `json:"revokedHandoffs"`
	Notes             []string `json:"notes"`
}

// VerifyConflictCert independently checks a certificate.
//
// ring may be nil: then only the structural contradiction and self-hash are
// checked (suitable for pure manual/database-free detection). When ring is
// non-nil, all Ed25519 seals and the handoff/revocation authorization are
// verified and the returned error is non-nil unless the certificate proves a
// currently-admissible, authentic contradiction.
func VerifyConflictCert(cert *ConflictCert, ring model.KeyRing) (*CertVerdict, error) {
	v := &CertVerdict{
		Partition:  cert.Partition,
		Seq:        cert.Seq,
		HashIntact: cert.VerifyCertHash(),
	}
	if !v.HashIntact {
		v.Notes = append(v.Notes, "certificate self-hash mismatch (content tampered or corrupted)")
	}

	kind, derr := DetectPair(cert.A.Boundary, cert.B.Boundary)
	if derr != nil {
		return v, fmt.Errorf("%w: %v", ErrNoContradiction, derr)
	}
	v.PairDetected = true
	v.Kind = kind
	v.StrongContradiction = kind == PairPrevMismatch

	// Coordinate fields must agree with the embedded boundaries.
	if cert.Partition != cert.A.Partition || cert.Seq != cert.A.Seq ||
		cert.Partition != cert.B.Partition || cert.Seq != cert.B.Seq {
		return v, fmt.Errorf("certificate coordinate does not match embedded pair")
	}

	if ring == nil {
		v.Notes = append(v.Notes, "no trusted key ring supplied: authenticity NOT checked")
		// Structural detection succeeded; absence of ring is not a hard error
		// for the database-free contradiction requirement.
		return v, nil
	}

	v.AuthenticityChecked = true
	sigOK := true
	if err := cert.A.Verify(ring); err != nil {
		sigOK = false
		v.Notes = append(v.Notes, "boundary A: "+err.Error())
	}
	if err := cert.B.Verify(ring); err != nil {
		sigOK = false
		v.Notes = append(v.Notes, "boundary B: "+err.Error())
	}

	revoked, validHands, rejected := model.EffectiveRevocations(cert.Handoffs, cert.Revocations, ring)
	for _, rj := range rejected {
		v.Notes = append(v.Notes, "rejected revocation/handoff: "+rj.Reason)
	}
	for id := range validHands {
		if _, isRev := revoked[id]; isRev {
			v.RevokedHandoffs = append(v.RevokedHandoffs, id)
		} else {
			v.EffectiveHandoffs = append(v.EffectiveHandoffs, id)
		}
	}
	sort.Strings(v.EffectiveHandoffs)
	sort.Strings(v.RevokedHandoffs)

	v.ContextAdmissible = Admissible(cert.A.Boundary, validHands, revoked) &&
		Admissible(cert.B.Boundary, validHands, revoked)
	v.SignaturesValid = sigOK

	if !v.HashIntact {
		return v, errors.New("certificate hash verification failed")
	}
	if !sigOK {
		return v, errors.New("one or more boundary signatures failed trusted-key verification")
	}
	if !v.ContextAdmissible {
		return v, errors.New("pair is structurally contradictory but a boundary is not admissible under embedded handoff context")
	}
	return v, nil
}

// Admissible is the exported handoff-gate predicate shared by the kernel and
// the standalone certificate verifier.
func Admissible(
	b model.Boundary,
	handoffs map[string]model.Handoff,
	revoked map[string]model.Revocation,
) bool {
	if b.HandoffID == "" {
		return true
	}
	h, ok := handoffs[b.HandoffID]
	if !ok {
		return false
	}
	if _, isRevoked := revoked[h.ID]; isRevoked {
		return false
	}
	return h.Partition == b.Partition &&
		h.Seq == b.Seq &&
		h.FromDigest == b.Prev
}
