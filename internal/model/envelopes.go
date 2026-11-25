package model

import (
	"errors"
	"fmt"
)

// SealedBoundary is a boundary plus the producer's Ed25519 seal.
type SealedBoundary struct {
	Boundary
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"` // encoding/json renders []byte as base64
}

// SealBoundary signs the canonical boundary id.
func SealBoundary(s *Signer, b Boundary) SealedBoundary {
	return SealedBoundary{Boundary: b, Signer: s.Name, Signature: s.sign(DomainBoundary, b.ID())}
}

// Verify checks the seal against the key ring.
func (sb SealedBoundary) Verify(ring KeyRing) error {
	if err := ring.Verify(sb.Signer, DomainBoundary, sb.Boundary.ID(), sb.Signature); err != nil {
		return err
	}
	return nil
}

// SealedHandoff is a signed partition hand-off record.
type SealedHandoff struct {
	Handoff
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"`
}

// SealHandoff signs the handoff content id.
func SealHandoff(s *Signer, h Handoff) SealedHandoff {
	return SealedHandoff{Handoff: h, Signer: s.Name, Signature: s.sign(DomainHandoff, h.ContentID())}
}

// Verify checks the handoff seal.
func (sh SealedHandoff) Verify(ring KeyRing) error {
	return ring.Verify(sh.Signer, DomainHandoff, sh.Handoff.ContentID(), sh.Signature)
}

// SealedRevocation is a signed withdrawal of a handoff.
type SealedRevocation struct {
	Revocation
	Signer    string `json:"signer"`
	Signature []byte `json:"signature"`
}

// SealRevocation signs the revocation content id.
func SealRevocation(s *Signer, r Revocation) SealedRevocation {
	return SealedRevocation{Revocation: r, Signer: s.Name, Signature: s.sign(DomainRevocation, r.ContentID())}
}

// Verify checks the revocation seal.
func (sr SealedRevocation) Verify(ring KeyRing) error {
	return ring.Verify(sr.Signer, DomainRevocation, sr.Revocation.ContentID(), sr.Signature)
}

// RejectedRevocation explains why a purported revocation is not effective.
type RejectedRevocation struct {
	RevocationID string `json:"revocationId"`
	TargetID     string `json:"targetId"`
	Reason       string `json:"reason"`
}

// EffectiveRevocations authenticates handoffs and revocations and returns the
// set of handoff ids that are validly withdrawn ("后来有效撤销"), together with
// any revocations that were rejected (bad seal, unknown target, wrong authority,
// or not actually later). It never panics on malformed input.
//
// Authorization rule (deliberately small and explicit): a revocation is
// effective only when it has a valid pinned signature, names a known handoff,
// is issued strictly after that handoff, and is signed by the handoff Owner.
func EffectiveRevocations(
	handoffs []SealedHandoff,
	revocations []SealedRevocation,
	ring KeyRing,
) (revoked map[string]Revocation, validHandoffs map[string]Handoff, rejected []RejectedRevocation) {
	validHandoffs = make(map[string]Handoff, len(handoffs))
	for _, sh := range handoffs {
		if err := sh.Verify(ring); err != nil {
			rejected = append(rejected, RejectedRevocation{
				RevocationID: "(handoff " + sh.ID + ")", TargetID: sh.ID,
				Reason: "handoff seal invalid: " + err.Error(),
			})
			continue
		}
		validHandoffs[sh.ID] = sh.Handoff
	}

	revoked = make(map[string]Revocation)
	for _, sr := range revocations {
		rr := sr.Revocation
		reject := func(reason string) {
			rejected = append(rejected, RejectedRevocation{
				RevocationID: rr.ID, TargetID: rr.RevokesID, Reason: reason,
			})
		}
		if err := sr.Verify(ring); err != nil {
			reject("revocation seal invalid: " + err.Error())
			continue
		}
		h, ok := validHandoffs[rr.RevokesID]
		if !ok {
			reject("target handoff unknown or itself failed seal verification")
			continue
		}
		if rr.Revoker != h.Owner || sr.Signer != h.Owner {
			reject(fmt.Sprintf("revoker %q is not authorized owner %q", rr.Revoker, h.Owner))
			continue
		}
		if rr.IssuedSeq <= h.IssuedSeq {
			reject(fmt.Sprintf("revocation issuedSeq %d is not later than handoff issuedSeq %d",
				rr.IssuedSeq, h.IssuedSeq))
			continue
		}
		// Last effective revocation wins deterministically; content is same effect.
		revoked[h.ID] = rr
	}
	return revoked, validHandoffs, rejected
}

// ErrTampered is returned by integrity checks on certificates.
var ErrTampered = errors.New("certificate content does not match its digest/seal")
