package reconcile

import (
	"testing"

	"reviewer12731/internal/model"
)

// TestStructuralPairDetection covers the database-free contradiction predicate
// and certificate verification with no key ring.
func TestStructuralPairDetection(t *testing.T) {
	anchor, chain := testChain("cert", 3)
	b2, b3 := chain[1], chain[2]

	// A genuine predecessor mismatch.
	fork := model.Boundary{
		Partition: "cert", Seq: 2,
		Prev: model.HashBytes("alt", "root"), Nonce: "fork2",
	}
	c := &Conflict{
		Partition: "cert", Seq: 2, Kind: PairPrevMismatch,
		PrevA: b2.Prev, PrevB: fork.Prev, A: b2, B: fork,
	}
	cert := NewStructuralConflictCert(anchor, 3, *c)
	v, err := VerifyConflictCert(cert, nil)
	if err != nil {
		t.Fatalf("structural verify: %v", err)
	}
	if !v.PairDetected || !v.StrongContradiction {
		t.Fatalf("expected strong contradiction, got %+v", v)
	}
	if v.AuthenticityChecked {
		t.Fatalf("nil ring must not claim authenticity")
	}

	// Same boundary replicated is not a contradiction.
	if _, err := DetectPair(b2, b2); err == nil {
		t.Fatalf("identical boundaries must not be a contradiction")
	}
	// Different sequence is not a same-coordinate contradiction.
	if _, err := DetectPair(b2, b3); err == nil {
		t.Fatalf("different seq must not be a contradiction")
	}
	// Equivocates / Contradictory predicates agree.
	if !Contradictory(b2, fork) {
		t.Fatalf("Contradictory predicate should be true")
	}
	if Equivocates(b2, b3) {
		t.Fatalf("different seq must not equivocate")
	}
}

// TestCertDetectsTampering ensures any content mutation invalidates either the
// self hash or (with a ring) the signature.
func TestCertDetectsTampering(t *testing.T) {
	signer, err := model.NewSigner("n1")
	if err != nil {
		t.Fatal(err)
	}
	ring := model.KeyRing{}
	ring.Add(signer)

	anchor, chain := testChain("tamper", 2)
	good := chain[1]
	fork := model.Boundary{
		Partition: "tamper", Seq: 2, Prev: model.HashBytes("z", "z"), Nonce: "f",
	}
	sealedA := model.SealBoundary(signer, good)
	sealedB := model.SealBoundary(signer, fork)

	cert := &ConflictCert{
		Schema: "reviewer12731/cert/v1", CertKind: "conflict-boundary-pair/v1",
		PairKind: PairPrevMismatch, Partition: "tamper", Seq: 2, Watermark: 2,
		Anchor: anchor, A: sealedA, B: sealedB,
	}
	cert.CertHash = hashCert(cert)

	if _, err := VerifyConflictCert(cert, ring); err != nil {
		t.Fatalf("honest sealed cert should verify: %v", err)
	}

	// Tamper with B's predecessor but leave signature/hash untouched.
	tampered := *cert
	tampered.B.Prev = model.HashBytes("tampered", "prev")
	if _, err := VerifyConflictCert(&tampered, ring); err == nil {
		t.Fatalf("tampered predecessor must fail verification")
	}

	// Recompute only the self-hash after tampering: signature must still fail.
	tampered2 := *cert
	tampered2.B.Nonce = "mutated-body"
	tampered2.CertHash = hashCert(&tampered2)
	if _, err := VerifyConflictCert(&tampered2, ring); err == nil {
		t.Fatalf("re-hashed tampered cert must still fail signature check")
	}

	// A certificate whose pair no longer contradicts must be rejected even if
	// an attacker re-signs with their own trusted-ish key is out of scope; here
	// we just swap in two non-equivocating boundaries and re-hash.
	bad := NewStructuralConflictCert(anchor, 2, Conflict{A: chain[0], B: chain[1], Seq: 1})
	if _, err := VerifyConflictCert(bad, nil); err == nil {
		t.Fatalf("non-contradictory cert must be rejected")
	}
}

// TestTwoCertsContradict demonstrates the headline third-party property: given
// two minimal boundary certificates/claims without the database, the verifier
// can detect that their boundaries are mutually contradictory.
func TestTwoCertsContradict(t *testing.T) {
	_, chain := testChain("x", 2)
	one := chain[1]
	other := model.Boundary{
		Partition: "x", Seq: 2, Prev: model.HashBytes("different", "past"), Nonce: "o",
	}
	ka, err := DetectPair(one, other)
	if err != nil || ka != PairPrevMismatch {
		t.Fatalf("two boundary claims should be detected as contradictory: %v %v", ka, err)
	}
}
