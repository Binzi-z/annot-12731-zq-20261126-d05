package model

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
)

// SignatureDomain separates signatures by message kind.
const (
	DomainBoundary   = "boundary"
	DomainHandoff    = "handoff"
	DomainRevocation = "revocation"
)

func signMessage(domain string, id Digest) []byte {
	return []byte("reviewer12731-sig/" + domain + "/" + string(id))
}

// Signer is a named Ed25519 signing key held by a synthetic log node.
type Signer struct {
	Name string
	priv ed25519.PrivateKey
	Pub  ed25519.PublicKey
}

// NewSigner generates a fresh random key (used by ad-hoc tests).
func NewSigner(name string) (*Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Signer{Name: name, priv: priv, Pub: pub}, nil
}

// NewDeterministicSigner derives a key from a 32-byte seed so synthesized
// scenarios and their signatures are reproducible without randomness.
func NewDeterministicSigner(name string, seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return &Signer{Name: name, priv: priv, Pub: priv.Public().(ed25519.PublicKey)}, nil
}

func (s *Signer) sign(domain string, id Digest) []byte {
	return ed25519.Sign(s.priv, signMessage(domain, id))
}

// KeyRing is the tiny out-of-band trust bundle: signer names to pinned public
// keys. A third party needs only this constant-size bundle plus a certificate,
// never the whole log database.
type KeyRing map[string]ed25519.PublicKey

// Add registers a signer's public key.
func (k KeyRing) Add(s *Signer) { k[s.Name] = s.Pub }

// ErrUntrustedSigner means the signer name is not in the pinned key ring.
var ErrUntrustedSigner = errors.New("untrusted signer")

// Verify checks an Ed25519 signature against the pinned key for signer.
func (k KeyRing) Verify(signer, domain string, id Digest, sig []byte) error {
	pub, ok := k[signer]
	if !ok {
		return fmt.Errorf("%w: %q", ErrUntrustedSigner, signer)
	}
	if !ed25519.Verify(pub, signMessage(domain, id), sig) {
		return fmt.Errorf("invalid %s signature by %q on %s", domain, signer, id)
	}
	return nil
}

// TrustBundleJSON is the serializable, constant-size counterpart of KeyRing.
type TrustBundleJSON struct {
	Signers map[string]string `json:"signers"` // name -> hex/base64 public key
	Anchor  Anchor            `json:"anchor"`
}
