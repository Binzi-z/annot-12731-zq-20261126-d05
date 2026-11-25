package model

import (
	"encoding/base64"
	"fmt"
)

// Bundle exports the constant-size trust material (pinned signer public keys
// and the trusted anchor) to a JSON-serializable form. A third party needs
// only this plus a conflict certificate.
func (k KeyRing) Bundle(anchor Anchor) TrustBundleJSON {
	tb := TrustBundleJSON{Signers: map[string]string{}, Anchor: anchor}
	for name, pub := range k {
		tb.Signers[name] = base64.StdEncoding.EncodeToString(pub)
	}
	return tb
}

// LoadTrustBundle reconstructs a KeyRing from its serialized form.
func LoadTrustBundle(tb TrustBundleJSON) (KeyRing, error) {
	ring := KeyRing{}
	for name, s := range tb.Signers {
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("signer %q key not base64: %w", name, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("signer %q ed25519 public key must be 32 bytes, got %d", name, len(raw))
		}
		ring[name] = raw
	}
	return ring, nil
}
