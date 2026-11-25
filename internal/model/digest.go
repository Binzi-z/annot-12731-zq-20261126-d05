// Package model defines the sealed log vocabulary and deterministic digests.
//
// All hashing uses SHA-256 over a length-prefixed canonical encoding so that
// field boundaries are unambiguous. The package depends only on the standard
// library.
package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"hash"
)

// Digest is a lowercase hex SHA-256 summary (the "前序摘要").
type Digest string

// NilDigest is the predecessor of the genesis boundary.
const NilDigest Digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

// enc is a small canonical encoder. Every field is written either as a
// uvarint length prefix plus bytes, or as a fixed-width integer, which removes
// ambiguity between adjacent fields.
type enc struct{ h hash.Hash }

func newEncoder(domain string) *enc {
	e := &enc{h: sha256.New()}
	e.string("reviewer12731/v1/" + domain)
	return e
}

func (e *enc) string(s string) {
	var l [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(l[:], uint64(len(s)))
	_, _ = e.h.Write(l[:n])
	_, _ = e.h.Write([]byte(s))
}

func (e *enc) int64(v int64) {
	var b [binary.MaxVarintLen64]byte
	// zig-zag so negative sequence/issue values encode compactly and uniquely.
	uv := uint64(v<<1) ^ uint64(v>>63)
	n := binary.PutUvarint(b[:], uv)
	_, _ = e.h.Write(b[:n])
}

func (e *enc) digest(d Digest) { e.string(string(d)) }

func (e *enc) sum() Digest {
	return Digest("sha256:" + hex.EncodeToString(e.h.Sum(nil)))
}

// SumCanonical hashes an already-assembled canonical byte string with a domain
// tag. It is used for whole-report conclusion hashes.
func SumCanonical(domain string, payload []byte) Digest {
	h := sha256.New()
	var l [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(l[:], uint64(len(domain)))
	_, _ = h.Write(l[:n])
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write(payload)
	return Digest("sha256:" + hex.EncodeToString(h.Sum(nil)))
}

// HashBytes exposes a tagged digest for tests/tools that need one-off hashes.
func HashBytes(domain string, parts ...string) Digest {
	e := newEncoder(domain)
	for _, p := range parts {
		e.string(p)
	}
	return e.sum()
}
