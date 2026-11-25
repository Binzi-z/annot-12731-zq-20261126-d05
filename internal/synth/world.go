// Package synth generates deterministic local synthetic data: three sealed
// copies exhibiting missing segments, same-sequence predecessor equivocation,
// and a later effective handoff revocation (plus an ineffective one). It also
// builds the large partitioned fixture used for locality measurements.
package synth

import (
	"crypto/sha256"
	"fmt"

	"reviewer12731/internal/model"
	"reviewer12731/internal/reconcile"
)

// Scenario constants pin the canonical worked example.
const (
	Partition      = "acct"
	ConflictSeq    = int64(7)
	LastTrusted    = int64(4)
	GapFrom        = int64(5)
	GapToBefore    = int64(6)
	HandoffRevoked = "ho-acct-9"
	HandoffActive  = "ho-acct-10"
)

// Watermarks is the deterministic set of historical recovery watermarks.
var Watermarks = []int64{3, 4, 6, 7, 8, 10}

// Copy is one machine-room sealed replica.
type Copy struct {
	Name        string                   `json:"name"`
	Location    string                   `json:"location"`
	Missing     []string                 `json:"missingSegments,omitempty"`
	Boundaries  []model.SealedBoundary   `json:"boundaries"`
	Handoffs    []model.SealedHandoff    `json:"handoffs,omitempty"`
	Revocations []model.SealedRevocation `json:"revocations,omitempty"`
}

// World holds everything the CLI/tests need from the canonical scenario.
type World struct {
	Ring    model.KeyRing
	Signers map[string]*model.Signer
	Anchor  model.Anchor
	Copies  []Copy

	MergedBoundaries  []model.SealedBoundary
	MergedHandoffs    []model.SealedHandoff
	MergedRevocations []model.SealedRevocation

	Facts    reconcile.Facts
	Reviewer *reconcile.Reviewer
	Source   *reconcile.MemEnvelopes

	// Convenience labels for assertions / targeted certificates.
	Correct map[int64]model.Boundary
	ForkAt7 model.Boundary
	Gated9  model.Boundary
	Gated10 model.Boundary
}

func deterministicSigner(name string) (*model.Signer, error) {
	sum := sha256.Sum256([]byte("reviewer12731-seed/" + name))
	return model.NewDeterministicSigner(name, sum[:])
}

// NewCanonicalWorld builds the deterministic three-copy scenario.
func NewCanonicalWorld() (*World, error) {
	w := &World{
		Ring:    model.KeyRing{},
		Signers: map[string]*model.Signer{},
		Correct: map[int64]model.Boundary{},
	}
	for _, name := range []string{"node-a", "node-b", "node-c", "node-handoff"} {
		s, err := deterministicSigner(name)
		if err != nil {
			return nil, err
		}
		w.Signers[name] = s
		w.Ring.Add(s)
	}
	a := w.Signers["node-a"]
	b := w.Signers["node-b"]
	hsigner := w.Signers["node-handoff"]

	// Trusted genesis (seq 0).
	genesis := model.Boundary{
		Partition: Partition, Seq: 0, Prev: model.NilDigest, Nonce: "genesis-acct",
	}
	w.Anchor = model.Anchor{
		Partition: Partition, Seq: 0, Digest: genesis.ID(), Label: "pinned-genesis",
	}

	// Canonical correct chain seq 1..10.
	prev := w.Anchor.Digest
	for seq := int64(1); seq <= 10; seq++ {
		bnd := model.Boundary{
			Partition: Partition, Seq: seq, Prev: prev,
			Nonce: fmt.Sprintf("valid-record-%02d", seq),
		}
		w.Correct[seq] = bnd
		prev = bnd.ID()
	}

	// Equivocating fork at seq 7 with a DIFFERENT predecessor summary.
	fork7 := model.Boundary{
		Partition: Partition, Seq: 7,
		Prev:  model.HashBytes("rogue-prev", "forked-history-at-6"),
		Nonce: "forked-record-07",
	}
	w.ForkAt7 = fork7

	// Handoff H9 (later effectively revoked) gating a seq-9 boundary.
	h9 := model.Handoff{
		ID: HandoffRevoked, Partition: Partition, Seq: 9,
		FromPartition: Partition, FromDigest: w.Correct[8].ID(),
		ToPartition: Partition, IssuedSeq: 900, Owner: "node-handoff",
	}
	gated9 := model.Boundary{
		Partition: Partition, Seq: 9, Prev: w.Correct[8].ID(),
		Nonce: "transferred-record-09", HandoffID: h9.ID,
	}
	w.Gated9 = gated9

	// Handoff H10 (stays effective; a forged/unauthorized revocation is rejected).
	h10 := model.Handoff{
		ID: HandoffActive, Partition: Partition, Seq: 10,
		FromPartition: Partition, FromDigest: w.Correct[9].ID(),
		ToPartition: Partition, IssuedSeq: 910, Owner: "node-handoff",
	}
	gated10 := model.Boundary{
		Partition: Partition, Seq: 10, Prev: w.Correct[9].ID(),
		Nonce: "transferred-record-10", HandoffID: h10.ID,
	}
	w.Gated10 = gated10

	// Effective later revocation of h9 by its owner.
	rev9 := model.Revocation{
		ID: "revoke-ho-acct-9", RevokesID: h9.ID, IssuedSeq: 1000,
		Revoker: "node-handoff", Reason: "transfer invalidated by quorum",
	}
	// Ineffective revocation of h10: valid node-b signature but node-b is not
	// the handoff owner, so authorization fails.
	badRev10 := model.Revocation{
		ID: "revoke-bad-acct-10", RevokesID: h10.ID, IssuedSeq: 1001,
		Revoker: "node-b", Reason: "attempted takeover",
	}

	// ---- Sealed envelopes -------------------------------------------------
	sealCorrect := func(seq int64) model.SealedBoundary {
		return model.SealBoundary(a, w.Correct[seq])
	}
	sealedCorrect := map[int64]model.SealedBoundary{}
	for seq := int64(1); seq <= 10; seq++ {
		sealedCorrect[seq] = sealCorrect(seq)
	}
	sealedFork7 := model.SealBoundary(b, fork7)
	sealedGated9 := model.SealBoundary(hsigner, gated9)
	sealedGated10 := model.SealBoundary(hsigner, gated10)
	sealedH9 := model.SealHandoff(hsigner, h9)
	sealedH10 := model.SealHandoff(hsigner, h10)
	sealedRev9 := model.SealRevocation(hsigner, rev9)
	sealedBadRev10 := model.SealRevocation(b, badRev10)

	// ---- Three copies -----------------------------------------------------
	// All three omit seq 5 (a segment lost everywhere => genuine unproven gap).
	// central additionally loses the whole seq 2..3 segment but the union
	// recovers it. south carries the equivocating seq-7 fork.
	seqList := func(seqs ...int64) []model.SealedBoundary {
		out := make([]model.SealedBoundary, 0, len(seqs))
		for _, s := range seqs {
			out = append(out, sealedCorrect[s])
		}
		return out
	}

	north := Copy{
		Name: "dc-north", Location: "Langfang",
		Missing:     []string{"segment-seq05"},
		Boundaries:  append(seqList(1, 2, 3, 4, 6, 7, 8), sealedCorrect[9], sealedCorrect[10], sealedGated9, sealedGated10),
		Handoffs:    []model.SealedHandoff{sealedH9, sealedH10},
		Revocations: []model.SealedRevocation{sealedRev9, sealedBadRev10},
	}
	central := Copy{
		Name: "dc-central", Location: "Hohhot",
		Missing:    []string{"segment-seq02-03", "segment-seq05"},
		Boundaries: seqList(1, 4, 6, 7, 8, 9, 10),
	}
	south := Copy{
		Name: "dc-south", Location: "Guiyang",
		Missing:    []string{"segment-seq05", "segment-seq08"},
		Boundaries: append(seqList(1, 2, 3, 4, 6), sealedFork7, sealedCorrect[9], sealedCorrect[10]),
	}
	w.Copies = []Copy{north, central, south}

	// ---- Merge + authenticate --------------------------------------------
	seenB := map[model.Digest]model.SealedBoundary{}
	seenH := map[string]model.SealedHandoff{}
	var allR []model.SealedRevocation
	for _, cp := range w.Copies {
		for _, sb := range cp.Boundaries {
			if err := sb.Verify(w.Ring); err != nil {
				return nil, fmt.Errorf("copy %s boundary verify: %w", cp.Name, err)
			}
			seenB[sb.Boundary.ID()] = sb
		}
		for _, sh := range cp.Handoffs {
			if err := sh.Verify(w.Ring); err != nil {
				return nil, fmt.Errorf("copy %s handoff verify: %w", cp.Name, err)
			}
			seenH[sh.ID] = sh
		}
		for _, sr := range cp.Revocations {
			if err := sr.Verify(w.Ring); err != nil {
				return nil, fmt.Errorf("copy %s revocation verify: %w", cp.Name, err)
			}
			allR = append(allR, sr)
		}
	}
	// Replicate handoffs/revocations into merged lists deterministically.
	for _, sh := range []model.SealedHandoff{sealedH9, sealedH10} {
		seenH[sh.ID] = sh
	}

	bIDs := make([]model.Digest, 0, len(seenB))
	for id := range seenB {
		bIDs = append(bIDs, id)
	}
	sortDigests(bIDs)
	for _, id := range bIDs {
		w.MergedBoundaries = append(w.MergedBoundaries, seenB[id])
	}
	hIDs := make([]string, 0, len(seenH))
	for id := range seenH {
		hIDs = append(hIDs, id)
	}
	sortStrings(hIDs)
	for _, id := range hIDs {
		w.MergedHandoffs = append(w.MergedHandoffs, seenH[id])
	}
	w.MergedRevocations = allR

	revoked, validHands, rejected := model.EffectiveRevocations(
		w.MergedHandoffs, w.MergedRevocations, w.Ring)

	w.Facts = reconcile.Facts{Anchor: w.Anchor}
	for _, sb := range w.MergedBoundaries {
		w.Facts.Boundaries = append(w.Facts.Boundaries, sb.Boundary)
	}
	for _, h := range validHands {
		w.Facts.Handoffs = append(w.Facts.Handoffs, h)
	}
	for _, r := range revoked {
		w.Facts.Revocations = append(w.Facts.Revocations, r)
	}

	w.Reviewer = reconcile.NewReviewer(w.Facts)
	w.Reviewer.RejectedRevocations = rejected
	w.Source = reconcile.NewMemEnvelopes(
		w.MergedBoundaries, w.MergedHandoffs, w.MergedRevocations)
	return w, nil
}

// ReviewAll returns one reproducible report per historical watermark.
func (w *World) ReviewAll() []*reconcile.Report {
	out := make([]*reconcile.Report, 0, len(Watermarks))
	for _, wm := range Watermarks {
		out = append(out, w.Reviewer.Review(wm))
	}
	return out
}
