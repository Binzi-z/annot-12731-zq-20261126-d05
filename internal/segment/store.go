package segment

import (
	"fmt"
	"sort"

	"reviewer12731/internal/model"
)

// Segment is a contiguous stored run of boundaries within one partition.
// Lo/Hi are inclusive sequence bounds and Items are sorted by Seq.
type Segment struct {
	Partition string
	ID        string
	Lo        int64
	Hi        int64
	Items     []model.Boundary
}

// Store keeps an index partition -> sorted (by Lo) segment list. It never
// mixes partition indexes, so every lookup is inherently partition-local.
type Store struct {
	parts map[string][]*Segment
	// order preserves insertion for the naive global-scan baseline.
	all   []*Segment
	Meter *Meter
}

// NewStore returns an empty partitioned segment store using meter.
func NewStore(meter *Meter) *Store {
	if meter == nil {
		meter = NewMeter()
	}
	return &Store{parts: map[string][]*Segment{}, Meter: meter}
}

// Add inserts a segment. Call Build after bulk loading to sort indexes.
func (s *Store) Add(seg *Segment) {
	s.parts[seg.Partition] = append(s.parts[seg.Partition], seg)
	s.all = append(s.all, seg)
}

// Build sorts each partition's segments by Lo and validates basic shape.
func (s *Store) Build() error {
	for p, segs := range s.parts {
		sort.Slice(segs, func(i, j int) bool {
			if segs[i].Lo != segs[j].Lo {
				return segs[i].Lo < segs[j].Lo
			}
			return segs[i].ID < segs[j].ID
		})
		s.parts[p] = segs
		for _, g := range segs {
			if g.Partition != p {
				return fmt.Errorf("segment %s filed under %q but declares %q", g.ID, p, g.Partition)
			}
			if g.Lo > g.Hi {
				return fmt.Errorf("segment %s has inverted range [%d,%d]", g.ID, g.Lo, g.Hi)
			}
		}
	}
	return nil
}

// Partitions returns sorted partition ids.
func (s *Store) Partitions() []string {
	out := make([]string, 0, len(s.parts))
	for p := range s.parts {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Segments returns the sorted segments of one partition.
func (s *Store) Segments(partition string) []*Segment { return s.parts[partition] }

// AllSegments returns every segment in insertion order.
func (s *Store) AllSegments() []*Segment { return s.all }

// lowerBound returns the first index in the partition's sorted segment slice
// whose Lo >= lo. Every predicate is a counted, partition-local probe.
func (s *Store) lowerBound(partition string, lo int64) int {
	segs := s.parts[partition]
	return sort.Search(len(segs), func(i int) bool {
		seg := segs[i]
		s.Meter.probeSegment(seg.ID, seg.Partition)
		return seg.Lo >= lo
	})
}

// Bracket returns the segments immediately left and right of a missing range
// beginning at gapLo. right is the first segment with Lo >= gapLo; left is its
// predecessor. Either may be nil at the partition edge. The single binary
// search touches only the named partition's index.
func (s *Store) Bracket(partition string, gapLo int64) (left, right *Segment, idx int) {
	segs := s.parts[partition]
	idx = s.lowerBound(partition, gapLo)
	if idx < len(segs) {
		right = segs[idx]
	}
	if idx > 0 {
		left = segs[idx-1]
	}
	return left, right, idx
}

// FillReport is the measured result of verifying a recovered segment fills a
// gap and links to both brackets.
type FillReport struct {
	Partition       string
	GapLo, GapHi    int64
	LeftID, RightID string
	FillID          string
	ScannedSegments []string
	MeterSnapshot   Meter
}

// VerifyFill checks that fill exactly occupies [gapLo,gapHi], is internally
// contiguous and hash-chained, and links to the left/right bracket segments.
//
// Only the fill segment and its two brackets have their items scanned; locating
// the brackets is one partition-local binary search. The meter proves it.
func (s *Store) VerifyFill(gapLo, gapHi int64, fill *Segment) (*FillReport, error) {
	m := s.Meter
	if fill.Lo != gapLo || fill.Hi != gapHi {
		return nil, fmt.Errorf("fill range [%d,%d] does not match gap [%d,%d]",
			fill.Lo, fill.Hi, gapLo, gapHi)
	}
	if fill.Partition == "" {
		fill.Partition = s.partitionFor(fill)
	}
	p := fill.Partition

	left, right, _ := s.Bracket(p, gapLo)
	if left != nil {
		m.scanSegment(left.ID, left.Partition)
	}
	m.scanSegment(fill.ID, fill.Partition)
	if right != nil {
		m.scanSegment(right.ID, right.Partition)
	}

	if err := checkContiguousChain(m, fill); err != nil {
		return nil, fmt.Errorf("fill %s invalid: %w", fill.ID, err)
	}

	if left != nil && len(left.Items) > 0 {
		tail := left.Items[len(left.Items)-1]
		head := fill.Items[0]
		if c := m.CompareKeys(Key{left.Partition, tail.Seq}, Key{fill.Partition, head.Seq}); c >= 0 {
			return nil, fmt.Errorf("left bracket %s tail seq %d not before fill head %d",
				left.ID, tail.Seq, head.Seq)
		}
		if !m.CheckLink(head.Prev, tail.ID()) {
			return nil, fmt.Errorf("fill head does not reference left tail %s", tail.ID())
		}
	}
	if right != nil && len(right.Items) > 0 {
		tail := fill.Items[len(fill.Items)-1]
		head := right.Items[0]
		if c := m.CompareKeys(Key{fill.Partition, tail.Seq}, Key{right.Partition, head.Seq}); c >= 0 {
			return nil, fmt.Errorf("fill tail seq %d not before right head %d", tail.Seq, head.Seq)
		}
		if !m.CheckLink(head.Prev, tail.ID()) {
			return nil, fmt.Errorf("right head does not reference fill tail %s", tail.ID())
		}
	}

	rep := &FillReport{
		Partition: p, GapLo: gapLo, GapHi: gapHi,
		FillID: fill.ID, ScannedSegments: m.ScannedSegmentIDs(),
		MeterSnapshot: Meter{
			SegmentProbeCompares: m.SegmentProbeCompares,
			ItemKeyCompares:      m.ItemKeyCompares,
			LinkCompares:         m.LinkCompares,
		},
	}
	if left != nil {
		rep.LeftID = left.ID
	}
	if right != nil {
		rep.RightID = right.ID
	}
	return rep, nil
}

func (s *Store) partitionFor(seg *Segment) string { return seg.Partition }

// checkContiguousChain counts item-key and hash-link comparisons while
// verifying seq increases by one and each Prev equals the prior ID.
func checkContiguousChain(m *Meter, seg *Segment) error {
	for i := 1; i < len(seg.Items); i++ {
		prev, cur := seg.Items[i-1], seg.Items[i]
		if c := m.CompareKeys(Key{seg.Partition, prev.Seq}, Key{seg.Partition, cur.Seq}); c != -1 {
			return fmt.Errorf("items not strictly ordered at index %d", i)
		}
		if cur.Seq != prev.Seq+1 {
			return fmt.Errorf("non-contiguous seq %d -> %d", prev.Seq, cur.Seq)
		}
		if !m.CheckLink(cur.Prev, prev.ID()) {
			return fmt.Errorf("broken Prev link between seq %d and %d", prev.Seq, cur.Seq)
		}
	}
	return nil
}

// Reconstruction is the measured result of reading one whole partition.
type Reconstruction struct {
	Partition string
	Items     []model.Boundary
	Gaps      []model.Interval
}

// ReconstructPartition reads exactly the segments belonging to partition in
// order, counting adjacent item comparisons and detecting gaps between segment
// ranges. No other partition's index or items are touched.
func (s *Store) ReconstructPartition(partition string) (*Reconstruction, error) {
	m := s.Meter
	segs := s.parts[partition]
	out := &Reconstruction{Partition: partition, Gaps: []model.Interval{}}
	var prev *model.Boundary

	for _, seg := range segs {
		m.scanSegment(seg.ID, seg.Partition)
		for i := range seg.Items {
			b := seg.Items[i]
			if prev != nil {
				if c := m.CompareKeys(Key{partition, prev.Seq}, Key{partition, b.Seq}); c != -1 {
					return nil, fmt.Errorf("partition %s order error near seq %d", partition, b.Seq)
				}
				if b.Seq != prev.Seq+1 {
					// Item-level detection also covers jumps between adjacent
					// stored segments, so a removed segment yields one gap.
					out.Gaps = append(out.Gaps, model.Interval{
						Partition: partition, From: prev.Seq + 1, To: b.Seq - 1,
					})
				}
				m.CheckLink(b.Prev, prev.ID())
			}
			tmp := b
			prev = &tmp
			out.Items = append(out.Items, b)
		}
	}
	return out, nil
}

// NaiveGlobalScanComparisons simulates an unindexed scan that examines every
// stored segment across every partition to locate target, returning the number
// of comparisons under the same full-key comparator. Used only as a baseline to
// quantify the locality win; it deliberately does not touch the live Meter.
func (s *Store) NaiveGlobalScanComparisons(target Key) int64 {
	baseline := NewMeter()
	var examined int64
	for _, seg := range s.all {
		examined++ // one segment-entry examination
		baseline.CompareKeys(Key{Partition: seg.Partition, Seq: seg.Lo}, target)
	}
	return examined + baseline.ItemKeyCompares
}
