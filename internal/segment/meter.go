package segment

import (
	"fmt"
	"sort"
	"strings"

	"reviewer12731/internal/model"
)

// Key is the partition-aware ordering key used by segment/item comparisons.
type Key struct {
	Partition string
	Seq       int64
}

func (k Key) String() string { return fmt.Sprintf("%s#%d", k.Partition, k.Seq) }

// Meter counts every ordering/link comparison a recovery performs and records
// which partitions/segments were touched. It is the instrument that lets the
// large-data test prove a partition fill scans only relevant segments.
//
// A Meter is intended for single-goroutine offline review.
type Meter struct {
	// SegmentProbeCompares counts binary-search predicates over segment Lo.
	SegmentProbeCompares int64
	// ItemKeyCompares counts partition+seq ordering comparisons of records.
	ItemKeyCompares int64
	// LinkCompares counts Prev-digest == prior-ID hash link checks.
	LinkCompares int64

	// TouchedPartitions counts comparison touches per partition.
	TouchedPartitions map[string]int64
	// ProbedSegments are segment ids compared during index binary search.
	ProbedSegments map[string]struct{}
	// ScannedSegments are segment ids whose items were actually iterated.
	ScannedSegments map[string]struct{}
}

// NewMeter returns an empty meter.
func NewMeter() *Meter {
	return &Meter{
		TouchedPartitions: map[string]int64{},
		ProbedSegments:    map[string]struct{}{},
		ScannedSegments:   map[string]struct{}{},
	}
}

// Reset zeroes all counters and touch sets.
func (m *Meter) Reset() {
	m.SegmentProbeCompares = 0
	m.ItemKeyCompares = 0
	m.LinkCompares = 0
	m.TouchedPartitions = map[string]int64{}
	m.ProbedSegments = map[string]struct{}{}
	m.ScannedSegments = map[string]struct{}{}
}

func (m *Meter) touchPartition(p string) {
	if m == nil {
		return
	}
	m.TouchedPartitions[p]++
}

func (m *Meter) probeSegment(id, partition string) {
	m.SegmentProbeCompares++
	m.touchPartition(partition)
	m.ProbedSegments[id] = struct{}{}
}

func (m *Meter) scanSegment(id, partition string) {
	m.touchPartition(partition)
	m.ScannedSegments[id] = struct{}{}
}

// CompareKeys performs a counted three-way ordering comparison of two keys.
func (m *Meter) CompareKeys(a, b Key) int {
	m.ItemKeyCompares++
	m.touchPartition(a.Partition)
	m.touchPartition(b.Partition)
	if a.Partition != b.Partition {
		if a.Partition < b.Partition {
			return -1
		}
		return 1
	}
	switch {
	case a.Seq < b.Seq:
		return -1
	case a.Seq > b.Seq:
		return 1
	default:
		return 0
	}
}

// CheckLink counts and performs a hash-link equality check.
func (m *Meter) CheckLink(prev model.Digest, id model.Digest) bool {
	m.LinkCompares++
	return prev == id
}

// TotalComparisons returns the grand total of all counted comparisons.
func (m *Meter) TotalComparisons() int64 {
	return m.SegmentProbeCompares + m.ItemKeyCompares + m.LinkCompares
}

// PartitionSet returns the sorted partitions touched by comparisons.
func (m *Meter) PartitionSet() []string {
	out := make([]string, 0, len(m.TouchedPartitions))
	for p := range m.TouchedPartitions {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ScannedSegmentIDs returns sorted ids of item-iterated segments.
func (m *Meter) ScannedSegmentIDs() []string {
	out := make([]string, 0, len(m.ScannedSegments))
	for id := range m.ScannedSegments {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ProbedSegmentIDs returns sorted ids touched by index binary search.
func (m *Meter) ProbedSegmentIDs() []string {
	out := make([]string, 0, len(m.ProbedSegments))
	for id := range m.ProbedSegments {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Report renders a compact measurement line.
func (m *Meter) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "comparisons total=%d (segmentProbe=%d itemKey=%d link=%d)",
		m.TotalComparisons(), m.SegmentProbeCompares, m.ItemKeyCompares, m.LinkCompares)
	fmt.Fprintf(&b, " partitionsTouched=[%s]", strings.Join(m.PartitionSet(), ","))
	fmt.Fprintf(&b, " scannedSegments=%d probedSegments=%d",
		len(m.ScannedSegments), len(m.ProbedSegments))
	return b.String()
}
