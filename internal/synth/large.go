package synth

import (
	"fmt"

	"reviewer12731/internal/model"
	"reviewer12731/internal/segment"
)

// GapSpec names one removed segment by partition index and block index.
type GapSpec struct {
	PartitionIndex int
	BlockIndex     int
}

// GapFill is a removed segment retained as the "recovered" fill material.
type GapFill struct {
	Partition  string
	BlockIndex int
	GapLo      int64
	GapHi      int64
	Segment    *segment.Segment
}

// LargeFixture is a many-partition, many-segment store with three spaced gaps.
type LargeFixture struct {
	Store    *segment.Store
	Meter    *segment.Meter
	Fills    []GapFill
	GapByKey map[string]GapFill

	Partitions    int
	BlocksPer     int
	ItemsPerBlock int
	Watermark     int64
	TotalSegments int
	Names         []string
}

// DefaultGaps are the "隔开的三个空档": different partitions and well-spaced
// block indices (early / middle / late).
func DefaultGaps(blocks int) []GapSpec {
	return []GapSpec{
		{PartitionIndex: 2, BlockIndex: blocks / 4},
		{PartitionIndex: 5, BlockIndex: blocks / 2},
		{PartitionIndex: 8, BlockIndex: 3 * blocks / 4},
	}
}

// NewDefaultLarge builds a ~74k-boundary fixture: 12 partitions x 96 segments
// x 64 boundaries, with three separated missing segments.
func NewDefaultLarge() (*LargeFixture, error) {
	const partitions, blocks, items = 12, 96, 64
	return NewLargeFixture(partitions, blocks, items, DefaultGaps(blocks))
}

// NewLargeFixture deterministically builds np independent hash chains, each
// split into `blocks` segments of `items` boundaries, removing the segments
// named by gaps (kept as recoverable fills).
func NewLargeFixture(np, blocks, items int, gaps []GapSpec) (*LargeFixture, error) {
	meter := segment.NewMeter()
	store := segment.NewStore(meter)

	f := &LargeFixture{
		Store: store, Meter: meter,
		Partitions: np, BlocksPer: blocks, ItemsPerBlock: items,
		GapByKey: map[string]GapFill{},
	}
	for pi := 0; pi < np; pi++ {
		name := fmt.Sprintf("p%02d", pi)
		f.Names = append(f.Names, name)
	}
	isGap := map[string]bool{}
	for _, g := range gaps {
		isGap[fmt.Sprintf("%d/%d", g.PartitionIndex, g.BlockIndex)] = true
	}

	for pi := 0; pi < np; pi++ {
		pname := f.Names[pi]
		genesis := model.Boundary{
			Partition: pname, Seq: 0, Prev: model.NilDigest,
			Nonce: fmt.Sprintf("genesis-%s", pname),
		}
		prev := genesis.ID()

		for bi := 0; bi < blocks; bi++ {
			seg := &segment.Segment{
				Partition: pname,
				ID:        fmt.Sprintf("%s/seg-%03d", pname, bi),
			}
			for k := 0; k < items; k++ {
				seq := int64(bi*items + k + 1)
				b := model.Boundary{
					Partition: pname, Seq: seq, Prev: prev,
					Nonce: fmt.Sprintf("%s/rec-%06d", pname, seq),
				}
				seg.Items = append(seg.Items, b)
				prev = b.ID()
			}
			seg.Lo = seg.Items[0].Seq
			seg.Hi = seg.Items[len(seg.Items)-1].Seq

			if isGap[fmt.Sprintf("%d/%d", pi, bi)] {
				gf := GapFill{
					Partition: pname, BlockIndex: bi,
					GapLo: seg.Lo, GapHi: seg.Hi, Segment: seg,
				}
				f.Fills = append(f.Fills, gf)
				f.GapByKey[pname] = gf
				continue // removed => the gap
			}
			store.Add(seg)
		}
	}
	if err := store.Build(); err != nil {
		return nil, err
	}
	f.Watermark = int64(blocks * items)
	f.TotalSegments = np*blocks - len(gaps)
	return f, nil
}

// AddFill writes a recovered segment back into the store and rebuilds indexes.
func (f *LargeFixture) AddFill(g GapFill) error {
	f.Store.Add(g.Segment)
	return f.Store.Build()
}
