package synth

import (
	"sort"

	"reviewer12731/internal/model"
)

func sortDigests(ds []model.Digest) {
	sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
}

func sortStrings(ss []string) { sort.Strings(ss) }
