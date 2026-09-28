package builder

import (
	"path"
	"reflect"
	"testing"
	"time"
)

var (
	t1 time.Time
)

func init() {
	var err error
	t1, err = time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
	if err != nil {
		panic(err)
	}
}

func TestSnapshots(t *testing.T) {
	for _, tc := range []struct {
		name     string
		snapshot []*snapshot
	}{
		{
			name:     "empty",
			snapshot: []*snapshot{},
		},
		{
			name:     "nil",
			snapshot: nil,
		},
		{
			name: "single",
			snapshot: []*snapshot{
				{
					timestamp:         t1,
					referencedPackets: map[string][]uint64{"a": {1, 2, 3}},
					chunkCount:        42,
				},
			},
		},
		{
			name: "multiple",
			snapshot: []*snapshot{
				{
					timestamp:         t1,
					referencedPackets: map[string][]uint64{"a": {1, 2, 3}},
					chunkCount:        42,
				},
				{
					timestamp:         t1.Add(time.Hour),
					referencedPackets: map[string][]uint64{"b": {4, 5, 6}},
					chunkCount:        43,
				},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fn := path.Join(t.TempDir(), "test.snap")
			if err := saveSnapshots(fn, tc.snapshot); err != nil {
				t.Fatalf("saveSnapshots failed: %v", err)
			}
			got, err := loadSnapshots(fn)
			if err != nil {
				t.Fatalf("loadSnapshots failed: %v", err)
			}
			if len(got) != len(tc.snapshot) {
				t.Fatalf("len(got)=%d, want %d", len(got), len(tc.snapshot))
			}
			for i, want := range tc.snapshot {
				got := *got[i]
				if got.timestamp.UTC() != want.timestamp.UTC() {
					t.Errorf("got=%v, want %v", got.timestamp, want.timestamp)
				}
				if got.chunkCount != want.chunkCount {
					t.Errorf("got=%v, want %v", got.chunkCount, want.chunkCount)
				}
				if !reflect.DeepEqual(got.referencedPackets, want.referencedPackets) {
					t.Errorf("got=%v, want %v", got.referencedPackets, want.referencedPackets)
				}
			}
		})
	}
}

func TestCompactSnapshots(t *testing.T) {
	snapshots := []*snapshot{}
	for i := 0; i < 1024; i++ {
		snapshots = compactSnapshots(append(snapshots, &snapshot{
			timestamp:         t1.Add(time.Duration(i) * time.Second),
			chunkCount:        1,
			referencedPackets: map[string][]uint64{"pcap": {uint64(i)}},
		}))
	}
	if len(snapshots) > 22 {
		t.Fatalf("kept %d snapshots for 1024 chunks", len(snapshots))
	}
	if !snapshots[0].timestamp.Equal(t1) || !snapshots[len(snapshots)-1].timestamp.Equal(t1.Add(1023*time.Second)) {
		t.Fatalf("lost oldest or newest checkpoint")
	}
	total := uint64(0)
	counts := map[uint64]int{}
	for i, s := range snapshots {
		total += s.chunkCount
		counts[s.chunkCount]++
		if counts[s.chunkCount] > 2 {
			t.Fatalf("retained more than two snapshots of weight %d", s.chunkCount)
		}
		if i > 0 && !snapshots[i-1].timestamp.Before(s.timestamp) {
			t.Fatalf("snapshots are out of order")
		}
	}
	if total != 1024 {
		t.Fatalf("snapshot coverage = %d, want 1024", total)
	}
	filename := path.Join(t.TempDir(), "compacted.snap")
	if err := saveSnapshots(filename, snapshots); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadSnapshots(filename)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) != len(snapshots) {
		t.Fatalf("reloaded %d snapshots, want %d", len(loaded), len(snapshots))
	}
	for i := range loaded {
		if !loaded[i].timestamp.Equal(snapshots[i].timestamp) || loaded[i].chunkCount != snapshots[i].chunkCount || !reflect.DeepEqual(loaded[i].referencedPackets, snapshots[i].referencedPackets) {
			t.Fatalf("snapshot %d changed after roundtrip", i)
		}
	}
}
