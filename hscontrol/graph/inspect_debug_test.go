//go:build headscale_debug

package graph

import (
	"slices"
	"testing"
)

func TestInspectSnapshotDependenciesAndIsolation(t *testing.T) {
	g := New()
	choose := g.NewInput("choose", true, Same[bool])
	a := g.NewInput("a", 7, Same[int])
	b := g.NewInput("b", 7, Same[int])
	NewDerived(g, "selected", Same[int], func(s *Snapshot, _ int) int {
		if s.Get(choose) {
			return s.Get(a) + s.Get(a)
		}

		return s.Get(b) + s.Get(b)
	})

	old, err := g.Update(func(*Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	next, err := g.Update(func(tx *Tx) error { Set(tx, choose, false); return nil })
	if err != nil {
		t.Fatal(err)
	}

	first, second := g.Inspect(old), g.Inspect(next)
	if first[0].Kind != "input" || first[3].Kind != "derived" || first[3].Name != "selected" {
		t.Fatalf("wrong metadata: %+v", first)
	}

	if !slices.Equal(first[3].Dependencies, []string{"choose", "a"}) || !slices.Equal(second[3].Dependencies, []string{"choose", "b"}) {
		t.Fatalf("dependencies must follow the supplied snapshot: %+v / %+v", first, second)
	}

	if second[3].ChangedAt != old.Rev() || second[0].ChangedAt != next.Rev() {
		t.Fatalf("equality cutoff lost: %+v", second)
	}

	first[3].Dependencies[0], first[0].Name = "corrupt", "corrupt"
	if got := g.Inspect(old); got[0].Name != "choose" || got[3].Dependencies[0] != "choose" {
		t.Fatalf("metadata aliases snapshot: %+v", got)
	}
}
