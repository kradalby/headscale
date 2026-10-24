package graph

import (
	"errors"
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
)

func TestDerivedRecomputesOnlyOnChange(t *testing.T) {
	g := New()
	a := NewInput(g, "a", 1, Same[int])
	b := NewInput(g, "b", 10, Same[int])

	parityRuns, sumRuns := 0, 0
	parity := NewDerived(g, "parity", Same[int], func(s *Snapshot, _ int) int {
		parityRuns++

		return Get(s, a) % 2
	})
	sum := NewDerived(g, "sum", Same[int], func(s *Snapshot, _ int) int {
		sumRuns++

		return Get(s, parity) + Get(s, b)
	})

	s, err := g.Update(func(*Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	if got := Get(s, sum); got != 11 || parityRuns != 1 || sumRuns != 1 {
		t.Fatalf("first: sum=%d parity runs=%d sum runs=%d", got, parityRuns, sumRuns)
	}

	// 1 -> 3 keeps the parity: the cutoff skips sum.
	s, _ = g.Update(func(tx *Tx) error { Set(tx, a, 3); return nil })
	if got := Get(s, sum); got != 11 || parityRuns != 2 || sumRuns != 1 {
		t.Fatalf("cutoff: sum=%d parity runs=%d sum runs=%d", got, parityRuns, sumRuns)
	}

	// b feeds only sum.
	s, _ = g.Update(func(tx *Tx) error { Set(tx, b, 20); return nil })
	if got := Get(s, sum); got != 21 || parityRuns != 2 || sumRuns != 2 {
		t.Fatalf("b: sum=%d parity runs=%d sum runs=%d", got, parityRuns, sumRuns)
	}

	rev := s.Rev()

	// Setting an equal value commits nothing.
	s, _ = g.Update(func(tx *Tx) error { Set(tx, b, 20); return nil })
	if s.Rev() != rev {
		t.Fatalf("no-op commit published rev %d, want %d", s.Rev(), rev)
	}
}

func TestSnapshotsAreImmutable(t *testing.T) {
	g := New()
	a := NewInput(g, "a", "x", Same[string])

	old, _ := g.Update(func(tx *Tx) error { return nil })
	_, _ = g.Update(func(tx *Tx) error { Set(tx, a, "y"); return nil })

	if Get(old, a) != "x" || Get(g.Snapshot(), a) != "y" {
		t.Fatalf("old=%q latest=%q", Get(old, a), Get(g.Snapshot(), a))
	}

	if ChangedAt(old, a) == ChangedAt(g.Snapshot(), a) {
		t.Fatal("change revision did not move")
	}
}

func TestDerivedSeesPrevious(t *testing.T) {
	g := New()
	a := NewInput(g, "a", 1, Same[int])
	highest := NewDerived(g, "highest", Same[int], func(s *Snapshot, prev int) int {
		return max(prev, Get(s, a))
	})

	for _, v := range []int{5, 2, 7, 3} {
		_, _ = g.Update(func(tx *Tx) error { Set(tx, a, v); return nil })
	}

	if got := Get(g.Snapshot(), highest); got != 7 {
		t.Fatalf("max=%d, want 7", got)
	}
}

func TestDynamicDependencies(t *testing.T) {
	g := New()
	useB := NewInput(g, "useB", false, Same[bool])
	a := NewInput(g, "a", 1, Same[int])
	b := NewInput(g, "b", 2, Same[int])

	runs := 0
	pick := NewDerived(g, "pick", Same[int], func(s *Snapshot, _ int) int {
		runs++

		if Get(s, useB) {
			return Get(s, b)
		}

		return Get(s, a)
	})

	_, _ = g.Update(func(*Tx) error { return nil })
	// b is not read while useB is false.
	_, _ = g.Update(func(tx *Tx) error { Set(tx, b, 3); return nil })

	if runs != 1 {
		t.Fatalf("runs=%d after unread input changed, want 1", runs)
	}

	s, _ := g.Update(func(tx *Tx) error { Set(tx, useB, true); return nil })
	if Get(s, pick) != 3 || runs != 2 {
		t.Fatalf("pick=%d runs=%d", Get(s, pick), runs)
	}
}

var errBoom = errors.New("boom")

func TestAbortedUpdatePublishesNothing(t *testing.T) {
	g := New()
	a := NewInput(g, "a", 1, Same[int])
	_, _ = g.Update(func(*Tx) error { return nil })

	_, err := g.Update(func(tx *Tx) error {
		Set(tx, a, 2)

		if Peek(tx, a) != 2 {
			t.Fatal("peek misses staged value")
		}

		return errBoom
	})
	if !errors.Is(err, errBoom) || Get(g.Snapshot(), a) != 1 {
		t.Fatalf("err=%v a=%d", err, Get(g.Snapshot(), a))
	}
}

func TestSubscriptionCoalesces(t *testing.T) {
	g := New()
	a := NewInput(g, "a", 0, Same[int])

	sub := g.Subscribe()
	defer sub.Close()

	for i := 1; i <= 3; i++ {
		_, _ = g.Update(func(tx *Tx) error { Set(tx, a, i); return nil })
	}

	<-sub.C

	select {
	case <-sub.C:
		t.Fatal("wake-ups not coalesced")
	default:
	}

	if Get(g.Snapshot(), a) != 3 {
		t.Fatal("latest snapshot missing last commit")
	}
}

// fullDiff is the keys whose entry differs between a and b, by comparing
// every key.
func fullDiff(a, b map[int]int) []int {
	var keys []int

	for k, v := range b {
		if ov, ok := a[k]; !ok || ov != v {
			keys = append(keys, k)
		}
	}

	for k := range a {
		if _, ok := b[k]; !ok {
			keys = append(keys, k)
		}
	}

	slices.Sort(keys)

	return keys
}

func toNative[K comparable, V any](m *Map[K, V]) map[K]V {
	out := maps.Collect(m.All())

	return out
}

func sortedUnique(keys []int) []int {
	keys = slices.Clone(keys)
	slices.Sort(keys)

	return slices.Compact(keys)
}

// TestMapChangesMatchFullDiff applies random edits, some net-zero, and
// checks that between any two Maps of the history the changes reported
// equal a full comparison, through the edit log while it reaches and by
// comparison beyond it.
func TestMapChangesMatchFullDiff(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // deterministic test input

	const edits = 600

	history := make([]*Map[int, int], 1, edits+1)
	history[0] = NewMap(Same[int], map[int]int{1: 1, 2: 2})

	for range edits {
		e := history[len(history)-1].Edit()

		for range r.IntN(4) {
			k := r.IntN(20)

			switch r.IntN(3) {
			case 0:
				e.Delete(k)
			case 1:
				v, _ := e.Get(k)
				e.Set(k, v) // net-zero when present
			default:
				e.Set(k, r.IntN(5))
			}
		}

		history = append(history, e.Done())
	}

	for range 2000 {
		i := r.IntN(len(history))
		j := i + r.IntN(min(len(history)-i, mapLog+40))
		old, cur := history[i], history[j]

		want := fullDiff(toNative(old), toNative(cur))
		if got := Changes(old, cur); !slices.Equal(sortedUnique(got), want) || len(got) != len(want) {
			t.Fatalf("Changes(%d, %d) = %v, want %v", i, j, got, want)
		}

		if keys, ok := cur.ChangedSince(old); ok {
			// The log may name keys that changed back; never fewer.
			for _, k := range want {
				if !slices.Contains(keys, k) {
					t.Fatalf("ChangedSince(%d, %d) misses %d", i, j, k)
				}
			}
		} else if j-i <= mapLog && old != cur {
			// Equal Maps are skipped by Done, so a short distance always
			// reaches unless the edits were net-zero in between.
			if !slices.Contains(history[i+1:j+1], old) && len(want) > 0 && distinctEdits(history[i:j+1]) <= mapLog {
				t.Fatalf("ChangedSince(%d, %d) did not reach back", i, j)
			}
		}
	}
}

// distinctEdits counts the Maps in h that differ from the one before.
func distinctEdits[K comparable, V any](h []*Map[K, V]) int {
	n := 0

	for i := 1; i < len(h); i++ {
		if h[i] != h[i-1] {
			n++
		}
	}

	return n
}

func TestMapEditFromOlderMapStaysCorrect(t *testing.T) {
	base := NewMap(Same[int], map[int]int{1: 1})

	e := base.Edit()
	e.Set(2, 2)
	a := e.Done()

	e = base.Edit()
	e.Set(3, 3)
	b := e.Done()

	// a and b both come from base; neither is in the other's log.
	if _, ok := b.ChangedSince(a); ok {
		t.Fatal("sibling edits must not read as a lineage")
	}

	if got := sortedUnique(Changes(a, b)); !slices.Equal(got, []int{2, 3}) {
		t.Fatalf("Changes(a, b) = %v", got)
	}
}

func TestMapNetZeroEditReturnsSameMap(t *testing.T) {
	m := NewMap(Same[int], map[int]int{1: 1})

	e := m.Edit()
	e.Set(1, 2)
	e.Set(1, 1)
	e.Delete(9)

	if e.Done() != m {
		t.Fatal("an edit that changes nothing must return the same Map")
	}
}

// TestMapOperatorsMatchRebuild drives random edits through MapValues and
// GroupBy and checks each result equals computing it from scratch.
func TestMapOperatorsMatchRebuild(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // deterministic test input

	double := func(_ int, v int) (int, bool) { return 2 * v, v%3 != 0 }
	groups := func(k, v int) []int { return []int{v % 4, k % 2 * 10} }

	in := NewMap(Same[int], map[int]int{})

	var (
		mapped  Mapped[int, int, int]
		grouped Grouped[int, int, int]
	)

	for step := range 500 {
		e := in.Edit()

		for range 1 + r.IntN(3) {
			if r.IntN(4) == 0 {
				e.Delete(r.IntN(30))
			} else {
				e.Set(r.IntN(30), r.IntN(12))
			}
		}

		in = e.Done()

		// Skip a step now and then so the operators catch up over
		// several edits.
		if r.IntN(3) == 0 {
			continue
		}

		mapped = MapValues(mapped, in, double, Same[int])
		grouped = GroupBy(grouped, in, groups)

		wantMapped := map[int]int{}
		wantGroups := map[int][]int{}

		for k, v := range toNative(in) {
			if w, ok := double(k, v); ok {
				wantMapped[k] = w
			}

			for _, g := range groups(k, v) {
				wantGroups[g] = append(wantGroups[g], k)
			}
		}

		for g, keys := range wantGroups {
			wantGroups[g] = sortedUnique(keys)
		}

		if got := toNative(mapped.Out); !maps.Equal(got, wantMapped) {
			t.Fatalf("step %d: MapValues = %v, want %v", step, got, wantMapped)
		}

		if got := toNative(grouped.Groups); !maps.EqualFunc(got, wantGroups, slices.Equal[[]int]) {
			t.Fatalf("step %d: GroupBy = %v, want %v", step, got, wantGroups)
		}
	}
}
