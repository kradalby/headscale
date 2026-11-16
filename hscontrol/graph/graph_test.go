package graph

import (
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"pgregory.net/rapid"
)

func TestDerivedRecomputesOnlyOnChange(t *testing.T) {
	g := New()
	a := g.NewInput("a", 1, Same[int])
	b := g.NewInput("b", 10, Same[int])

	parityRuns, sumRuns := 0, 0
	parity := NewDerived(g, "parity", Same[int], func(s *Snapshot, _ int) int {
		parityRuns++

		return s.Get(a) % 2
	})
	sum := NewDerived(g, "sum", Same[int], func(s *Snapshot, _ int) int {
		sumRuns++

		return s.Get(parity) + s.Get(b)
	})

	s, err := g.Update(func(*Tx) error { return nil })
	if err != nil {
		t.Fatal(err)
	}

	if got := s.Get(sum); got != 11 || parityRuns != 1 || sumRuns != 1 {
		t.Fatalf("first: sum=%d parity runs=%d sum runs=%d", got, parityRuns, sumRuns)
	}

	// 1 -> 3 keeps the parity: the cutoff skips sum.
	s, _ = g.Update(func(tx *Tx) error { Set(tx, a, 3); return nil })
	if got := s.Get(sum); got != 11 || parityRuns != 2 || sumRuns != 1 {
		t.Fatalf("cutoff: sum=%d parity runs=%d sum runs=%d", got, parityRuns, sumRuns)
	}

	// b feeds only sum.
	s, _ = g.Update(func(tx *Tx) error { Set(tx, b, 20); return nil })
	if got := s.Get(sum); got != 21 || parityRuns != 2 || sumRuns != 2 {
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
	a := g.NewInput("a", "x", Same[string])

	old, _ := g.Update(func(tx *Tx) error { return nil })
	_, _ = g.Update(func(tx *Tx) error { Set(tx, a, "y"); return nil })

	if old.Get(a) != "x" || g.Snapshot().Get(a) != "y" {
		t.Fatalf("old=%q latest=%q", old.Get(a), g.Snapshot().Get(a))
	}

	if ChangedAt(old, a) == ChangedAt(g.Snapshot(), a) {
		t.Fatal("change revision did not move")
	}
}

func TestDerivedSeesPrevious(t *testing.T) {
	g := New()
	a := g.NewInput("a", 1, Same[int])
	highest := NewDerived(g, "highest", Same[int], func(s *Snapshot, prev int) int {
		return max(prev, s.Get(a))
	})

	for _, v := range []int{5, 2, 7, 3} {
		_, _ = g.Update(func(tx *Tx) error { Set(tx, a, v); return nil })
	}

	if got := g.Snapshot().Get(highest); got != 7 {
		t.Fatalf("max=%d, want 7", got)
	}
}

func TestDynamicDependencies(t *testing.T) {
	g := New()
	useB := g.NewInput("useB", false, Same[bool])
	a := g.NewInput("a", 1, Same[int])
	b := g.NewInput("b", 2, Same[int])

	runs := 0
	pick := NewDerived(g, "pick", Same[int], func(s *Snapshot, _ int) int {
		runs++

		if s.Get(useB) {
			return s.Get(b)
		}

		return s.Get(a)
	})

	_, _ = g.Update(func(*Tx) error { return nil })
	// b is not read while useB is false.
	_, _ = g.Update(func(tx *Tx) error { Set(tx, b, 3); return nil })

	if runs != 1 {
		t.Fatalf("runs=%d after unread input changed, want 1", runs)
	}

	s, _ := g.Update(func(tx *Tx) error { Set(tx, useB, true); return nil })
	if s.Get(pick) != 3 || runs != 2 {
		t.Fatalf("pick=%d runs=%d", s.Get(pick), runs)
	}
}

var errBoom = errors.New("boom")

func TestAbortedUpdatePublishesNothing(t *testing.T) {
	g := New()
	a := g.NewInput("a", 1, Same[int])
	_, _ = g.Update(func(*Tx) error { return nil })

	_, err := g.Update(func(tx *Tx) error {
		Set(tx, a, 2)

		if Peek(tx, a) != 2 {
			t.Fatal("peek misses staged value")
		}

		return errBoom
	})
	if !errors.Is(err, errBoom) || g.Snapshot().Get(a) != 1 {
		t.Fatalf("err=%v a=%d", err, g.Snapshot().Get(a))
	}
}

// TestPanickingUpdateReleasesTheGraph panics in a compute and checks the
// next update still commits and the panicked one published nothing.
func TestPanickingUpdateReleasesTheGraph(t *testing.T) {
	g := New()
	a := g.NewInput("a", 1, Same[int])
	_ = NewDerived(g, "boom", Same[int], func(s *Snapshot, _ int) int {
		if v := s.Get(a); v != 2 {
			return v
		}

		panic("boom")
	})
	_, _ = g.Update(func(*Tx) error { return nil })

	func() {
		defer func() { _ = recover() }()

		_, _ = g.Update(func(tx *Tx) error { Set(tx, a, 2); return nil })
	}()

	done := make(chan *Snapshot)

	go func() {
		s, _ := g.Update(func(tx *Tx) error { Set(tx, a, 3); return nil })
		done <- s
	}()

	select {
	case s := <-done:
		if s.Get(a) != 3 || s.Rev() != 2 {
			t.Fatalf("a=%d rev=%d, want 3 at rev 2", s.Get(a), s.Rev())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("update after a panicked one never returned")
	}
}

// TestGetPanicsOnAnotherGraphsHandle reads a cell through a handle of
// another graph: it must fail loudly, not return an empty value.
func TestGetPanicsOnAnotherGraphsHandle(t *testing.T) {
	g, other := New(), New()
	_ = g.NewInput("a", "x", Same[string])
	n := other.NewInput("n", 1, Same[int])

	s, _ := g.Update(func(*Tx) error { return nil })

	defer func() {
		if recover() == nil {
			t.Fatal("reading another graph's cell did not panic")
		}
	}()

	s.Get(n)
}

// TestConcurrentUpdatesAndReaders commits from several writers while
// readers and subscribers come and go: no snapshot may mix revisions of
// its cells, and every subscriber must reach the last commit.
func TestConcurrentUpdatesAndReaders(t *testing.T) {
	g := New()
	a := g.NewInput("a", 0, Same[int])
	double := NewDerived(g, "double", Same[int], func(s *Snapshot, _ int) int { return 2 * s.Get(a) })
	triple := NewDerived(g, "triple", Same[int], func(s *Snapshot, _ int) int {
		return s.Get(a) + s.Get(double)
	})

	_, _ = g.Update(func(*Tx) error { return nil })

	const writers, writes = 4, 200

	final := uint64(1 + writers*writes)

	var (
		wg   sync.WaitGroup
		errs = make(chan string, 16)
	)

	for range writers {
		wg.Go(func() {
			for range writes {
				_, _ = g.Update(func(tx *Tx) error { Set(tx, a, Peek(tx, a)+1); return nil })
			}
		})
	}

	for range 4 {
		wg.Go(func() {
			sub := g.Subscribe()
			defer sub.Close()

			var last uint64

			for {
				s := g.Snapshot()
				if v := s.Get(a); s.Get(double) != 2*v || s.Get(triple) != 3*v {
					errs <- fmt.Sprintf("rev %d mixes cells: a=%d double=%d triple=%d",
						s.Rev(), v, s.Get(double), s.Get(triple))

					return
				}

				if s.Rev() < last {
					errs <- fmt.Sprintf("rev went back from %d to %d", last, s.Rev())

					return
				}

				if last = s.Rev(); last == final {
					return
				}

				select {
				case <-sub.C:
				case <-time.After(5 * time.Second):
					errs <- fmt.Sprintf("subscriber stuck at rev %d of %d", last, final)

					return
				}
			}
		})
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	if s := g.Snapshot(); s.Rev() != final || s.Get(a) != writers*writes {
		t.Fatalf("rev=%d a=%d, want rev %d a=%d", s.Rev(), s.Get(a), final, writers*writes)
	}
}

func TestSubscriptionCoalesces(t *testing.T) {
	g := New()
	a := g.NewInput("a", 0, Same[int])

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

	if g.Snapshot().Get(a) != 3 {
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

	// Long enough to trim the log several times.
	const edits = 6 * mapLog

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

	misses := 0

	for range 2000 {
		i := r.IntN(len(history))
		j := i + r.IntN(min(len(history)-i, 2*mapLog+40))
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
		} else {
			misses++

			// Done skips edits that change nothing, so the log is counted
			// in distinct Maps.
			if distinctEdits(history[i:j+1]) <= mapLog {
				t.Fatalf("ChangedSince(%d, %d) did not reach back", i, j)
			}
		}
	}

	if misses == 0 {
		t.Fatal("test sanity: some reads must fall outside a trimmed log")
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

// TestGroupByMatchesRebuild drives random edits through GroupBy and
// checks each result equals computing it from scratch.
func TestGroupByMatchesRebuild(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 4)) //nolint:gosec // deterministic test input

	// Some values name enough groups to take the set lookup.
	groups := func(k, v int) []int {
		g := []int{v % 4, k % 2 * 10}
		if v%3 == 0 {
			for i := range 20 {
				g = append(g, 100+v%4*20+i)
			}
		}

		return g
	}
	// groups reads v only modulo 12.
	sameGroups := func(a, b int) bool { return a%12 == b%12 }

	in := NewMap(Same[int], map[int]int{})

	var grouped, skipping Grouped[int, int, int]

	for step := range 500 {
		e := in.Edit()

		for range 1 + r.IntN(3) {
			if r.IntN(4) == 0 {
				e.Delete(r.IntN(30))
			} else {
				e.Set(r.IntN(30), r.IntN(36))
			}
		}

		in = e.Done()

		// Skip a step now and then so the operators catch up over
		// several edits.
		if r.IntN(3) == 0 {
			continue
		}

		grouped = GroupBy(grouped, in, groups, nil)
		skipping = GroupBy(skipping, in, groups, sameGroups)

		wantGroups := map[int][]int{}

		for k, v := range toNative(in) {
			for _, g := range groups(k, v) {
				wantGroups[g] = append(wantGroups[g], k)
			}
		}

		for g, keys := range wantGroups {
			wantGroups[g] = sortedUnique(keys)
		}

		if got := toNative(grouped.Groups); !maps.EqualFunc(got, wantGroups, slices.Equal[[]int]) {
			t.Fatalf("step %d: GroupBy = %v, want %v", step, got, wantGroups)
		}

		if got := toNative(skipping.Groups); !maps.EqualFunc(got, wantGroups, slices.Equal[[]int]) {
			t.Fatalf("step %d: GroupBy with sameGroups = %v, want %v", step, got, wantGroups)
		}
	}
}

func TestGroupByPreservesMembershipSnapshots(t *testing.T) {
	groups := func(_ int, v int) []int { return []int{v % 2, v % 2, 2} }
	in := NewMap(Same[int], map[int]int{3: 0, 1: 0, 2: 1})
	initial := GroupBy(Grouped[int, int, int]{}, in, groups, nil)

	want := map[int][]int{0: {1, 3}, 1: {2}, 2: {1, 2, 3}}
	if got := toNative(initial.Groups); !maps.EqualFunc(got, want, slices.Equal[[]int]) {
		t.Fatalf("initial groups = %v, want %v", got, want)
	}

	e := in.Edit()
	e.Set(1, 1)
	e.Delete(2)
	e.Delete(3)
	e.Set(4, 0)
	next := GroupBy(initial, e.Done(), groups, nil)

	wantNext := map[int][]int{0: {4}, 1: {1}, 2: {1, 4}}
	if got := toNative(next.Groups); !maps.EqualFunc(got, wantNext, slices.Equal[[]int]) {
		t.Fatalf("changed groups = %v, want %v", got, wantNext)
	}

	if got := toNative(initial.Groups); !maps.EqualFunc(got, want, slices.Equal[[]int]) {
		t.Fatalf("old groups changed to %v, want %v", got, want)
	}

	e = next.In.Edit()
	e.Set(1, 3)

	cutoff := GroupBy(next, e.Done(), func(int, int) []int {
		t.Fatal("sameGroups must skip groupsOf")

		return nil
	}, func(a, b int) bool { return a%2 == b%2 })
	if cutoff.Groups != next.Groups || cutoff.In == next.In {
		t.Fatal("sameGroups must advance the input without changing groups")
	}

	empty := GroupBy(next, NewMap(Same[int], map[int]int{}), groups, nil)
	if empty.Groups.Len() != 0 {
		t.Fatalf("deleted all members, groups = %v", toNative(empty.Groups))
	}

	if got := toNative(next.Groups); !maps.EqualFunc(got, wantNext, slices.Equal[[]int]) {
		t.Fatalf("deleted members changed old groups to %v, want %v", got, wantNext)
	}
}

func TestGroupByEmptyInput(t *testing.T) {
	groups := func(int, int) []int {
		t.Fatal("empty input must not call groupsOf")

		return nil
	}
	for _, in := range []*Map[int, int]{nil, NewMap[int, int](Same[int], nil)} {
		initial := GroupBy(Grouped[int, int, int]{}, in, groups, nil)
		if initial.In != in || initial.Groups == nil || initial.Groups.Len() != 0 {
			t.Fatal("empty input must produce empty groups")
		}

		if next := GroupBy(initial, in, groups, nil); next.Groups != initial.Groups {
			t.Fatal("unchanged empty input must preserve groups")
		}
	}
}

func BenchmarkGroupBy(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("keys=%d", size), func(b *testing.B) {
			entries := make(map[int]int, size)
			for k := range size {
				entries[k] = 0
			}

			in := NewMap(Same[int], entries)
			groups := func(_ int, v int) []int { return []int{v} }
			initial := GroupBy(Grouped[int, int, int]{}, in, groups, nil)
			one := in.Edit()
			one.Set(0, 1)

			bulk := in.Edit()
			for k := range size {
				bulk.Set(k, 1)
			}

			for _, scenario := range []struct {
				name string
				prev Grouped[int, int, int]
				in   *Map[int, int]
			}{
				{"initial", Grouped[int, int, int]{}, in},
				{"one-member", initial, one.Done()},
				{"all-members", initial, bulk.Done()},
			} {
				b.Run(scenario.name, func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						result := GroupBy(scenario.prev, scenario.in, groups, nil)
						runtime.KeepAlive(result)
					}
				})
			}
		})
	}
}

// TestUpdateCheckedRefusalPublishesNothing refuses a built snapshot: the
// graph must keep its last one, wake no subscriber, and return the error.
func TestUpdateCheckedRefusalPublishesNothing(t *testing.T) {
	g := New()
	a := g.NewInput("a", 1, Same[int])
	double := NewDerived(g, "double", Same[int], func(s *Snapshot, _ int) int { return 2 * s.Get(a) })

	before, _ := g.Update(func(*Tx) error { return nil })

	sub := g.Subscribe()
	defer sub.Close()

	_, err := g.UpdateChecked(
		func(tx *Tx) error { Set(tx, a, 5); return nil },
		func(next *Snapshot) error {
			if next.Get(double) != 10 {
				t.Fatal("check must see the built snapshot")
			}

			if g.Snapshot() == next {
				t.Fatal("check must run before the snapshot is stored, or readers see it")
			}

			return errBoom
		},
	)
	if !errors.Is(err, errBoom) {
		t.Fatalf("err = %v, want the check's", err)
	}

	if g.Snapshot() != before || g.Snapshot().Get(a) != 1 {
		t.Fatal("a refused snapshot must not be published")
	}

	select {
	case <-sub.C:
		t.Fatal("a refused snapshot must wake nobody")
	default:
	}

	next, err := g.Update(func(tx *Tx) error { Set(tx, a, 7); return nil })
	if err != nil || next.Rev() != before.Rev()+1 || next.Get(double) != 14 {
		t.Fatalf("the update after a refusal must build on the published snapshot: rev %d, double %d",
			next.Rev(), next.Get(double))
	}

	_, err = g.UpdateChecked(func(*Tx) error { return nil }, func(*Snapshot) error {
		t.Fatal("a transaction changing nothing must not be checked")

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	func() {
		defer func() { _ = recover() }()

		_, _ = g.UpdateChecked(func(tx *Tx) error { Set(tx, a, 9); return nil }, func(*Snapshot) error { panic("check") })
	}()

	if g.Snapshot() != next {
		t.Fatal("a panicking check must publish nothing")
	}

	_, err = g.Update(func(tx *Tx) error { Set(tx, a, 9); return nil })
	if err != nil {
		t.Fatalf("the graph must stay usable after a panicking check: %v", err)
	}
}

// TestMapCursorAnswersChangedSince pins that a Cursor stands in for its Map
// as the old side of ChangedSince, edits ahead or none, and holds no entries.
func TestMapCursorAnswersChangedSince(t *testing.T) {
	base := NewMap(Same[int], map[int]int{1: 1, 2: 2})
	cur := base.Cursor()

	if cur.Len() != 0 {
		t.Fatalf("cursor holds %d entries", cur.Len())
	}

	if keys, ok := base.ChangedSince(cur); !ok || len(keys) != 0 {
		t.Fatalf("unchanged map from its cursor = %v, %t", keys, ok)
	}

	e := base.Edit()
	e.Set(3, 3)
	next := e.Done()

	want, _ := next.ChangedSince(base)

	got, ok := next.ChangedSince(cur)
	if !ok || !slices.Equal(got, want) {
		t.Fatalf("ChangedSince(cursor) = %v, %t; want %v", got, ok, want)
	}

	e = base.Edit()
	e.Set(4, 4)

	if _, ok := e.Done().ChangedSince(next.Cursor()); ok {
		t.Fatal("a sibling's cursor must not read as a lineage")
	}
}

// TestInitialValuesReleaseAfterPublication checks that a cell's initial
// value outlives a refused first update, so the retry still starts from
// it, but is not kept once a snapshot is published and replaced.
func TestInitialValuesReleaseAfterPublication(t *testing.T) {
	type payload struct{ _ [1 << 16]byte }

	g := New()
	// The graph must outlive the check, or it is collected whole.
	defer runtime.KeepAlive(g)

	boot := &payload{}
	released := make(chan struct{})
	runtime.AddCleanup(boot, func(c chan struct{}) { close(c) }, released)

	in := g.NewInput("in", boot, Same[*payload])

	_, err := g.UpdateChecked(func(*Tx) error { return nil }, func(*Snapshot) error { return errBoom })
	if !errors.Is(err, errBoom) {
		t.Fatalf("first update: %v, want the refusal", err)
	}

	snap, err := g.Update(func(*Tx) error { return nil })
	if err != nil || snap.Get(in) == nil {
		t.Fatalf("the retry must start from the initial value: %v", err)
	}

	_, err = g.Update(func(tx *Tx) error {
		Set(tx, in, &payload{})

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	snap = nil
	_ = snap

	deadline := time.After(5 * time.Second)

	for {
		runtime.GC()

		select {
		case <-released:
			return
		case <-deadline:
			t.Fatal("the graph retains the replaced initial value")
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func TestMapChangesDirectParent(t *testing.T) {
	comparisons := 0
	base := NewMap(func(a, b int) bool { comparisons++; return a == b }, map[int]int{1: 1, 2: 2, 4: 4})
	e := base.Edit()
	e.Set(1, 10)
	e.Set(1, 11)
	e.Delete(2)
	e.Set(3, 3)
	e.Set(4, 40)
	e.Set(4, 4)
	e.Set(5, 5)
	e.Delete(5)
	next := e.Done()
	comparisons = 0

	got := Changes(base, next)
	if !slices.Equal(sortedUnique(got), []int{1, 2, 3}) || len(got) != 3 {
		t.Fatalf("Changes = %v, want [1 2 3]", got)
	}

	if comparisons != 0 {
		t.Fatalf("direct edit rechecked %d values", comparisons)
	}
	// A caller owns its result; changing it must not corrupt the shared log.
	got[0] = 99

	if keys, ok := next.ChangedSince(base); !ok || !slices.Equal(sortedUnique(keys), []int{1, 2, 3}) {
		t.Fatalf("mutated log = %v, %t", keys, ok)
	}

	if v, ok := base.Get(1); !ok || v != 1 {
		t.Fatalf("retained base = %d, %t", v, ok)
	}
	// Coalescing can restore a value or cancel an earlier addition.
	e = next.Edit()
	e.Set(1, 1)
	e.Delete(3)

	later := e.Done()
	if keys := Changes(base, later); !slices.Equal(keys, []int{2}) {
		t.Fatalf("coalesced Changes = %v, want [2]", keys)
	}
}

func TestMapChangesEmptyAndCursor(t *testing.T) {
	var absent *Map[int, int]

	empty := NewMap[int, int](Same[int], nil)
	zero := new(Map[int, int])
	base := NewMap(Same[int], map[int]int{1: 1, 2: 2})
	e := base.Edit()
	e.Delete(1)
	e.Set(2, 20)
	e.Set(3, 3)

	next := e.Done()
	for _, tc := range []struct {
		name      string
		old, next *Map[int, int]
		want      []int
	}{
		{"nil", absent, absent, nil},
		{"same", base, base, nil},
		{"empty", empty, empty, nil},
		{"zero", zero, zero, nil},
		{"nil_to_empty", absent, empty, nil},
		{"nil_to_map", absent, base, []int{1, 2}},
		{"map_to_nil", base, absent, []int{1, 2}},
		// Cursor is only a ChangedSince token; other reads see an empty map.
		{"cursor", base.Cursor(), next, []int{2, 3}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Changes(tc.old, tc.next); !slices.Equal(sortedUnique(got), tc.want) {
				t.Fatalf("Changes = %v, want %v", got, tc.want)
			}
		})
	}
}

func BenchmarkMapChanges(b *testing.B) {
	for _, size := range []int{100, 1000, 10000} {
		entries := make(map[int]int, size)
		for k := range size {
			entries[k] = k
		}

		base := NewMap(Same[int], entries)
		for _, delta := range []int{1, 10, size / 2} {
			e := base.Edit()
			for k := range delta {
				e.Set(k, -1)
			}

			direct := e.Done()
			e = direct.Edit()
			e.Set(size, size)
			coalesced := e.Done()

			fallback := NewMap(Same[int], toNative(direct))
			for _, tc := range []struct {
				name      string
				old, next *Map[int, int]
				want      int
			}{
				{"direct", base, direct, delta},
				{"coalesced", base, coalesced, delta + 1},
				{"fallback", base, fallback, delta},
			} {
				b.Run(fmt.Sprintf("nodes=%d/delta=%d/%s", size, delta, tc.name), func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						if got := Changes(tc.old, tc.next); len(got) != tc.want {
							b.Fatal(len(got))
						}
					}
				})
			}
		}

		for _, tc := range []struct {
			name string
			m    *Map[int, int]
		}{{"same", base}, {"nil", nil}} {
			b.Run(fmt.Sprintf("nodes=%d/%s", size, tc.name), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					if got := Changes(tc.m, tc.m); len(got) != 0 {
						b.Fatal(got)
					}
				}
			})
		}
	}
}

// These helpers belong to the concurrency properties only. The oracle uses
// integer tuples and enumerates at most 5! serial histories, not graph internals.
type concurrencyValues struct {
	a, b int
	useB bool
}

type concurrencyView struct {
	concurrencyValues

	rev       uint64
	sum, pick int
}

type concurrencyCells struct {
	a, b      Input[int]
	useB      Input[bool]
	sum, pick Derived[int]
}

func newConcurrencyGraph(initial concurrencyValues) (*Graph, concurrencyCells) {
	g := New()
	c := concurrencyCells{
		a:    g.NewInput("a", initial.a, Same[int]),
		b:    g.NewInput("b", initial.b, Same[int]),
		useB: g.NewInput("useB", initial.useB, Same[bool]),
	}
	c.sum = NewDerived(g, "sum", Same[int], func(s *Snapshot, _ int) int {
		return s.Get(c.a) + s.Get(c.b)
	})
	c.pick = NewDerived(g, "pick", Same[int], func(s *Snapshot, _ int) int {
		if s.Get(c.useB) {
			return s.Get(c.b)
		}

		return s.Get(c.a)
	})

	return g, c
}

func (c concurrencyCells) read(s *Snapshot) concurrencyView {
	if s == nil {
		return concurrencyView{}
	}

	return concurrencyView{
		rev:               s.Rev(),
		concurrencyValues: concurrencyValues{s.Get(c.a), s.Get(c.b), s.Get(c.useB)},
		sum:               s.Get(c.sum),
		pick:              s.Get(c.pick),
	}
}

func concurrencyExpected(v concurrencyValues, rev uint64) concurrencyView {
	pick := v.a
	if v.useB {
		pick = v.b
	}

	return concurrencyView{v, rev, v.a + v.b, pick}
}

type concurrencyOp struct {
	kind, decision string
	a, b, limit    int
	useB           bool
	phase          int
}

func drawConcurrencyOp(t *rapid.T) concurrencyOp {
	return concurrencyOp{
		kind:     rapid.SampledFrom([]string{"add", "set", "switch", "equal", "revert", "empty"}).Draw(t, "operation"),
		decision: rapid.SampledFrom([]string{"accept", "abort", "check"}).Draw(t, "decision"),
		a:        rapid.IntRange(-3, 3).Draw(t, "a"),
		b:        rapid.IntRange(-3, 3).Draw(t, "b"),
		limit:    rapid.IntRange(-4, 4).Draw(t, "limit"),
		useB:     rapid.Bool().Draw(t, "useB"),
		phase:    rapid.IntRange(0, 2).Draw(t, "phase"),
	}
}

var (
	errConcurrencyAbort  = errors.New("concurrency transaction aborted")
	errConcurrencyRefuse = errors.New("concurrency candidate refused")
)

type concurrencyResult struct {
	op         concurrencyOp
	start, end uint64
	snap       *Snapshot
	view       concurrencyView
	checked    bool
	candidate  concurrencyView
	err        error
}

func (c concurrencyCells) run(g *Graph, op concurrencyOp) concurrencyResult {
	r := concurrencyResult{op: op}
	if op.kind == "read" {
		r.snap = g.Snapshot()
		r.view = c.read(r.snap)

		return r
	}

	var check func(*Snapshot) error
	if op.decision == "check" {
		check = func(s *Snapshot) error {
			r.checked, r.candidate = true, c.read(s)
			if s.Get(c.sum) > op.limit {
				return errConcurrencyRefuse
			}

			return nil
		}
	}

	r.snap, r.err = g.UpdateChecked(func(tx *Tx) error {
		// Stage the fixture's initial values before Peek; an unpublished
		// graph has no latest snapshot from which an unstaged read can read.
		if g.Snapshot() == nil {
			Set(tx, c.a, 0)
			Set(tx, c.b, 0)
			Set(tx, c.useB, false)
		}

		switch op.kind {
		case "add":
			Set(tx, c.a, Peek(tx, c.a)+op.a)
			Set(tx, c.b, Peek(tx, c.b)+op.b)
		case "set":
			Set(tx, c.a, op.a)
			Set(tx, c.a, op.a) // Duplicate writes have one final value.
			Set(tx, c.b, op.b)
			Set(tx, c.useB, op.useB)
		case "switch":
			Set(tx, c.useB, !Peek(tx, c.useB))
		case "equal":
			Set(tx, c.a, Peek(tx, c.a))
			Set(tx, c.b, Peek(tx, c.b))
		case "revert":
			a := Peek(tx, c.a)
			Set(tx, c.a, op.a)
			Set(tx, c.a, a)
		case "empty":
		}

		if op.decision == "abort" {
			return errConcurrencyAbort
		}

		return nil
	}, check)
	r.view = c.read(r.snap)

	return r
}

// concurrencyStep specifies the externally visible transaction, including
// check being skipped on a no-op. It never reads a graph or a transaction.
func concurrencyStep(before concurrencyView, op concurrencyOp) (concurrencyView, concurrencyView, bool, error) {
	if op.kind == "read" {
		return before, concurrencyView{}, false, nil
	}

	if op.decision == "abort" {
		return before, concurrencyView{}, false, errConcurrencyAbort
	}

	v := before.concurrencyValues

	switch op.kind {
	case "add":
		v.a += op.a
		v.b += op.b
	case "set":
		v = concurrencyValues{op.a, op.b, op.useB}
	case "switch":
		v.useB = !v.useB
	}

	if before.rev != 0 && v == before.concurrencyValues {
		return before, concurrencyView{}, false, nil
	}

	next := concurrencyExpected(v, before.rev+1)
	if op.decision == "check" {
		if next.sum > op.limit {
			return before, next, true, errConcurrencyRefuse
		}

		return next, next, true, nil
	}

	return next, concurrencyView{}, false, nil
}

func concurrencySerial(history []concurrencyResult, used uint, state, final concurrencyView) bool {
	if used == (1<<len(history))-1 {
		return state == final
	}

	for i, r := range history {
		if used&(1<<i) != 0 {
			continue
		}

		eligible := true

		for j, other := range history {
			// A completed call must precede a subsequently invoked call.
			if used&(1<<j) == 0 && other.end < r.start {
				eligible = false
			}
		}

		if !eligible {
			continue
		}

		next, candidate, checked, err := concurrencyStep(state, r.op)
		if r.view == next && r.checked == checked && r.candidate == candidate && errors.Is(r.err, err) &&
			concurrencySerial(history, used|(1<<i), next, final) {
			return true
		}
	}

	return false
}

func TestRapidConcurrentHistory(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g, cells := newConcurrencyGraph(concurrencyValues{})

		var retained []concurrencyResult

		t.Repeat(map[string]func(*rapid.T){
			"batch": func(t *rapid.T) {
				// Draw every call and release phase before starting any goroutine.
				writers := rapid.IntRange(1, 3).Draw(t, "writers")

				history := make([]concurrencyResult, writers, writers+2)
				for i := range history {
					history[i].op = drawConcurrencyOp(t)
				}

				for range 2 {
					history = append(history, concurrencyResult{op: concurrencyOp{
						kind: "read", phase: rapid.IntRange(0, 2).Draw(t, "reader phase"),
					}})
				}

				before := cells.read(g.Snapshot())

				var clock atomic.Uint64

				for phase := range 3 {
					start := make(chan struct{})

					var wg sync.WaitGroup

					for i := range history {
						if history[i].op.phase != phase {
							continue
						}

						wg.Go(func() {
							<-start

							begin := clock.Add(1)
							r := cells.run(g, history[i].op)
							r.start, r.end = begin, clock.Add(1)
							history[i] = r
						})
					}

					close(start)
					wg.Wait()
				}

				final := cells.read(g.Snapshot())
				if !concurrencySerial(history, 0, before, final) {
					t.Fatalf("no atomic serial history: before=%+v calls=%+v final=%+v", before, history, final)
				}

				retained = append(retained, history...)
				for _, old := range retained {
					if got := cells.read(old.snap); got != old.view {
						t.Fatalf("retained snapshot changed: got=%+v want=%+v", got, old.view)
					}
				}
			},
		})
	})
}

func TestRapidConcurrentRollback(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		err      error
		panicked any
	}{
		{name: "abort", err: errConcurrencyAbort},
		{name: "refuse", err: errConcurrencyRefuse},
		{name: "callback panic", panicked: "callback panic"},
		{name: "compute panic", panicked: "compute panic"},
		{name: "check panic", panicked: "check panic"},
		{name: "accept"},
	} {
		failure := testCase.name
		t.Run(failure, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				initial := concurrencyValues{
					a: rapid.IntRange(-5, 5).Draw(t, "initial a"), b: rapid.IntRange(-5, 5).Draw(t, "initial b"),
					useB: rapid.Bool().Draw(t, "initial selector"),
				}
				first := rapid.Bool().Draw(t, "first publication")
				delta := rapid.IntRange(1, 5).Draw(t, "delta")
				g, cells := newConcurrencyGraph(initial)
				entered, release := make(chan struct{}), make(chan struct{})

				var armed atomic.Bool

				_ = NewDerived(g, "panic barrier", Same[int], func(s *Snapshot, _ int) int {
					v := s.Get(cells.sum)

					if armed.Swap(false) {
						close(entered)
						<-release
						panic(failure)
					}

					return v
				})
				if !first {
					_, err := g.Update(func(*Tx) error { return nil })
					if err != nil {
						t.Fatal(err)
					}
				}

				before := g.Snapshot()
				beforeView := cells.read(before)

				sub := g.Subscribe()
				defer sub.Close()

				candidate := concurrencyValues{initial.a + delta, initial.b + delta, !initial.useB}

				type outcome struct {
					snap     *Snapshot
					err      error
					panicked any
				}

				finished := make(chan outcome, 1)

				go func() {
					var out outcome
					defer func() {
						out.panicked = recover()
						finished <- out
					}()

					armed.Store(failure == "compute panic")

					out.snap, out.err = g.UpdateChecked(func(tx *Tx) error {
						Set(tx, cells.a, candidate.a)
						Set(tx, cells.b, candidate.b)
						Set(tx, cells.useB, candidate.useB)

						switch failure {
						case "abort", "callback panic":
							close(entered)
							<-release

							if failure == "callback panic" {
								panic(failure)
							}

							return errConcurrencyAbort
						}

						return nil
					}, func(*Snapshot) error {
						close(entered)
						<-release

						switch failure {
						case "refuse":
							return errConcurrencyRefuse
						case "check panic":
							panic(failure)
						default:
							return nil
						}
					})
				}()

				<-entered

				// A second Update is invoked while the first is held in fn,
				// compute, or check. Hold its callback too, to inspect rollback
				// before its own commit can hide an incorrectly published value.
				waiting, nextEntered, nextRelease := make(chan struct{}), make(chan struct{}), make(chan struct{})
				nextDone := make(chan outcome, 1)

				go func() {
					close(waiting)

					snap, err := g.Update(func(tx *Tx) error {
						input, initialValue := cells.a, initial.a
						if initial.useB {
							input, initialValue = cells.b, initial.b
						}

						if g.Snapshot() == nil {
							Set(tx, input, initialValue)
						}

						Set(tx, input, Peek(tx, input)+delta)
						close(nextEntered)
						<-nextRelease

						return nil
					})
					nextDone <- outcome{snap: snap, err: err}
				}()

				<-waiting

				// Collect observations now, assert only after both workers exit.
				during := g.Snapshot()
				duringView := cells.read(during)
				prematureWake := false

				select {
				case <-sub.C:
					prematureWake = true
				default:
				}

				close(release)

				out := <-finished

				<-nextEntered

				after := g.Snapshot()
				afterView := cells.read(after)
				woke := false

				select {
				case <-sub.C:
					woke = true
				default:
				}

				close(nextRelease)

				next := <-nextDone

				if during != before || duringView != beforeView || prematureWake {
					t.Fatalf("in-flight transaction published: before=%+v during=%+v wake=%t", beforeView, duringView, prematureWake)
				}

				want := beforeView
				if failure == "accept" {
					want = concurrencyExpected(candidate, beforeView.rev+1)
				}

				if afterView != want || woke != (failure == "accept") {
					t.Fatalf("publication after %s: got=%+v want=%+v wake=%t", failure, afterView, want, woke)
				}

				if !errors.Is(out.err, testCase.err) || out.panicked != testCase.panicked {
					t.Fatalf("%s result: %+v, want err=%v panic=%v", failure, out, testCase.err, testCase.panicked)
				}

				if testCase.panicked == nil && out.snap != after {
					t.Fatalf("%s returned snapshot %p, want published %p", failure, out.snap, after)
				}

				v := want.concurrencyValues

				if want.rev == 0 {
					v = initial
				}

				if initial.useB {
					v.b += delta
				} else {
					v.a += delta
				}

				wantNext := concurrencyExpected(v, want.rev+1)
				if next.err != nil || cells.read(next.snap) != wantNext || cells.read(g.Snapshot()) != wantNext {
					t.Fatalf("waiting update: err=%v got=%+v want=%+v", next.err, cells.read(next.snap), wantNext)
				}

				if cells.read(before) != beforeView || cells.read(after) != afterView {
					t.Fatal("waiting writer changed a retained snapshot")
				}
			})
		})
	}
}

// concurrencyWakes drains enough to distinguish no wake, one coalesced wake,
// and a broken queue (including a channel closed by Subscription.Close).
func concurrencyWakes(sub *Subscription) int {
	wakes := 0

	for range 2 {
		select {
		case <-sub.C:
			wakes++
		default:
		}
	}

	return wakes
}

func TestRapidConcurrentSubscriptions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		deltas := rapid.SliceOfN(rapid.IntRange(1, 3), 2, 40).Draw(t, "deltas")
		closeAt := rapid.IntRange(0, len(deltas)).Draw(t, "close at")
		rapid.SyncTest(t, func(t *rapid.T) {
			g, cells := newConcurrencyGraph(concurrencyValues{})

			slow, closing, closed := g.Subscribe(), g.Subscribe(), g.Subscribe()
			defer slow.Close()
			defer closing.Close()

			closed.Close()
			closed.Close()

			done := make(chan struct{})
			results := make([]concurrencyResult, len(deltas))

			go func() {
				defer close(done)

				for i, delta := range deltas {
					if i == closeAt {
						closing.Close()
					}

					results[i] = cells.run(g, concurrencyOp{kind: "add", a: delta, b: -delta})
				}
			}()
			// No receiver drains a subscription until the writer has finished.
			// A blocked send is detected by quiescence, never by elapsed time.
			synctest.Wait()

			select {
			case <-done:
			default:
				// Release the writer before failing so a broken blocking send
				// cannot also block subscription cleanup and Rapid shrinking.
			unblock:
				for {
					select {
					case <-done:
						break unblock
					case <-slow.C:
					case <-closing.C:
					case <-closed.C:
					}
				}

				t.Fatal("writer blocked behind a slow or closed subscriber")
			}

			total := 0
			for i, r := range results {
				total += deltas[i]

				want := concurrencyExpected(concurrencyValues{a: total, b: -total}, uint64(i+1))
				if r.err != nil || r.view != want || cells.read(r.snap) != want {
					t.Fatalf("write %d: got=%+v err=%v want=%+v", i, r.view, r.err, want)
				}
			}

			for _, sub := range []*Subscription{slow, closing, closed} {
				wantWake := sub == slow || sub == closing && closeAt != 0
				wakes := concurrencyWakes(sub)

				if (wakes == 1) != wantWake || wakes > 1 {
					t.Fatalf("coalesced wakes=%d, want pending=%t", wakes, wantWake)
				}
			}

			// Race subscription registration and removal against publication.
			// The racing wake is optional; the following commit must reach the
			// new subscriber and must not reach either closed subscriber.
			start := make(chan struct{})
			joined := make(chan *Subscription, 1)
			written := make(chan concurrencyResult, 1)

			go func() {
				<-start
				closing.Close()

				joined <- g.Subscribe()
			}()
			go func() {
				<-start

				written <- cells.run(g, concurrencyOp{kind: "add", a: 1, b: -1})
			}()

			close(start)
			synctest.Wait()

			fresh := <-joined
			defer fresh.Close()

			r := <-written
			total++

			want := concurrencyExpected(concurrencyValues{a: total, b: -total}, uint64(len(deltas)+1))
			if r.err != nil || r.view != want {
				t.Fatalf("publication racing subscriptions: got=%+v err=%v want=%+v", r.view, r.err, want)
			}

			for _, sub := range []*Subscription{slow, closing, fresh} {
				concurrencyWakes(sub)
			}

			r = cells.run(g, concurrencyOp{kind: "add", a: 1, b: -1})
			total++

			want = concurrencyExpected(concurrencyValues{a: total, b: -total}, uint64(len(deltas)+2))
			if r.err != nil || r.view != want || cells.read(g.Snapshot()) != want {
				t.Fatalf("post-close publication: got=%+v err=%v want=%+v", r.view, r.err, want)
			}

			for _, sub := range []*Subscription{slow, closing, closed, fresh} {
				wakes := concurrencyWakes(sub)
				if (wakes == 1) != (sub == slow || sub == fresh) || wakes > 1 {
					t.Fatalf("wake after close/subscribe: got=%d want pending=%t", wakes, sub == slow || sub == fresh)
				}
			}
		})
	})
}

type graphExpression struct {
	kind    string
	a, b, c int
}

// evaluate rebuilds pure expressions without consulting graph dependencies,
// change revisions, or cached values. Stateful derived cells are tested separately.
func (e graphExpression) evaluate(values []int) int {
	switch e.kind {
	case "sum":
		return (values[e.a] + values[e.b]) % 17
	case "parity":
		return values[e.a] % 2
	case "pick":
		if values[e.a]%2 == 0 {
			return values[e.b]
		}

		return values[e.c]
	default:
		return e.a
	}
}

func (e graphExpression) dependencies(values []int) []int {
	switch e.kind {
	case "sum":
		return []int{e.a, e.b}
	case "parity":
		return []int{e.a}
	case "pick":
		if values[e.a]%2 == 0 {
			return []int{e.a, e.b}
		}

		return []int{e.a, e.c}
	default:
		return nil
	}
}

type graphReference struct {
	rev     uint64
	values  []int
	changed []uint64
}

func (m graphReference) check(t *rapid.T, s *Snapshot, nodes []Node[int]) {
	t.Helper()

	if m.rev == 0 {
		if s != nil {
			t.Fatal("uncommitted graph published a snapshot")
		}

		return
	}

	if s == nil || s.Rev() != m.rev {
		t.Fatalf("snapshot %v, want revision %d", s, m.rev)
	}

	for i, n := range nodes {
		if got := s.Get(n); got != m.values[i] {
			t.Fatalf("rev %d cell %d: value %d, want %d", m.rev, i, got, m.values[i])
		}

		if got := ChangedAt(s, n); got != m.changed[i] {
			t.Fatalf("rev %d cell %d: ChangedAt %d, want %d", m.rev, i, got, m.changed[i])
		}
	}
}

type graphPropertySubscription struct {
	sub             *Subscription
	pending, closed bool
}

func (s *graphPropertySubscription) drain(t *rapid.T) {
	t.Helper()

	got := false

	select {
	case <-s.sub.C:
		got = true
	default:
	}

	if got != s.pending {
		t.Fatalf("notification = %t, want %t (closed=%t)", got, s.pending, s.closed)
	}

	select {
	case <-s.sub.C:
		t.Fatal("notifications did not coalesce")
	default:
	}

	s.pending = false
}

// Keeping the actions together makes their shared reference state explicit.
func TestGraphPropertyTransactions(t *testing.T) { //nolint:gocyclo
	rapid.Check(t, func(t *rapid.T) {
		g := New()
		initial := rapid.SliceOfN(rapid.IntRange(-8, 8), 0, 5).Draw(t, "initial")
		expressions := make([]graphExpression, rapid.IntRange(0, 10).Draw(t, "derived-count"))
		inputs := make([]Input[int], len(initial))
		nodes := make([]Node[int], len(initial), len(initial)+len(expressions))

		for i, value := range initial {
			inputs[i] = g.NewInput(fmt.Sprintf("input-%d", i), value, Same[int])
			nodes[i] = inputs[i]
		}

		calls := make([]int, len(expressions))

		for i := range expressions {
			e := graphExpression{kind: "constant", a: rapid.IntRange(-8, 8).Draw(t, "constant")}
			if len(nodes) > 0 {
				e.kind = rapid.SampledFrom([]string{"constant", "sum", "parity", "pick"}).Draw(t, "operator")
				if e.kind != "constant" {
					e.a = rapid.IntRange(0, len(nodes)-1).Draw(t, "a")
					e.b = rapid.IntRange(0, len(nodes)-1).Draw(t, "b")
					e.c = rapid.IntRange(0, len(nodes)-1).Draw(t, "c")
				}
			}

			expressions[i] = e
			n := NewDerived(g, fmt.Sprintf("derived-%d", i), Same[int], func(s *Snapshot, _ int) int {
				calls[i]++

				switch e.kind {
				case "sum":
					return (s.Get(nodes[e.a]) + s.Get(nodes[e.b])) % 17
				case "parity":
					return s.Get(nodes[e.a]) % 2
				case "pick":
					if s.Get(nodes[e.a])%2 == 0 {
						return s.Get(nodes[e.b])
					}

					return s.Get(nodes[e.c])
				default:
					return e.a
				}
			})
			nodes = append(nodes, n)
		}

		type retained struct {
			snapshot *Snapshot
			model    graphReference
			at       time.Time
		}

		var (
			model   graphReference
			history []retained
			subs    []*graphPropertySubscription
		)

		defer func() {
			for _, sub := range subs {
				sub.sub.Close()
			}
		}()

		type write struct{ index, value int }

		update := func(t *rapid.T, writes []write, outcome string) {
			t.Helper()

			before := g.Snapshot()

			values := slices.Clone(initial)
			if model.rev != 0 {
				values = slices.Clone(model.values[:len(inputs)])
			}

			for _, w := range writes {
				values[w.index] = w.value
			}

			build := model.rev == 0 || !slices.Equal(values, model.values[:len(inputs)])
			next := graphReference{rev: model.rev + 1, changed: make([]uint64, len(nodes))}

			for _, e := range expressions {
				values = append(values, e.evaluate(values))
			}

			next.values = values
			for i, value := range values {
				next.changed[i] = next.rev
				if model.rev != 0 && value == model.values[i] {
					next.changed[i] = model.changed[i]
				}
			}

			wantCalls := slices.Clone(calls)

			if build && outcome != "abort" {
				for i, e := range expressions {
					run := model.rev == 0
					if !run {
						for _, dependency := range e.dependencies(model.values) {
							run = run || values[dependency] != model.values[dependency]
						}
					}

					if run {
						wantCalls[i]++
					}
				}
			}

			checked := false
			got, err := g.UpdateChecked(func(tx *Tx) error {
				staged := make(map[int]int)
				peek := func() {
					for i, n := range nodes {
						want, set := staged[i]
						if !set {
							// No published snapshot means no documented unstaged value.
							if model.rev == 0 {
								continue
							}

							want = model.values[i]
						}

						if value := Peek(tx, n); value != want {
							t.Fatalf("Peek cell %d = %d, want %d", i, value, want)
						}
					}
				}

				peek()

				for _, w := range writes {
					Set(tx, inputs[w.index], w.value)
					staged[w.index] = w.value

					peek()
				}

				if outcome == "abort" {
					return errBoom
				}

				return nil
			}, func(s *Snapshot) error {
				checked = true

				next.check(t, s, nodes)

				if g.Snapshot() != before {
					t.Fatal("candidate published before check accepted it")
				}

				if outcome == "refuse" {
					return errBoom
				}

				return nil
			})

			wantError := outcome == "abort" || build && outcome == "refuse"
			if wantError && !errors.Is(err, errBoom) || !wantError && err != nil {
				t.Fatalf("outcome %s: error %v, want error=%t", outcome, err, wantError)
			}

			if checked != (build && outcome != "abort") || !slices.Equal(calls, wantCalls) {
				t.Fatalf("outcome %s build=%t: checked=%t calls=%v, want %v", outcome, build, checked, calls, wantCalls)
			}

			if build && outcome == "commit" {
				model = next
				history = append(history, retained{got, model, got.Time()})

				for _, sub := range subs {
					if !sub.closed {
						sub.pending = true
					}
				}
			} else if got != before {
				t.Fatal("aborted, refused, or no-op update replaced the snapshot")
			}

			if got != g.Snapshot() {
				t.Fatal("update did not return the published snapshot")
			}

			model.check(t, got, nodes)
		}

		drawWrites := func(t *rapid.T) []write {
			var writes []write

			if len(inputs) != 0 {
				for range rapid.IntRange(0, 6).Draw(t, "writes") {
					writes = append(writes, write{
						rapid.IntRange(0, len(inputs)-1).Draw(t, "input"),
						rapid.IntRange(-8, 8).Draw(t, "value"),
					})
				}
			}

			return writes
		}

		subs = append(subs, &graphPropertySubscription{sub: g.Subscribe()})

		t.Repeat(map[string]func(*rapid.T){
			"commit": func(t *rapid.T) { update(t, drawWrites(t), "commit") },
			"abort":  func(t *rapid.T) { update(t, drawWrites(t), "abort") },
			"refuse": func(t *rapid.T) { update(t, drawWrites(t), "refuse") },
			"empty":  func(t *rapid.T) { update(t, nil, "commit") },
			"revert": func(t *rapid.T) {
				if model.rev == 0 || len(inputs) == 0 {
					t.Skip("reversion needs a published input")
				}

				i := rapid.IntRange(0, len(inputs)-1).Draw(t, "input")
				update(t, []write{{i, model.values[i] + 1}, {i, model.values[i]}}, "commit")
			},
			"subscribe": func(t *rapid.T) {
				if len(subs) >= 8 {
					t.Skip("enough subscriptions")
				}

				sub := &graphPropertySubscription{sub: g.Subscribe()}
				subs = append(subs, sub)
				sub.drain(t)
			},
			"drain": func(t *rapid.T) {
				subs[rapid.IntRange(0, len(subs)-1).Draw(t, "subscriber")].drain(t)
			},
			"close": func(t *rapid.T) {
				sub := subs[rapid.IntRange(0, len(subs)-1).Draw(t, "subscriber")]
				// Drain before Close; the contract does not promise to discard pending wakes.
				sub.drain(t)
				sub.sub.Close()
				sub.closed = true
			},
			"": func(t *rapid.T) {
				model.check(t, g.Snapshot(), nodes)

				for _, old := range history {
					old.model.check(t, old.snapshot, nodes)

					if old.snapshot.Time() != old.at {
						t.Fatal("retained snapshot commit time changed")
					}
				}
			},
		})

		for _, sub := range subs {
			sub.drain(t)
		}
	})
}

func TestGraphPropertyEqualOutputRetainsPreviousState(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		type state struct{ visible, generation int }

		g := New()
		in := g.NewInput("in", 0, Same[int])
		modulus := rapid.IntRange(1, 5).Draw(t, "modulus")
		cell := NewDerived(g, "state", func(a, b state) bool { return a.visible == b.visible },
			func(s *Snapshot, prev state) state {
				return state{s.Get(in) % modulus, prev.generation + 1}
			})
		runs := 0
		sink := NewDerived(g, "sink", Same[int], func(s *Snapshot, _ int) int {
			runs++

			return s.Get(cell).visible
		})

		snapshot, err := g.Update(func(*Tx) error { return nil })
		if err != nil {
			t.Fatal(err)
		}

		want := state{generation: 1}
		lastChange, wantRuns := uint64(1), 1

		for step := range rapid.IntRange(1, 40).Draw(t, "steps") {
			before, previous := snapshot, want

			value := (step + 1) * rapid.IntRange(1, 5).Draw(t, "multiple") * modulus
			if rapid.Bool().Draw(t, "change-visible") {
				value++
			}

			refuse := rapid.Bool().Draw(t, "refuse")
			changed := value != before.Get(in)
			next := state{value % modulus, want.generation + 1}

			wantError := refuse && changed
			if changed && next.visible != want.visible {
				wantRuns++
			}

			snapshot, err = g.UpdateChecked(func(tx *Tx) error {
				Set(tx, in, value)

				return nil
			}, func(s *Snapshot) error {
				if got := s.Get(cell); got != next {
					t.Fatalf("candidate state %v, want %v", got, next)
				}

				if refuse {
					return errBoom
				}

				return nil
			})
			if wantError && !errors.Is(err, errBoom) || !wantError && err != nil {
				t.Fatalf("error=%v, want refusal=%t", err, wantError)
			}

			if changed && !refuse {
				if next.visible != want.visible {
					lastChange = before.Rev() + 1
				}

				want = next
			} else if snapshot != before {
				t.Fatal("no-op or refused state published")
			}

			if got := snapshot.Get(cell); got != want || ChangedAt(snapshot, cell) != lastChange {
				t.Fatalf("state=%v ChangedAt=%d, want %v at %d", got, ChangedAt(snapshot, cell), want, lastChange)
			}

			if snapshot.Get(sink) != want.visible || runs != wantRuns {
				t.Fatalf("sink=%d runs=%d, want %d runs=%d", snapshot.Get(sink), runs, want.visible, wantRuns)
			}

			if before.Get(cell) != previous {
				t.Fatal("equal output mutated a retained snapshot")
			}
		}
	})
}

func TestGraphPropertyEqualSwitchReplacesDependencies(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := New()
		value := rapid.IntRange(-100, 100).Draw(t, "initial")
		selector := g.NewInput("selector", false, Same[bool])
		left := g.NewInput("left", value, Same[int])
		right := g.NewInput("right", value, Same[int])
		runs, downstream := 0, 0
		pick := NewDerived(g, "pick", Same[int], func(s *Snapshot, _ int) int {
			runs++

			if s.Get(selector) {
				return s.Get(right)
			}

			return s.Get(left)
		})
		_ = NewDerived(g, "downstream", Same[int], func(s *Snapshot, _ int) int {
			downstream++

			return s.Get(pick)
		})

		before, err := g.Update(func(*Tx) error { return nil })
		if err != nil {
			t.Fatal(err)
		}

		// Both branches have the same value: switching must still replace the reads.
		switched, err := g.Update(func(tx *Tx) error { Set(tx, selector, true); return nil })
		if err != nil || runs != 2 || downstream != 1 || ChangedAt(switched, pick) != ChangedAt(before, pick) {
			t.Fatalf("equal switch: error=%v runs=%d downstream=%d", err, runs, downstream)
		}

		for range rapid.IntRange(1, 12).Draw(t, "unread-writes") {
			value += rapid.IntRange(1, 10).Draw(t, "delta")

			_, err = g.Update(func(tx *Tx) error { Set(tx, left, value); return nil })
			if err != nil || runs != 2 || downstream != 1 {
				t.Fatalf("unread branch: error=%v runs=%d downstream=%d", err, runs, downstream)
			}
		}

		next, err := g.Update(func(tx *Tx) error { Set(tx, right, value); return nil })
		if err != nil || runs != 3 || downstream != 2 || next.Get(pick) != value || ChangedAt(next, pick) != next.Rev() {
			t.Fatalf("selected branch: error=%v runs=%d downstream=%d", err, runs, downstream)
		}
	})
}

func TestGraphPropertyFailedUpdateCanRetry(t *testing.T) {
	for _, failure := range []string{"abort", "refuse", "transaction-panic", "compute-panic", "check-panic"} {
		t.Run(failure, func(t *testing.T) {
			rapid.Check(t, func(t *rapid.T) {
				g := New()
				initial := rapid.IntRange(1, 100).Draw(t, "initial")
				in := g.NewInput("in", initial, Same[int])
				failCompute := false
				cell := NewDerived(g, "accumulate", Same[int], func(s *Snapshot, prev int) int {
					if failCompute {
						panic(errBoom)
					}

					return prev + s.Get(in)
				})

				var before *Snapshot

				if rapid.Bool().Draw(t, "already-published") {
					var err error

					before, err = g.Update(func(*Tx) error { return nil })
					if err != nil {
						t.Fatal(err)
					}
				}

				sub := &graphPropertySubscription{sub: g.Subscribe()}
				defer sub.sub.Close()

				failCompute = failure == "compute-panic"

				var recovered any

				func() {
					defer func() { recovered = recover() }()

					got, err := g.UpdateChecked(func(tx *Tx) error {
						Set(tx, in, initial+1)

						if failure == "transaction-panic" {
							panic(errBoom)
						}

						if failure == "abort" {
							return errBoom
						}

						return nil
					}, func(*Snapshot) error {
						if failure == "check-panic" {
							panic(errBoom)
						}

						return errBoom
					})
					if got != before || !errors.Is(err, errBoom) {
						t.Fatalf("failure returned snapshot=%v error=%v", got, err)
					}
				}()

				wantPanic := failure != "abort" && failure != "refuse"

				panicError, _ := recovered.(error)
				if wantPanic && !errors.Is(panicError, errBoom) || !wantPanic && recovered != nil {
					t.Fatalf("recovered=%v, want panic=%t", recovered, wantPanic)
				}

				if g.Snapshot() != before {
					t.Fatal("failed update published a snapshot")
				}

				sub.drain(t)

				failCompute = false
				want, revision := initial, uint64(1)

				next, err := g.Update(func(tx *Tx) error {
					if before != nil {
						Set(tx, in, initial+2)
						want += initial + 2
						revision++
					}

					return nil
				})
				if err != nil || next.Rev() != revision || next.Get(cell) != want {
					t.Fatalf("retry: snapshot=%v error=%v, want value %d revision %d", next, err, want, revision)
				}

				sub.pending = true
				sub.drain(t)
			})
		})
	}
}

func TestGraphPropertyNeverForcesChange(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := New()
		value := rapid.IntRange(-100, 100).Draw(t, "initial")
		in := g.NewInput("in", value, Never[int])
		forcedRuns, sinkRuns := 0, 0
		forced := NewDerived(g, "forced", Never[int], func(s *Snapshot, _ int) int {
			forcedRuns++

			return s.Get(in)
		})
		sink := NewDerived(g, "sink", Same[int], func(s *Snapshot, _ int) int {
			sinkRuns++

			return s.Get(forced)
		})

		snapshot, err := g.Update(func(*Tx) error { return nil })
		if err != nil {
			t.Fatal(err)
		}

		for step := range rapid.IntRange(1, 30).Draw(t, "steps") {
			before := snapshot

			snapshot, err = g.Update(func(tx *Tx) error {
				Set(tx, in, rapid.IntRange(-100, 100).Draw(t, "temporary"))
				Set(tx, in, value)

				return nil
			})
			if err != nil || snapshot.Rev() != uint64(step+2) || forcedRuns != step+2 || sinkRuns != step+2 {
				t.Fatalf("Never: error=%v snapshot=%v forced=%d sink=%d", err, snapshot, forcedRuns, sinkRuns)
			}

			if snapshot.Get(sink) != value || ChangedAt(snapshot, sink) != 1 || ChangedAt(snapshot, in) != snapshot.Rev() || ChangedAt(snapshot, forced) != snapshot.Rev() {
				t.Fatal("Never must propagate equal writes; Same must cut off the equal sink value")
			}

			if before.Get(in) != value || before.Rev() != uint64(step+1) {
				t.Fatal("forced change altered a retained snapshot")
			}

			unchanged, err := g.Update(func(*Tx) error { return nil })
			if err != nil || unchanged != snapshot || forcedRuns != step+2 || sinkRuns != step+2 {
				t.Fatal("Never must not cause an empty transaction to commit or compute")
			}
		}
	})
}

func TestGraphPropertyRegistrationGuards(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		g := New()
		initial := rapid.IntRange(-100, 100).Draw(t, "initial")
		in := g.NewInput("in", initial, Same[int])

		var later Node[int]

		illegal := true
		cell := NewDerived(g, "reader", Same[int], func(s *Snapshot, _ int) int {
			if illegal {
				return s.Get(later)
			}

			return s.Get(in)
		})

		later = cell
		if rapid.Bool().Draw(t, "forward-read") {
			later = g.NewInput("later", initial, Same[int])
		}

		var recovered any

		func() {
			defer func() { recovered = recover() }()

			_, _ = g.Update(func(*Tx) error { return nil })
		}()

		if recovered == nil || g.Snapshot() != nil {
			t.Fatal("self/forward read must panic without publishing")
		}

		// A failed first update must not freeze registration or lose initial values.
		extra := g.NewInput("after-failure", initial+1, Same[int])
		illegal = false

		before, err := g.Update(func(*Tx) error { return nil })
		if err != nil || before.Get(cell) != initial || before.Get(extra) != initial+1 {
			t.Fatalf("retry lost initial values: snapshot=%v error=%v", before, err)
		}

		func() {
			defer func() { recovered = recover() }()

			if rapid.Bool().Draw(t, "late-derived") {
				_ = NewDerived(g, "too-late", Same[int], func(*Snapshot, int) int { return initial })
			} else {
				_ = g.NewInput("too-late", initial, Same[int])
			}
		}()

		if recovered == nil || g.Snapshot() != before {
			t.Fatal("registration after publication must panic without changing the snapshot")
		}

		next, err := g.Update(func(tx *Tx) error { Set(tx, in, initial+2); return nil })
		if err != nil || next.Get(cell) != initial+2 || next.Rev() != 2 {
			t.Fatalf("registration panic left graph unusable: snapshot=%v error=%v", next, err)
		}
	})
}
