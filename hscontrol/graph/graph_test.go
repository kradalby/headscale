package graph

import (
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
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
