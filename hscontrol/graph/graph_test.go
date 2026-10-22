package graph

import (
	"errors"
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
