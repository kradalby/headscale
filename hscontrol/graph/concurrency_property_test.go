package graph

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"pgregory.net/rapid"
)

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
