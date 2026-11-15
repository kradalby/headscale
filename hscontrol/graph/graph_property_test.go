package graph

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"pgregory.net/rapid"
)

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
