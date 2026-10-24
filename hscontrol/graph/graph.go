// Package graph is a small, typed dataflow graph.
//
// A [Graph] holds cells. An input cell is set by a transaction; a derived
// cell is computed from other cells. Each committed transaction publishes
// one immutable [Snapshot] in which every derived cell is consistent with
// the inputs of that same snapshot, so a reader never sees a mix of old and
// new values.
//
// Derived cells are recomputed only when a cell they read during their last
// computation changed. A recomputed value equal to the previous one is not
// a change (equality cutoff), so the cells reading it are skipped as well;
// it is still stored, so the next computation receives it as prev.
// A derived cell receives its previous value, which lets it carry state from
// one snapshot to the next, such as an election that keeps its incumbent.
//
// Subscribers are woken after each commit and read the latest snapshot; a
// slow subscriber coalesces wake-ups and never blocks the writer.
package graph

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Graph holds cells and publishes snapshots of their values.
type Graph struct {
	// mu serialises transactions and registration.
	mu    sync.Mutex
	cells []cellDef
	snap  atomic.Pointer[Snapshot]

	subsMu sync.Mutex
	subs   map[*Subscription]struct{}
}

type cellDef struct {
	name    string
	derived bool
	initial any
	equal   func(a, b any) bool
	compute func(s *Snapshot, prev any) any
}

// New returns an empty graph. Register every cell before the first
// [Graph.Update].
func New() *Graph {
	return &Graph{subs: make(map[*Subscription]struct{})}
}

// Node is a typed handle to a cell: an [Input] or a [Derived].
type Node[T any] interface {
	ref() cellRef[T]
}

// cellRef is a cell index typed by its value, so [Get] infers T.
type cellRef[T any] int

// Input is a cell set by transactions.
type Input[T any] struct{ idx int }

func (i Input[T]) ref() cellRef[T] { return cellRef[T](i.idx) }

// Derived is a cell computed from other cells.
type Derived[T any] struct{ idx int }

func (d Derived[T]) ref() cellRef[T] { return cellRef[T](d.idx) }

// NewInput registers an input cell with an initial value. equal decides
// whether a set value is a change.
func NewInput[T any](g *Graph, name string, initial T, equal func(a, b T) bool) Input[T] {
	return Input[T]{idx: g.register(cellDef{
		name:    name,
		initial: initial,
		equal:   eraseEqual(equal),
	})}
}

// NewDerived registers a cell computed by compute from the cells it reads
// with [Get]. It may only read cells registered before it. prev is the
// cell's previous value, or the zero value on the first computation.
func NewDerived[T any](
	g *Graph,
	name string,
	equal func(a, b T) bool,
	compute func(s *Snapshot, prev T) T,
) Derived[T] {
	return Derived[T]{idx: g.register(cellDef{
		name:    name,
		derived: true,
		equal:   eraseEqual(equal),
		compute: func(s *Snapshot, prev any) any {
			p, _ := prev.(T)

			return compute(s, p)
		},
	})}
}

func eraseEqual[T any](equal func(a, b T) bool) func(a, b any) bool {
	return func(a, b any) bool {
		ta, _ := a.(T)
		tb, _ := b.(T)

		return equal(ta, tb)
	}
}

func (g *Graph) register(c cellDef) int {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.snap.Load() != nil {
		panic(fmt.Sprintf("graph: cell %q registered after the first update", c.name))
	}

	g.cells = append(g.cells, c)

	return len(g.cells) - 1
}

// Snapshot is one consistent, immutable set of cell values. Its methods
// and [Get] are safe for concurrent use once it is published.
type Snapshot struct {
	rev     uint64
	at      time.Time
	values  []any
	changed []uint64 // revision at which each value last changed
	deps    [][]int  // derived cells: the cells read by their last computation

	// reads records the cells read while a derived cell computes; nil once
	// the snapshot is published.
	reads    *[]int
	building int // index of the computing cell, bounds what it may read
}

// Rev is the snapshot's revision. Revisions increase by one per commit.
func (s *Snapshot) Rev() uint64 { return s.rev }

// Time is when the snapshot was committed.
func (s *Snapshot) Time() time.Time { return s.at }

// Get returns the value of n in s.
func Get[T any](s *Snapshot, n Node[T]) T {
	i := int(n.ref())
	if s.reads != nil {
		if i >= s.building {
			panic(fmt.Sprintf("graph: cell %d read by cell %d registered before it", i, s.building))
		}

		*s.reads = append(*s.reads, i)
	}

	v, _ := s.values[i].(T)

	return v
}

// ChangedAt returns the revision at which n last changed in s. Two
// snapshots that report the same revision hold the same value of n.
func ChangedAt[T any](s *Snapshot, n Node[T]) uint64 {
	return s.changed[int(n.ref())]
}

// Snapshot returns the latest published snapshot, or nil before the first
// [Graph.Update].
func (g *Graph) Snapshot() *Snapshot {
	return g.snap.Load()
}

// Tx stages input values for one commit.
type Tx struct {
	base *Snapshot
	sets map[int]any
}

// Set stages v as the new value of in.
func Set[T any](tx *Tx, in Input[T], v T) {
	tx.sets[in.idx] = v
}

// Rev is the revision this transaction publishes if it changes anything.
func (tx *Tx) Rev() uint64 {
	if tx.base == nil {
		return 1
	}

	return tx.base.rev + 1
}

// Peek returns the value of n as the transaction sees it: the staged
// value of an input set earlier in tx, otherwise its value in the latest
// snapshot.
func Peek[T any](tx *Tx, n Node[T]) T {
	if v, ok := tx.sets[int(n.ref())]; ok {
		t, _ := v.(T)

		return t
	}

	if tx.base == nil {
		return Zero[T]()
	}

	return Get(tx.base, n)
}

// Zero returns the zero value of T.
func Zero[T any]() T {
	var z T

	return z
}

// Update runs fn and commits the inputs it set, recomputes the derived
// cells affected, publishes the new snapshot and wakes subscribers. An
// error from fn aborts the transaction. A transaction that changes nothing
// publishes nothing and returns the latest snapshot. The first Update
// computes every derived cell. fn must not call Update.
func (g *Graph) Update(fn func(tx *Tx) error) (*Snapshot, error) {
	g.mu.Lock()

	prev := g.snap.Load()
	tx := &Tx{base: prev, sets: make(map[int]any)}

	err := fn(tx)
	if err != nil {
		g.mu.Unlock()

		return prev, err
	}

	next, changed := g.commit(prev, tx.sets)
	if !changed {
		g.mu.Unlock()

		return prev, nil
	}

	g.snap.Store(next)
	g.mu.Unlock()

	g.notify()

	return next, nil
}

// commit builds the snapshot following prev with sets applied.
func (g *Graph) commit(prev *Snapshot, sets map[int]any) (*Snapshot, bool) {
	n := len(g.cells)
	next := &Snapshot{
		at:      time.Now(),
		values:  make([]any, n),
		changed: make([]uint64, n),
		deps:    make([][]int, n),
	}

	first := prev == nil
	if first {
		next.rev = 1
	} else {
		next.rev = prev.rev + 1
		copy(next.values, prev.values)
		copy(next.changed, prev.changed)
		copy(next.deps, prev.deps)
	}

	anyChanged := first

	for i, c := range g.cells {
		if c.derived {
			continue
		}

		if first {
			next.values[i] = c.initial
			next.changed[i] = next.rev
		}

		v, ok := sets[i]
		if !ok {
			continue
		}

		if first || !c.equal(next.values[i], v) {
			next.values[i] = v
			next.changed[i] = next.rev
			anyChanged = true
		}
	}

	if !anyChanged {
		return prev, false
	}

	for i, c := range g.cells {
		if !c.derived || !first && !depsChanged(next, i) {
			continue
		}

		reads := make([]int, 0, len(next.deps[i]))
		next.reads, next.building = &reads, i
		v := c.compute(next, next.values[i])
		next.reads = nil
		next.deps[i] = reads

		// An equal value is still stored, so the next computation sees
		// the latest state it carried, but is not a change.
		if first || !c.equal(next.values[i], v) {
			next.changed[i] = next.rev
		}

		next.values[i] = v
	}

	return next, true
}

// depsChanged reports whether a cell read by derived cell i changed in s.
func depsChanged(s *Snapshot, i int) bool {
	for _, d := range s.deps[i] {
		if s.changed[d] == s.rev {
			return true
		}
	}

	return false
}

// Subscription wakes its owner after commits. C receives at most one
// pending wake-up; read [Graph.Snapshot] after each.
type Subscription struct {
	C <-chan struct{}

	c chan struct{}
	g *Graph
}

// Subscribe returns a subscription woken after every commit.
func (g *Graph) Subscribe() *Subscription {
	c := make(chan struct{}, 1)
	sub := &Subscription{C: c, c: c, g: g}

	g.subsMu.Lock()
	g.subs[sub] = struct{}{}
	g.subsMu.Unlock()

	return sub
}

// Close stops wake-ups.
func (s *Subscription) Close() {
	s.g.subsMu.Lock()
	delete(s.g.subs, s)
	s.g.subsMu.Unlock()
}

func (g *Graph) notify() {
	g.subsMu.Lock()
	defer g.subsMu.Unlock()

	for sub := range g.subs {
		select {
		case sub.c <- struct{}{}:
		default:
		}
	}
}

// Same is an equality for comparable values, including pointers compared
// by identity.
func Same[T comparable](a, b T) bool { return a == b }

// Never is an equality that reports every value as changed.
func Never[T any](_, _ T) bool { return false }
