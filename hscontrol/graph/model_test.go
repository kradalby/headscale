package graph

import (
	"errors"
	"fmt"
	"maps"
	"slices"
)

// The models the properties hold the package to. They share with it only
// the cells' own functions (cellPlan.eval) and the Map's equality.

var (
	errFn        = errors.New("the transaction fails")
	errRefused   = errors.New("the check refuses")
	errFnPanic   = errors.New("the transaction panics")
	errCellPanic = errors.New("a cell panics")
)

// Counted exceptions: what the package does that its doc comments do not
// say. Where one applies, the model or the property follows the package
// and counts the case; each is pinned by a hand test that fails once the
// package changes.
const (
	excInputEqualKept  = "graph/input-equal-kept"
	excPeekFirstZero   = "graph/peek-first-zero"
	excChangedAtValues = "graph/changedat-values"
)

// graphModel is a graph as the package doc describes it, recomputed from
// scratch at every commit: every derived cell is evaluated from what it
// reads now and its value before, which gives an unchanged cell's value
// back because the cells that carry state do so idempotently (count, which
// does not, is the exception: it counts the runs the model predicts). A
// cell runs when the commit is the first or a cell it read at the latest
// revision changed in it; a cell changes when it runs and its equality
// calls the new value different.
type graphModel struct {
	plan    graphPlan
	rev     uint64   // the latest published revision, 0 before the first
	values  []int    // inputs' initial values and zero cells before the first
	changed []uint64 // the revision each cell last changed at
	reads   [][]int  // what each derived cell read at rev
}

func newGraphModel(p graphPlan) graphModel {
	n := len(p.Cells)
	m := graphModel{plan: p, values: make([]int, n), changed: make([]uint64, n), reads: make([][]int, n)}

	for i, c := range p.Cells {
		if c.Input {
			m.values[i] = c.Init
		}
	}

	return m
}

// commitOutcome is what the model says a commit does.
type commitOutcome struct {
	next      graphModel // the model after the commit
	built     graphModel // the snapshot the check sees, when it runs
	published bool
	checked   bool  // the check runs
	panics    bool  // Update panics
	err       error // what Update returns
	ran       []int // the derived cells computed, in order, the one that panicked last
	changed   []int // the cells changed at the new revision
	excepts   []string
}

// fail is what fn returns after its sets: an error, a panic, or nil.
func (c commitPlan) fail() error {
	if c.Kind == commitFnPanic {
		panic(errFnPanic)
	}

	if c.Kind == commitFnError {
		return errFn
	}

	return nil
}

func (m graphModel) step(c commitPlan) commitOutcome {
	out := commitOutcome{next: m}

	if c.Kind == commitFnPanic {
		out.panics = true

		return out
	}

	if c.Kind == commitFnError {
		out.err = errFn

		return out
	}

	first := m.rev == 0
	cells := m.plan.Cells
	vals := slices.Clone(m.values)
	now := make([]bool, len(cells)) // changed in this commit
	anyChanged := first

	staged := map[int]int{}
	for _, s := range c.Sets {
		staged[s.In] = s.V
	}

	for i, cell := range cells {
		if !cell.Input {
			continue
		}

		now[i] = first

		v, ok := staged[i]
		if !ok {
			continue
		}

		if first || !cell.Eq.equal(vals[i], v) {
			vals[i], now[i], anyChanged = v, true, true

			continue
		}

		// TODO(kradalby): graph/input-equal-kept: an input set to a value
		// its equality calls equal keeps the value it held, where a derived
		// cell stores the new one; NewInput's doc does not say which. The
		// model keeps it, as the package does. Delete with
		// TestInputKeepsAValueItsEqualityCallsEqual once the doc says.
		if v != vals[i] {
			out.excepts = append(out.excepts, excInputEqualKept)
		}
	}

	if !anyChanged {
		return out
	}

	reads := slices.Clone(m.reads)

	for i, cell := range cells {
		if cell.Input {
			continue
		}

		var read []int

		prev := vals[i]
		ran := first || slices.ContainsFunc(m.reads[i], func(d int) bool { return now[d] })
		v := cell.eval(prev, func(d int) int {
			read = append(read, d)

			return cells[d].Eq.view(vals[d])
		})

		if !ran {
			if cell.Op == opCount {
				v = prev
			}

			// A cell none of whose reads changed computes to what it holds:
			// otherwise the cells or the model are wrong, not the package.
			if v != prev || !slices.Equal(read, m.reads[i]) {
				panic(fmt.Sprintf("model: cell %d unchanged computes %d from %d, reads %v after %v", i, v, prev, read, m.reads[i]))
			}

			continue
		}

		out.ran = append(out.ran, i)

		if i == c.Cell && (c.Kind == commitCellPanic || c.Kind == commitReadAhead) {
			out.panics = true

			return out
		}

		reads[i] = read
		now[i] = first || !cell.Eq.equal(prev, v)
		vals[i] = v
	}

	built := graphModel{plan: m.plan, rev: m.rev + 1, values: vals, changed: slices.Clone(m.changed), reads: reads}

	for i, ch := range now {
		if ch {
			built.changed[i] = built.rev
			out.changed = append(out.changed, i)
		}
	}

	out.built = built
	out.checked = c.Kind == commitChecked || c.Kind == commitRefused

	if c.Kind == commitRefused {
		out.err = errRefused
		out.changed = nil

		return out
	}

	out.next, out.published = built, true

	return out
}

// The Map's counted exceptions.
const (
	excChangesCursor = "graph/changes-cursor"
	excChangesNever  = "graph/changes-never"
	excNilEditDone   = "graph/nil-edit-done"
)

// mapIdent is one Map as the model knows it: the Maps a net-zero edit
// returns are the one it started from, and every zero Map is one.
type mapIdent struct {
	m        *Map[int, int]
	contents map[int]int
	parent   int   // the ident it was edited from, or -1
	changed  []int // the keys its edit changed, by its equality
	written  []int // the keys its edit wrote
	logLen   int   // how many edits back its log reaches
	hasEq    bool  // a NewMap lineage; the others call nothing equal
}

const (
	zeroIdent = iota
	nilIdent
)

// mapVersion is one step of a history.
type mapVersion struct {
	m      *Map[int, int]
	ident  int
	base   int // the version it was edited from, or -1
	filler bool
}

// mapRun is a history replayed: the versions, and the model of each.
type mapRun struct {
	eq       eqKind
	idents   []mapIdent
	versions []mapVersion
	named    []int // the versions edits and pairs name
	fillers  int
	excepts  map[string]int
	problem  string
	check    bool
}

func newMapRun(eq eqKind, check bool) *mapRun {
	return &mapRun{
		eq: eq, check: check, excepts: map[string]int{},
		idents: []mapIdent{
			zeroIdent: {m: new(Map[int, int]), contents: map[int]int{}, parent: -1},
			nilIdent:  {contents: map[int]int{}, parent: -1},
		},
	}
}

// eqOf is the equality ident's Map has.
func (r *mapRun) eqOf(ident int) eqKind {
	if r.idents[ident].hasEq {
		return r.eq
	}

	return eqNever
}

func (r *mapRun) failf(format string, args ...any) {
	if r.problem == "" {
		r.problem = fmt.Sprintf(format, args...)
	}
}

func (r *mapRun) add(m *Map[int, int], ident, base int, filler bool) {
	r.versions = append(r.versions, mapVersion{m: m, ident: ident, base: base, filler: filler})
	if !filler {
		r.named = append(r.named, len(r.versions)-1)
	}
}

func (r *mapRun) root(e editPlan) {
	switch e.Kind {
	case rootZero:
		r.add(new(Map[int, int]), zeroIdent, -1, false)
	case rootNil:
		r.add(nil, nilIdent, -1, false)
	case rootNew, rootCopy:
		contents := entriesOf(e.Init)
		if e.Kind == rootCopy {
			contents = maps.Clone(r.idents[r.versions[r.versionAt(e.Of)].ident].contents)
		}

		m := NewMap(r.eq.fn(), contents)
		r.idents = append(r.idents, mapIdent{m: m, contents: contents, parent: -1, hasEq: true})
		r.add(m, len(r.idents)-1, -1, false)
	}
}

func entriesOf(ops []mapOp) map[int]int {
	m := map[int]int{}
	for _, o := range ops {
		m[o.K] = o.V
	}

	return m
}

// versionAt is the named version back from the latest.
func (r *mapRun) versionAt(back int) int {
	return r.named[len(r.named)-1-back%len(r.named)]
}

// edit applies ops to version at through MapEdit, alongside a plain map,
// and adds the version Done returns.
func (r *mapRun) edit(at int, ops []mapOp, filler bool) int {
	base := r.versions[at]
	b := r.idents[base.ident]
	staged := maps.Clone(b.contents)
	written := map[int]bool{}
	e := base.m.Edit()

	for _, o := range ops {
		switch o.Kind {
		case mapDelete:
			e.Delete(o.K)
			delete(staged, o.K)
		case mapSetSame:
			if v, ok := staged[o.K]; ok {
				e.Set(o.K, v)
			} else {
				e.Delete(o.K)
			}
		case mapReAdd:
			e.Delete(o.K)
			e.Set(o.K, o.V)
			staged[o.K] = o.V
		case mapRestore:
			v, ok := staged[o.K]

			e.Set(o.K, o.V)

			if ok {
				e.Set(o.K, v)
			} else {
				e.Delete(o.K)
			}
		case mapSet:
			e.Set(o.K, o.V)
			staged[o.K] = o.V
		}

		written[o.K] = true

		if r.check {
			got, ok := e.Get(o.K)
			want, wantOK := staged[o.K]

			if ok != wantOK || got != want || e.Len() != len(staged) {
				r.failf("after %s an edit reads %d=%d (%t) of %d entries, want %d (%t) of %d", o, o.K, got, ok, e.Len(), want, wantOK, len(staged))
			}
		}
	}

	if r.check {
		if got := maps.Collect(e.All()); !maps.Equal(got, staged) {
			r.failf("an edit holds %v, want %v", got, staged)
		}
	}

	// The equality judges only what the edit wrote: an entry it did not
	// touch is the one the base holds.
	got := e.Done()
	changed := slices.DeleteFunc(diffKeys(b.contents, staged, r.eqOf(base.ident)), func(k int) bool { return !written[k] })

	switch {
	case len(changed) == 0 && base.ident != nilIdent:
		if got != base.m {
			r.failf("an edit changing nothing returned a new Map")
		}

		r.add(got, base.ident, at, filler)

		return len(r.versions) - 1
	case got == nil:
		if base.ident != nilIdent || len(changed) > 0 {
			r.failf("Done returned nil")
		}

		r.add(nil, nilIdent, at, filler)

		return len(r.versions) - 1
	case got == base.m:
		r.failf("an edit changing %v returned the Map it started from", changed)
	}

	id := mapIdent{m: got, contents: staged, parent: base.ident, changed: changed, written: sortedKeys(written), hasEq: b.hasEq}

	if base.ident == nilIdent {
		// TODO(kradalby): graph/nil-edit-done: an edit of a nil Map that
		// changes nothing returns a new empty Map, where Done's doc says it
		// returns the Map it started from. The model takes the new Map, as
		// an edit changing something from nil returns: a lineage with no
		// log and no equality. Delete with TestEditOfANilMapReturnsAMap
		// once the doc says so, or Done returns nil.
		if len(changed) == 0 {
			r.excepts[excNilEditDone]++
		}

		id.parent, id.hasEq = -1, false
	} else {
		id.logLen = b.logLen + 1
		if id.logLen > 2*mapLog {
			id.logLen = mapLog
		}
	}

	r.idents = append(r.idents, id)
	r.add(got, len(r.idents)-1, at, filler)

	return len(r.versions) - 1
}

// replayHistory runs h; with check, it holds every version and edit to
// the model as it goes and every version again at the end.
func replayHistory(h mapHistory, check bool) *mapRun {
	r := newMapRun(h.Eq, check)
	r.root(editPlan{Init: h.Init})

	for _, e := range h.Edits {
		if e.Root {
			r.root(e)

			continue
		}

		base := r.versionAt(e.Base)
		for range e.Filler {
			k := r.fillers % mapKeys
			base = r.edit(base, []mapOp{{K: k, V: 100 + r.fillers}}, true)
			r.fillers++
		}

		r.edit(base, e.Ops, false)

		if check && r.problem == "" {
			r.holds(r.named)
		}
	}

	if check && r.problem == "" {
		all := make([]int, len(r.versions))
		for i := range all {
			all[i] = i
		}

		r.holds(all)
	}

	return r
}

// holds checks that every listed version still reads as its model: no
// edit after it shows through.
func (r *mapRun) holds(versions []int) {
	for _, i := range versions {
		v := r.versions[i]
		want := r.idents[v.ident].contents

		if v.m.Len() != len(want) {
			r.failf("version %d holds %d entries, want %d", i, v.m.Len(), len(want))

			return
		}

		for k := range mapKeys {
			got, ok := v.m.Get(k)
			if w, wok := want[k]; ok != wok || got != w {
				r.failf("version %d reads %d=%d (%t), want %d (%t)", i, k, got, ok, w, wok)

				return
			}
		}

		if v.filler {
			continue
		}

		if got := maps.Collect(v.m.All()); !maps.Equal(got, want) {
			r.failf("version %d iterates %v, want %v", i, got, want)

			return
		}
	}
}

// moved is the equality that calls a value equal to itself as well: what
// a reader holding a and reading b would see as no change.
func (k eqKind) moved() eqKind {
	if k == eqNever {
		return eqSame
	}

	return k
}

// diffKeys is the keys whose entry differs between a and b by eq, sorted.
func diffKeys(a, b map[int]int, eq eqKind) []int {
	keys := map[int]bool{}

	for k, v := range b {
		if w, ok := a[k]; !ok || !eq.equal(w, v) {
			keys[k] = true
		}
	}

	for k := range a {
		if _, ok := b[k]; !ok {
			keys[k] = true
		}
	}

	return sortedKeys(keys)
}

func sortedKeys[V any](m map[int]V) []int {
	return slices.Sorted(maps.Keys(m))
}

// descends reports whether ident a is b or one b was edited from, however
// far back.
func (r *mapRun) descends(b, a int) bool {
	for ; b >= 0; b = r.idents[b].parent {
		if b == a {
			return true
		}
	}

	return false
}

func (r *mapRun) rootOf(id int) int {
	for r.idents[id].parent >= 0 {
		id = r.idents[id].parent
	}

	return id
}
