package graph

import (
	"errors"
	"fmt"
	"slices"
)

// The models the properties hold the package to. They share with it only
// the cells' own functions (cellPlan.eval).

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
