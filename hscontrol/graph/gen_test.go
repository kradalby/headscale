package graph

import (
	"flag"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Generators for the package's properties. Every draw shrinks towards the
// plain case: the first alternative, false flags, the smallest counts. A
// rare shape sits behind chance, which is false at zero. Cells, commits,
// edits and steps are each one group the shrinker can drop whole.
//
// The parts compose. cellGraphs draws cells; drawCommit draws one commit
// against a graphModel; scenarios is a graph and the commits run on it,
// which the scheduler, subscription and concurrency properties share.
// mapHistories draws Map edits and the pairs to compare; groupingCases adds
// what GroupBy groups by and the steps it takes over such a history. The
// plans hold indices and small numbers only, so a failure prints itself.

// chance is true one time in k, and false at zero.
func chance(t *rapid.T, k int, label string) bool {
	return rapid.IntRange(0, k-1).Draw(t, label) == k-1
}

// index draws one of n positions, the first at zero.
func index(t *rapid.T, n int, label string) int {
	return rapid.IntRange(0, n-1).Draw(t, label)
}

// anyOf draws one of n positions where n depends on earlier draws: the
// word drawn does not, so deleting an earlier element leaves the draws
// after it aligned.
func anyOf(t *rapid.T, n int, label string) int {
	return rapid.IntRange(0, 63).Draw(t, label) % n
}

// maxValue bounds drawn values: small, so that writes repeat values.
const maxValue = 4

// eqKind is the equality a cell or Map is registered with.
type eqKind uint8

const (
	eqSame  eqKind = iota // ==
	eqClass               // the same v/classWidth
	eqNever               // every value a change
)

// classWidth is how many values an eqClass class holds.
const classWidth = 2

func (k eqKind) equal(a, b int) bool {
	switch k {
	case eqClass:
		return a/classWidth == b/classWidth
	case eqNever:
		return false
	default:
		return a == b
	}
}

// view is what a reader sees of a value of equality k. A reader that saw
// more than its equality would see changes the cutoff withholds, and no
// model could say what it holds.
func (k eqKind) view(v int) int {
	if k == eqClass {
		return v / classWidth
	}

	return v
}

// fn is the equality as the package takes it.
func (k eqKind) fn() func(a, b int) bool {
	switch k {
	case eqSame:
		return Same[int]
	case eqNever:
		return Never[int]
	default:
		return k.equal
	}
}

func (k eqKind) String() string { return [...]string{"same", "class", "never"}[k] }

func drawEq(t *rapid.T, label string) eqKind {
	switch rapid.IntRange(0, 5).Draw(t, label) {
	case 4:
		return eqClass
	case 5:
		return eqNever
	default:
		return eqSame
	}
}

// opKind is what a derived cell computes from what it reads.
type opKind uint8

const (
	opSum    opKind = iota // the sum
	opMin                  // the least; a write to another read leaves it
	opParity               // the sum mod 2; most writes leave it
	opConst                // reads, then ignores: no write changes it
	opPick                 // the first read selects which other it reads
	opMax                  // the most it has ever been: carries prev
	opSticky               // prev while a read still holds it, else the least
	opCount                // prev+1: how often it computed
	opGate                 // the first read, and the others while it is even
)

const opKinds = int(opGate) + 1

func (o opKind) String() string {
	return [...]string{"sum", "min", "parity", "const", "pick", "max", "sticky", "count", "gate"}[o]
}

// carries reports whether the op reads prev. All but count do so
// idempotently: computed again from what it computed, it gives that back.
func (o opKind) carries() bool { return o == opMax || o == opSticky || o == opCount }

// cellPlan is one cell: an input with its initial value, or a derived cell
// reading cells below it.
type cellPlan struct {
	Input bool
	Init  int
	Eq    eqKind
	Op    opKind
	Reads []int
}

// eval computes a derived cell. read returns what it sees of a cell. Which
// cells it reads depends only on what it read before them, never on prev,
// so a cell whose reads hold still reads the same cells again.
func (c cellPlan) eval(prev int, read func(int) int) int {
	sum := func() int {
		s := 0
		for _, r := range c.Reads {
			s += read(r)
		}

		return s
	}

	switch c.Op {
	case opMin, opSticky:
		vals := make([]int, len(c.Reads))
		for i, r := range c.Reads {
			vals[i] = read(r)
		}

		if len(vals) == 0 {
			return 0
		}

		if c.Op == opSticky {
			for _, v := range vals {
				if v == prev {
					return prev
				}
			}
		}

		least := vals[0]
		for _, v := range vals[1:] {
			least = min(least, v)
		}

		return least
	case opParity:
		return sum() % 2
	case opConst:
		sum()

		return 1
	case opPick:
		if len(c.Reads) == 0 {
			return 0
		}

		sel := read(c.Reads[0])
		if len(c.Reads) == 1 {
			return sel
		}

		return read(c.Reads[1+sel%(len(c.Reads)-1)])
	case opGate:
		if len(c.Reads) == 0 {
			return 0
		}

		g := read(c.Reads[0])
		if g%2 != 0 {
			return g
		}

		for _, r := range c.Reads[1:] {
			g += read(r)
		}

		return g
	case opMax:
		return max(prev, sum())
	case opCount:
		sum()

		return prev + 1
	default:
		return sum()
	}
}

func (c cellPlan) String() string {
	if c.Input {
		return fmt.Sprintf("input=%d eq=%s", c.Init, c.Eq)
	}

	return fmt.Sprintf("%s%v eq=%s", c.Op, c.Reads, c.Eq)
}

// graphPlan is the cells of a graph in registration order.
type graphPlan struct{ Cells []cellPlan }

func (p graphPlan) inputs() []int {
	var ins []int

	for i, c := range p.Cells {
		if c.Input {
			ins = append(ins, i)
		}
	}

	return ins
}

func (p graphPlan) derived() []int {
	var ds []int

	for i, c := range p.Cells {
		if !c.Input {
			ds = append(ds, i)
		}
	}

	return ds
}

func (p graphPlan) GoString() string {
	var b strings.Builder
	for i, c := range p.Cells {
		fmt.Fprintf(&b, "\n  %d %s", i, c)
	}

	return b.String()
}

// graphSizes bounds what the graph generators draw.
type graphSizes struct {
	inputs, derived, fanIn int
	commits, sets          int
}

// defaultSizes keeps a case to well under a millisecond; one graph in
// bigGraphs takes bigTimes as many derived cells and commits.
var defaultSizes = graphSizes{inputs: 4, derived: 10, fanIn: 3, commits: 16, sets: 3}

const (
	bigGraphs = 8
	bigTimes  = 3
)

// cellGraphs draws a graph: inputs, then derived cells, each reading cells
// below it, and now and then another input among them.
func cellGraphs(sz graphSizes) *rapid.Generator[graphPlan] {
	return rapid.Custom(func(t *rapid.T) graphPlan {
		big := chance(t, bigGraphs, "big")

		var (
			cells []cellPlan
			ins   []int
		)

		for _, c := range rapid.SliceOfN(inputs, 1, sz.inputs).Draw(t, "inputs") {
			ins = append(ins, len(cells))
			cells = append(cells, c)
		}

		maxDer := sz.derived
		if big {
			maxDer *= bigTimes
		}

		cell := rapid.Custom(func(t *rapid.T) cellPlan {
			// The scheduler walks cells in registration order, not
			// inputs first.
			if chance(t, 12, "late-input") {
				return inputs.Draw(t, "input")
			}

			c := cellPlan{Op: opKind(rapid.IntRange(0, opKinds-1).Draw(t, "op")), Eq: drawEq(t, "eq")}

			// A pick needs two cells to choose between, or it reads the
			// same ones whatever its selector holds; a gate one to open.
			least := 1
			if c.Op == opPick {
				least = 3
			} else if c.Op == opGate {
				least = 2
			}

			c.Reads = drawReads(t, sz, len(cells), ins, least)

			return c
		})

		for range rapid.IntRange(0, maxDer).Draw(t, "derived") {
			c := cell.Draw(t, "cell")
			if c.Input {
				ins = append(ins, len(cells))
			}

			cells = append(cells, c)
		}

		return graphPlan{Cells: cells}
	})
}

var inputs = rapid.Custom(func(t *rapid.T) cellPlan {
	return cellPlan{Input: true, Init: rapid.IntRange(0, maxValue).Draw(t, "init"), Eq: drawEq(t, "eq")}
})

// drawReads draws what derived cell i reads, at least least cells unless
// none: mostly the cell just below, so chains and diamonds come first, and
// inputs directly, so they fan out.
func drawReads(t *rapid.T, sz graphSizes, i int, ins []int, least int) []int {
	if chance(t, 8, "no-reads") {
		return nil
	}

	reads := make([]int, max(least, 1+rapid.IntRange(0, sz.fanIn-1).Draw(t, "fan-in")))
	for j := range reads {
		if chance(t, 3, "reads-input") {
			reads[j] = ins[anyOf(t, len(ins), "input")]
		} else {
			reads[j] = i - 1 - anyOf(t, i, "back")
		}
	}

	return reads
}

// setKind is how a set's value is chosen.
type setKind uint8

const (
	setValue setKind = iota // a drawn value
	setSame                 // the value the input holds: a change only to eqNever
	setClass                // another value of its class: a change only to eqSame and eqNever
)

// setPlan sets cell In to V.
type setPlan struct {
	In   int
	Kind setKind
	V    int
}

// commitKind is how a commit is made, and how it fails.
type commitKind uint8

const (
	commitPlain     commitKind = iota // Update
	commitChecked                     // UpdateChecked, accepted
	commitFnError                     // fn returns an error after its sets
	commitFnPanic                     // fn panics after its sets
	commitCellPanic                   // derived cell Cell panics, if it computes
	commitReadAhead                   // derived cell Cell reads Ahead cells past itself, if it computes
	commitRefused                     // UpdateChecked, refused
)

func (k commitKind) String() string {
	return [...]string{"plain", "checked", "fn-error", "fn-panic", "cell-panic", "read-ahead", "refused"}[k]
}

// commitPlan is one transaction.
type commitPlan struct {
	Sets  []setPlan
	Kind  commitKind
	Cell  int
	Ahead int
}

func (c commitPlan) String() string {
	var b strings.Builder

	b.WriteString(c.Kind.String())

	switch c.Kind {
	case commitCellPanic:
		fmt.Fprintf(&b, "(%d)", c.Cell)
	case commitReadAhead:
		fmt.Fprintf(&b, "(%d+%d)", c.Cell, c.Ahead)
	}

	for _, s := range c.Sets {
		fmt.Fprintf(&b, " %d=%d", s.In, s.V)

		switch s.Kind {
		case setSame:
			b.WriteString("(same)")
		case setClass:
			b.WriteString("(class)")
		}
	}

	return b.String()
}

// drawCommit draws a commit of ins against m, so that a set of the value
// an input holds is one. Without whole, no cell fails: whether it computes
// would turn on other writers' commits.
func drawCommit(t *rapid.T, sz graphSizes, m graphModel, ins []int, whole bool) commitPlan {
	if len(ins) == 0 {
		sz.sets = 0
		ins = []int{0}
	}

	set := rapid.Custom(func(t *rapid.T) setPlan {
		in := ins[anyOf(t, len(ins), "input")]

		s := setPlan{In: in}

		switch rapid.IntRange(0, 5).Draw(t, "how") {
		case 4:
			s.Kind, s.V = setSame, m.values[in]
		case 5:
			s.Kind, s.V = setClass, m.values[in]^1
		default:
			s.V = rapid.IntRange(0, maxValue).Draw(t, "value")
		}

		return s
	})

	c := commitPlan{Sets: rapid.SliceOfN(set, 0, sz.sets).Draw(t, "sets")}

	switch rapid.IntRange(0, 16).Draw(t, "kind") {
	case 8, 9:
		c.Kind = commitChecked
	case 10:
		c.Kind = commitFnError
	case 11:
		c.Kind = commitFnPanic
	case 12, 13:
		c.Kind = commitCellPanic
	case 14:
		c.Kind = commitReadAhead
	case 15, 16:
		c.Kind = commitRefused
	}

	if c.Kind == commitCellPanic || c.Kind == commitReadAhead {
		ds := m.plan.derived()
		if len(ds) == 0 || !whole {
			c.Kind = commitPlain

			return c
		}

		// Counted from the last, which shrinking keeps last.
		c.Cell = ds[len(ds)-1-anyOf(t, len(ds), "cell")]

		if c.Kind == commitReadAhead {
			c.Ahead = anyOf(t, len(m.plan.Cells)-c.Cell, "ahead")
		}
	}

	return c
}

// scenario is a graph and the commits run on it, in order.
type scenario struct {
	Graph   graphPlan
	Commits []commitPlan
}

func (s scenario) GoString() string {
	var b strings.Builder

	b.WriteString("cells:")
	b.WriteString(s.Graph.GoString())
	b.WriteString("\ncommits:")

	for k, c := range s.Commits {
		fmt.Fprintf(&b, "\n  %d %s", k, c)
	}

	return b.String()
}

// scenarios draws a graph and commits on it, each drawn against the model
// as the earlier ones left it.
func scenarios(sz graphSizes) *rapid.Generator[scenario] {
	return rapid.Custom(func(t *rapid.T) scenario {
		s := scenario{Graph: cellGraphs(sz).Draw(t, "graph")}
		m := newGraphModel(s.Graph)

		n := sz.commits
		if len(s.Graph.derived()) > sz.derived {
			n *= bigTimes
		}

		commit := rapid.Custom(func(t *rapid.T) commitPlan { return drawCommit(t, sz, m, s.Graph.inputs(), true) })

		for range rapid.IntRange(0, n).Draw(t, "commits") {
			c := commit.Draw(t, "commit")
			m = m.step(c).next
			s.Commits = append(s.Commits, c)
		}

		return s
	})
}

// writersPlan is a graph, published once, and the commits two writers
// then make at once, each on its own inputs: they alternate between them.
type writersPlan struct {
	Graph   graphPlan
	Commits [2][]commitPlan
}

func (p writersPlan) GoString() string {
	var b strings.Builder

	b.WriteString("cells:")
	b.WriteString(p.Graph.GoString())

	for w, cs := range p.Commits {
		fmt.Fprintf(&b, "\nwriter %d:", w)

		for k, c := range cs {
			fmt.Fprintf(&b, "\n  %d %s", k, c)
		}
	}

	return b.String()
}

// owned is the inputs writer w of two owns.
func (p graphPlan) owned(w int) []int {
	var ins []int

	for j, in := range p.inputs() {
		if j%2 == w {
			ins = append(ins, in)
		}
	}

	return ins
}

// writersPlans draws each writer's commits against a model of the graph
// that only it writes: right about its own inputs, whatever the other does.
func writersPlans(sz graphSizes) *rapid.Generator[writersPlan] {
	return rapid.Custom(func(t *rapid.T) writersPlan {
		p := writersPlan{Graph: cellGraphs(sz).Draw(t, "graph")}

		for w := range p.Commits {
			m := newGraphModel(p.Graph).step(commitPlan{}).next
			commit := rapid.Custom(func(t *rapid.T) commitPlan { return drawCommit(t, sz, m, p.Graph.owned(w), false) })

			for range rapid.IntRange(0, sz.commits).Draw(t, "commits") {
				c := commit.Draw(t, "commit")
				m = m.step(c).next
				p.Commits[w] = append(p.Commits[w], c)
			}
		}

		return p
	})
}

// subKind is what a subscriber does between commits.
type subKind uint8

const (
	subConsume   subKind = iota // takes a wake-up, if one is pending, and diffs
	subSubscribe                // a new subscriber
	subClose                    // subscriber Sub closes
)

type subEvent struct {
	Kind subKind
	Sub  int
}

func (e subEvent) String() string {
	return fmt.Sprintf("%s(%d)", [...]string{"consume", "subscribe", "close"}[e.Kind], e.Sub)
}

// subSchedule interleaves subscribers' events with a scenario's commits:
// Events[k] come before commit k, the last after every commit. Subscriber
// 0 subscribes before anything else.
type subSchedule struct {
	Scenario scenario
	Events   [][]subEvent
}

func (s subSchedule) GoString() string {
	var b strings.Builder

	b.WriteString("cells:")
	b.WriteString(s.Scenario.Graph.GoString())
	b.WriteString("\nschedule:")

	for k, evs := range s.Events {
		for _, e := range evs {
			fmt.Fprintf(&b, "\n  %s", e)
		}

		if k < len(s.Scenario.Commits) {
			fmt.Fprintf(&b, "\n  commit %d %s", k, s.Scenario.Commits[k])
		}
	}

	return b.String()
}

func subSchedules(sz graphSizes) *rapid.Generator[subSchedule] {
	return rapid.Custom(func(t *rapid.T) subSchedule {
		s := subSchedule{Scenario: scenarios(sz).Draw(t, "scenario")}
		subs := 1

		event := rapid.Custom(func(t *rapid.T) subEvent {
			e := subEvent{Sub: anyOf(t, subs, "sub")}

			switch rapid.IntRange(0, 5).Draw(t, "what") {
			case 4:
				e.Kind, e.Sub = subSubscribe, subs
				subs++
			case 5:
				e.Kind = subClose
			}

			return e
		})

		for range len(s.Scenario.Commits) + 1 {
			s.Events = append(s.Events, rapid.SliceOfN(event, 0, 3).Draw(t, "events"))
		}

		return s
	})
}

// scenarioShapes names the shapes s reaches, running it on the model.
func scenarioShapes(s scenario) map[string]bool {
	shapes := map[string]bool{}
	p := s.Graph
	readers := make([]int, len(p.Cells))
	depth := make([]int, len(p.Cells))
	below := make([]map[int]bool, len(p.Cells)) // every cell a cell reads, through any path, itself included

	for i, c := range p.Cells {
		below[i] = map[int]bool{i: true}

		if c.Input {
			shapes[c.Eq.String()+" input"] = true

			if len(p.derived()) > 0 && i > p.derived()[0] {
				shapes["late input"] = true
			}

			continue
		}

		shapes["op "+c.Op.String()] = true
		shapes[c.Eq.String()+" cell"] = true

		if len(c.Reads) == 0 {
			shapes["no reads"] = true
		}

		for j, r := range c.Reads {
			readers[r]++
			depth[i] = max(depth[i], depth[r]+1)

			for b := range below[r] {
				below[i][b] = true
			}

			for _, q := range c.Reads[:j] {
				if q == r {
					continue
				}

				for b := range below[q] {
					if below[r][b] {
						shapes["diamond"] = true
					}
				}
			}
		}

		if depth[i] >= 4 {
			shapes["chain of 4"] = true
		}
	}

	for _, n := range readers {
		if n >= 3 {
			shapes["fan-out of 3"] = true
		}
	}

	m := newGraphModel(p)

	for _, c := range s.Commits {
		first := m.rev == 0
		o := m.step(c)

		seen := map[int]bool{}
		for _, st := range c.Sets {
			if seen[st.In] {
				shapes["input set twice"] = true
			}

			seen[st.In] = true
		}

		for _, e := range o.excepts {
			shapes[e] = true
		}

		switch {
		case o.panics && c.Kind != commitFnPanic:
			shapes[c.Kind.String()] = true

			if c.Kind == commitReadAhead && c.Ahead == 0 {
				shapes["reads itself"] = true
			}
		case c.Kind == commitCellPanic || c.Kind == commitReadAhead:
			shapes["armed cell skipped"] = true
		case c.Kind == commitRefused && o.checked:
			shapes["refused"] = true
		case c.Kind == commitRefused:
			shapes["refusal unchecked"] = true
		default:
			shapes[c.Kind.String()] = true
		}

		if first && !o.published {
			shapes["first commit fails"] = true
		}

		// A refused commit whose cells read other cells than they did:
		// the published snapshot must not take on what they read.
		if o.checked && !o.published && !first {
			for _, i := range o.ran {
				if !slices.Equal(m.reads[i], o.built.reads[i]) {
					shapes["reads moved, refused"] = true
				}
			}
		}

		if !first && !o.published && !o.panics && o.err == nil {
			shapes["no-op commit"] = true
		}

		if !o.published {
			continue
		}

		if len(o.ran) < len(p.derived()) && !first {
			shapes["computation skipped"] = true
		}

		for _, i := range o.ran {
			changed := slices.Contains(o.changed, i)

			switch {
			case !changed && readers[i] > 0:
				shapes["cutoff"] = true
			case changed && p.Cells[i].Eq == eqNever && o.next.values[i] == m.values[i] && !first:
				shapes["never cell recomputes its value"] = true
			}

			if !first && !slices.Equal(m.reads[i], o.next.reads[i]) {
				shapes["reads moved"] = true
			}

			if c := p.Cells[i]; c.Op == opSticky && len(c.Reads) > 1 {
				least := c.eval(-1, func(d int) int { return p.Cells[d].Eq.view(o.next.values[d]) })
				if least != o.next.values[i] {
					shapes["sticky keeps its incumbent"] = true
				}
			}
		}

		m = o.next
	}

	return shapes
}

// coverageSamples is how many drawn cases each coverage test classifies.
const coverageSamples = 500

// requireShapes classifies coverageSamples drawn cases and fails for every
// shape below its floor, a share of the cases. A floor sits far below what
// the generator draws, so no seed misses it.
func requireShapes[V any](t *testing.T, gen *rapid.Generator[V], shapes func(V) map[string]bool, floors map[string]float64) {
	t.Helper()

	counts := map[string]int{}

	for i := range coverageSamples {
		for s := range shapes(gen.Example(i)) {
			counts[s]++
		}
	}

	var table strings.Builder

	for _, name := range slices.Sorted(maps.Keys(floors)) {
		floor := int(floors[name] * coverageSamples)
		fmt.Fprintf(&table, "\n  %-34s %4d  floor %d", name, counts[name], floor)

		if counts[name] < floor {
			t.Errorf("%s in %d of %d cases, floor %d", name, counts[name], coverageSamples, floor)
		}
	}

	t.Logf("cases out of %d reaching each shape:%s", coverageSamples, table.String())
}

// TestScenarioCoverage holds the graph and commit generators to the shapes
// the scheduler properties need.
func TestScenarioCoverage(t *testing.T) {
	t.Parallel()

	requireShapes(t, scenarios(defaultSizes), scenarioShapes, map[string]float64{
		"diamond": 0.1, "chain of 4": 0.05, "fan-out of 3": 0.1, "late input": 0.05, "no reads": 0.05,
		"class input": 0.05, "never input": 0.05, "class cell": 0.05, "never cell": 0.05,
		"op sum": 0.1, "op min": 0.1, "op parity": 0.1, "op const": 0.1, "op pick": 0.1, "op max": 0.1, "op sticky": 0.1, "op count": 0.1, "op gate": 0.1,
		"input set twice": 0.05, "no-op commit": 0.1, "computation skipped": 0.1, "cutoff": 0.06, "reads moved": 0.03, "reads moved, refused": 0.01,
		"never cell recomputes its value": 0.01, "sticky keeps its incumbent": 0.004,
		"cell-panic": 0.05, "read-ahead": 0.02, "reads itself": 0.01, "armed cell skipped": 0.05,
		"refused": 0.05, "refusal unchecked": 0.01, "fn-error": 0.05, "fn-panic": 0.05, "checked": 0.1, "first commit fails": 0.05,
		excInputEqualKept: 0.01,
	})
}

// TestScenariosShrinkToSmallCases fails a property on a shape the
// generators rarely draw and holds the case rapid reports to the smallest
// that has it: a draw that stops shrinking fails here, not in a failure no
// one can read. Shrinking takes seconds, so it runs at deep budgets only.
func TestScenariosShrinkToSmallCases(t *testing.T) {
	shrinking(t)

	var last scenario

	failing(t, func(t *rapid.T) {
		last = scenarios(defaultSizes).Draw(t, "scenario")
		if scenarioShapes(last)["reads moved"] {
			t.Fatal("reads moved")
		}
	})

	// Two inputs and a pick between them; the first commit and one moving
	// the selector.
	if len(last.Graph.Cells) > 3 || len(last.Commits) > 2 {
		t.Errorf("minimised to %d cells and %d commits:%#v", len(last.Graph.Cells), len(last.Commits), last)
	}
}

// shrinking skips t short of a deep budget, and otherwise fixes the seed
// and sends fail files nowhere: shrinking reaches the smallest case from
// some seeds, not all. Flags are process-wide, so not parallel.
func shrinking(t *testing.T) {
	t.Helper()

	if !deep() {
		t.Skip("runs at -rapid.checks=1000 or more")
	}

	for name, value := range map[string]string{"rapid.nofailfile": "true", "rapid.seed": "1", "rapid.checks": "1000"} {
		old := flag.Lookup(name).Value.String()

		err := flag.Set(name, value)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = flag.Set(name, old) })
	}
}

// deep reports whether the run asks for at least 1000 cases.
func deep() bool {
	n, err := strconv.Atoi(flag.Lookup("rapid.checks").Value.String())

	return err == nil && n >= 1000
}

// failing runs prop, which must fail, and keeps rapid's report off t.
func failing(t *testing.T, prop func(*rapid.T)) {
	t.Helper()

	fl := &failureLog{name: t.Name()}
	rapid.Check(fl, prop)

	if !fl.failed {
		t.Fatal("the property did not fail")
	}
}

// failureLog is a [rapid.TB] that keeps what rapid reports instead of
// failing the test.
type failureLog struct {
	name   string
	failed bool
}

func (*failureLog) Helper()                 {}
func (r *failureLog) Name() string          { return r.name }
func (*failureLog) Logf(string, ...any)     {}
func (*failureLog) Log(...any)              {}
func (*failureLog) Skipf(string, ...any)    {}
func (*failureLog) Skip(...any)             {}
func (*failureLog) SkipNow()                {}
func (r *failureLog) Errorf(string, ...any) { r.failed = true }
func (r *failureLog) Error(...any)          { r.failed = true }
func (r *failureLog) Fatalf(string, ...any) { r.failed = true }
func (r *failureLog) Fatal(...any)          { r.failed = true }
func (r *failureLog) FailNow()              { r.failed = true }
func (r *failureLog) Fail()                 { r.failed = true }
func (r *failureLog) Failed() bool          { return r.failed }

// mapKeys bounds the keys of drawn Maps: few, so that edits collide.
const mapKeys = 6

// mapOpKind is one write of an edit.
type mapOpKind uint8

const (
	mapSet     mapOpKind = iota // K = V
	mapDelete                   // K removed
	mapSetSame                  // K set to what it holds, or deleted while absent
	mapReAdd                    // K deleted, then set to V
	mapRestore                  // K set to V, then back to what it held
)

const mapOpKinds = int(mapRestore) + 1

type mapOp struct {
	Kind mapOpKind
	K, V int
}

func (o mapOp) String() string {
	switch o.Kind {
	case mapDelete:
		return fmt.Sprintf("del %d", o.K)
	case mapSetSame:
		return fmt.Sprintf("same %d", o.K)
	case mapReAdd:
		return fmt.Sprintf("readd %d=%d", o.K, o.V)
	case mapRestore:
		return fmt.Sprintf("restore %d=%d", o.K, o.V)
	default:
		return fmt.Sprintf("%d=%d", o.K, o.V)
	}
}

// rootKind is how a lineage starts.
type rootKind uint8

const (
	rootNew  rootKind = iota // NewMap of drawn entries
	rootCopy                 // NewMap of the entries of version Of: equal, unrelated
	rootZero                 // the zero Map
	rootNil                  // a nil *Map
)

// editPlan is one step of a history: a new lineage, or an edit of the
// version Base back from the latest, after Filler one-key edits of it.
type editPlan struct {
	Root   bool
	Kind   rootKind
	Of     int
	Init   []mapOp
	Base   int
	Filler int
	Ops    []mapOp
}

func (e editPlan) String() string {
	if e.Root {
		k := [...]string{"new", "copy", "zero", "nil"}[e.Kind]

		switch e.Kind {
		case rootNew:
			return fmt.Sprintf("root %s %v", k, e.Init)
		case rootCopy:
			return fmt.Sprintf("root copy of -%d", e.Of)
		default:
			return "root " + k
		}
	}

	s := fmt.Sprintf("edit -%d %v", e.Base, e.Ops)
	if e.Filler > 0 {
		s += fmt.Sprintf(" after %d fillers", e.Filler)
	}

	return s
}

// pairKind is how a pair's sides are read.
type pairKind uint8

const (
	pairPlain  pairKind = iota
	pairCursor          // Old through its Cursor
	pairNilOld
	pairNilNew
)

// pairPlan compares two versions, each named versions back from the latest.
type pairPlan struct {
	Kind     pairKind
	Old, New int
}

// mapHistory is a first lineage of Init, then edits and lineages, then the
// pairs to compare. Every step adds one named version.
type mapHistory struct {
	Eq    eqKind
	Init  []mapOp
	Edits []editPlan
	Pairs []pairPlan
}

func (h mapHistory) GoString() string {
	var b strings.Builder

	fmt.Fprintf(&b, "eq=%s\n  0 root new %v", h.Eq, h.Init)

	for k, e := range h.Edits {
		fmt.Fprintf(&b, "\n  %d %s", k+1, e)
	}

	for _, p := range h.Pairs {
		fmt.Fprintf(&b, "\n  pair %s %d -> %d", [...]string{"plain", "cursor", "nil-old", "nil-new"}[p.Kind], p.Old, p.New)
	}

	return b.String()
}

// mapSizes bounds what the Map generators draw. One edit in longEdits
// first makes a run of one-key edits, up to three logs long.
type mapSizes struct{ entries, edits, ops, pairs int }

var defaultMapSizes = mapSizes{entries: 4, edits: 12, ops: 4, pairs: 6}

const longEdits = 24

var entries = rapid.Custom(func(t *rapid.T) mapOp {
	return mapOp{K: index(t, mapKeys, "k"), V: rapid.IntRange(0, maxValue).Draw(t, "v")}
})

// mapHistories draws an edit history: mostly edits of the latest version,
// some of older ones (branches), some new lineages.
func mapHistories(sz mapSizes) *rapid.Generator[mapHistory] {
	return rapid.Custom(func(t *rapid.T) mapHistory {
		h := mapHistory{Eq: drawEq(t, "eq"), Init: rapid.SliceOfN(entries, 0, sz.entries).Draw(t, "init")}
		named := 1

		op := rapid.Custom(func(t *rapid.T) mapOp {
			return mapOp{
				Kind: mapOpKind(rapid.IntRange(0, mapOpKinds-1).Draw(t, "op")),
				K:    index(t, mapKeys, "k"),
				V:    rapid.IntRange(0, maxValue).Draw(t, "v"),
			}
		})

		edit := rapid.Custom(func(t *rapid.T) editPlan {
			if chance(t, 8, "root") {
				e := editPlan{Root: true, Kind: rootKind(rapid.IntRange(0, 3).Draw(t, "root-kind"))}

				switch e.Kind {
				case rootNew:
					e.Init = rapid.SliceOfN(entries, 0, sz.entries).Draw(t, "init")
				case rootCopy:
					e.Of = anyOf(t, named, "of")
				}

				return e
			}

			e := editPlan{}
			if branch, back := chance(t, 3, "branch"), anyOf(t, max(1, named-1), "base"); branch && named > 1 {
				e.Base = 1 + back
			}

			// Fillers carry a lineage to its log's edges: a few, about
			// mapLog, or past twice that, where the log is trimmed. Shrinking
			// takes the few when the length does not matter.
			if chance(t, longEdits, "long") {
				switch rapid.IntRange(0, 2).Draw(t, "filler-size") {
				case 0:
					e.Filler = rapid.IntRange(1, 8).Draw(t, "filler")
				case 1:
					e.Filler = rapid.IntRange(mapLog-2, mapLog+2).Draw(t, "filler")
				default:
					e.Filler = rapid.IntRange(2*mapLog-2, 3*mapLog).Draw(t, "filler")
				}
			}

			e.Ops = rapid.SliceOfN(op, 0, sz.ops).Draw(t, "ops")

			return e
		})

		for range rapid.IntRange(0, sz.edits).Draw(t, "edits") {
			h.Edits = append(h.Edits, edit.Draw(t, "edit"))
			named++
		}

		pair := rapid.Custom(func(t *rapid.T) pairPlan {
			p := pairPlan{Old: anyOf(t, named, "old"), New: anyOf(t, named, "new")}

			switch rapid.IntRange(0, 5).Draw(t, "pair-kind") {
			case 3:
				p.Kind = pairCursor
			case 4:
				p.Kind = pairNilOld
			case 5:
				p.Kind = pairNilNew
			}

			return p
		})

		h.Pairs = rapid.SliceOfN(pair, 0, sz.pairs).Draw(t, "pairs")

		return h
	})
}

// groupingPlan is what groupsOf names for an entry: a group by the value
// modulo Mod (none for 0 when None), one by the key's parity when ByKey,
// the first again when Dup, and Wide more for values whose group is a
// multiple of 3. Groups read the value only through the Map's equality,
// as GroupBy needs (see TestGroupByTrustsTheInputsEquality).
type groupingPlan struct {
	Mod   int
	ByKey bool
	Dup   bool
	None  bool
	Wide  int
	Skip  bool // GroupBy is given sameGroups
}

func (p groupingPlan) groups(eq eqKind) func(k, v int) []int {
	return func(k, v int) []int {
		c := eq.view(v) % p.Mod

		var gs []int
		if !p.None || c != 0 {
			gs = append(gs, c)
		}

		if p.ByKey {
			gs = append(gs, 10+k%2)
		}

		if p.Dup && len(gs) > 0 {
			gs = append(gs, gs[0])
		}

		if c%3 == 0 {
			for i := range p.Wide {
				gs = append(gs, 100+i)
			}
		}

		return gs
	}
}

func (p groupingPlan) same(eq eqKind) func(a, b int) bool {
	if !p.Skip {
		return nil
	}

	return func(a, b int) bool { return eq.view(a)%p.Mod == eq.view(b)%p.Mod }
}

// groupStepKind is how GroupBy is called for a version.
type groupStepKind uint8

const (
	stepNext    groupStepKind = iota // from the latest result
	stepSkip                         // not at all: the next step catches up over several edits
	stepOlder                        // from the result Back before the latest: a branch
	stepScratch                      // from nothing
)

type groupStep struct {
	Kind groupStepKind
	Back int
}

// groupingCase is a history, what to group its versions by, and one step
// for each named version, in order.
type groupingCase struct {
	History  mapHistory
	Grouping groupingPlan
	Steps    []groupStep
}

func (c groupingCase) GoString() string {
	return fmt.Sprintf("%#v\ngrouping %+v\nsteps %v", c.History, c.Grouping, c.Steps)
}

func groupingCases(sz mapSizes) *rapid.Generator[groupingCase] {
	return rapid.Custom(func(t *rapid.T) groupingCase {
		c := groupingCase{History: mapHistories(sz).Draw(t, "history")}

		c.Grouping = groupingPlan{
			Mod:   1 + rapid.IntRange(0, 3).Draw(t, "mod"),
			ByKey: chance(t, 2, "by-key"),
			Dup:   chance(t, 4, "dup"),
			None:  chance(t, 4, "none"),
			Skip:  chance(t, 2, "same-groups"),
		}

		if chance(t, 4, "wide") {
			c.Grouping.Wide = smallGroupList + 1 + rapid.IntRange(0, 3).Draw(t, "wide")
		}

		step := rapid.Custom(func(t *rapid.T) groupStep {
			switch rapid.IntRange(0, 7).Draw(t, "step") {
			case 5:
				return groupStep{Kind: stepSkip}
			case 6:
				return groupStep{Kind: stepOlder, Back: rapid.IntRange(1, 4).Draw(t, "back")}
			case 7:
				return groupStep{Kind: stepScratch}
			default:
				return groupStep{}
			}
		})

		n := 1 + len(c.History.Edits)
		c.Steps = rapid.SliceOfN(step, n, n).Draw(t, "steps")

		return c
	})
}

// historyShapes names the shapes h reaches, replaying it.
func historyShapes(h mapHistory) map[string]bool {
	shapes := map[string]bool{h.Eq.String() + " eq": true}
	r := replayHistory(h, false)

	for _, e := range h.Edits {
		switch {
		case e.Root:
			shapes["root "+[...]string{"new", "copy", "zero", "nil"}[e.Kind]] = true
		case e.Base > 0:
			shapes["branch"] = true
		}

		if e.Filler > 0 {
			shapes["long lineage"] = true
		}

		for _, o := range e.Ops {
			shapes["op "+[...]string{"set", "delete", "same", "readd", "restore"}[o.Kind]] = true
		}
	}

	for k := range r.excepts {
		shapes[k] = true
	}

	for _, v := range r.versions {
		if v.base < 0 || v.filler {
			continue
		}

		base := r.versions[v.base]

		switch {
		case base.ident == zeroIdent:
			shapes["edit of the zero Map"] = true
		case base.ident == nilIdent:
			shapes["edit of nil"] = true
		}

		if v.ident == base.ident && base.ident != nilIdent {
			shapes["net-zero edit"] = true
		}
	}

	for _, id := range r.idents {
		if id.parent >= 0 && id.logLen == mapLog && r.idents[id.parent].logLen == 2*mapLog {
			shapes["log trimmed"] = true
		}
	}

	kin := func(old, new int, what string) {
		switch {
		case old == nilIdent || new == nilIdent || old == new:
		case r.descends(new, old):
			shapes["ancestor "+what] = true
		case r.descends(old, new):
			shapes["descendant "+what] = true
		case r.rootOf(old) == r.rootOf(new):
			shapes["sibling "+what] = true
		default:
			shapes["unrelated "+what] = true
		}
	}

	for _, p := range h.Pairs {
		switch p.Kind {
		case pairCursor:
			shapes["cursor pair"] = true
		case pairNilOld, pairNilNew:
			shapes["nil pair"] = true

			continue
		}

		kin(r.versions[r.versionAt(p.Old)].ident, r.versions[r.versionAt(p.New)].ident, "pair")
	}

	for i := 1; i < len(r.named); i++ {
		kin(r.versions[r.named[i-1]].ident, r.versions[r.named[i]].ident, "in turn")
	}

	return shapes
}

// TestMapHistoryCoverage holds the history generator to the shapes the Map
// property needs.
func TestMapHistoryCoverage(t *testing.T) {
	t.Parallel()

	requireShapes(t, mapHistories(defaultMapSizes), historyShapes, map[string]float64{
		"same eq": 0.2, "class eq": 0.05, "never eq": 0.05,
		"op set": 0.2, "op delete": 0.1, "op same": 0.1, "op readd": 0.1, "op restore": 0.1,
		"branch": 0.1, "net-zero edit": 0.1, "long lineage": 0.05, "log trimmed": 0.02,
		"root new": 0.02, "root copy": 0.02, "root zero": 0.02, "root nil": 0.02,
		"edit of the zero Map": 0.01, "edit of nil": 0.01, excNilEditDone: 0.002,
		"ancestor pair": 0.06, "descendant pair": 0.05, "sibling pair": 0.02, "unrelated pair": 0.02,
		"ancestor in turn": 0.2, "sibling in turn": 0.1, "unrelated in turn": 0.05,
		"cursor pair": 0.05, "nil pair": 0.05,
	})
}

// groupingShapes names the shapes c reaches, from the plan alone.
func groupingShapes(c groupingCase) map[string]bool {
	shapes := map[string]bool{c.History.Eq.String() + " eq": true}
	g := c.Grouping

	for _, e := range c.History.Edits {
		if !e.Root && e.Base > 0 {
			shapes["branch"] = true
		}
	}

	for name, on := range map[string]bool{"by key": g.ByKey, "dup": g.Dup, "none": g.None, "wide": g.Wide > 0, "same groups": g.Skip} {
		if on {
			shapes[name] = true
		}
	}

	for _, st := range c.Steps {
		shapes["step "+[...]string{"next", "skip", "older", "scratch"}[st.Kind]] = true
	}

	return shapes
}

// TestGroupingCoverage holds the grouping generator to the shapes the
// GroupBy property needs.
func TestGroupingCoverage(t *testing.T) {
	t.Parallel()

	requireShapes(t, groupingCases(defaultMapSizes), groupingShapes, map[string]float64{
		"by key": 0.2, "dup": 0.1, "none": 0.1, "wide": 0.1, "same groups": 0.2,
		"step next": 0.3, "step skip": 0.1, "step older": 0.1, "step scratch": 0.1,
		"branch": 0.1, "class eq": 0.05,
	})
}

// TestMapHistoriesShrinkToSmallCases is TestScenariosShrinkToSmallCases for
// edit histories.
func TestMapHistoriesShrinkToSmallCases(t *testing.T) {
	shrinking(t)

	var last mapHistory

	failing(t, func(t *rapid.T) {
		last = mapHistories(defaultMapSizes).Draw(t, "history")
		if historyShapes(last)["sibling in turn"] {
			t.Fatal("siblings")
		}
	})

	// An edit, and another of the version before it.
	if len(last.Edits) > 2 || len(last.Pairs) > 0 {
		t.Errorf("minimised to%#v", last)
	}
}
