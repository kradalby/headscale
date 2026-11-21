package graph

import (
	"errors"
	"fmt"
	"maps"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"
)

// graphSUT is a graph built from a plan, with every computation logged.
type graphSUT struct {
	g     *Graph
	plan  graphPlan
	nodes []Node[int]
	ins   []Input[int]
	calls []cellCall

	// armed is the derived cell set to fail should it compute in the
	// commit at hand. fn sets it, under the graph's lock, so concurrent
	// writers arm only their own commits.
	armed     int
	readAhead bool
	ahead     int

	problems []string
	excepts  map[string]int
}

type cellCall struct{ cell, prev int }

func newGraphSUT(p graphPlan) *graphSUT {
	h := &graphSUT{g: New(), plan: p, armed: -1, excepts: map[string]int{}}
	h.nodes = make([]Node[int], len(p.Cells))
	h.ins = make([]Input[int], len(p.Cells))

	for i, c := range p.Cells {
		name := fmt.Sprintf("cell%d", i)

		if c.Input {
			in := h.g.NewInput(name, c.Init, c.Eq.fn())
			h.nodes[i], h.ins[i] = in, in

			continue
		}

		h.nodes[i] = NewDerived(h.g, name, c.Eq.fn(), func(s *Snapshot, prev int) int {
			h.calls = append(h.calls, cellCall{cell: i, prev: prev})

			if h.armed == i {
				if !h.readAhead {
					panic(errCellPanic)
				}

				// The package refuses a read of a cell not registered
				// before the one computing.
				s.Get(h.nodes[i+h.ahead])
			}

			return c.eval(prev, func(d int) int { return p.Cells[d].Eq.view(s.Get(h.nodes[d])) })
		})
	}

	return h
}

// applied is what one Update did.
type applied struct {
	snap      *Snapshot
	err       error
	recovered any
	checks    int
	built     *Snapshot // what the check saw
	inCheck   *Snapshot // the latest snapshot while it ran
}

// apply runs c as one Update. m is the model before it, for what Peek
// should see.
func (h *graphSUT) apply(c commitPlan, m graphModel) applied {
	var a applied

	h.calls, h.problems = h.calls[:0], nil

	fn := func(tx *Tx) error {
		h.armed, h.readAhead, h.ahead = -1, false, 0
		if c.Kind == commitCellPanic || c.Kind == commitReadAhead {
			h.armed, h.readAhead, h.ahead = c.Cell, c.Kind == commitReadAhead, c.Ahead
		}

		staged := map[int]int{}
		h.peeks(tx, m, staged, "before its sets")

		for _, s := range c.Sets {
			Set(tx, h.ins[s.In], s.V)
			staged[s.In] = s.V
		}

		h.peeks(tx, m, staged, "after its sets")

		return c.fail()
	}

	var check func(*Snapshot) error

	if c.Kind == commitChecked || c.Kind == commitRefused {
		check = func(s *Snapshot) error {
			a.checks++
			a.built, a.inCheck = s, h.g.Snapshot()

			if c.Kind == commitRefused {
				return errRefused
			}

			return nil
		}
	}

	func() {
		defer func() { a.recovered = recover() }()

		if check == nil {
			a.snap, a.err = h.g.Update(fn)
		} else {
			a.snap, a.err = h.g.UpdateChecked(fn, check)
		}
	}()

	h.armed = -1

	return a
}

// peeks holds Peek to what the transaction sees: what it staged, otherwise
// the latest snapshot's value, which before the first is an input's initial
// value and a derived cell's zero value.
func (h *graphSUT) peeks(tx *Tx, m graphModel, staged map[int]int, when string) {
	for i, c := range h.plan.Cells {
		want, ok := staged[i]
		if !ok {
			want = m.values[i]
		}

		got := Peek(tx, h.nodes[i])
		if got == want {
			continue
		}

		// TODO(kradalby): graph/peek-first-zero: Peek in the first
		// transaction returns the zero value of an input it did not set,
		// not its initial value, which the first snapshot will hold;
		// Peek's doc names only the latest snapshot. Counted here; delete
		// with TestPeekInTheFirstUpdateSeesZero once the doc says, or Peek
		// returns the initial value.
		if m.rev == 0 && c.Input && !ok && got == 0 {
			h.excepts[excPeekFirstZero]++

			continue
		}

		h.problems = append(h.problems, fmt.Sprintf("Peek of cell %d %s: %d, want %d", i, when, got, want))
	}
}

// differs describes the first cell of s that differs from m, or "".
func (h *graphSUT) differs(s *Snapshot, m graphModel) string {
	if s == nil {
		return "no snapshot"
	}

	if s.Rev() != m.rev {
		return fmt.Sprintf("rev %d, model %d", s.Rev(), m.rev)
	}

	for i, n := range h.nodes {
		if v := s.Get(n); v != m.values[i] {
			return fmt.Sprintf("rev %d cell %d = %d, model %d", m.rev, i, v, m.values[i])
		}

		if at := ChangedAt(s, n); at != m.changed[i] {
			return fmt.Sprintf("rev %d cell %d changed at %d, model %d", m.rev, i, at, m.changed[i])
		}
	}

	return ""
}

// tally counts the shapes a run reached and the exceptions it met.
type tally map[string]int

// require fails the test for every name a run of the default length or
// longer did not reach.
func (tl tally) require(t *testing.T, names ...string) {
	t.Helper()

	var b strings.Builder
	for _, k := range slices.Sorted(maps.Keys(tl)) {
		fmt.Fprintf(&b, " %s=%d", k, tl[k])
	}

	t.Logf("reached:%s", b.String())

	if testing.Short() {
		return
	}

	for _, n := range names {
		if tl[n] == 0 {
			t.Errorf("no case reached %s", n)
		}
	}
}

// graphRun is a scenario under way: the graph, the model, and every
// snapshot published, each with the model of its revision.
type graphRun struct {
	h       *graphSUT
	m       graphModel
	history []graphModel // by revision
	held    []*Snapshot  // by revision; none at 0
	latest  *Snapshot

	// sub is open throughout: each published commit wakes it once.
	sub *Subscription
	tl  tally
}

func newGraphRun(p graphPlan, tl tally) *graphRun {
	h := newGraphSUT(p)
	m := newGraphModel(p)

	return &graphRun{h: h, m: m, history: []graphModel{m}, held: []*Snapshot{nil}, sub: h.g.Subscribe(), tl: tl}
}

// commit runs c on the graph and the model, and returns the model's outcome
// and the first way the graph departs from it, or "".
func (r *graphRun) commit(c commitPlan) (commitOutcome, string) {
	o := r.m.step(c)
	a := r.h.apply(c, r.m)

	if d := r.judge(c, o, a); d != "" {
		return o, d
	}

	r.count(c, o)

	if o.published {
		if r.latest != nil && a.snap.Time().Before(r.latest.Time()) {
			return o, fmt.Sprintf("rev %d committed before rev %d", a.snap.Rev(), r.latest.Rev())
		}

		r.m = o.next
		r.history = append(r.history, o.next)
		r.held = append(r.held, a.snap)
		r.latest = a.snap
	}

	if d := r.holds(); d != "" {
		return o, d
	}

	woken := len(r.sub.C)

	select {
	case <-r.sub.C:
	default:
	}

	if woken != b2i(o.published) {
		return o, fmt.Sprintf("a subscriber holds %d wake-ups after a commit that published %t", woken, o.published)
	}

	return o, ""
}

func b2i(b bool) int {
	if b {
		return 1
	}

	return 0
}

// judge compares what one Update did with the model's outcome.
func (r *graphRun) judge(c commitPlan, o commitOutcome, a applied) string {
	if len(r.h.problems) > 0 {
		return r.h.problems[0]
	}

	switch {
	case o.panics && a.recovered == nil:
		return "Update returned; the model says it panics"
	case !o.panics && a.recovered != nil:
		return fmt.Sprintf("Update panicked: %v", a.recovered)
	case o.panics:
		if d := panicMatches(c, a.recovered); d != "" {
			return d
		}
	}

	ran := make([]int, len(r.h.calls))
	for i, call := range r.h.calls {
		ran[i] = call.cell

		if call.prev != r.m.values[call.cell] {
			return fmt.Sprintf("cell %d computed from prev %d, model %d", call.cell, call.prev, r.m.values[call.cell])
		}
	}

	if !slices.Equal(ran, o.ran) {
		return fmt.Sprintf("computed cells %v, model %v", ran, o.ran)
	}

	if a.checks != b2i(o.checked) {
		return fmt.Sprintf("the check ran %d times, model %d", a.checks, b2i(o.checked))
	}

	if a.checks > 0 {
		if a.inCheck != r.latest {
			return "the check ran after its snapshot was published"
		}

		if d := r.h.differs(a.built, o.built); d != "" {
			return "the check saw " + d
		}
	}

	if !o.panics {
		switch {
		case !errors.Is(a.err, o.err):
			return fmt.Sprintf("Update returned %v, model %v", a.err, o.err)
		case o.published && (a.snap == nil || a.snap != r.h.g.Snapshot()):
			return "Update returned a snapshot other than the one it published"
		case !o.published && a.snap != r.latest:
			return "Update published nothing and returned a snapshot other than the latest"
		}
	}

	if !o.published && r.h.g.Snapshot() != r.latest {
		return "a commit the model publishes nothing for published a snapshot"
	}

	return ""
}

func panicMatches(c commitPlan, v any) string {
	err, _ := v.(error)

	switch c.Kind {
	case commitFnPanic:
		if errors.Is(err, errFnPanic) {
			return ""
		}
	case commitCellPanic:
		if errors.Is(err, errCellPanic) {
			return ""
		}
	case commitReadAhead:
		if s, ok := v.(string); ok && strings.HasPrefix(s, "graph: ") {
			return ""
		}
	case commitPlain, commitChecked, commitFnError, commitRefused:
	}

	return fmt.Sprintf("Update panicked with %v", v)
}

// holds checks the latest snapshot and every one published before: a
// snapshot never changes once published.
func (r *graphRun) holds() string {
	if s := r.h.g.Snapshot(); s != r.latest {
		return "the latest snapshot is not the one the last commit published"
	}

	for rev := 1; rev < len(r.held); rev++ {
		if d := r.h.differs(r.held[rev], r.history[rev]); d != "" {
			return "held " + d
		}
	}

	return ""
}

// count tallies what the commit reached.
func (r *graphRun) count(c commitPlan, o commitOutcome) {
	for _, e := range o.excepts {
		r.tl[e]++
	}

	first := r.m.rev == 0

	switch {
	case o.published && !first && len(o.ran) < len(r.m.plan.derived()):
		r.tl["computations skipped"]++
	case !o.published && !o.panics && o.err == nil && !first:
		r.tl["no-op commits"]++
	}

	if o.published {
		r.tl["published"]++

		for _, i := range o.ran {
			if !slices.Contains(o.changed, i) {
				r.tl["cutoffs"]++

				break
			}
		}

		for _, i := range o.ran {
			if !first && !slices.Equal(r.m.reads[i], o.next.reads[i]) {
				r.tl["reads moved"]++

				break
			}
		}
	}

	switch c.Kind {
	case commitCellPanic, commitReadAhead:
		if o.panics {
			r.tl[c.Kind.String()]++
		} else {
			r.tl["armed cell skipped"]++
		}
	case commitRefused:
		if o.checked {
			r.tl["refused"]++
		}
	case commitPlain, commitChecked, commitFnError, commitFnPanic:
		r.tl[c.Kind.String()]++
	}
}

// finish checks what holds once the commits are done: registration is
// closed once a snapshot is published, and two snapshots reporting the
// same change revision of a cell hold values its equality calls equal.
func (r *graphRun) finish() string {
	for k, n := range r.h.excepts {
		r.tl[k] += n
	}

	r.sub.Close()
	r.sub.Close()

	refused := false

	func() {
		defer func() { refused = recover() != nil }()

		r.h.g.NewInput("late", 0, Same[int])
	}()

	if refused != (r.m.rev > 0) {
		return fmt.Sprintf("registering after %d published snapshots panicked: %t", r.m.rev, refused)
	}

	for i, n := range r.h.nodes {
		eq := r.m.plan.Cells[i].Eq

		for rev := 2; rev < len(r.held); rev++ {
			s, before := r.held[rev], r.held[rev-1]
			if ChangedAt(s, n) != ChangedAt(before, n) {
				continue
			}

			v, w := s.Get(n), before.Get(n)
			if v != w && !eq.equal(v, w) {
				return fmt.Sprintf("cell %d holds %d at rev %d and %d at rev %d, both changed at %d", i, w, rev-1, v, rev, ChangedAt(s, n))
			}

			// TODO(kradalby): graph/changedat-values: ChangedAt's doc says
			// two snapshots reporting the same revision hold the same value;
			// they hold values the cell's equality calls equal, and a
			// derived cell stores each new one. Counted here; delete with
			// TestChangedAtSpansValuesItsEqualityCallsEqual once the doc
			// says equal.
			if v != w {
				r.tl[excChangedAtValues]++
			}
		}
	}

	return ""
}

// TestGraphMatchesFromScratch runs drawn commits on drawn graphs and holds
// the graph after each to graphModel, which recomputes every cell from
// scratch at every commit and shares with the package only the cells'
// functions. It holds every cell's value and change revision; which cells
// compute in each commit, in order, at most once, and from which prev;
// what Peek sees; what Update returns and whether it panics; whether the
// check runs and sees what would be published; that a refused, failed or
// empty commit publishes and wakes nothing; that no published snapshot
// ever changes; and that registration closes at the first publication.
func TestGraphMatchesFromScratch(t *testing.T) {
	tl := tally{}

	rapid.Check(t, func(t *rapid.T) {
		sc := scenarios(defaultSizes).Draw(t, "scenario")
		r := newGraphRun(sc.Graph, tl)

		for k, c := range sc.Commits {
			if _, d := r.commit(c); d != "" {
				t.Fatalf("commit %d %s: %s", k, c, d)
			}
		}

		if d := r.finish(); d != "" {
			t.Fatal(d)
		}
	})

	tl.require(t, "published", "computations skipped", "cutoffs", "reads moved", "no-op commits", "refused",
		"cell-panic", "read-ahead", "armed cell skipped", "fn-error", "fn-panic", "checked")
}

// subModel is a subscriber as the model sees it: whether a wake-up is
// pending, and the snapshot it read last.
type subModel struct {
	sub     *Subscription
	open    bool
	pending bool
	last    *Snapshot
}

func (r *graphRun) subscribe() *subModel {
	return &subModel{sub: r.h.g.Subscribe(), open: true, last: r.h.g.Snapshot()}
}

func revOf(s *Snapshot) uint64 {
	if s == nil {
		return 0
	}

	return s.Rev()
}

// consume takes a pending wake-up, if any, and diffs the latest snapshot
// against the one sm read last: every cell a commit between them changed
// reports a later change revision, and every other holds a value its
// equality calls equal.
func (r *graphRun) consume(i int, sm *subModel) string {
	woken := false

	select {
	case <-sm.sub.C:
		woken = true
	default:
	}

	if woken != sm.pending {
		return fmt.Sprintf("subscriber %d woken %t, model %t", i, woken, sm.pending)
	}

	if !woken {
		return ""
	}

	sm.pending = false
	s, from := r.h.g.Snapshot(), revOf(sm.last)

	if s.Rev() <= from {
		return fmt.Sprintf("subscriber %d woken at rev %d, having read %d", i, s.Rev(), from)
	}

	for c, n := range r.h.nodes {
		moved := false
		for rev := from + 1; rev <= s.Rev(); rev++ {
			moved = moved || r.history[rev].changed[c] == rev
		}

		if got := ChangedAt(s, n) > from; got != moved {
			return fmt.Sprintf("subscriber %d diffing rev %d against %d: cell %d changed %t, model %t", i, s.Rev(), from, c, got, moved)
		}

		if moved || sm.last == nil {
			continue
		}

		if v, w := s.Get(n), sm.last.Get(n); v != w && !r.m.plan.Cells[c].Eq.equal(v, w) {
			return fmt.Sprintf("subscriber %d: cell %d moved from %d to %d between rev %d and %d unreported", i, c, w, v, from, s.Rev())
		}
	}

	sm.last = s

	return ""
}

// TestSubscriptionsSeeEveryCommit interleaves drawn subscriber events
// (take a wake-up, subscribe, close) with a scenario's commits. A
// subscriber holds a wake-up exactly when a commit published after it last
// took one and before it closed, never more than one; the snapshot it then
// reads is later than the one it read last, and diffing the two through
// ChangedAt names exactly the cells the commits between them changed.
func TestSubscriptionsSeeEveryCommit(t *testing.T) {
	tl := tally{}

	rapid.Check(t, func(t *rapid.T) {
		s := subSchedules(defaultSizes).Draw(t, "schedule")
		r := newGraphRun(s.Scenario.Graph, tl)
		subs := []*subModel{r.subscribe()}

		hold := func(when string) {
			for i, sm := range subs {
				if n := len(sm.sub.C); n != b2i(sm.pending) {
					t.Fatalf("%s: subscriber %d holds %d wake-ups, model %d", when, i, n, b2i(sm.pending))
				}
			}
		}

		for k, evs := range s.Events {
			for _, e := range evs {
				switch e.Kind {
				case subSubscribe:
					subs = append(subs, r.subscribe())
				case subClose:
					subs[e.Sub].sub.Close()
					subs[e.Sub].open = false
					tl["closed"]++
				case subConsume:
					if subs[e.Sub].pending {
						tl["woken"]++

						if revOf(r.latest)-revOf(subs[e.Sub].last) > 1 {
							tl["coalesced"]++
						}
					}

					if d := r.consume(e.Sub, subs[e.Sub]); d != "" {
						t.Fatalf("before commit %d: %s", k, d)
					}
				}

				hold(fmt.Sprintf("before commit %d, after %s", k, e))
			}

			if k == len(s.Scenario.Commits) {
				break
			}

			c := s.Scenario.Commits[k]

			o, d := r.commit(c)
			if d != "" {
				t.Fatalf("commit %d %s: %s", k, c, d)
			}

			for _, sm := range subs {
				sm.pending = sm.pending || sm.open && o.published
			}

			hold(fmt.Sprintf("after commit %d", k))
		}

		if d := r.finish(); d != "" {
			t.Fatal(d)
		}
	})

	tl.require(t, "woken", "coalesced", "closed")
}

// observation is what a reader read of one snapshot.
type observation struct {
	rev     uint64
	values  []int
	changed []uint64
}

func observe(s *Snapshot, nodes []Node[int]) observation {
	o := observation{rev: s.Rev(), values: make([]int, len(nodes)), changed: make([]uint64, len(nodes))}
	for i, n := range nodes {
		o.values[i], o.changed[i] = s.Get(n), ChangedAt(s, n)
	}

	return o
}

func (o observation) equal(p observation) bool {
	return o.rev == p.rev && slices.Equal(o.values, p.values) && slices.Equal(o.changed, p.changed)
}

// readSnapshots reads whatever snapshot is latest until stop, and re-reads
// one it holds after each new one, and returns what it read of each.
func readSnapshots(g *Graph, nodes []Node[int], stop <-chan struct{}, report func(string)) []observation {
	var (
		log  []observation
		held []*Snapshot
		last uint64
	)

	for {
		select {
		case <-stop:
			return log
		default:
		}

		s := g.Snapshot()
		if s == nil || s.Rev() == last {
			runtime.Gosched()

			continue
		}

		if s.Rev() < last {
			report(fmt.Sprintf("read rev %d after %d", s.Rev(), last))

			return log
		}

		log = append(log, observe(s, nodes))
		held = append(held, s)
		last = s.Rev()

		k := len(held) / 2
		if o := observe(held[k], nodes); !o.equal(log[k]) {
			report(fmt.Sprintf("rev %d changed while held", o.rev))

			return log
		}
	}
}

// TestSnapshotsHoldUnderConcurrentReaders runs a scenario's commits while
// readers in other goroutines read whatever snapshot is latest, and re-read
// ones they hold, and subscribers take wake-ups, some closing and
// subscribing again after each. Every snapshot a reader sees is the model's
// at its revision and never changes under it; revisions never go back; and
// every subscriber reaches the last commit. Run it under the race detector:
// the package promises its snapshots safe for concurrent reads.
func TestSnapshotsHoldUnderConcurrentReaders(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sc := scenarios(defaultSizes).Draw(t, "scenario")
		readers := 1 + rapid.IntRange(0, 2).Draw(t, "readers")
		subscribers := rapid.IntRange(0, 2).Draw(t, "subscribers")
		churn := chance(t, 3, "churn")

		r := newGraphRun(sc.Graph, tally{})
		g, nodes := r.h.g, r.h.nodes

		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			problems []string
			final    uint64
		)

		report := func(format string, args ...any) {
			mu.Lock()

			problems = append(problems, fmt.Sprintf(format, args...))

			mu.Unlock()
		}

		stop, done := make(chan struct{}), make(chan struct{})
		logs := make([][]observation, readers)

		for i := range readers {
			wg.Go(func() { logs[i] = readSnapshots(g, nodes, stop, func(msg string) { report("reader %d: %s", i, msg) }) })
		}

		for i := range subscribers {
			wg.Go(func() {
				sub := g.Subscribe()
				defer func() { sub.Close() }()

				last := revOf(g.Snapshot())
				read := func() bool {
					s := g.Snapshot()
					if revOf(s) < last {
						report("subscriber %d read rev %d after %d", i, revOf(s), last)

						return false
					}

					last = revOf(s)

					return true
				}

				for {
					select {
					case <-sub.C:
						if !read() {
							return
						}

						if churn {
							sub.Close()
							sub = g.Subscribe()

							if !read() {
								return
							}
						}
					case <-done:
						if last == final {
							return
						}

						// The last commit's wake-up is pending, or was taken
						// before a read that saw it.
						select {
						case <-sub.C:
							if read() && last != final {
								report("subscriber %d woken after the last commit reads rev %d of %d", i, last, final)
							}
						case <-time.After(10 * time.Second):
							report("subscriber %d stuck at rev %d of %d", i, last, final)
						}

						return
					}
				}
			})
		}

		var failed string

		for k, c := range sc.Commits {
			if _, d := r.commit(c); d != "" {
				failed = fmt.Sprintf("commit %d %s: %s", k, c, d)

				break
			}

			runtime.Gosched()
		}

		// What the graph published, which after a failed commit is not the
		// model's: subscribers wait for it.
		final = revOf(g.Snapshot())

		close(done)
		close(stop)
		wg.Wait()

		if failed != "" {
			t.Fatal(failed)
		}

		if len(problems) > 0 {
			t.Fatal(problems[0])
		}

		for i, log := range logs {
			for _, o := range log {
				if want := observe(r.held[o.rev], nodes); !o.equal(want) || r.h.differs(r.held[o.rev], r.history[o.rev]) != "" {
					t.Fatalf("reader %d read rev %d as %v, model %v", i, o.rev, o.values, r.history[o.rev].values)
				}
			}
		}
	})
}

// inconsistent describes the first cell of o whose value is not what its
// function gives over the cells it reads in o, or "". It judges only cells
// that carry no state, through any read: the others hold what the order of
// commits made them.
func inconsistent(p graphPlan, o observation) string {
	pure := make([]bool, len(p.Cells))

	for i, c := range p.Cells {
		pure[i] = c.Input || !c.Op.carries() && !slices.ContainsFunc(c.Reads, func(d int) bool { return !pure[d] })

		if o.changed[i] > o.rev || o.changed[i] == 0 {
			return fmt.Sprintf("rev %d cell %d changed at %d", o.rev, i, o.changed[i])
		}

		if c.Input || !pure[i] {
			continue
		}

		if want := c.eval(0, func(d int) int { return p.Cells[d].Eq.view(o.values[d]) }); o.values[i] != want {
			return fmt.Sprintf("rev %d cell %d = %d over its reads, which give %d", o.rev, i, o.values[i], want)
		}
	}

	return ""
}

// TestConcurrentWritersPublishWholeSnapshots publishes a graph, then runs
// two writers at once, each committing to the inputs it owns, while
// readers read. No order of their commits is the model's, so it holds what
// every order shares: each snapshot a writer gets back or a reader reads
// holds every stateless cell at what its function gives over that same
// snapshot; revisions a writer gets back only grow; each writer's commits
// publish, fail and are refused as a model of it alone says; and the last
// snapshot holds each writer's inputs as it left them, one revision per
// published commit.
func TestConcurrentWritersPublishWholeSnapshots(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := writersPlans(defaultSizes).Draw(t, "plan")
		h := newGraphSUT(p.Graph)

		_, err := h.g.Update(func(*Tx) error { return nil })
		if err != nil {
			t.Fatal(err)
		}

		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			problems []string
			models   [2]graphModel
			got      [2][]observation
		)

		report := func(format string, args ...any) {
			mu.Lock()

			problems = append(problems, fmt.Sprintf(format, args...))

			mu.Unlock()
		}

		stop := make(chan struct{})

		var logs []observation

		wg.Go(func() { logs = readSnapshots(h.g, h.nodes, stop, func(msg string) { report("reader: %s", msg) }) })

		var writers sync.WaitGroup

		for w, commits := range p.Commits {
			writers.Go(func() {
				m := newGraphModel(p.Graph).step(commitPlan{}).next
				last := uint64(1)

				for k, c := range commits {
					o := m.step(c)

					fn := func(tx *Tx) error {
						for _, s := range c.Sets {
							Set(tx, h.ins[s.In], s.V)
						}

						return c.fail()
					}

					check := func(*Snapshot) error {
						if c.Kind == commitRefused {
							return errRefused
						}

						return nil
					}

					var (
						s         *Snapshot
						err       error
						recovered any
					)

					func() {
						defer func() { recovered = recover() }()

						s, err = h.g.UpdateChecked(fn, check)
					}()

					switch {
					case (recovered != nil) != o.panics:
						report("writer %d commit %d %s: panicked with %v, model %t", w, k, c, recovered, o.panics)

						return
					case o.panics:
					case !errors.Is(err, o.err):
						report("writer %d commit %d %s: returned %v, model %v", w, k, c, err, o.err)

						return
					case o.published && s.Rev() <= last:
						report("writer %d commit %d %s: published rev %d after %d", w, k, c, s.Rev(), last)

						return
					case o.published:
						last = s.Rev()
						got[w] = append(got[w], observe(s, h.nodes))
					}

					m = o.next

					runtime.Gosched()
				}

				models[w] = m
			})
		}

		writers.Wait()
		close(stop)
		wg.Wait()

		if len(problems) > 0 {
			t.Fatal(problems[0])
		}

		final := observe(h.g.Snapshot(), h.nodes)
		published := uint64(1)

		for w, m := range models {
			published += m.rev - 1

			for _, in := range p.Graph.owned(w) {
				if final.values[in] != m.values[in] {
					t.Fatalf("writer %d left input %d at %d; the last snapshot holds %d", w, in, m.values[in], final.values[in])
				}
			}
		}

		if final.rev != published {
			t.Fatalf("last snapshot rev %d after %d published commits", final.rev, published)
		}

		for _, o := range slices.Concat(logs, got[0], got[1], []observation{final}) {
			if d := inconsistent(p.Graph, o); d != "" {
				t.Fatal(d)
			}
		}
	})
}

// TestInputKeepsAValueItsEqualityCallsEqual pins graph/input-equal-kept:
// an input set to a value its equality calls equal keeps the value it held,
// even when the commit publishes for another input, where a derived cell
// computing a value its equality calls equal stores it.
func TestInputKeepsAValueItsEqualityCallsEqual(t *testing.T) {
	tens := func(a, b int) bool { return a/10 == b/10 }

	g := New()
	a := g.NewInput("a", 1, tens)
	b := g.NewInput("b", 1, Same[int])
	d := NewDerived(g, "d", tens, func(s *Snapshot, _ int) int { return s.Get(b) })

	_, _ = g.Update(func(*Tx) error { return nil })

	s, err := g.Update(func(tx *Tx) error {
		Set(tx, a, 3)
		Set(tx, b, 3)

		return nil
	})
	if err != nil || s.Rev() != 2 {
		t.Fatalf("rev %d, %v", s.Rev(), err)
	}

	if s.Get(d) != 3 {
		t.Fatalf("derived cell holds %d, want the equal value 3 it computed", s.Get(d))
	}

	if s.Get(a) != 1 {
		t.Fatalf("input holds %d: it now stores a value its equality calls equal; see graph/input-equal-kept", s.Get(a))
	}
}

// TestPeekInTheFirstUpdateSeesZero pins graph/peek-first-zero: before the
// first snapshot Peek returns an input's zero value, not the initial value
// the first snapshot holds.
func TestPeekInTheFirstUpdateSeesZero(t *testing.T) {
	g := New()
	a := g.NewInput("a", 7, Same[int])

	var peeked int

	s, _ := g.Update(func(tx *Tx) error {
		peeked = Peek(tx, a)

		return nil
	})
	if s.Get(a) != 7 {
		t.Fatalf("first snapshot holds %d, want 7", s.Get(a))
	}

	if peeked != 0 {
		t.Fatalf("Peek in the first update = %d: it now sees the initial value; see graph/peek-first-zero", peeked)
	}
}

// TestChangedAtSpansValuesItsEqualityCallsEqual pins graph/changedat-values:
// a derived cell stores a new value its equality calls equal without moving
// its change revision, so two snapshots reporting the same revision hold
// different values.
func TestChangedAtSpansValuesItsEqualityCallsEqual(t *testing.T) {
	g := New()
	a := g.NewInput("a", 0, Same[int])
	d := NewDerived(g, "d", func(x, y int) bool { return x/10 == y/10 }, func(s *Snapshot, _ int) int { return s.Get(a) })

	s1, _ := g.Update(func(*Tx) error { return nil })
	s2, _ := g.Update(func(tx *Tx) error { Set(tx, a, 2); return nil })

	if ChangedAt(s1, d) != ChangedAt(s2, d) {
		t.Fatalf("change revision moved from %d to %d", ChangedAt(s1, d), ChangedAt(s2, d))
	}

	if s1.Get(d) == s2.Get(d) {
		t.Fatalf("both hold %d: see graph/changedat-values", s1.Get(d))
	}
}
