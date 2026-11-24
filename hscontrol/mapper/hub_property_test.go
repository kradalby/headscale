package mapper

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

// watchAt names where a stepped watcher is.
type watchAt int

const (
	// watchIdle: waiting on its subscription, nothing to route.
	watchIdle watchAt = iota
	// watchLoad: about to load the latest snapshot and route to it.
	watchLoad
	// watchShard: the routing has moved every shard up to shard on and
	// holds shard's lock.
	watchShard
	// watchRouted: the routing moved every shard, advanced the caches,
	// ended the sessions of deleted nodes and woke what it reached.
	watchRouted
)

type watchPoint struct {
	at       watchAt
	shard    int
	from, to uint64
	between  int
}

func (p watchPoint) String() string {
	switch p.at {
	case watchLoad:
		return "load"
	case watchShard:
		return fmt.Sprintf("shard %d", p.shard)
	case watchRouted:
		return fmt.Sprintf("routed r%d→r%d", p.from, p.to)
	case watchIdle:
	}

	return "idle"
}

// steppedWatcher runs the hub's own watcher, [Hub.Watch]'s goroutine, one
// point at a time. The hub's test hooks hand control to the test at each
// point and wait for it to be handed back, so the watcher and the test
// goroutine never run at once and which runs between two points is the
// test's choice. The points are before the watcher loads a snapshot
// (beforeRoute), after it visited a shard the test marks (the render log's
// routingDrained, under that shard's lock) and once it woke what the
// routing reached (routed). Shard 0 and the last shard are always marked
// and hold no session (see [hubMachine.admit]): stopped there, the routing
// has loaded and computed its answer but visited no session's shard, or
// visited every one but advanced nothing and woken nobody.
//
// Commits wake the watcher through a subscription holding one wake-up.
// Between routings the watcher waits at routed rather than on its
// subscription, so the commits of a State call, however many, land while
// nothing takes their wake-ups and coalesce into one the test hands it;
// it is parked there once at the start.
type steppedWatcher struct {
	t      pbtT
	h      *Hub
	s      *state.State
	at     watchPoint
	parked chan watchPoint
	resume chan struct{}
	quit   chan struct{}

	mu     sync.Mutex
	waitAt map[int]bool

	// token is set by a commit the watcher has not taken the wake-up of.
	token bool
	// held is set while it is idle at routed, its goroutine parked.
	held bool
	// loaded is what the routing in progress loaded; routed what the last
	// one routed to.
	loaded, routed *state.Snapshot

	// decided, when set, runs where a render's end has decided, if the
	// render's shard is not locked there.
	decided func(sh *renderShard)
}

func newSteppedWatcher(t pbtT, h *Hub, s *state.State) *steppedWatcher {
	w := &steppedWatcher{
		t: t, h: h, s: s,
		parked: make(chan watchPoint), resume: make(chan struct{}), quit: make(chan struct{}),
		waitAt: map[int]bool{0: true, renderShards - 1: true},
	}

	h.beforeRoute = func() { w.park(watchPoint{at: watchLoad}) }
	h.routed = func(from, to uint64, between int) {
		w.park(watchPoint{at: watchRouted, from: from, to: to, between: between})
	}
	h.renders.hook = func(p renderPoint, sh *renderShard) {
		switch p {
		case routingDrained:
			i := shardIndex(h, sh)

			w.mu.Lock()
			wait := w.waitAt[i]
			w.mu.Unlock()

			if wait {
				w.park(watchPoint{at: watchShard, shard: i})
			}
		case renderDecided:
			if w.decided != nil && shardFree(sh) {
				w.decided(sh)
			}
		}
	}

	h.Watch(s)
	w.routed = s.Snapshot()

	t.Cleanup(func() {
		close(w.quit)
		h.Close()
	})

	// A DERP region in and out again parks the goroutine at routed before
	// any write it is to route.
	dm := s.DERPMap().AsStruct()
	other := &tailcfg.DERPMap{Regions: maps.Clone(dm.Regions)}
	other.Regions[901] = &tailcfg.DERPRegion{RegionID: 901}

	for _, m := range []*tailcfg.DERPMap{other, dm} {
		before := s.Snapshot().Rev()
		s.SetDERPMap(m)
		w.committed(before)
		w.settle()
	}

	return w
}

func shardIndex(h *Hub, sh *renderShard) int {
	for i := range h.renders.shards {
		if &h.renders.shards[i] == sh {
			return i
		}
	}

	return -1
}

// shardFree reports whether sh's lock is free: a render can end there now.
func shardFree(sh *renderShard) bool {
	if sh.mu.TryLock() {
		sh.mu.Unlock()

		return true
	}

	return false
}

// park runs on the watcher: it reports p and waits for the test.
func (w *steppedWatcher) park(p watchPoint) {
	select {
	case w.parked <- p:
	case <-w.quit:
		return
	}

	select {
	case <-w.resume:
	case <-w.quit:
	}
}

// await takes the watcher's next point; the timer only guards a hang.
func (w *steppedWatcher) await() {
	w.t.Helper()

	select {
	case p := <-w.parked:
		w.at = p
	case <-time.After(time.Minute):
		w.t.Fatalf("the watcher did not reach a point after %s", w.at)
	}

	switch w.at.at {
	case watchLoad:
		// It took its subscription's wake-up just before.
		w.token = false
	case watchRouted:
		if w.at.from != w.routed.Rev() || w.at.to != w.loaded.Rev() {
			w.t.Fatalf("the watcher routed r%d→r%d, expected r%d→r%d", w.at.from, w.at.to, w.routed.Rev(), w.loaded.Rev())
		}

		w.routed = w.loaded
	case watchIdle, watchShard:
	}
}

// committed is [pbtWorld.committed]: a write moved the world from
// revision before.
func (w *steppedWatcher) committed(before uint64) {
	w.t.Helper()

	switch rev := w.s.Snapshot().Rev(); {
	case rev == before:
	case w.at.at == watchIdle && !w.held && rev > before+1:
		w.t.Fatalf("one State call committed %d times before the watcher first routed", rev-before)
	case w.at.at == watchIdle:
		if w.held {
			w.held = false
			w.resume <- struct{}{}
		}

		w.await()

		if w.at.at != watchLoad {
			w.t.Fatalf("a commit woke the watcher at %s", w.at)
		}
	default:
		w.token = true
	}
}

// step moves the watcher to its next point, or to idle; false when it was
// idle already.
func (w *steppedWatcher) step() bool {
	w.t.Helper()

	at := w.at.at
	if at == watchIdle {
		return false
	}

	if at == watchLoad {
		// Nothing commits before the watcher loads: the test is waiting.
		w.loaded = w.s.Snapshot()
	}

	if at == watchRouted && !w.token {
		w.at, w.held = watchPoint{}, true

		return true
	}

	w.resume <- struct{}{}

	w.await()

	return true
}

// routing reports whether a routing is part way through its shards.
func (w *steppedWatcher) routing() bool { return w.at.at == watchShard }

// finish ends the routing in progress, if any, and leaves the watcher
// idle or about to load.
func (w *steppedWatcher) finish() {
	for w.at.at == watchLoad || w.at.at == watchShard {
		w.step()
	}

	if w.at.at == watchRouted {
		w.step()
	}
}

// settle routes until the watcher is idle.
func (w *steppedWatcher) settle() {
	for w.step() {
	}
}

// wait sets the shards the watcher stops at besides the first and last.
func (w *steppedWatcher) wait(shards map[int]bool) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.waitAt = map[int]bool{0: true, renderShards - 1: true}
	for i := range shards {
		w.waitAt[i] = true
	}
}

var errInjected = errors.New("injected render failure")

// hubSess is one session of [hubMachine], driven by the test goroutine as
// poll drives it: it takes a wake, takes the latest snapshot, renders and
// ends the render, and between taking and ending anything may happen.
type hubSess struct {
	n      int
	id     types.NodeID
	st     *Stream
	sess   *Session
	capVer tailcfg.CapabilityVersion
	client *modelClient
	// first is set until its first map rendered.
	first bool
	// took is the snapshot of the render in flight.
	took *state.Snapshot
	// last is what its last render rendered, or failed to; ok whether it
	// succeeded.
	last *state.Snapshot
	ok   bool
	// ended is set when the hub ended it (its node deleted).
	ended atomic.Bool
	// held is the routed revision and map last found fresh, so a check
	// renders afresh only when either moved.
	held struct {
		rev uint64
		nm  *netMap
	}
}

func (s *hubSess) String() string { return fmt.Sprintf("s%d(n%d)", s.n, s.id) }

func (s *hubSess) shard(h *Hub) *renderShard { return h.renders.shard(s.sess) }

// hubMachine drives the real hub, its watcher stepped, against a State
// written from a generated world, with sessions run by the test.
type hubMachine struct {
	t     *rapid.T
	p     *pbtWorld
	w     *steppedWatcher
	h     *Hub
	sess  []*hubSess
	n     int
	touch int
	mixed bool
	// undo takes the last write back, when there is a write that does.
	undo  func()
	reach *hubPropertyReach
	// audit is set when the route audit runs, after every routing: it
	// must hold no session it did not wake to the routing's end in vain.
	audit   bool
	audited uint64
	// audits holds what every audit logs while audit is set (see
	// [auditLines.judge]).
	audits *auditLines
	// kind names the last commit's write, for what woke renders after it.
	kind string
	// script holds the acts of the script in progress (see [drawScript]),
	// played one commit event at a time.
	script     []scriptAct
	scriptName string
	// dropped is Route's answers with each part taken out, by pair.
	dropped droppedWakes
}

// hubPropertyReach counts the windows the schedules reached.
type hubPropertyReach struct {
	coalesced, logWoke, endWoke, endedPast, endedMidRouting, retried, firstNewer, decidedRouting int
	events                                                                                       map[string]int
	// wakes counts what woke each render that sent something.
	wakes *wakeTally
}

func (r hubPropertyReach) String() string {
	return fmt.Sprintf("coalesced routings %d, render-log wakes by a routing %d, by a render's end %d, renders ended past a routing %d, ended mid-routing %d, failures retried %d, first maps of a newer snapshot %d; events %v; renders that sent something: %s",
		r.coalesced, r.logWoke, r.endWoke, r.endedPast, r.endedMidRouting, r.retried, r.firstNewer, r.events, r.wakes)
}

// TestHubSessionsConvergeUnderDrawnSchedules drives the real hub — its
// watcher goroutine, the render log and [Route] — through schedules rapid
// draws, one event at a time, so every interleaving replays and shrinks.
//
// It draws a world from policymodel and filter_chunks, then events: a
// commit (a policymodel step, its edits one commit each; a node's
// endpoint write, which names only it and its readers; a write a client,
// the HA prober or an operator makes through its production entry point;
// a script's next move, its setup played when it is drawn); the watcher
// moving to its next point (load, after a session's shard, routed); a
// session taking its wake and the latest snapshot; a session ending its
// render, which may fail (a failure no snapshot explains, as Update's
// error path ends it); a node's session admitted, its first map rendered
// later; a session leaving or reconnecting; a node with a session opening
// another, as a reconnect that overlaps its old stream does. Sessions end renders only where their shard's lock is
// free; at the point a render's end decides, if its shard's lock were free
// there (it is not), the watcher could finish a routing.
//
// It judges by rendering afresh, never by reading the hub's bookkeeping:
// whenever no routing is part way, every live session that is not
// rendering and has no wake pending, and whose last render is of a
// snapshot older than the last routing's end R, must have succeeded and
// hold what a fresh render of R gives. At the end every session settles
// (renders it is woken for; one more commit retries a failure) and must
// hold the latest snapshot's fresh render. Each render that succeeds must
// equal a fresh render of what it rendered, and the responses it returned,
// applied to what the client held, must give a fresh session's client.
//
// With the policy audit on (one subtest, capability mode), the hub's own
// route audit runs after every routing and must find no session it holds
// to the routing's end stale: a session the render log woke again is due.
// No audit may log anything else either.
//
// What it cannot see: data races (the handoffs order everything; the
// stress test runs under -race); preemption inside a render or between a
// render's end and its wake; orderings inside one shard's visit.
func TestHubSessionsConvergeUnderDrawnSchedules(t *testing.T) {
	t.Setenv(state.TestFilterChunksEnv, "false")

	for _, mode := range []struct {
		name              string
		capSources, audit bool
	}{{"capability=false", false, false}, {"capability=true", true, false}, {"audit/capability=true", true, true}} {
		t.Run(mode.name, func(t *testing.T) {
			envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", strconv.FormatBool(mode.audit))
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(mode.capSources))

			reach := hubPropertyReach{events: map[string]int{}, wakes: newWakeTally()}

			var audits *auditLines
			if mode.audit {
				audits = watchAudits(t)
			}

			rapid.Check(t, func(t *rapid.T) { runHubMachine(t, &reach, audits) })

			t.Log(reach)

			if !testing.Short() && !mode.audit {
				floors := map[string]int{
					"coalesced": reach.coalesced, "endedPast": reach.endedPast,
					"endedMidRouting": reach.endedMidRouting, "second sessions": reach.events["second session"],
				}

				// Render-log wakes and retried failures come from few
				// schedules, so a run of the default length can meet
				// none; deep runs alone are asked for them.
				if f := flag.Lookup("rapid.checks"); f != nil {
					n, err := strconv.Atoi(f.Value.String())
					if err == nil && n >= 1000 {
						floors["render-log wakes"], floors["retried"] = reach.logWoke+reach.endWoke, reach.retried
					}
				}

				for name, n := range floors {
					if n == 0 {
						t.Errorf("no schedule reached %s", name)
					}
				}
			}
		})
	}
}

func runHubMachine(t *rapid.T, reach *hubPropertyReach, audits *auditLines) {
	// What a failed case logged after its failure is not this case's.
	audits.take()

	world := policymodel.Worlds().Draw(t, "world")
	mixed := pbtChance(t, 4, "mixed-versions")

	m := &hubMachine{t: t, mixed: mixed, reach: reach, audit: audits != nil, audited: RouteAuditFailures(), audits: audits, dropped: droppedWakes{}}
	m.p = newDrawnWorld(t, world)
	m.h = NewHub()
	m.w = newSteppedWatcher(t, m.h, m.p.s)
	m.p.committed = func(before uint64) {
		m.w.committed(before)
	}
	m.w.decided = func(*renderShard) {
		// Only a render deciding outside its shard's lock gets here, and
		// only a routing to come can run there.
		if m.w.at.at != watchIdle && pbtChance(t, 2, "route-at-decision") {
			t.Logf("a routing at the point a render's end decided")
			m.w.finish()

			m.reach.decidedRouting++
		}
	}

	for _, n := range m.p.s.Snapshot().ListNodes().All() {
		s := m.admit(n.ID())
		m.take(s)
		m.finish(s, true)
	}

	count := func(name string, f func(*rapid.T)) func(*rapid.T) {
		return func(t *rapid.T) {
			f(t)

			m.reach.events[name]++
		}
	}

	// Keys sort into rapid's choice of action, which favours the first and
	// the last: a routing takes several watcher steps.
	t.Repeat(map[string]func(*rapid.T){
		"advance":  count("advance", m.advance),
		"advance2": count("advance", m.advance),
		"advance3": count("advance", m.advance),
		"commit":   count("commit", m.commit),
		"commit2":  count("commit", m.commit),
		"finish":   count("finish", m.finishAny),
		"finish2":  count("finish", m.finishAny),
		"finish3":  count("finish", m.finishAny),
		"session":  count("session", m.session),
		"take":     count("take", m.takeAny),
		"":         m.check,
	})

	m.settle()

	for k, n := range m.p.made {
		m.reach.events["write "+k] += n
	}

	if slices.ContainsFunc(m.sess, func(s *hubSess) bool { return !s.ok }) {
		// A failure no snapshot explains is retried at the next routing,
		// whatever it names.
		m.touchNode(m.p.s.Snapshot().ListNodes().At(0).ID())
		m.settle()
	}

	latest := m.p.s.Snapshot()
	if m.w.routed.Rev() != latest.Rev() {
		t.Fatalf("settled with the watcher at r%d, latest r%d", m.w.routed.Rev(), latest.Rev())
	}

	fresh := latest.Uncached()

	for _, s := range m.sess {
		if !s.ok {
			t.Fatalf("%s settled on a failed render of r%d", s, s.last.Rev())
		}

		out, err := freshDiff(m.p.cfg, fresh, s.id, s.capVer, s.st.sent, &versionCache{})
		if err != nil {
			t.Fatalf("%s: rendering r%d afresh: %v", s, latest.Rev(), err)
		}

		if len(out) > 0 {
			t.Fatalf("settled: %s holds a stale map, its last render r%d, latest r%d: %s", s, s.last.Rev(), latest.Rev(), describeResponses(out))
		}
	}

	if msg := m.audits.judge(); msg != "" {
		t.Fatalf("settled: an audit objects: %s", msg)
	}
}

// admit opens a session of id, its first map to be rendered.
func (m *hubMachine) admit(id types.NodeID) *hubSess {
	m.h.mu.Lock()
	next := m.h.core.admitted + 1
	m.h.mu.Unlock()

	// Keep the first and last shard free of sessions, see [steppedWatcher].
	for next%renderShards == 0 || next%renderShards == renderShards-1 {
		m.h.Leave(m.h.Join(1<<40, func() {}))

		next++
	}

	m.n++
	s := &hubSess{n: m.n, id: id, first: true, capVer: capVer}

	if m.mixed && id%2 == 1 {
		s.capVer = capver.MinSupportedCapabilityVersion
	}

	s.sess = m.h.Join(id, func() { s.ended.Store(true) })
	s.st = NewStream(m.p.cfg, m.h, id, s.capVer)
	s.st.Attach(s.sess)

	m.sess = append(m.sess, s)
	m.shards()
	m.t.Logf("%s admitted", s)

	return s
}

// shards marks for the watcher to stop at the shards of the sessions
// rendering: only they can end a render on either side of their shard's
// visit.
func (m *hubMachine) shards() {
	at := map[int]bool{}

	for _, s := range m.sess {
		if s.took != nil {
			at[shardIndex(m.h, s.shard(m.h))] = true
		}
	}

	m.w.wait(at)
}

func (m *hubMachine) drop(s *hubSess) {
	m.h.Leave(s.sess)
	m.sess = slices.DeleteFunc(m.sess, func(o *hubSess) bool { return o == s })
	m.shards()
}

// reap drops the sessions the hub ended that are not rendering, as poll's
// loop returns on stop.
func (m *hubMachine) reap() {
	for _, s := range slices.Clone(m.sess) {
		if s.ended.Load() && s.took == nil {
			m.t.Logf("%s ended by the hub", s)
			m.drop(s)
		}
	}
}

// commit lands a write: a policymodel step, its edits a commit each; a
// node's endpoint, which names it and its readers; or, now and then, the
// last write taken back, so a change and its reversal can fall between
// two routings. A step taken back at once ("flash"), or a node that joins
// and leaves ("transient"), lets sessions woken before take a snapshot
// holding it in between: the shape only the render log can wake them for,
// a routing's two ends having neither.
func (m *hubMachine) commit(t *rapid.T) {
	undo := pbtChance(t, 2, "undo")
	step := !pbtChance(t, 3, "endpoint")
	flash := pbtChance(t, 2, "flash")
	transient := pbtChance(t, 3, "transient")
	scripted := pbtChance(t, 2, "script-act")
	session := pbtChance(t, 4, "session-write")
	nodes := m.p.s.Snapshot().ListNodes()
	before := m.p.s.Snapshot().Rev()

	switch {
	case scripted && len(m.script) > 0:
		// A script's next act, so its steps can fall between routings or
		// inside one, and its viewer read before or after; one the writes
		// since made a refused write ends the script.
		a := m.script[0]
		m.script = m.script[1:]

		if !a.accepted(m.p.w) {
			t.Logf("script %s ends: its next write is refused now", m.scriptName)
			m.script = nil

			return
		}

		m.kind = "script " + m.scriptName
		t.Logf("commit r%d→r%d: %s: %s", before, m.p.s.Snapshot().Rev(), m.scriptName, a.play(m.p))
		m.undo = nil
	case scripted && pbtChance(t, 4, "script"):
		// The script's setup at once, its moves an event each.
		m.scriptName, m.script = drawScript(t, m.p.w)
		m.kind = "script " + m.scriptName
		m.reach.events["script "+m.scriptName]++
		t.Logf("script %s, %d acts", m.scriptName, len(m.script))

		for len(m.script) > 0 && !m.script[0].key {
			t.Logf("commit r%d: %s: %s", m.p.s.Snapshot().Rev(), m.scriptName, m.script[0].play(m.p))
			m.script = m.script[1:]
		}

		m.undo = nil
	case session:
		sw := sessionWrites.Draw(t, "session")
		m.kind = "session " + sw.Kind.String()
		t.Logf("commit r%d→r%d: %s", before, m.p.s.Snapshot().Rev(), m.p.session(sw))
		m.undo = nil
	case undo && m.undo != nil:
		m.kind = "undo"
		m.undo()
		m.undo = nil
	case transient && nodes.Len() > 0 && len(m.p.w.Topology.Users) > 0:
		m.kind = "transient"
		n := transientNode(m.p.w, nodes.At(rapid.IntRange(0, nodes.Len()-1).Draw(t, "like")).ID())
		m.p.edit(policymodel.Join{Node: n})
		t.Logf("commit r%d→r%d: join %s", before, m.p.s.Snapshot().Rev(), n)
		m.flash(t)

		before = m.p.s.Snapshot().Rev()
		m.p.edit(policymodel.Leave{ID: n.ID})
		t.Logf("commit r%d→r%d: leave n%d", before, m.p.s.Snapshot().Rev(), n.ID)

		m.undo = nil
	case step || nodes.Len() == 0:
		from := m.p.w
		st := policymodel.Step(stepsOf(from).Draw(t, "step"))
		m.kind = "step"

		for _, e := range st.Edits {
			m.p.edit(e)
		}

		t.Logf("commit r%d→r%d: %s", before, m.p.s.Snapshot().Rev(), policymodel.Step{Edits: st.Edits})

		m.undo = nil
		if inv, ok := policymodel.Undo(from, st); ok {
			m.undo = func() {
				before := m.p.s.Snapshot().Rev()
				m.p.write(m.p.w.Apply(inv.Edits...))
				t.Logf("commit r%d→r%d: undo, %s", before, m.p.s.Snapshot().Rev(), inv)
			}
		}

		if flash && m.undo != nil {
			m.flash(t)
			m.undo()
			m.undo = nil
		}
	default:
		id := nodes.At(rapid.IntRange(0, nodes.Len()-1).Draw(t, "node")).ID()
		nv, _ := m.p.s.Snapshot().GetNode(id)
		was := nv.Endpoints().AsSlice()
		m.kind = "endpoint"

		m.touchNode(id)

		m.undo = func() {
			m.setEndpoints(id, was)
			m.t.Logf("commit r%d: undo, endpoint of n%d back", m.p.s.Snapshot().Rev(), id)
		}
	}

	m.reap()
}

// flash has some of the sessions woken take the latest snapshot now, and
// some of those end their render before the write is taken back: the
// newest snapshot the hub saw is then one the reversal undoes, which a
// first map ending later renders. Renders in flight since before may end
// in between too, so a first map handed an older snapshot renders that
// newest one before the reversal commits.
func (m *hubMachine) flash(t *rapid.T) {
	var took, inFlight []*hubSess

	for _, s := range m.sess {
		if s.took != nil {
			inFlight = append(inFlight, s)
		}
	}

	for _, s := range slices.Clone(m.sess) {
		if !s.ended.Load() && s.took == nil && (s.first || len(s.sess.wakes) > 0) && rapid.Bool().Draw(t, "takes") {
			m.take(s)
			took = append(took, s)
		}
	}

	for _, s := range slices.Concat(took, inFlight) {
		if s.took != nil && shardFree(s.shard(m.h)) && rapid.Bool().Draw(t, "ends") {
			m.finish(s, true)
		}
	}

	m.reap()
}

// transientNode is a node of like's owner, or with its tags, at addresses
// of its own: the node a transient commit has join and leave.
func transientNode(w policymodel.World, like types.NodeID) policymodel.Node {
	id := max(w.Topology.NextID, 1)
	if n := len(w.Topology.Nodes); n > 0 {
		id = max(id, w.Topology.Nodes[n-1].ID+1)
	}

	n := policymodel.Node{ID: id, User: w.Topology.Users[0].ID}
	if l, ok := w.Topology.Node(like); ok {
		n.User, n.Tags = l.User, slices.Clone(l.Tags)
	}

	n.V4 = netip.AddrFrom4([4]byte{100, 64, byte(id >> 8), byte(id)})                                      //nolint:gosec // the low 16 bits
	n.V6 = netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: byte(id >> 8), 15: byte(id)}) //nolint:gosec // the low 16 bits

	return n
}

// printedStep is a policymodel step that prints as its edits when rapid
// logs the draw.
type printedStep policymodel.Step

func (s printedStep) GoString() string { return policymodel.Step{Edits: s.Edits}.String() }

func stepsOf(w policymodel.World) *rapid.Generator[printedStep] {
	return rapid.Custom(func(t *rapid.T) printedStep { return printedStep(policymodel.Steps(w).Draw(t, "step")) })
}

// touchNode writes a new endpoint of id: it names id and its readers.
func (m *hubMachine) touchNode(id types.NodeID) {
	m.touch++
	m.setEndpoints(id, []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(m.touch))}) //nolint:gosec // small
	m.t.Logf("commit r%d: endpoint of n%d", m.p.s.Snapshot().Rev(), id)
}

func (m *hubMachine) setEndpoints(id types.NodeID, eps []netip.AddrPort) { m.p.endpoint(id, eps) }

func (m *hubMachine) advance(t *rapid.T) {
	if m.w.at.at == watchIdle {
		t.Skip("the watcher is idle")
	}

	m.w.step()
	t.Logf("watcher: %s", m.w.at)

	if m.w.at.at == watchRouted {
		if m.w.at.to > m.w.at.from+1 {
			m.reach.coalesced++
		}

		if m.w.at.between > 0 {
			m.reach.logWoke++
		}

		m.reap()
	}
}

// pickSess draws one of the sessions ok accepts, skipping when none does.
func (m *hubMachine) pickSess(t *rapid.T, ok func(*hubSess) bool) *hubSess {
	var from []*hubSess

	for _, s := range m.sess {
		if ok(s) {
			from = append(from, s)
		}
	}

	if len(from) == 0 {
		t.Skip("no session")
	}

	return from[rapid.IntRange(0, len(from)-1).Draw(t, "session")]
}

func (m *hubMachine) takeAny(t *rapid.T) {
	m.take(m.pickSess(t, func(s *hubSess) bool {
		return !s.ended.Load() && s.took == nil && (s.first || len(s.sess.wakes) > 0)
	}))
}

// take has s take its wake, if it has one, and the latest snapshot.
func (m *hubMachine) take(s *hubSess) {
	if !s.first {
		<-s.sess.wakes
	}

	s.took = m.p.s.Snapshot()
	m.shards()
	m.t.Logf("%s takes r%d", s, s.took.Rev())
}

func (m *hubMachine) finishAny(t *rapid.T) {
	s := m.pickSess(t, func(s *hubSess) bool { return s.took != nil && shardFree(s.shard(m.h)) })
	m.finish(s, s.first || !pbtChance(t, 4, "fail"))
}

// finish ends s's render of what it took, as Initial and Update do, or as
// Update's error path does for a failure no snapshot explains.
func (m *hubMachine) finish(s *hubSess, ok bool) {
	t := m.t
	took := s.took
	s.took = nil

	m.shards()

	if m.w.routing() {
		m.reach.endedMidRouting++

		if m.w.at.shard == shardIndex(m.h, s.shard(m.h)) {
			m.reach.events["ended-in-own-shard"]++
		}
	}

	if took.Rev() < m.w.routed.Rev() {
		m.reach.endedPast++
	}

	woken := len(s.sess.wakes)
	defer func() {
		if woken == 0 && len(s.sess.wakes) > 0 {
			m.reach.endWoke++
		}
	}()

	if !ok {
		s.st.hub.observe(took)
		s.st.rendered(took, errInjected)
		s.last, s.ok = took, false
		t.Logf("%s fails to render r%d", s, took.Rev())

		return
	}

	var (
		resps []*tailcfg.MapResponse
		err   error
		at    = took
	)

	if s.first {
		// A first map renders the newest snapshot the hub saw.
		m.h.mu.Lock()
		if m.h.latest != nil && m.h.latest.Rev() > at.Rev() {
			at = m.h.latest
			m.reach.firstNewer++
		}
		m.h.mu.Unlock()

		resps, err = s.st.Initial(took)
	} else {
		resps, err = s.st.Update(took)
	}

	if errors.Is(err, ErrNodeGone) {
		t.Logf("%s renders r%d: its node is gone", s, at.Rev())
		m.drop(s)

		return
	}

	if err != nil {
		t.Fatalf("%s renders r%d: %v", s, at.Rev(), err)
	}

	s.st.Delivered()

	if s.first {
		s.client = newModelClient(resps[0])
		resps = resps[1:]
	}

	for _, r := range resps {
		s.client.apply(r)
	}

	if !s.ok && !s.first && s.last != nil {
		m.reach.retried++
	}

	if !s.first && s.ok && len(resps) > 0 {
		c := at.Since(s.last)
		all, _ := Route(s.last, at, c)
		m.reach.wakes.add(m.dropped, s.last, at, all, c, s.id, s.last.Rev()+1 < at.Rev(), false, m.kind)
	}

	s.first, s.last, s.ok = false, at, true
	t.Logf("%s renders r%d: %s", s, at.Rev(), describeResponses(resps))

	requireRenderFresh(t, m.p.cfg, at, s.id, s.capVer, s.st.sent, s.client)

	if s.ended.Load() {
		m.drop(s)
	}
}

// session admits a session of a node that has none, or has a session
// that is not rendering leave, or reconnect.
func (m *hubMachine) session(t *rapid.T) {
	var free []types.NodeID

	for _, n := range m.p.s.Snapshot().ListNodes().All() {
		if !slices.ContainsFunc(m.sess, func(s *hubSess) bool { return s.id == n.ID() }) {
			free = append(free, n.ID())
		}
	}

	var idle []*hubSess

	for _, s := range m.sess {
		if s.took == nil && !s.ended.Load() {
			idle = append(idle, s)
		}
	}

	// A node with a live session can open another, as a reconnect that
	// overlaps its old stream does; past the hub's bound, the oldest ends.
	var second []types.NodeID

	for _, n := range m.p.s.Snapshot().ListNodes().All() {
		if c := countSessions(m.sess, n.ID()); c > 0 && c <= maxConcurrentMapSessionsPerNode {
			second = append(second, n.ID())
		}
	}

	kinds := []string{}
	if len(free) > 0 {
		kinds = append(kinds, "admit")
	}

	if len(idle) > 0 {
		kinds = append(kinds, "reconnect", "leave")
	}

	if len(second) > 0 {
		kinds = append(kinds, "second")
	}

	if len(kinds) == 0 {
		t.Skip("no node to admit, no session to end")
	}

	switch rapid.SampledFrom(kinds).Draw(t, "kind") {
	case "admit":
		m.admit(free[rapid.IntRange(0, len(free)-1).Draw(t, "node")])
	case "reconnect":
		s := idle[rapid.IntRange(0, len(idle)-1).Draw(t, "session")]
		t.Logf("%s reconnects", s)
		m.drop(s)
		m.admit(s.id)
	case "leave":
		s := idle[rapid.IntRange(0, len(idle)-1).Draw(t, "session")]
		t.Logf("%s leaves", s)
		m.drop(s)
	case "second":
		id := second[rapid.IntRange(0, len(second)-1).Draw(t, "node")]
		t.Logf("n%d opens a second session", id)
		m.admit(id)

		m.reach.events["second session"]++
	}
}

// countSessions counts the sessions of id in sess the hub has not ended.
func countSessions(sess []*hubSess, id types.NodeID) int {
	n := 0

	for _, s := range sess {
		if s.id == id && !s.ended.Load() {
			n++
		}
	}

	return n
}

// check holds, whenever no routing is part way, every session that is
// idle with no wake pending and last rendered before the last routing's
// end to a fresh render of that end.
func (m *hubMachine) check(t *rapid.T) {
	if m.w.routing() {
		return
	}

	if m.audit && RouteAuditFailures() != m.audited {
		t.Fatalf("the route audit held a session to r%d that is stale or due", m.w.routed.Rev())
	}

	if msg := m.audits.judge(); msg != "" {
		t.Fatalf("an audit objects at r%d: %s", m.p.s.Snapshot().Rev(), msg)
	}

	r := m.w.routed

	var (
		fresh  *state.Snapshot
		caches = map[tailcfg.CapabilityVersion]*versionCache{}
	)

	for _, s := range m.sess {
		if s.ended.Load() || s.first || s.took != nil || len(s.sess.wakes) > 0 || s.last.Rev() >= r.Rev() {
			continue
		}

		if !s.ok {
			t.Fatalf("%s failed to render r%d, a routing went to r%d, and no wake is pending", s, s.last.Rev(), r.Rev())
		}

		if s.held.rev == r.Rev() && s.held.nm == s.st.sent {
			continue
		}

		if fresh == nil {
			fresh = r.Uncached()
		}

		pcv := peerCapVer(s.capVer)
		if caches[pcv] == nil {
			caches[pcv] = &versionCache{}
		}

		out, err := freshDiff(m.p.cfg, fresh, s.id, s.capVer, s.st.sent, caches[pcv])
		if err != nil {
			t.Fatalf("%s: rendering r%d afresh: %v", s, r.Rev(), err)
		}

		if len(out) > 0 {
			t.Fatalf("%s holds a stale map: it rendered r%d, the watcher routed to r%d, no wake is pending: %s",
				s, s.last.Rev(), r.Rev(), describeResponses(out))
		}

		s.held.rev, s.held.nm = r.Rev(), s.st.sent
	}
}

// settle routes, takes and renders, successfully, in a fixed order, until
// nothing is pending, checking at every step.
func (m *hubMachine) settle() {
	for range 100_000 {
		m.check(m.t)

		if m.w.step() {
			if m.w.at.at == watchRouted {
				m.reap()
			}

			continue
		}

		if i := slices.IndexFunc(m.sess, func(s *hubSess) bool { return s.took != nil }); i >= 0 {
			m.finish(m.sess[i], true)

			continue
		}

		if i := slices.IndexFunc(m.sess, func(s *hubSess) bool { return !s.ended.Load() && (s.first || len(s.sess.wakes) > 0) }); i >= 0 {
			m.take(m.sess[i])

			continue
		}

		m.reap()

		return
	}

	m.t.Fatalf("the hub did not settle")
}

// requireRenderFresh holds a render of snap that succeeded, and the client
// that applied what it returned, to a fresh render and a fresh session's
// client.
func requireRenderFresh(t pbtT, cfg *types.Config, snap *state.Snapshot, id types.NodeID, cv tailcfg.CapabilityVersion, sent *netMap, client *modelClient) {
	t.Helper()

	fresh := snap.Uncached()

	out, err := freshDiff(cfg, fresh, id, cv, sent, &versionCache{})
	if err != nil {
		t.Fatalf("n%d: rendering r%d afresh: %v", id, snap.Rev(), err)
	}

	if len(out) > 0 {
		t.Fatalf("n%d's render of r%d differs from a fresh one: %s", id, snap.Rev(), describeResponses(out))
	}

	resps, err := NewStream(cfg, NewHub(), id, cv).Initial(fresh)
	if err != nil {
		t.Fatalf("n%d: a fresh session of r%d: %v", id, snap.Rev(), err)
	}

	want := newModelClient(resps[0])
	for _, r := range resps[1:] {
		want.apply(r)
	}

	if d := client.sameAs(want); d != "" {
		t.Fatalf("n%d's client, after its responses up to r%d, differs from a fresh session's: %s", id, snap.Rev(), d)
	}
}

// TestHubSessionsConvergeUnderConcurrency runs the hub as production runs
// it: the watcher on its goroutine, every session on a goroutine of its
// own that takes its wake, waits a moment, takes the latest snapshot and
// renders, as poll does, against writes drawn from policymodel — a world,
// then its steps, endpoint writes, now and then the last step taken back,
// clients reconnecting — committed while sessions render and the watcher
// routes. The watcher now and then waits before it loads a snapshot, so
// commits coalesce; now and then it is held while a node joins and leaves,
// after a write that woke sessions, which then take a snapshot holding the
// node and end their render before the routing over both commits or after. Every ten writes and at the end, once the watcher
// routed the last commit and every session is idle with no wake pending,
// each must hold what a fresh render gives. HEADSCALE_HUB_SEED replays the
// world and the writes, not the schedule.
//
// It is the one hub test with real concurrency, so the one where the race
// detector sees the hub, the render log, Since on render goroutines and the
// render caches race. Which interleavings it reaches depends on the
// machine and its load, so it cannot be relied on to reach any one
// ordering, and a failing seed does not replay its schedule; the ordering
// properties are [TestHubSessionsConvergeUnderDrawnSchedules]'s.
func TestHubSessionsConvergeUnderConcurrency(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")
	// Runs set filter_chunks in turn, and a configuration can only pin an
	// option on.
	t.Setenv(state.TestFilterChunksEnv, "false")

	seed := uint64(time.Now().UnixNano()) //nolint:gosec // any seed

	if v := os.Getenv("HEADSCALE_HUB_SEED"); v != "" {
		var err error

		seed, err = strconv.ParseUint(v, 10, 64)
		require.NoError(t, err)
	}

	t.Logf("HEADSCALE_HUB_SEED=%d", seed)

	runs, writes := 4, 120
	if testing.Short() {
		runs, writes = 1, 60
	}

	var reach stressReach

	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))

			for run := range uint64(runs) { //nolint:gosec // small
				reach.add(stressConverges(t, seed, run, writes, false, (seed+run)%2 == 1))
			}
		})
	}

	// With the audit on, as the integration runs set it: a session the
	// render log woke again is due to render, no session the route audit
	// holds to the routing's end is stale, and no other audit objects,
	// counted or only logged.
	// The writes are those the other audits agree on (see [audited]): the
	// compile's incremental node attributes and SSH policies differ from
	// its compile from scratch after an address moves.
	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("audit/capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))
			envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

			audits := watchAudits(t)

			for _, chunks := range []bool{false, true} {
				failures, audited, policy := RouteAuditFailures(), RouteAuditRuns(), state.PolicyAuditFailures()

				run := stressConverges(t, seed, 100, writes, true, chunks)
				reach.add(run)

				if msg := audits.judge(); msg != "" {
					t.Errorf("filter_chunks=%t: an audit logged a line: %s", chunks, msg)
				}

				assert.Equal(t, failures, RouteAuditFailures(), "filter_chunks=%t: the route audit found no stale session", chunks)
				assert.Equal(t, policy, state.PolicyAuditFailures(), "filter_chunks=%t: no other audit line", chunks)
				assert.Greater(t, RouteAuditRuns(), audited, "filter_chunks=%t: test sanity: the route audit rendered sessions afresh", chunks)
			}
		})
	}

	t.Logf("%+v", reach)
	require.Positive(t, reach.compared, "sessions were held to a fresh render")
	require.Positive(t, reach.coalesced, "commits coalesced into one routing")
	require.Positive(t, reach.reconnected, "clients reconnected while the hub routed")
	require.Positive(t, reach.straddled, "nodes joined and left while the watcher was held")
}

// stressReach counts what [TestHubSessionsConvergeUnderConcurrency]
// reached; it depends on the schedule.
type stressReach struct {
	compared, coalesced, between, reconnected, undone, straddled int
}

func (r *stressReach) add(o stressReach) {
	r.straddled += o.straddled
	r.compared += o.compared
	r.coalesced += o.coalesced
	r.between += o.between
	r.reconnected += o.reconnected
	r.undone += o.undone
}

// stressSession is a session on a goroutine of its own.
type stressSession struct {
	st     *Stream
	sess   *Session
	capVer tailcfg.CapabilityVersion
	// stop is closed when the hub ends the session, or end does.
	stop chan struct{}
	end  func()
	// busy is set from the session's start and from each wake it takes
	// until its render ends: the test's own view of whether it is idle.
	// A wake taken is not busy yet, so renders counts what ended.
	busy    atomic.Bool
	renders atomic.Int64
}

// stressRun is one run of [TestHubSessionsConvergeUnderConcurrency].
type stressRun struct {
	t         *testing.T
	seed, run uint64
	r         *rand.Rand
	p         *pbtWorld
	hub       *Hub
	reach     stressReach
	audit     bool

	coalesced, between atomic.Int64
	routedTo           atomic.Uint64

	// hubMu guards hubRand, which slows the watcher. pause holds the
	// watcher before it loads while the test straddles a routing.
	hubMu   sync.Mutex
	hubRand *rand.Rand
	pause   sync.RWMutex
	paused  atomic.Bool

	mu       sync.Mutex
	failures []error
	// sessions are the test goroutine's: each live node's session.
	sessions map[types.NodeID]*stressSession
	wg       sync.WaitGroup
	quit     chan struct{}
	example  int
}

func stressConverges(t *testing.T, seed, run uint64, writes int, audit, chunks bool) stressReach {
	t.Helper()

	h := &stressRun{
		t: t, seed: seed, run: run, audit: audit,
		r:        rand.New(rand.NewPCG(seed, run)),       //nolint:gosec // reproducible
		hubRand:  rand.New(rand.NewPCG(seed, run+1<<32)), //nolint:gosec // reproducible
		sessions: map[types.NodeID]*stressSession{},
		quit:     make(chan struct{}),
		example:  int(seed%(1<<30)) + int(run)<<20, //nolint:gosec // any example index
	}

	// A world of a few nodes at least, so several sessions render at once.
	world := policymodel.Worlds().Example(h.next())
	for len(world.Topology.Nodes) < 5 {
		world = policymodel.Worlds().Example(h.next())
	}

	h.p = newPBTWorld(t, world, func(cfg *types.Config) { cfg.Policy.FilterChunks = chunks })

	h.hub = NewHub()
	t.Cleanup(h.hub.Close)

	h.hub.beforeRoute = h.slowly
	h.hub.routed = func(from, to uint64, between int) {
		if to > from+1 {
			h.coalesced.Add(1)
		}

		h.between.Add(int64(between))
		h.routedTo.Store(to)
	}
	h.hub.Watch(h.p.s)

	for _, n := range h.p.s.Snapshot().ListNodes().All() {
		h.spawn(n.ID())
	}

	var undo func()

	for step := range writes {
		undo = h.write(undo)

		if step%10 == 9 {
			h.settled(step)
		}
	}

	h.settled(writes)
	close(h.quit)
	h.wg.Wait()
	require.Empty(t, h.failures)

	h.reach.coalesced = int(h.coalesced.Load())
	h.reach.between = int(h.between.Load())

	return h.reach
}

func (h *stressRun) next() int {
	h.example++

	return h.example
}

// audited reports whether st, from w, is a write the filter audit agrees
// on: no address moves.
func audited(st policymodel.Step) bool {
	for _, e := range st.Edits {
		if _, ok := e.(policymodel.SetAddr); ok {
			return false
		}
	}

	return true
}

// slowly now and then holds the watcher before it loads a snapshot, so
// the commits that land meanwhile coalesce.
func (h *stressRun) slowly() {
	h.pause.RLock()
	h.pause.RUnlock() //nolint:staticcheck // waits for the writer, holds nothing

	h.hubMu.Lock()
	d := h.hubRand.IntN(8)
	h.hubMu.Unlock()

	if d < 3 {
		time.Sleep(time.Duration(d+1) * 300 * time.Microsecond) //nolint:forbidigo // a slow watcher, not a wait
	}
}

// spawn opens a session of id on a goroutine of its own, as poll runs it.
func (h *stressRun) spawn(id types.NodeID) {
	ls := &stressSession{
		capVer: []tailcfg.CapabilityVersion{capVer, capver.MinSupportedCapabilityVersion}[h.r.IntN(2)],
		stop:   make(chan struct{}),
	}

	var once sync.Once

	ls.end = func() { once.Do(func() { close(ls.stop) }) }
	ls.sess = h.hub.Join(id, ls.end)
	ls.st = NewStream(h.p.cfg, h.hub, id, ls.capVer)
	ls.st.Attach(ls.sess)
	ls.busy.Store(true)

	h.sessions[id] = ls

	hold := rand.New(rand.NewPCG(h.seed, h.run<<32|uint64(id))) //nolint:gosec // reproducible

	h.wg.Go(func() {
		defer h.hub.Leave(ls.sess)

		if !h.render(ls, hold, true) {
			return
		}

		ls.renders.Add(1)
		ls.busy.Store(false)

		for {
			select {
			case <-h.quit:
				return
			case <-ls.stop:
				return
			case <-ls.sess.Wakes():
				ls.busy.Store(true)

				if !h.render(ls, hold, false) {
					return
				}

				ls.renders.Add(1)
				ls.busy.Store(false)
			}
		}
	})
}

// render renders ls's next map, now and then slow to take its snapshot or
// to end; false when the session ends.
func (h *stressRun) render(ls *stressSession, hold *rand.Rand, first bool) bool {
	if hold.IntN(2) == 0 {
		time.Sleep(time.Duration(hold.IntN(300)) * time.Microsecond) //nolint:forbidigo // slow to take the snapshot, not a wait
	}

	snap := h.p.s.Snapshot()

	switch {
	case h.paused.Load() && hold.IntN(2) == 0:
		// A snapshot taken while the watcher is held: end the render once
		// a routing went past it, or a while later.
		for range 50 {
			if h.routedTo.Load() > snap.Rev() {
				break
			}

			time.Sleep(100 * time.Microsecond) //nolint:forbidigo // a render held in flight, not a wait
		}
	case hold.IntN(3) == 0:
		time.Sleep(time.Duration(hold.IntN(500)) * time.Microsecond) //nolint:forbidigo // a render held in flight, not a wait
	}

	var err error
	if first {
		_, err = ls.st.Initial(snap)
	} else {
		_, err = ls.st.Update(snap)
	}

	if errors.Is(err, ErrNodeGone) {
		return false
	}

	if err != nil {
		h.mu.Lock()
		h.failures = append(h.failures, fmt.Errorf("node %d at commit %d: %w", ls.st.nodeID, snap.Rev(), err))
		h.mu.Unlock()

		return false
	}

	ls.st.Delivered()

	return true
}

// write commits a step drawn from the world as it is, or an endpoint
// write, or takes back the last step; now and then a client reconnects.
// It returns how to take back what it wrote, if anything does.
func (h *stressRun) write(undo func()) func() {
	r, p := h.r, h.p
	nodes := p.s.Snapshot().ListNodes()

	var next func()

	switch {
	case nodes.Len() > 0 && len(p.w.Topology.Users) > 0 && r.IntN(5) == 0 && h.straddle():
	case undo != nil && r.IntN(3) == 0:
		undo()

		h.reach.undone++
	case nodes.Len() == 0 || r.IntN(2) == 0:
		from := p.w

		st := policymodel.Steps(from).Example(h.next())
		for h.audit && !audited(st) {
			st = policymodel.Steps(from).Example(h.next())
		}

		for _, e := range st.Edits {
			p.edit(e)
		}

		if inv, ok := policymodel.Undo(from, st); ok {
			next = func() { p.write(p.w.Apply(inv.Edits...)) }
		}
	case r.IntN(4) == 0:
		// A client, the HA prober or an operator writes through its
		// production entry point, racing the renders.
		p.session(sessionWrite{Kind: sessionKind(r.IntN(int(numSessionKinds))), Who: r.IntN(16), Value: r.IntN(3)}) //nolint:gosec // small
	default:
		p.endpoint(nodes.At(r.IntN(nodes.Len())).ID(), []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(r.IntN(1<<16)))}) //nolint:gosec // any port
	}

	h.follow()

	if r.IntN(4) == 0 {
		// A client reconnects while the commits land.
		cur := p.s.Snapshot().ListNodes()
		if cur.Len() > 0 {
			id := cur.At(r.IntN(cur.Len())).ID()
			h.sessions[id].end()
			h.spawn(id)

			h.reach.reconnected++
		}
	}

	if r.IntN(2) == 0 {
		time.Sleep(time.Duration(r.IntN(300)) * time.Microsecond) //nolint:forbidigo // writes spread out, not a wait
	}

	return next
}

// straddle has sessions take a snapshot no routing's end holds: an
// endpoint write wakes some, the watcher is held once it routed that, a
// node joins (with a session of its own) and, a moment later, leaves; the
// routing over both commits names neither, and the sessions that took a
// snapshot holding the node end their renders before it or after. Under
// the audit it declines a joiner the audits disagree on, writing nothing.
func (h *stressRun) straddle() bool {
	t, r, p := h.t, h.r, h.p

	nodes := p.s.Snapshot().ListNodes()

	joiner := transientNode(p.w, nodes.At(r.IntN(nodes.Len())).ID())

	p.endpoint(nodes.At(r.IntN(nodes.Len())).ID(), []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.2"), uint16(r.IntN(1<<16)))}) //nolint:gosec // any port

	woke := p.s.Snapshot().Rev()

	require.Eventually(t, func() bool { return h.routedTo.Load() >= woke }, time.Minute, 50*time.Microsecond)

	h.pause.Lock()
	h.paused.Store(true)

	p.edit(policymodel.Join{Node: joiner})
	h.follow()

	time.Sleep(time.Duration(100+r.IntN(400)) * time.Microsecond) //nolint:forbidigo // a node joined for a moment, not a wait

	p.edit(policymodel.Leave{ID: joiner.ID})
	h.paused.Store(false)
	h.pause.Unlock()

	h.reach.straddled++

	return true
}

// follow opens a session for every node that has none, and forgets the
// sessions of nodes gone.
func (h *stressRun) follow() {
	snap := h.p.s.Snapshot()

	for id := range h.sessions {
		if _, ok := snap.GetNode(id); !ok {
			delete(h.sessions, id)
		}
	}

	for _, n := range snap.ListNodes().All() {
		if _, ok := h.sessions[n.ID()]; !ok {
			h.spawn(n.ID())
		}
	}
}

// settled waits for the watcher to route the last commit and for every
// live session to be idle with no wake pending, at three looks in a row,
// then holds each to a fresh render. It reads none of the render log, which
// is what it checks; an idle session's last render ended before it cleared
// busy, which the wait read after it.
func (h *stressRun) settled(step int) {
	t, s := h.t, h.p.s
	last := s.Snapshot()
	idle := 0

	require.Eventually(t, func() bool {
		if h.routedTo.Load() < last.Rev() {
			return false
		}

		for _, nv := range last.ListNodes().All() {
			if ls := h.sessions[nv.ID()]; ls.busy.Load() || len(ls.sess.wakes) > 0 {
				idle = 0

				return false
			}
		}

		idle++

		return idle >= 3
	}, time.Minute, time.Millisecond, "the hub routed the last commit and every session rendered")

	require.Equal(t, last.Rev(), s.Snapshot().Rev(), "test sanity: nothing committed while settling")

	h.mu.Lock()
	require.Empty(t, h.failures)
	h.mu.Unlock()

	fresh := last.Uncached()

	for _, nv := range last.ListNodes().All() {
		ls := h.sessions[nv.ID()]

		select {
		case <-ls.stop:
			t.Fatalf("seed %d run %d: node %d's session was ended", h.seed, h.run, nv.ID())
		default:
		}

		renders := ls.renders.Load()

		out, err := freshDiff(h.p.cfg, fresh, nv.ID(), ls.capVer, ls.st.sent, &versionCache{})
		require.NoError(t, err)

		// Idle, to the check above, is also a session that took its wake
		// and has not marked itself busy: it renders in a moment, and one
		// never woken does not.
		for len(out) > 0 && ls.rendersAgain(renders) {
			renders = ls.renders.Load()

			out, err = freshDiff(h.p.cfg, fresh, nv.ID(), ls.capVer, ls.st.sent, &versionCache{})
			require.NoError(t, err)
		}

		if len(out) > 0 {
			t.Fatalf("HEADSCALE_HUB_SEED=%d run %d step %d: node %d's session holds a stale map: %s\n%#v", h.seed, h.run, step, nv.ID(), describeResponses(out), h.p.w)
		}

		h.reach.compared++
	}
}

// rendersAgain reports whether ls ends a render after its renders-th
// within a while and is idle again.
func (ls *stressSession) rendersAgain(renders int64) bool {
	for range 2000 {
		if ls.renders.Load() > renders && !ls.busy.Load() && len(ls.sess.wakes) == 0 {
			return true
		}

		time.Sleep(time.Millisecond) //nolint:forbidigo // a render taken up late, not a wait
	}

	return false
}

// auditLines collects, while installed, every line the policy audits log,
// read as the integration runs read them: any line saying "policy audit",
// whatever counter it moved, if any.
type auditLines struct {
	mu    sync.Mutex
	lines []auditLine
}

type auditLine struct {
	Message string `json:"message"`
	Error   string `json:"error"`
	Diff    string `json:"diff"`
}

func (a *auditLines) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("policy audit")) {
		l := auditLine{Message: string(p)}
		_ = json.Unmarshal(p, &l)

		a.mu.Lock()
		a.lines = append(a.lines, l)
		a.mu.Unlock()
	}

	return os.Stderr.Write(p)
}

// watchAudits collects the audit lines for the rest of t.
func watchAudits(t *testing.T) *auditLines {
	t.Helper()

	a := &auditLines{}
	tapTo(t, a)

	return a
}

// take returns the lines logged since it last returned.
func (a *auditLines) take() []auditLine {
	if a == nil {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	out := a.lines
	a.lines = nil

	return out
}

// judge returns the first line logged since the last judge: no audit
// line is a known false alarm.
func (a *auditLines) judge() string {
	for _, l := range a.take() {
		return fmt.Sprintf("%s: %s%s", l.Message, l.Error, l.Diff)
	}

	return ""
}

// TestHubCoreInterleavings drives the hub's decisions one event at a time on
// the test goroutine, against a model: a node's map at a commit is a value the
// model holds, and Route over two commits names the nodes whose value moved,
// or every node across a commit every map reads. The hub's own code makes
// every decision: a routing (Hub.route, the render log and its memo), a
// render's end and the wake it may owe (Stream.rendered), a first map's
// snapshot (Hub.initialState), peer history, sessions. Spelled out here are
// only the watcher's loop body and a stream's calls into the hub; no map is
// rendered, and the snapshots are minted once from one State.
//
// It judges, after every event (a routing runs whole here): every session
// that is idle, has no wake pending and last rendered a commit before the
// one routed to must have succeeded and hold that commit's value; once
// nothing is left to do, every session holds the latest commit's value, one
// more commit retrying a failure; a deleted node's history is gone once the
// hub forgot it; a node's history never returns to an older revision.
//
// exhaustive walks every schedule of every scenario in a small scope, each
// state once; drawn has rapid draw larger scenarios and schedules. Neither
// can see what one goroutine runs whole: data races, or anything between
// two of the hub's critical sections (the stress test and the hub
// schedules); nor what a render holds (the scenarios and delivery
// properties).
func TestHubCoreInterleavings(t *testing.T) {
	snaps := mintSnapshots(t, 16)

	// Each scope is small enough to walk whole; together they hold commits
	// coalescing over changes and their reversals, renders of a commit in
	// between and past a routing, failures, deletions with renders and
	// writes still in flight, and two sessions of one node.
	for _, sc := range []struct {
		name  string
		scope coreScope
	}{
		{"one node, four commits, a failure", coreScope{nodes: 1, commits: 4, failures: 1, quiet: true}},
		{"two nodes, a failure, a leave", coreScope{nodes: 2, commits: 2, failures: 1, leaves: 1, global: true}},
		{"two nodes, a failure, a deletion", coreScope{nodes: 2, commits: 2, failures: 1, deletions: 1, global: true}},
		{"a second session, a failure", coreScope{nodes: 1, commits: 2, joins: 1, failures: 1, quiet: true, global: true}},
	} {
		t.Run("exhaustive/"+sc.name, func(t *testing.T) {
			states, leaves := exploreCore(t, snaps, sc.scope)
			t.Logf("%d states, %d of them with nothing left to do", states, leaves)
		})
	}

	t.Run("drawn", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			scope := coreScope{
				nodes:     rapid.IntRange(1, 4).Draw(t, "nodes"),
				commits:   rapid.IntRange(1, len(snaps)-2).Draw(t, "commits"),
				joins:     rapid.IntRange(0, 3).Draw(t, "joins"),
				failures:  rapid.IntRange(0, 3).Draw(t, "failures"),
				deletions: rapid.IntRange(0, 1).Draw(t, "deletions"),
				leaves:    rapid.IntRange(0, 2).Draw(t, "leaves"),
				drawn:     true,
			}

			m := newCoreMachine(t, snaps, scope)
			for {
				evs := m.enabled()
				if len(evs) == 0 {
					break
				}

				m.apply(rapid.SampledFrom(evs).Draw(t, "event"))
			}

			m.settle()
		})
	})
}

// mintSnapshots returns n snapshots of one State, one commit apart.
func mintSnapshots(t *testing.T, n int) []*state.Snapshot {
	t.Helper()

	_, s, ids := streamTestState(t, ownUserOnly)

	out := []*state.Snapshot{s.Snapshot()}
	for i := 1; i < n; i++ {
		scalingEndpoint(t, s, ids[0], i)
		out = append(out, s.Snapshot())
		require.Equal(t, out[i-1].Rev()+1, out[i].Rev(), "test sanity: one commit per write")
	}

	return out
}

// coreScope bounds what a core machine may do: its nodes, and how many
// commits, extra sessions, failed renders, node deletions and leaves.
type coreScope struct {
	nodes, commits, joins, failures, deletions, leaves int
	// A commit flips one node's value, or every node's; quiet offers one
	// that changes nothing a node is sent, global one every map reads.
	quiet, global bool
	// drawn draws each commit's flips instead, any bits of any values.
	drawn bool
}

type coreKind int

const (
	coreCommit coreKind = iota
	coreLoad
	coreRoute
	coreTake
	coreEnd
	coreFail
	coreDeliver
	coreJoin
	coreLeave
)

// coreEvent is one step of a core machine. For a commit, edit is what it
// does; sess is the session acted on, or the node joined.
type coreEvent struct {
	kind coreKind
	sess int
	edit coreEdit
}

func (e coreEvent) String() string {
	switch e.kind {
	case coreCommit:
		return "commit " + e.edit.String()
	case coreLoad:
		return "load"
	case coreRoute:
		return "route"
	case coreJoin:
		return fmt.Sprintf("join n%d", e.sess+1)
	case coreTake, coreEnd, coreFail, coreDeliver, coreLeave:
	}

	return fmt.Sprintf("%s s%d", [...]string{coreTake: "take", coreEnd: "end", coreFail: "fail", coreDeliver: "deliver", coreLeave: "leave"}[e.kind], e.sess)
}

// coreEdit is a commit's change: each node's value flipped by flip[n], a
// commit every map reads, or a node deleted.
type coreEdit struct {
	flip   [4]uint8
	global bool
	del    int // the node deleted, plus one; zero for none
}

func (e coreEdit) String() string {
	switch {
	case e.del > 0:
		return fmt.Sprintf("delete n%d", e.del)
	case e.global:
		return fmt.Sprintf("global %v", e.flip)
	}

	return fmt.Sprintf("%v", e.flip)
}

const (
	coreIdle = iota
	coreTook
	coreWritten
)

// coreSess is one session of a core machine.
type coreSess struct {
	n     int
	sess  *Session
	st    *Stream
	first bool
	phase int
	// took is the commit the render in flight took (for a first map, the
	// one it was handed); held the commit whose value it holds; tried the
	// commit its last render was of, and ok whether that succeeded.
	took, held, tried int
	ok                bool
	pending           sentView
	// ended is set when the hub ended it; gone once it left the hub.
	ended, gone bool
}

// coreMachine is the hub, its watcher's routing and its sessions' streams,
// run by the test goroutine against the model's views.
type coreMachine struct {
	t     pbtT
	scope coreScope
	snaps []*state.Snapshot
	h     *Hub

	// views[i][n] is node n's value at commit i: the peers it sees, as bits,
	// and one bit no peer stands for.
	views     [][4]uint8
	global    []bool
	deletedAt [4]int // the commit deleting node n; zero while it lives

	committed, routed, target int
	loaded                    bool

	sess                          []*coreSess
	joins, failures, dels, leaves int
	histRev                       [4]uint64
	path                          []coreEvent
}

func newCoreMachine(t pbtT, snaps []*state.Snapshot, scope coreScope) *coreMachine {
	m := &coreMachine{t: t, scope: scope, snaps: snaps, h: NewHub(), views: make([][4]uint8, 1), global: make([]bool, 1)}
	m.h.renders.route = m.route

	// Every node sees every other.
	for n := range scope.nodes {
		m.views[0][n] = uint8(1<<scope.nodes-1) &^ (1 << n)
	}

	m.h.route(snaps[0], snaps[0])
	m.h.advance(snaps[0])

	for n := range scope.nodes {
		s := m.join(n)
		m.take(s)
		m.end(s, true)
		m.deliver(s)
	}

	return m
}

func (m *coreMachine) id(n int) types.NodeID { return types.NodeID(n + 1) } //nolint:gosec // small

func (m *coreMachine) index(snap *state.Snapshot) int { return int(snap.Rev() - m.snaps[0].Rev()) } //nolint:gosec // small

// route is the model's Route over two snapshots.
func (m *coreMachine) route(old, cur *state.Snapshot) (bool, map[types.NodeID]struct{}) {
	x, c := m.index(old), m.index(cur)
	if slices.Contains(m.global[x+1:c+1], true) {
		return true, nil
	}

	wake := map[types.NodeID]struct{}{}

	for n := range m.scope.nodes {
		if m.views[x][n] != m.views[c][n] {
			wake[m.id(n)] = struct{}{}
		}
	}

	return false, wake
}

// alive reports whether node n lives at commit i.
func (m *coreMachine) alive(n, i int) bool { return m.deletedAt[n] == 0 || i < m.deletedAt[n] }

func (m *coreMachine) live(s *coreSess) bool { return !s.gone && !s.ended }

func (m *coreMachine) edits() []coreEdit {
	if m.scope.drawn {
		// A drawn machine draws its edit as it commits.
		return []coreEdit{{}}
	}

	var out []coreEdit

	for n := range m.scope.nodes {
		var e coreEdit

		e.flip[n] = m.flipOf(n)
		out = append(out, e)
	}

	var all coreEdit
	for n := range m.scope.nodes {
		all.flip[n] = m.flipOf(n)
	}

	if m.scope.nodes > 1 {
		out = append(out, all)
	}

	if m.scope.global {
		all.global = true
		out = append(out, all)
	}

	if m.scope.quiet {
		out = append(out, coreEdit{})
	}

	if m.dels < m.scope.deletions && m.scope.nodes > 1 && m.alive(m.scope.nodes-1, m.committed+1) {
		out = append(out, coreEdit{del: m.scope.nodes})
	}

	return out
}

// flipOf is how an edit of node n flips its value: the peers it sees, or,
// for a node alone, a bit no peer stands for.
func (m *coreMachine) flipOf(n int) uint8 {
	if m.scope.nodes == 1 {
		return 1 << 7
	}

	return uint8(1<<m.scope.nodes-1) &^ (1 << n)
}

// enabled lists what may happen next.
func (m *coreMachine) enabled() []coreEvent {
	var out []coreEvent

	if m.committed < m.scope.commits {
		for _, e := range m.edits() {
			out = append(out, coreEvent{kind: coreCommit, edit: e})
		}
	}

	if !m.loaded && m.routed < m.committed {
		out = append(out, coreEvent{kind: coreLoad})
	}

	if m.loaded {
		out = append(out, coreEvent{kind: coreRoute})
	}

	for i, s := range m.sess {
		switch {
		case s.gone:
		case s.phase == coreTook:
			out = append(out, coreEvent{kind: coreEnd, sess: i})
			if !s.first && m.failures < m.scope.failures {
				out = append(out, coreEvent{kind: coreFail, sess: i})
			}
		case s.phase == coreWritten:
			out = append(out, coreEvent{kind: coreDeliver, sess: i})
		case s.ended:
		default:
			if s.first || len(s.sess.wakes) > 0 {
				out = append(out, coreEvent{kind: coreTake, sess: i})
			}

			if m.leaves < m.scope.leaves {
				out = append(out, coreEvent{kind: coreLeave, sess: i})
			}
		}
	}

	if m.joins < m.scope.joins {
		for n := range m.scope.nodes {
			if m.alive(n, m.committed) {
				out = append(out, coreEvent{kind: coreJoin, sess: n})
			}
		}
	}

	return out
}

// apply makes e happen and judges the result.
func (m *coreMachine) apply(e coreEvent) {
	m.path = append(m.path, e)

	switch e.kind {
	case coreCommit:
		if m.scope.drawn {
			e.edit = m.drawEdit()
			m.path[len(m.path)-1].edit = e.edit
		}

		m.commit(e.edit)
	case coreLoad:
		m.loaded, m.target = true, m.committed
	case coreRoute:
		m.routing()
	case coreTake:
		m.take(m.sess[e.sess])
	case coreEnd, coreFail:
		m.end(m.sess[e.sess], e.kind == coreEnd)
	case coreDeliver:
		m.deliver(m.sess[e.sess])
	case coreJoin:
		m.joins++
		m.join(e.sess)
	case coreLeave:
		m.leaves++
		m.leave(m.sess[e.sess])
	}

	m.reap()
	m.judge()
}

// drawEdit draws a drawn machine's commit: any flips, now and then one
// every map reads, or a deletion.
func (m *coreMachine) drawEdit() coreEdit {
	t, _ := m.t.(*rapid.T)

	var e coreEdit

	if m.dels < m.scope.deletions && m.scope.nodes > 1 && rapid.IntRange(0, 3).Draw(t, "delete") == 0 {
		if n := rapid.IntRange(0, m.scope.nodes-1).Draw(t, "deleted"); m.alive(n, m.committed+1) {
			return coreEdit{del: n + 1}
		}
	}

	for n := range m.scope.nodes {
		e.flip[n] = rapid.Uint8Range(0, 1<<m.scope.nodes-1).Draw(t, "flip") &^ (1 << n)
	}

	e.global = rapid.IntRange(0, 5).Draw(t, "global") == 0

	return e
}

func (m *coreMachine) commit(e coreEdit) {
	v := m.views[m.committed]
	for n := range m.scope.nodes {
		v[n] ^= e.flip[n]
	}

	if e.del > 0 {
		m.dels++
		m.deletedAt[e.del-1] = m.committed + 1

		for n := range m.scope.nodes {
			v[n] &^= 1 << (e.del - 1)
		}
	}

	m.committed++
	m.views = append(m.views, v)
	m.global = append(m.global, e.global)
}

// routing is the watcher's loop body over the commits since it last routed:
// route, advance, forget the deleted, wake.
func (m *coreMachine) routing() {
	_, all, wake, _ := m.h.route(m.snaps[m.routed], m.snaps[m.target])
	m.h.advance(m.snaps[m.target])

	for n := range m.scope.nodes {
		if d := m.deletedAt[n]; d > m.routed && d <= m.target {
			m.h.forget(m.id(n))
			m.histRev[n] = 0
		}
	}

	m.h.wake(all, wake)
	m.routed, m.loaded = m.target, false
}

func (m *coreMachine) join(n int) *coreSess {
	s := &coreSess{n: n, first: true}
	s.sess = m.h.Join(m.id(n), func() { s.ended = true })
	s.st = &Stream{hub: m.h, nodeID: m.id(n)}
	s.st.Attach(s.sess)
	m.sess = append(m.sess, s)

	return s
}

// take has s take its wake, unless it is a first map, and the newest commit,
// as poll does; an update observes it as it starts.
func (m *coreMachine) take(s *coreSess) {
	if !s.first {
		<-s.sess.wakes
		m.h.observe(m.snaps[m.committed])
	}

	s.took, s.phase = m.committed, coreTook
}

// end ends s's render as Initial and Update do, or fails it as Update's
// error path does. A render of a node no longer there fails, and its
// session ends.
func (m *coreMachine) end(s *coreSess, ok bool) {
	snap := m.snaps[s.took]
	s.phase = coreIdle

	if s.first {
		snap, _ = m.h.initialState(m.id(s.n), snap)
	}

	at := m.index(snap)

	if !m.alive(s.n, at) {
		s.st.rendered(snap, ErrNodeGone)
		m.leave(s)

		return
	}

	if !ok {
		m.failures++

		s.st.rendered(snap, errInjected)
		s.tried, s.ok = at, false

		return
	}

	changed := s.first || m.views[at][s.n] != m.views[s.held][s.n]
	s.st.rendered(snap, nil)
	s.first, s.held, s.tried, s.ok = false, at, at, true

	if changed {
		s.pending = sentView{ids: m.peers(at, s.n), rev: snap.Rev()}
		m.h.mayHavePeers(s.sess, m.id(s.n), s.pending)
		s.phase = coreWritten
	}
}

// peers is node n's peer view at commit i.
func (m *coreMachine) peers(i, n int) []types.NodeID {
	var out []types.NodeID

	for p := range m.scope.nodes {
		if m.views[i][n]&(1<<p) != 0 {
			out = append(out, m.id(p))
		}
	}

	return out
}

func (m *coreMachine) deliver(s *coreSess) {
	s.st.pending = &s.pending
	s.st.Delivered()
	s.phase = coreIdle
}

func (m *coreMachine) leave(s *coreSess) {
	m.h.Leave(s.sess)
	s.gone = true
}

// reap has the sessions the hub ended leave once nothing is in flight, as
// poll's loop returns on stop.
func (m *coreMachine) reap() {
	for _, s := range m.sess {
		if s.ended && !s.gone && s.phase == coreIdle {
			m.leave(s)
		}
	}
}

func (m *coreMachine) fatalf(format string, args ...any) {
	m.t.Helper()
	m.t.Fatalf("%s\nafter: %v", fmt.Sprintf(format, args...), m.path)
}

// judge holds the sessions to the commit routed to, and the peer history to
// what the hub forgot and what it delivered.
func (m *coreMachine) judge() {
	m.t.Helper()

	// A routing runs whole here, so its end is always a boundary.
	for i, s := range m.sess {
		if !m.live(s) || s.first || s.phase != coreIdle || len(s.sess.wakes) > 0 || s.tried >= m.routed || !m.alive(s.n, m.routed) {
			continue
		}

		if !s.ok {
			m.fatalf("s%d (n%d) failed to render r%d, the hub routed to r%d, and no wake is pending", i, s.n+1, s.tried, m.routed)
		}

		if m.views[s.held][s.n] != m.views[m.routed][s.n] {
			m.fatalf("s%d (n%d) holds r%d's map, stale at r%d, and no wake is pending", i, s.n+1, s.held, m.routed)
		}
	}

	for n := range m.scope.nodes {
		m.h.mu.Lock()
		v, ok := m.h.core.sentPeers[m.id(n)]
		m.h.mu.Unlock()

		switch {
		case !ok:
		case m.deletedAt[n] != 0 && m.deletedAt[n] <= m.routed:
			m.fatalf("n%d was deleted at r%d and forgotten, yet has peer history", n+1, m.deletedAt[n])
		case v.rev < m.histRev[n]:
			m.fatalf("n%d's peer history went back from revision %d to %d", n+1, m.histRev[n], v.rev)
		default:
			m.histRev[n] = v.rev
		}
	}
}

// settle routes, takes, renders and delivers, without failing, until nothing
// is left, one more commit retrying a failure; then every session holds the
// latest commit's value.
func (m *coreMachine) settle() {
	m.t.Helper()

	retried := false

	for range 1000 {
		evs := m.enabled()
		next := slices.IndexFunc(evs, func(e coreEvent) bool {
			return e.kind != coreCommit && e.kind != coreFail && e.kind != coreJoin && e.kind != coreLeave
		})

		if next >= 0 {
			m.apply(evs[next])

			continue
		}

		if !retried && slices.ContainsFunc(m.sess, func(s *coreSess) bool { return m.live(s) && !s.ok }) {
			// A failure no routing went past waits for the next commit,
			// which wakes it whatever it names.
			retried = true

			m.path = append(m.path, coreEvent{kind: coreCommit})
			m.commit(coreEdit{})
			m.judge()

			continue
		}

		for i, s := range m.sess {
			if !m.live(s) || !m.alive(s.n, m.committed) {
				continue
			}

			if !s.ok || s.first || m.views[s.held][s.n] != m.views[m.committed][s.n] {
				m.fatalf("settled: s%d (n%d) holds r%d (ok %t), latest r%d", i, s.n+1, s.held, s.ok, m.committed)
			}
		}

		return
	}

	m.fatalf("the core machine did not settle")
}

// key names the machine's state, the hub's own included, so a walk visits
// each once.
func (m *coreMachine) key() string {
	var b strings.Builder

	fmt.Fprintf(&b, "c%d r%d t%d l%t j%d f%d d%d v%d|", m.committed, m.routed, m.target, m.loaded, m.joins, m.failures, m.dels, m.leaves)

	for i := range m.committed + 1 {
		fmt.Fprintf(&b, "%v%t,", m.views[i][:m.scope.nodes], m.global[i])
	}

	fmt.Fprintf(&b, "%v|", m.deletedAt)

	for _, s := range m.sess {
		fmt.Fprintf(&b, "%d %t %d %d %d %d %t %t %t %d %v;", s.n, s.first, s.phase, s.took, s.held, s.tried, s.ok, s.ended, s.gone, len(s.sess.wakes), s.pending)
	}

	m.h.mu.Lock()
	defer m.h.mu.Unlock()

	fmt.Fprintf(&b, "|L%d|", m.h.latest.Rev())

	for n := range m.scope.nodes {
		v, ok := m.h.core.sentPeers[m.id(n)]
		_, off := m.h.core.offlineAt[m.id(n)]
		fmt.Fprintf(&b, "%t %v %d %v %t %t;", ok, v.ids, v.rev, v.attempts, v.folded, off)
	}

	for i := range m.h.renders.shards {
		sh := &m.h.renders.shards[i]
		if sh.routed == nil && len(sh.done) == 0 && len(sh.failed) == 0 {
			continue
		}

		done := make([]string, 0, len(sh.done))
		for _, d := range sh.done {
			done = append(done, fmt.Sprintf("%d@%d", d.id, d.snap.Rev()))
		}

		slices.Sort(done)

		failed := slices.Sorted(slices.Values(sh.failed))

		var routed uint64
		if sh.routed != nil {
			routed = sh.routed.Rev()
		}

		fmt.Fprintf(&b, "%d:%d %v %v;", i, routed, done, failed)
	}

	return b.String()
}

// exploreCore walks every schedule of every scenario scope allows, each
// state once, and returns how many states it met and how many had nothing
// left to do. A state is reached again by replaying its path on a new hub.
func exploreCore(t *testing.T, snaps []*state.Snapshot, scope coreScope) (int, int) {
	t.Helper()

	replay := func(path []coreEvent) *coreMachine {
		m := newCoreMachine(t, snaps, scope)
		for _, e := range path {
			m.apply(e)
		}

		return m
	}

	seen := map[string]bool{replay(nil).key(): true}
	stack := [][]coreEvent{nil}
	leaves := 0

	for len(stack) > 0 {
		path := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		evs := replay(path).enabled()
		if len(evs) == 0 {
			leaves++

			replay(path).settle()

			continue
		}

		for _, e := range evs {
			next := append(slices.Clip(path), e)

			k := replay(next).key()
			if !seen[k] {
				seen[k] = true

				stack = append(stack, next)
			}
		}
	}

	return len(seen), leaves
}
