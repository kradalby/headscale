package mapper

import (
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/state/statemodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"pgregory.net/rapid"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// regKeys is a node's tunnel keys as its client presented them when it
// registered; re-authentication rotates the node key.
type regKeys struct {
	node  key.NodePublic
	disco key.DiscoPublic
}

// pbtT is what the world driver needs of a test: a *testing.T or a
// *rapid.T, so a property's failures stay rapid's to shrink.
type pbtT interface {
	require.TestingT
	Helper()
	Fatalf(format string, args ...any)
	Logf(format string, args ...any)
	Cleanup(f func())
}

// pbtWorld is a State written from a policymodel world, one State call
// per write: users through the State's user API, the policy through
// SetPolicy, nodes through the State's production entry points where
// production can express the write, else straight into the database row
// and the world (see entry_property_test.go). committed, when set, hears
// of every call; a production call may commit more than once.
type pbtWorld struct {
	t   pbtT
	cfg *types.Config
	s   *state.State
	w   policymodel.World

	committed func(before uint64)
	// docs counts the policy writes so far.
	docs int

	// conns holds each node's connections, oldest first, by epoch; runs
	// counts the runs of connections begun, and elections is the history
	// the documented election reads, advanced at every commit.
	conns     map[types.NodeID][]uint64
	runs      uint64
	elections *policymodel.Elections
	// started is when the last run began, as the State stamped it.
	started time.Time
	// lastExpiryCheck is the expiry sweep's clock, as the server's task
	// loop keeps it.
	lastExpiryCheck time.Time
	// made counts the writes [pbtWorld.session] made, by kind, and each
	// node write by edit kind and the path it took.
	made map[string]int

	// reg is how each node registered; alloc the allocator's last
	// addresses, as predicted; reports counts the client reports made.
	reg     map[types.NodeID]statemodel.Joined
	regkeys map[types.NodeID]regKeys
	alloc   [2]netip.Addr
	reports int
	// kind is the edit being written; cur counts the node write in
	// progress, storing set while a store write commits.
	kind    string
	cur     *nodeWrite
	storing bool
	// unstored leaves the stored judge out of a run narrowed past it.
	unstored bool
}

// The driver is a level the shared judges read.
var _ statemodel.Level = (*pbtWorld)(nil)

func (p *pbtWorld) Model() policymodel.World                 { return p.w }
func (p *pbtWorld) State() *state.State                      { return p.s }
func (p *pbtWorld) Joined(id types.NodeID) statemodel.Joined { return p.reg[id] }
func (p *pbtWorld) Elections() *policymodel.Elections        { return p.elections }

func newPBTWorld(t pbtT, w policymodel.World, configure ...func(*types.Config)) *pbtWorld {
	t.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: ":memory:"},
		},
		ServerURL: "https://headscale.test",
		Policy:    types.PolicyConfig{Mode: types.PolicyModeDB},
		Prefixes:  types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential},
		DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
	}

	for _, c := range configure {
		c(cfg)
	}

	s, err := state.NewState(cfg)
	if err != nil {
		t.Fatalf("state: %v", err)
	}

	t.Cleanup(func() { _ = s.Close() })

	s.SetDERPMap(&tailcfg.DERPMap{
		Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
	})

	p := &pbtWorld{
		t: t, cfg: cfg, s: s, conns: map[types.NodeID][]uint64{}, elections: policymodel.NewElections(), made: map[string]int{},
		reg: map[types.NodeID]statemodel.Joined{}, regkeys: map[types.NodeID]regKeys{},
		alloc: [2]netip.Addr{cfg.Prefixes.V4.Masked().Addr(), cfg.Prefixes.V6.Masked().Addr()},
	}

	p.kind = "start"
	p.write(w)
	p.kind = ""

	return p
}

// call runs one State write and tells committed of it.
func (p *pbtWorld) call(write func()) {
	before := p.s.Snapshot().Rev()

	if p.cur != nil && !p.storing {
		p.cur.prod++
	}

	write()

	if p.s.Snapshot().Rev() != before {
		p.elect()
	}

	if p.committed != nil {
		p.committed(before)
	}
}

// write brings the State from p.w to w: deleted nodes, nodes leaving a
// deleted user ([pbtWorld.leaveUsers]), deleted users, changed and new
// users, the policy, then new and changed nodes (see
// [pbtWorld.register] and [pbtWorld.change]), and holds what production
// stored to w. A single edit touches one of them; a batch (a world written
// from scratch, a step taken back) needs that order — a policy can name a
// user only once the user who would make it ambiguous is gone, and a user
// can take a name only once its holder let it go — and renames in two
// passes, through names of their own, since two users of a batch can
// trade names.
func (p *pbtWorld) write(w policymodel.World) {
	p.t.Helper()

	users, nodes := w.Topology.Build()

	// cur is the world as written so far.
	cur := p.w

	for _, n := range p.w.Topology.Nodes {
		if _, ok := w.Topology.Node(n.ID); !ok {
			p.leave(n)
			cur = cur.Apply(policymodel.Leave{ID: n.ID})
		}
	}

	// built is node i of w as built, with its user as the State holds it,
	// as registration loads it.
	built := func(i int) *types.Node {
		tn := nodes[i]
		if tn.UserID != nil {
			u, err := p.s.GetUserByID(types.UserID(*tn.UserID))
			if err != nil {
				p.t.Fatalf("node %d's user: %v", tn.ID, err)
			}

			tn.User = u
		}

		return tn
	}

	cur, early, mids := p.leaveUsers(cur, w, built)

	for _, u := range p.w.Topology.Users {
		if _, ok := w.Topology.User(u.ID); !ok {
			p.call(func() {
				err := p.s.DeleteUser(types.UserID(u.ID))
				if err != nil {
					p.t.Fatalf("delete user %d: %v", u.ID, err)
				}
			})

			p.forgetKeys(u.ID)
		}
	}

	var changed, added []types.User

	for _, u := range users {
		was, ok := p.w.Topology.User(u.ID)
		now, _ := w.Topology.User(u.ID)

		switch {
		case !ok:
			added = append(added, u)
		case was != now:
			changed = append(changed, u)
		}
	}

	update := func(id uint, set func(*types.User)) {
		p.call(func() {
			_, err := p.s.UpdateUser(types.UserID(id), func(cur *types.User) error {
				set(cur)

				return nil
			})
			if err != nil {
				p.t.Fatalf("update user %d: %v", id, err)
			}
		})
	}

	if len(changed)+len(added) > 1 {
		for _, u := range changed {
			if was, _ := p.w.Topology.User(u.ID); was.Name != u.Name {
				update(u.ID, func(cur *types.User) { cur.Name = fmt.Sprintf("pbt-renaming-%d", u.ID) })
			}
		}
	}

	for _, u := range changed {
		update(u.ID, func(cur *types.User) {
			cur.Name, cur.Email, cur.Provider, cur.ProviderIdentifier = u.Name, u.Email, u.Provider, u.ProviderIdentifier
		})
	}

	for _, u := range added {
		u.Model = gorm.Model{ID: u.ID}

		p.call(func() {
			_, err := p.s.CreateUser(u)
			if err != nil {
				p.t.Fatalf("create user %d: %v", u.ID, err)
			}
		})
	}

	if string(w.Policy.HuJSON()) != string(p.w.Policy.HuJSON()) || len(p.w.Topology.Users) == 0 {
		p.docs++
		p.call(func() {
			_, err := p.s.SetPolicy(w.Policy.HuJSON())
			if err != nil {
				p.t.Fatalf("policy: %v", err)
			}
		})
	}

	cur.Policy, cur.Topology.Users, cur.Topology.NextUserID = w.Policy, w.Topology.Users, w.Topology.NextUserID

	var fresh []newcomer

	for i, n := range w.Topology.Nodes {
		was, existed := p.w.Topology.Node(n.ID)
		if mid, ok := mids[n.ID]; ok {
			was = mid
		}

		if existed && reflect.DeepEqual(was, n) || early[n.ID] {
			continue
		}

		tn := built(i)

		if !existed {
			fresh = append(fresh, newcomer{n: n, tn: tn})

			continue
		}

		p.change(cur, was, n, tn)
		cur = withNode(cur, n)
	}

	if len(fresh) > 0 {
		p.register(fresh, w)
	}

	p.w = w
	p.requireStored(p.kindOr("a write"))
}

// edit commits e, alone.
func (p *pbtWorld) edit(e policymodel.Edit) {
	p.kind = strings.TrimPrefix(fmt.Sprintf("%T", e), "policymodel.")
	if r, ok := e.(policymodel.Retag); ok && len(r.Tags) == 0 {
		p.kind = "Login"
	}

	p.write(p.w.Apply(e))
	p.kind = ""
}

// leaveUsers writes, of w's nodes, those leaving a user the batch deletes,
// under the document as it stands, before the deletion: headscale deletes
// no user who owns a node. Tags that document does not define a node
// takes after the document's write, holding meanwhile those it does, or,
// with none, the target's through the store ([pbtWorld.storeTags]). It returns the world as
// written, the nodes written whole, and where the others stand.
func (p *pbtWorld) leaveUsers(cur, w policymodel.World, built func(int) *types.Node) (policymodel.World, map[types.NodeID]bool, map[types.NodeID]policymodel.Node) {
	early := map[types.NodeID]bool{}
	mids := map[types.NodeID]policymodel.Node{}

	for i, n := range w.Topology.Nodes {
		was, existed := p.w.Topology.Node(n.ID)
		if _, kept := w.Topology.User(was.User); !existed || was.Tagged() || kept || reflect.DeepEqual(was, n) {
			continue
		}

		defined := slices.DeleteFunc(slices.Clone(n.Tags), func(t int) bool { return !cur.Policy.DefinesTag(t) })

		switch {
		case len(defined) == len(n.Tags):
			p.change(cur, was, n, built(i))
			cur = withNode(cur, n)
			early[n.ID] = true
		case len(defined) > 0:
			next := cur.Apply(policymodel.Retag{ID: n.ID, Tags: defined})
			mid, _ := next.Topology.Node(n.ID)
			p.change(cur, was, mid, next.Topology.BuildNode(mid))
			cur, mids[n.ID] = next, mid
		default:
			next := cur.Apply(policymodel.Retag{ID: n.ID, Tags: n.Tags})
			mid, _ := next.Topology.Node(n.ID)

			done := p.begin(p.kindOr("batch"))
			p.storeTags(n.ID, built(i).Tags)
			done()

			cur, mids[n.ID] = next, mid
		}
	}

	return cur, early, mids
}

// forgetKeys drops the pre-auth keys user uid made for itself, which go
// with it: a node it tagged away can no longer restart with one.
func (p *pbtWorld) forgetKeys(uid uint) {
	for id, ri := range p.reg {
		if ri.KeyUser == uid && !ri.Tagged {
			ri.Key = ""
			p.reg[id] = ri
		}
	}
}

// withNode is w with n in place of the node of its ID.
func withNode(w policymodel.World, n policymodel.Node) policymodel.World {
	w.Topology.Nodes = slices.Clone(w.Topology.Nodes)

	if i := slices.IndexFunc(w.Topology.Nodes, func(m policymodel.Node) bool { return m.ID == n.ID }); i >= 0 {
		w.Topology.Nodes[i] = n
	}

	return w
}

// pbtChance is true about once in k draws, and false shrunk.
func pbtChance(t *rapid.T, k int, label string) bool {
	return rapid.IntRange(0, k-1).Draw(t, label) == k-1
}

// newDrawnWorld is newPBTWorld with policy.filter_chunks drawn. A
// configuration can only pin an option on, so its caller pins the suite's
// switch off ([state.TestFilterChunksEnv]) and each case runs as drawn.
func newDrawnWorld(t *rapid.T, w policymodel.World) *pbtWorld {
	chunks := rapid.Bool().Draw(t, "filter-chunks")

	p := newPBTWorld(t, w, func(cfg *types.Config) { cfg.Policy.FilterChunks = chunks })
	if got := p.s.Snapshot().FilterChunks(); got != chunks {
		t.Fatalf("test sanity: filter_chunks=%t built a world with %t", chunks, got)
	}

	return p
}

// scenarioRun plays a policymodel scenario against a State, its hub's
// watcher routing in step, with a session per node that renders only
// where the scenario says it reads: the start, then the nodes each step
// names. A session that does not read keeps what it rendered last, for
// as many commits as it does not read.
type scenarioRun struct {
	t        *rapid.T
	p        *pbtWorld
	w        *steppedWatcher
	h        *Hub
	coalesce bool
	mixed    bool
	sess     map[types.NodeID]*scenarioSess
	// commits are the snapshot of each commit since the start, the start
	// first, with the edit that made it.
	commits []scenarioCommit
	edit    policymodel.Edit
	// kind, when set, names what the next commits are, for want of an edit.
	kind string

	fresh  map[freshKey]*netMap
	routes map[[2]uint64]routeAnswer
	reach  *scenarioReach
	// docs is the policy writes made by each commit's revision.
	docs map[uint64]int
	// dropped is Route's answers with each part taken out, by pair.
	dropped droppedWakes
}

type scenarioCommit struct {
	snap *state.Snapshot
	edit policymodel.Edit
	kind string
}

type scenarioSess struct {
	id     types.NodeID
	st     *Stream
	capVer tailcfg.CapabilityVersion
	client *modelClient
	reads  []sessionRead
}

// sessionRead is a session's render of snap, and what it then held.
type sessionRead struct {
	snap *state.Snapshot
	held *netMap
}

type freshKey struct {
	rev uint64
	id  types.NodeID
	cv  tailcfg.CapabilityVersion
}

type routeAnswer struct {
	all    bool
	wake   map[types.NodeID]struct{}
	change state.Change
}

// scenarioReach counts what the scenarios reached and what Route did with
// it: pairs judged, sessions they had to wake, and, between neighbouring
// commits, sessions woken that then had nothing to send, by the edit that
// made the commit and whom the change named.
type scenarioReach struct {
	pairs, stale, pairsBetween, staleBetween int
	reads, lagged                            int
	woken, idle                              map[string]int
	// joinWoken counts, by [ruleClass], the receivers a join in capability
	// mode wakes that are served capability form and recut by no D7 rule;
	// joinNamed those of them it names in Filters; joinIdle those of them
	// whose filter and SSH policy stayed.
	joinWoken, joinNamed, joinIdle map[string]int
	wakes                          *wakeTally
	// writes counts the writes made through production entry points, and
	// scripts the scripts played, by kind.
	writes, scripts map[string]int
}

// TestSessionsFollowGeneratedScenarios plays generated scenarios
// (policymodel's: arbitrary policies, topologies and steps, edits one
// commit each, now and then a node's endpoint moving after a step or a
// write through a production entry point, most cases ending with a script
// that moves one part of what a viewer is sent alone) against a State, a
// hub whose watcher routes after every commit or once per step, and a
// session per node rendering where the scenario's steps read; each source
// mode a subtest, filter_chunks drawn per case. It holds two properties.
//
// Route is sound (P10.1): for every session, every snapshot X it rendered
// and every later commit C, if what a fresh render of C would send the
// session holding X's render is not nothing, Route(X, C, C.Since(X))
// wakes it. X before C's neighbour is the coalesced routing's pair, and X
// strictly between a routing's ends is what the render log asks: every
// pair is one the hub asks. It judges by rendering afresh, with caches of
// its own and filters cut afresh; it shares render and diff with what it
// judges (they are held to the client below), not routing.
//
// Sessions that lag converge (L11): at every read, the session's render,
// made with the hub's shared caches after any number of commits it did not
// read, equals a fresh render, and the responses it returned, applied in
// order to what its client held since its first map, give a fresh
// session's client.
//
// Over-waking is allowed and counted, not judged: a session woken between
// neighbouring commits whose fresh renders are equal sends nothing. One
// part is a law: in capability mode, under a policy whose rules routing
// narrows (see [ruleClass]), a join names in Filters no receiver served
// capability form at both ends, other than the joiner and the exit nodes
// and subnet routers D7 recuts, whose filter and SSH policy stayed.
//
// Routing is judged for every part of a change it reads: each must be what
// alone wakes some stale pair, or a routing that forgot it would pass (see
// [requireAlone]).
func TestSessionsFollowGeneratedScenarios(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")
	t.Setenv(state.TestFilterChunksEnv, "false")

	for _, capSources := range []bool{false, true} {
		t.Run(fmt.Sprintf("capability=%t", capSources), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))

			reach := &scenarioReach{
				woken: map[string]int{}, idle: map[string]int{}, joinWoken: map[string]int{}, joinNamed: map[string]int{}, joinIdle: map[string]int{},
				wakes: newWakeTally(), writes: map[string]int{}, scripts: map[string]int{},
			}

			rapid.Check(t, func(t *rapid.T) { playScenario(t, reach) })

			t.Logf("pairs judged %d (%d needed a wake), of them strictly coalesced %d (%d); reads %d, after unread commits %d",
				reach.pairs, reach.stale, reach.pairsBetween, reach.staleBetween, reach.reads, reach.lagged)
			t.Logf("wakes: %s", reach.wakes)
			t.Logf("writes through production entry points %v; scripts played %v", reach.writes, reach.scripts)

			prod, all := carried(reach.writes)
			t.Logf("node writes that reached a production entry point %d of %d", prod, all)

			if f := flag.Lookup("rapid.checks"); !testing.Short() && f != nil {
				n, err := strconv.Atoi(f.Value.String())
				if err == nil && n >= 1000 {
					requireCarried(t, reach.writes)
				}
			}

			byField, idleByField := map[string]int{}, map[string]int{}

			for _, kind := range slices.Sorted(maps.Keys(reach.woken)) {
				t.Logf("woken between neighbouring commits, %s: %d, of them with nothing to send %d", kind, reach.woken[kind], reach.idle[kind])

				field := kind[strings.LastIndex(kind, " ")+1:]
				byField[field] += reach.woken[kind]
				idleByField[field] += reach.idle[kind]
			}

			for _, field := range slices.Sorted(maps.Keys(byField)) {
				t.Logf("woken by %s: %d, with nothing to send %d", field, byField[field], idleByField[field])
			}

			t.Logf("joins: capability-form receivers woken, by rule class %v; of them named in Filters %v; of those, filter and SSH policy unmoved %v",
				reach.joinWoken, reach.joinNamed, reach.joinIdle)

			// Not a law, a ceiling: what share of the sessions woken between
			// neighbouring commits have nothing to send, well above what a
			// deep run measures in either mode, so a routing that starts
			// waking far more than it reaches shows.
			//
			// TODO(kradalby): overwake/route-viewers,
			// overwake/announce-readers, overwake/routers-cover,
			// overwake/all-routers and the Filters keys ruleClass names:
			// lower the ceiling as each goes.
			woken, idle := 0, 0
			for kind, n := range reach.woken {
				woken, idle = woken+n, idle+reach.idle[kind]
			}

			t.Logf("woken between neighbouring commits %d, with nothing to send %d", woken, idle)

			if !testing.Short() && idle*100 > woken*37 {
				t.Errorf("%d of %d sessions woken between neighbouring commits had nothing to send", idle, woken)
			}

			if !testing.Short() && reach.staleBetween == 0 {
				t.Errorf("no coalesced pair needed a wake")
			}

			requireAlone(t, reach.wakes, capSources)
		})
	}
}

// requireAlone fails a run in which some part of a change Route reads
// woke no stale pair alone: a routing that forgot it would leave that
// session stale with nothing else to cover, and no case would show it. A
// deep run asks it of every part the mode makes alone, the default run of
// those it reaches by many. In capability mode a viewer whose routes move
// by its own membership is restamped too, so RouteViewers stands alone
// in address mode only.
func requireAlone(t *testing.T, w *wakeTally, capSources bool) {
	t.Helper()

	if testing.Short() {
		return
	}

	deep := false

	if f := flag.Lookup("rapid.checks"); f != nil {
		n, err := strconv.Atoi(f.Value.String())
		deep = err == nil && n >= 1000
	}

	for _, f := range wakeFields {
		floor, ok := aloneFloors[f.name]
		if !ok || f.name == "RouteViewers" && capSources {
			continue
		}

		if deep {
			floor = max(floor, 1)
		}

		if floor > 0 && w.sole[f.name] < floor {
			t.Errorf("%d stale pairs were woken by %s alone, want %d at least", w.sole[f.name], f.name, floor)
		}
	}

	if w.selective-w.coalesced == 0 || w.coalesced == 0 {
		t.Errorf("stale pairs woken selectively: %d, of them coalesced %d", w.selective, w.coalesced)
	}
}

// aloneFloors are the stale pairs a run of the default length wakes by
// each part alone at least, far below what runs measure; zero asks it of
// deep runs only, the rest coming in bursts, a script's case at a time.
// AllRouters is never asked: every policy write that sets it moves side
// sets too.
var aloneFloors = map[string]int{
	"Nodes": 25, "Primaries": 0, "PeerSets": 0, "Filters": 0, "Caps": 0, "RouteViewers": 0, "Routers": 0,
}

// scenarioSteps is how long the route property's scenarios run: half as
// long under the race detector, which watches the hub's goroutines, not
// what the scenario says.
func scenarioSteps() int {
	if util.RaceEnabled {
		return 5
	}

	return 10
}

func playScenario(t *rapid.T, reach *scenarioReach) {
	s := policymodel.Scenarios(scenarioSteps()).Draw(t, "scenario")
	coalesce := pbtChance(t, 3, "coalesce")
	mixed := pbtChance(t, 4, "mixed-versions")

	r := &scenarioRun{
		t: t, coalesce: coalesce, mixed: mixed, reach: reach,
		sess: map[types.NodeID]*scenarioSess{}, fresh: map[freshKey]*netMap{}, routes: map[[2]uint64]routeAnswer{},
		docs: map[uint64]int{}, dropped: droppedWakes{},
	}

	r.p = newDrawnWorld(t, s.Start)
	r.h = NewHub()
	r.w = newSteppedWatcher(t, r.h, r.p.s)
	r.p.committed = r.committed

	start := r.p.s.Snapshot()
	r.commits = append(r.commits, scenarioCommit{snap: start})
	r.docs[start.Rev()] = r.p.docs

	for _, n := range start.ListNodes().All() {
		r.read(n.ID())
	}

	for i, st := range s.Steps {
		// Now and then a node's endpoint moves too: the write production
		// sees most, which names the node and the nodes that see it.
		touch := pbtChance(t, 3, "endpoint")
		who := rapid.IntRange(0, 15).Draw(t, "who")

		for _, e := range st.Edits {
			r.edit = e
			r.p.edit(e)
		}

		if nodes := r.p.s.Snapshot().ListNodes(); touch && nodes.Len() > 0 {
			r.edit = nil
			r.p.endpoint(nodes.At(who%nodes.Len()).ID(), []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i+1))}) //nolint:gosec // small
		}

		// Now and then a client, the HA prober or an operator writes too,
		// through its production entry point.
		if pbtChance(t, 3, "session-write") {
			sw := sessionWrites.Draw(t, "session")
			r.edit, r.kind = nil, "session "+sw.Kind.String()

			if did := r.p.session(sw); did != "" {
				t.Logf("step %d: %s", i+1, did)
			}

			r.kind = ""
		}

		r.w.settle()

		for _, id := range st.Reads {
			r.read(id)
		}

		t.Logf("step %d done at r%d", i+1, r.p.s.Snapshot().Rev())
	}

	defer func() {
		for k, n := range r.p.made {
			reach.writes[k] += n
		}
	}()

	// One case in four ends with a script moving one part of what a
	// viewer is sent alone, most of its acts read by every session; none
	// in a large world ([scriptedWorld]) or under the race detector.
	if pbtChance(t, 4, "script") && !util.RaceEnabled && len(s.Start.Topology.Nodes) <= scriptedWorld {
		name, acts := drawScript(t, r.p.w)
		r.edit = nil
		reach.scripts[name]++

		for _, a := range acts {
			r.kind = "script " + name
			t.Logf("%s: %s", name, a.play(r.p))
			r.kind = ""

			r.w.settle()

			if rapid.IntRange(0, 3).Draw(t, "script-reads") > 0 {
				for _, n := range r.p.s.Snapshot().ListNodes().All() {
					r.read(n.ID())
				}
			}
		}
	}
}

// committed routes, unless routings coalesce a step's commits, and judges
// the new commit.
func (r *scenarioRun) committed(before uint64) {
	r.w.committed(before)

	snap := r.p.s.Snapshot()
	if snap.Rev() == before {
		return
	}

	if !r.coalesce {
		r.w.settle()
	}

	r.commits = append(r.commits, scenarioCommit{snap: snap, edit: r.edit, kind: r.kind})
	r.docs[snap.Rev()] = r.p.docs

	for id := range r.sess {
		if _, ok := snap.GetNode(id); !ok {
			delete(r.sess, id)
		}
	}

	r.judgeRoute(len(r.commits) - 1)
	r.judgeNewReaders(len(r.commits) - 1)
	r.countWakes(len(r.commits) - 1)
}

// judgeNewReaders pins why Route's readers walk needs no new-reader half:
// the peers cell and the readers it is asked for are one structure read
// each way, so a node whose view gains a changed node is named by the same
// change's PeerSets already, and a viewer PeerSets did not name is an old
// reader, which the walk wakes. It fails once the two diverge — the point
// where dropping the walk's new-reader half would leave a session stale.
func (r *scenarioRun) judgeNewReaders(j int) {
	c := r.commits[j].snap
	x := r.commits[j-1].snap
	change := c.Since(x)

	if change.Global {
		return
	}

	viewed := slices.Concat(change.Nodes, change.Primaries, change.Caps, change.Routers)
	if change.AllRouters {
		viewed = slices.Concat(viewed, x.RoutedNodes(), c.RoutedNodes())
	}

	for _, id := range viewed {
		var old []types.NodeID

		for _, l := range x.PeerReaders(id) {
			old = append(old, l...)
		}

		for _, l := range c.PeerReaders(id) {
			for _, v := range l {
				if slices.Contains(old, v) || slices.Contains(change.PeerSets, v) {
					continue
				}

				r.t.Errorf("r%d: n%d newly reads n%d, which changed, and the change names neither it nor its peers: Route's readers walk is its only cover",
					c.Rev(), v, id)
			}
		}
	}
}

// read has id's session render the latest snapshot, its first map if it
// has none, and holds the render to a fresh one.
func (r *scenarioRun) read(id types.NodeID) {
	t := r.t
	snap := r.p.s.Snapshot()
	ss := r.sess[id]

	var (
		resps []*tailcfg.MapResponse
		err   error
	)

	if ss == nil {
		ss = &scenarioSess{id: id, capVer: capVer}
		if r.mixed && id%2 == 1 {
			ss.capVer = capver.MinSupportedCapabilityVersion
		}

		ss.st = NewStream(r.p.cfg, r.h, id, ss.capVer)
		ss.st.Attach(r.h.Join(id, func() {}))
		r.sess[id] = ss

		resps, err = ss.st.Initial(snap)
		if err == nil {
			ss.client = newModelClient(resps[0])
			resps = resps[1:]
		}
	} else {
		resps, err = ss.st.Update(snap)
	}

	if err != nil {
		t.Fatalf("n%d renders r%d: %v", id, snap.Rev(), err)
	}

	ss.st.Delivered()

	for _, resp := range resps {
		ss.client.apply(resp)
	}

	r.reach.reads++
	if n := len(ss.reads); n > 0 && ss.reads[n-1].snap.Rev()+1 < snap.Rev() {
		r.reach.lagged++
	}

	ss.reads = append(ss.reads, sessionRead{snap: snap, held: ss.st.sent})
	t.Logf("n%d reads r%d: %s", id, snap.Rev(), describeResponses(resps))

	requireRenderFresh(t, r.p.cfg, snap, id, ss.capVer, ss.st.sent, ss.client)
}

// freshAt renders id at snap with caches of its own and filters cut
// afresh.
func (r *scenarioRun) freshAt(snap *state.Snapshot, id types.NodeID, cv tailcfg.CapabilityVersion) *netMap {
	k := freshKey{rev: snap.Rev(), id: id, cv: cv}
	if nm, ok := r.fresh[k]; ok {
		return nm
	}

	vc := &versionCache{}
	rd := &renderer{cfg: r.p.cfg, nodeID: id, capVer: cv, peerCapVer: peerCapVer(cv), renders: &vc.renders, classes: &vc.classes}

	nm, err := rd.render(snap.Uncached())
	if err != nil {
		r.t.Fatalf("n%d: rendering r%d afresh: %v", id, snap.Rev(), err)
	}

	r.fresh[k] = nm

	return nm
}

// route is Route over x and c, as the hub and the render log ask it.
func (r *scenarioRun) route(x, c *state.Snapshot) routeAnswer {
	k := [2]uint64{x.Rev(), c.Rev()}
	if a, ok := r.routes[k]; ok {
		return a
	}

	change := c.Since(x)
	all, wake := Route(x, c, change)
	a := routeAnswer{all: all, wake: wake, change: change}
	r.routes[k] = a

	return a
}

func (a routeAnswer) has(id types.NodeID) bool {
	_, ok := a.wake[id]

	return a.all || ok
}

// judgeRoute holds Route to every pair of a snapshot a live session
// rendered and commit j.
func (r *scenarioRun) judgeRoute(j int) {
	c := r.commits[j].snap

	for _, id := range slices.Sorted(maps.Keys(r.sess)) {
		ss := r.sess[id]
		fresh := r.freshAt(c, id, ss.capVer)

		for _, rd := range ss.reads {
			out := diff(rd.held, fresh, nil)
			between := rd.snap.Rev()+1 < c.Rev()

			r.reach.pairs++
			if between {
				r.reach.pairsBetween++
			}

			if len(out) == 0 {
				continue
			}

			r.reach.stale++
			if between {
				r.reach.staleBetween++
			}

			ans := r.route(rd.snap, c)
			if ans.has(id) {
				r.reach.wakes.add(r.dropped, rd.snap, c, ans.all, ans.change, id, between, r.docs[rd.snap.Rev()] != r.docs[c.Rev()], r.commitKind(j))
			}

			if !ans.has(id) {
				r.t.Fatalf("route: n%d rendered r%d; a fresh render of r%d would send it %s, and Route(r%d, r%d) does not wake it",
					id, rd.snap.Rev(), c.Rev(), describeResponses(out), rd.snap.Rev(), c.Rev())
			}
		}
	}
}

// commitKind names what made commit j: its edit, or what wrote it.
func (r *scenarioRun) commitKind(j int) string {
	switch c := r.commits[j]; {
	case c.kind != "":
		return c.kind
	case c.edit == nil:
		return "Endpoint"
	default:
		return strings.TrimPrefix(fmt.Sprintf("%T", c.edit), "policymodel.")
	}
}

// countWakes counts, between commit j and the one before, the sessions
// Route wakes and those of them whose fresh renders are equal; and holds
// joins in capability mode to naming no capability-form receiver in
// Filters whose filter stayed.
func (r *scenarioRun) countWakes(j int) {
	a, c := r.commits[j-1].snap, r.commits[j].snap

	kind := r.commitKind(j)

	ans := r.route(a, c)

	var change state.Change
	if !ans.all {
		change = c.Since(a)
	}

	join, isJoin := r.commits[j].edit.(policymodel.Join)

	for _, n := range c.ListNodes().All() {
		id := n.ID()
		if _, ok := a.GetNode(id); !ok || !ans.has(id) {
			continue
		}

		before, after := r.freshAt(a, id, capVer), r.freshAt(c, id, capVer)
		idle := len(diff(before, after, nil)) == 0

		named := "a reader"

		switch {
		case ans.all:
			named = "all"
		case slices.Contains(change.Filters, id):
			named = "Filters"
		case slices.Contains(change.PeerSets, id):
			named = "PeerSets"
		case slices.Contains(change.Nodes, id):
			named = "Nodes"
		case slices.Contains(change.Caps, id):
			named = "Caps"
		case slices.Contains(change.Primaries, id):
			named = "Primaries"
		case slices.Contains(change.RouteViewers, id):
			named = "RouteViewers"
		}

		r.reach.woken[kind+" "+named]++
		if idle {
			r.reach.idle[kind+" "+named]++
		}

		// TODO(kradalby): overwake/policy-facts-moved,
		// overwake/routers-wholesale: the joiner and exit nodes and subnet
		// routers stay out of the law while routing names them wholesale.
		if !isJoin || !c.CapabilitySources() || ans.all || id == join.Node.ID ||
			!capabilityForm(a.ReceiverFacts(id)) || !capabilityForm(c.ReceiverFacts(id)) || routes(a, id) || routes(c, id) {
			continue
		}

		class := ruleClass(r.p.w)
		if class == "plain" {
			class = ruleClass(r.p.w.Apply(join))
		}

		r.reach.joinWoken[class]++

		if !slices.Contains(change.Filters, id) {
			continue
		}

		r.reach.joinNamed[class]++

		if !reflect.DeepEqual(before.filter, after.filter) || !reflect.DeepEqual(before.ssh, after.ssh) {
			continue
		}

		r.reach.joinIdle[class]++

		if class == "plain" {
			r.t.Fatalf("route: n%d joined at r%d; n%d, served capability form, is named in Filters, and its filter and SSH policy stayed",
				join.Node.ID, c.Rev(), id)
		}
	}
}

// ruleClass names what in w routing names receivers in every form for,
// by decision: SSH, which the compile routes; an app capability or a
// protocol without ports, whose sources capability form writes as
// addresses; a via grant, whose tags' holders are named when anything of
// it moved; a self destination, whose owners are named in every form
// unless every source goes as their capability; an address two nodes
// hold, which turns a selector's capability into addresses. "plain" is
// none of them. A class goes, and the law covers it, when its key does.
func ruleClass(w policymodel.World) string {
	// TODO(kradalby): overwake/ssh-changed-nodes.
	if len(w.Policy.SSH) > 0 {
		return "ssh"
	}

	held := map[netip.Addr]bool{}

	for _, n := range w.Topology.Nodes {
		for _, a := range n.Addrs() {
			// TODO(kradalby): overwake/owner-sharing-flip,
			// overwake/delta-address-holders.
			if held[a] {
				return "shared-address"
			}

			held[a] = true
		}
	}

	portless := func(p int) bool { return slices.Contains([]string{"icmp", "ipv6-icmp", "gre"}, policymodel.Protos[p]) }
	self := false

	for _, r := range w.Policy.ACLs {
		if portless(r.Proto) {
			return "app-or-portless"
		}

		self = self || slices.ContainsFunc(r.Dst, func(d policymodel.Dest) bool { return d.Sel.Kind == policymodel.SelSelf })
	}

	for _, g := range w.Policy.Grants {
		// TODO(kradalby): overwake/address-pair-destinations,
		// overwake/companion-receivers.
		if len(g.App) > 0 || slices.ContainsFunc(g.IP, func(ip policymodel.IP) bool { return portless(ip.Proto) }) {
			return "app-or-portless"
		}

		// TODO(kradalby): overwake/via-tag-holders.
		if len(g.Via) > 0 {
			return "via"
		}

		self = self || slices.ContainsFunc(g.Dst, func(d policymodel.Dest) bool { return d.Sel.Kind == policymodel.SelSelf })
	}

	// TODO(kradalby): overwake/self-owners-every-form.
	if self {
		return "self"
	}

	return "plain"
}

// routes reports whether id serves an exit or a subnet route in snap.
func routes(snap *state.Snapshot, id types.NodeID) bool {
	n, ok := snap.GetNode(id)

	return ok && (n.IsExitNode() || len(n.SubnetRoutes()) > 0)
}
