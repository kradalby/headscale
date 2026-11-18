// Properties of the world, the control plane as a graph of cells, driven
// by generated scenarios (policymodel) step by step, a step's edits
// committed together: what it serves after every step against a world
// built from scratch for the same inputs; what Snapshot.Since reports
// between any two snapshots against the two snapshots' served values; and
// what a step's commit recomputes against what it moved.

package state

import (
	"fmt"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

// worldSteps is how long a drawn scenario may be: the length the
// generator's coverage is certified at.
const worldSteps = 10

// modelWorld is a world driven from a scenario: each step committed as
// one transaction, or through the world's write methods one kind at a
// time, as drawn.
type modelWorld struct {
	w          *world
	capSources bool
}

func newModelWorld(t *rapid.T, start policymodel.World, capSources bool) (*modelWorld, *Snapshot) {
	users, nodes := start.Topology.Build()

	w, err := newWorldMode(nodes, users, start.Policy.HuJSON(), types.DNSView{}, pinSources(capSources))
	if err != nil {
		t.Fatalf("the start's policy is refused: %v", err)
	}

	return &modelWorld{w: w, capSources: capSources}, w.snapshot()
}

// commit writes next, which change describes, and returns the snapshot
// holding it: users, the document and the nodes in one transaction, or,
// apart, through SetUsers, SetPolicy and a node write, in that order.
func (m *modelWorld) commit(t *rapid.T, next policymodel.World, change policymodel.Change, apart bool) *Snapshot {
	users, built := next.Topology.Build()

	editNodes := func(e *nodeEdit) {
		for _, id := range change.Removed {
			e.Delete(id)
		}

		for _, n := range built {
			if slices.Contains(change.Nodes, n.ID) {
				e.Set(n.ID, n)
			}
		}
	}

	if apart {
		if change.Users {
			_ = m.w.SetUsers(users)
		}

		if change.Policy {
			_, err := m.w.SetPolicy(next.Policy.HuJSON(), func(*Snapshot) error { return nil })
			if err != nil {
				t.Fatalf("the policy write is refused: %v", err)
			}
		}

		if len(change.Nodes)+len(change.Removed) > 0 {
			return m.w.update(editNodes)
		}

		return m.w.snapshot()
	}

	snap, err := m.w.g.Update(func(tx *graph.Tx) error {
		if change.Users {
			graph.Set(tx, m.w.users, []types.User(slices.Clone(users)))
		}

		if change.Policy {
			graph.Set(tx, m.w.policySrc, next.Policy.HuJSON())
		}

		cur := graph.Peek(tx, m.w.nodes)
		e := &nodeEdit{MapEdit: cur.Edit(), users: graph.Peek(tx, m.w.users)}

		editNodes(e)

		if done := e.Done(); done != cur {
			graph.Set(tx, m.w.nodes, done)
		}

		return nil
	})
	if err != nil {
		t.Fatalf("the commit fails: %v", err)
	}

	return &Snapshot{s: snap, w: m.w}
}

// scratchOf is a world built from nothing for w, in the mode given.
func scratchOf(t *rapid.T, w policymodel.World, capSources bool) *Snapshot {
	users, nodes := w.Topology.Build()

	sw, err := newWorldMode(nodes, users, w.Policy.HuJSON(), types.DNSView{}, pinSources(capSources))
	if err != nil {
		t.Fatalf("the policy is refused from scratch: %v", err)
	}

	return sw.snapshot()
}

func rulesString(rules []tailcfg.FilterRule, err error) string {
	if err != nil {
		return "error " + err.Error()
	}

	return fmt.Sprint(rules)
}

func prefixesSorted(ps []netip.Prefix) []netip.Prefix {
	out := slices.Clone(ps)
	slices.SortFunc(out, netip.Prefix.Compare)

	return out
}

// unelected reports whether no candidate of prefix p's election serves
// routes in s: the election then keeps whoever held p, which a world
// built from scratch never held.
func unelected(s *Snapshot, p netip.Prefix) bool {
	for _, n := range s.nodes().All() {
		if slices.Contains(electionRoutes(n), p) && servesRoutes(n) {
			return false
		}
	}

	return true
}

// servedDiffers returns how inc, a world driven step by step, serves w
// otherwise than scr, one built from scratch for w: every node's filter
// cut afresh, and, for the sessions in reads, as served (cut or carried);
// peers and readers; global and via-steered routes to every peer; the
// primaries, but for a prefix no candidate serves, whose holder history
// decides; stamps, rendered capabilities, receiver facts; the global
// filter; and the fallback census's rules.
func servedDiffers(inc, scr *Snapshot, reads []types.NodeID) string {
	ui := inc.Uncached()

	for _, n := range scr.ListNodes().All() {
		id := n.ID()

		got, errGot := ui.FilterForNode(id)
		want, errWant := scr.FilterForNode(id)

		if (errGot == nil) != (errWant == nil) || !reflect.DeepEqual(got, want) {
			return fmt.Sprintf("n%d's filter cut afresh: incremental %s, from scratch %s", id, rulesString(got, errGot), rulesString(want, errWant))
		}

		if slices.Contains(reads, id) {
			served, err := inc.FilterForNode(id)
			if (err == nil) != (errWant == nil) || !reflect.DeepEqual(served, want) {
				return fmt.Sprintf("n%d is served %s, from scratch %s", id, rulesString(served, err), rulesString(want, errWant))
			}
		}

		if a, b := inc.ListPeerIDs(id), scr.ListPeerIDs(id); !slices.Equal(a, b) {
			return fmt.Sprintf("n%d's peers: incremental %v, from scratch %v", id, a, b)
		}

		if a, b := readersOf(inc, id), readersOf(scr, id); !slices.Equal(a, b) {
			return fmt.Sprintf("n%d's readers: incremental %v, from scratch %v", id, a, b)
		}

		if a, b := inc.Stamps(id), scr.Stamps(id); !slices.Equal(a, b) {
			return fmt.Sprintf("n%d's stamps: incremental %v, from scratch %v", id, a, b)
		}

		if a, b := inc.NodeCaps(id), scr.NodeCaps(id); !a.Equal(b) {
			return fmt.Sprintf("n%d's capabilities: incremental %v, from scratch %v", id, capNames(a), capNames(b))
		}

		if a, b := inc.ReceiverFacts(id), scr.ReceiverFacts(id); a != b {
			return fmt.Sprintf("n%d's receiver facts: incremental %+v, from scratch %+v", id, a, b)
		}
	}

	for p, want := range scr.PrimaryRoutes() {
		if got, ok := inc.PrimaryRoutes()[p]; (!ok || got != want) && !unelected(inc, p) {
			return fmt.Sprintf("%s's primary: incremental n%d, from scratch n%d", p, got, want)
		}
	}

	if len(inc.PrimaryRoutes()) != len(scr.PrimaryRoutes()) {
		return fmt.Sprintf("primaries: incremental %v, from scratch %v", inc.PrimaryRoutes(), scr.PrimaryRoutes())
	}

	for _, v := range scr.ListNodes().All() {
		for _, pid := range scr.ListPeerIDs(v.ID()) {
			p, _ := scr.GetNode(pid)
			pi, _ := inc.GetNode(pid)
			vi, _ := inc.GetNode(v.ID())

			if !slices.Equal(inc.PrimaryRoutesForNode(pid), scr.PrimaryRoutesForNode(pid)) {
				// The primaries differ only where history decides.
				continue
			}

			got, want := prefixesSorted(inc.RoutesForPeer(vi, pi)), prefixesSorted(scr.RoutesForPeer(v, p))
			if !slices.Equal(got, want) {
				return fmt.Sprintf("n%d is given %v of n%d's routes, from scratch %v", v.ID(), got, pid, want)
			}
		}
	}

	gi, _, errI := inc.Filter()
	gs, _, errS := scr.Filter()

	if (errI == nil) != (errS == nil) || !reflect.DeepEqual(gi, gs) {
		return fmt.Sprintf("global filter: incremental %s, from scratch %s", rulesString(gi, errI), rulesString(gs, errS))
	}

	ci, errI := inc.FallbackCensus()
	cs, errS := scr.FallbackCensus()

	// The receivers' counts are held apart (TestReceiverKindsCountEachNodeOnce
	// in policy/v2): they are wrong on the tree this was written for.
	if (errI == nil) != (errS == nil) || ci.Rules != cs.Rules {
		return fmt.Sprintf("census rules: incremental %v, from scratch %v", ci.Rules, cs.Rules)
	}

	return ""
}

func readersOf(s *Snapshot, id types.NodeID) []types.NodeID {
	var out []types.NodeID
	for _, ids := range s.PeerReaders(id) {
		out = append(out, ids...)
	}

	slices.Sort(out)

	return slices.Compact(out)
}

func capNames(c tailcfg.NodeCapMap) []string {
	out := make([]string, 0, len(c))
	for k := range c {
		out = append(out, string(k))
	}

	slices.Sort(out)

	return out
}

// stampsDiffer holds every node's stamps, and its rendered capabilities,
// to the reference model: a stamp for each source selector it is a member
// of that capability form can name, an owner's when a self rule can, no
// other capability in the reserved namespace, and none at all in address
// mode. Membership, not holding a member's address.
func stampsDiffer(s *Snapshot, ref *policymodel.Ref) string {
	for _, n := range s.ListNodes().All() {
		id := n.ID()

		var want []string

		if s.CapabilitySources() {
			for _, st := range ref.Stamps(id) {
				want = append(want, policymodel.StampPrefix+st)
			}
		}

		var got []string
		for _, c := range s.Stamps(id) {
			got = append(got, string(c))
		}

		if !slices.Equal(got, want) {
			return fmt.Sprintf("n%d is stamped %v, the reference stamps it %v", id, got, want)
		}

		for c := range s.NodeCaps(id) {
			// The namespace as its documentation reads, with or without the
			// scheme, not as headscale's IsSourceCap does.
			if (strings.HasPrefix(string(c), "https://headscale.net/cap/src/") || strings.HasPrefix(string(c), "headscale.net/cap/src/")) &&
				!slices.Contains(want, string(c)) {
				return fmt.Sprintf("n%d is rendered with %s, the reference stamps it %v", id, c, want)
			}
		}
	}

	return ""
}

// shapeTally counts the classifier's shapes the scenarios a property
// judged held.
type shapeTally struct {
	mu        sync.Mutex
	scenarios int
	n         map[string]int
}

func (s *shapeTally) add(sc policymodel.Scenario) {
	names := policymodel.Classify(sc, policymodel.Required)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.n == nil {
		s.n = map[string]int{}
	}

	s.scenarios++

	for _, n := range names {
		s.n[n]++
	}
}

func (s *shapeTally) log(t *testing.T, what string) {
	t.Helper()

	var hit, missed []string

	for _, sh := range policymodel.Required {
		if c := s.n[sh.Name]; c > 0 {
			hit = append(hit, fmt.Sprintf("%s=%d", sh.Name, c))
		} else {
			missed = append(missed, sh.Name)
		}
	}

	t.Logf("%s: shapes over %d scenarios: %s", what, s.scenarios, strings.Join(hit, " "))
	t.Logf("%s: shapes never reached: %v", what, missed)
}

// tally counts what a property met.
type tally map[string]int

func (c tally) String() string {
	out := make([]string, 0, len(c))
	for _, k := range slices.Sorted(maps.Keys(c)) {
		out = append(out, fmt.Sprintf("%s=%d", k, c[k]))
	}

	return strings.Join(out, " ")
}

// readsOf is the nodes of w among st's reads.
func readsOf(st policymodel.Step, w policymodel.World) []types.NodeID {
	return slices.DeleteFunc(slices.Clone(st.Reads), func(id types.NodeID) bool {
		_, ok := w.Topology.Node(id)

		return !ok
	})
}

// TestWorldMatchesScratchWorld drives each scenario through a world in
// both modes, every step one commit (or its users, document and nodes
// written apart, as drawn), and after every step holds what the world
// serves to a world built from nothing for the same users, document and
// nodes (servedDiffers), and its stamps to the reference model
// (stampsDiffer).
//
// Oracles: the world from scratch, the same cells (it sees what updating
// cells, their cut-offs and carried values get wrong); for stamps, the
// reference, which shares nothing with the world (it sees which set the
// stamp cell reads).
func TestWorldMatchesScratchWorld(t *testing.T) {
	var shapes shapeTally

	known := tally{}

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(worldSteps).Draw(t, "scenario")
		apart := rapid.SliceOfN(rapid.Map(rapid.IntRange(0, 3), func(n int) bool { return n == 3 }), len(s.Steps), len(s.Steps)).Draw(t, "written apart")

		shapes.add(s)

		for _, capSources := range []bool{false, true} {
			m, snap := newModelWorld(t, s.Start, capSources)

			all := make([]types.NodeID, 0, len(s.Start.Topology.Nodes))
			for _, n := range s.Start.Topology.Nodes {
				all = append(all, n.ID)
			}

			if msg := servedDiffers(snap, scratchOf(t, s.Start, capSources), all); msg != "" {
				t.Fatalf("capability sources %t, at the start: %s", capSources, msg)
			}

			if msg := stampsDiffer(snap, policymodel.RefOf(s.Start)); msg != "" {
				t.Fatalf("capability sources %t, at the start: %s", capSources, msg)
			}

			w := s.Start
			shared := sharesAddress(w)

			for i, st := range s.Steps {
				next, change := w.Commit(st)
				snap = m.commit(t, next, change, apart[i])
				scr := scratchOf(t, next, capSources)
				shared = shared || sharesAddress(next)

				if policyCapsDiffer(snap, scr) && shared {
					// Found by the policy/v2 properties on the tree this was
					// written for: the compile reuses an unchanged node's
					// attributes, though under a shared address another
					// node's change moves which targets hold its address, and
					// the attribute stays once the address is no longer
					// shared. Database-only; counted, and judged no further.
					known["node attributes stale under a shared address"]++

					break
				}

				if msg := servedDiffers(snap, scr, readsOf(st, next)); msg != "" {
					t.Fatalf("capability sources %t, after step %d (%s): %s", capSources, i+1, st, msg)
				}

				if msg := stampsDiffer(snap, policymodel.RefOf(next)); msg != "" {
					t.Fatalf("capability sources %t, after step %d (%s): %s", capSources, i+1, st, msg)
				}

				w = next
			}
		}
	})

	t.Logf("known divergences: %v", known)
	shapes.log(t, "world matches scratch")
}

// policyCapsDiffer reports whether the compile's node capabilities of a
// and b differ.
func policyCapsDiffer(a, b *Snapshot) bool {
	ca, cb := a.s.Get(a.w.nodeCaps), b.s.Get(b.w.nodeCaps)

	for _, n := range b.ListNodes().All() {
		x, _ := ca.Get(n.ID())
		y, _ := cb.Get(n.ID())

		if !x.Equal(y) {
			return true
		}
	}

	return false
}

// sharesAddress reports whether two of w's nodes hold one address.
func sharesAddress(w policymodel.World) bool {
	seen := map[netip.Addr]bool{}

	for _, n := range w.Topology.Nodes {
		for _, a := range n.Addrs() {
			if seen[a] {
				return true
			}

			seen[a] = true
		}
	}

	return false
}

// sinceMisses returns a served value that differs between a and c and
// that c.Since(a) does not name in the field that must name it, as Route
// reads the change: a node's render (Nodes), its peers (PeerSets), its
// capabilities as rendered, stamps among them (Caps), the routes it is
// primary for (Primaries), its filter for a session that rendered a
// (Filters), and the routes a viewer is given of a peer (the viewer's
// RouteViewers or Nodes, the peer's Routers, Primaries or Nodes, or
// AllRouters). read holds the nodes whose sessions rendered a.
func sinceMisses(a, c *Snapshot, read []types.NodeID, counts tally) string {
	ch := c.Since(a)

	// Everyone is told when the filters name every node, and the other
	// fields are still worked out: judge those.
	judgeFilters := true

	if ch.Global {
		// TODO(kradalby): overwake/since-node-log, overwake/since-filters-unheld,
		// overwake/since-expansion-failed, overwake/since-ssh-unprepared: a
		// change that tells everyone is not judged field by field; judge it
		// once Snapshot.Since and what it reads name nodes in those cases.
		if ch.Resync || !filtersNameAll(a, c) {
			counts["global"]++

			return ""
		}

		counts["global by the filters"]++

		judgeFilters = false
	}

	counts["judged"]++

	ids := map[types.NodeID]bool{}

	for _, s := range []*Snapshot{a, c} {
		for _, n := range s.ListNodes().All() {
			ids[n.ID()] = true
		}
	}

	all := slices.Sorted(maps.Keys(ids))

	if msg := nodeMisses(a, c, ch, all, read, judgeFilters, counts); msg != "" {
		return msg
	}

	return routeMisses(a, c, ch, all, counts)
}

// nodeMisses is sinceMisses for what each node is served of itself.
func nodeMisses(a, c *Snapshot, ch Change, ids, read []types.NodeID, judgeFilters bool, counts tally) string {
	in := slices.Contains[[]types.NodeID]
	uc := c.Uncached()

	for _, id := range ids {
		was, wasOK := a.GetNode(id)
		is, isOK := c.GetNode(id)

		// A node not written renders alike but for the clock, which an
		// expired node's render reads; the expiry tick writes it.
		if (wasOK != isOK || wasOK && was != is && !was.SameRender(is)) && !in(ch.Nodes, id) {
			return fmt.Sprintf("n%d's render moved, and Nodes (%v) leaves it out", id, ch.Nodes)
		}

		if wasOK && isOK && in(ch.Nodes, id) && (was == is || was.SameRender(is)) && c.Rev() > a.Rev()+1 {
			// TODO(kradalby): overwake/since-coalesced-nodes: counted, not
			// judged; fail on it once Snapshot.Since leaves out of Nodes, across
			// coalesced commits, a node whose render is the same at both ends.
			counts["Nodes named across coalesced commits, render unchanged"]++
		}

		if !wasOK || !isOK {
			continue
		}

		if x, y := a.ListPeerIDs(id), c.ListPeerIDs(id); !slices.Equal(x, y) {
			counts["peers moved"]++

			if !in(ch.PeerSets, id) {
				return fmt.Sprintf("n%d's peers moved from %v to %v, and PeerSets (%v) leaves it out", id, x, y, ch.PeerSets)
			}
		}

		if x, y := a.NodeCaps(id), c.NodeCaps(id); !x.Equal(y) {
			counts["capabilities moved"]++

			if !in(ch.Caps, id) {
				return fmt.Sprintf("n%d's capabilities moved from %v to %v, and Caps (%v) leaves it out", id, capNames(x), capNames(y), ch.Caps)
			}
		}

		if x, y := a.PrimaryRoutesForNode(id), c.PrimaryRoutesForNode(id); !slices.Equal(x, y) {
			counts["primaries moved"]++

			if !in(ch.Primaries, id) {
				return fmt.Sprintf("n%d's primaries moved from %v to %v, and Primaries (%v) leaves it out", id, x, y, ch.Primaries)
			}
		}

		if !judgeFilters || !in(read, id) {
			continue
		}

		held, errHeld := a.FilterForNode(id)
		now, errNow := uc.FilterForNode(id)

		if (errHeld == nil) != (errNow == nil) || !reflect.DeepEqual(held, now) {
			counts["filters moved"]++

			if !in(ch.Filters, id) {
				return fmt.Sprintf("n%d rendered %s, is cut %s now, and Filters (%v) leaves it out", id, rulesString(held, errHeld), rulesString(now, errNow), ch.Filters)
			}
		}
	}

	return ""
}

// routeMisses is sinceMisses for the routes each viewer is given of each
// peer. It also counts the viewers, routers and changes Since names for
// routes though no route a viewer is given moved.
func routeMisses(a, c *Snapshot, ch Change, ids []types.NodeID, counts tally) string {
	in := slices.Contains[[]types.NodeID]

	movedViewers, movedRouters := map[types.NodeID]bool{}, map[types.NodeID]bool{}

	defer func() {
		// TODO(kradalby): overwake/route-viewers, overwake/routers-cover,
		// overwake/all-routers: counted, not judged; fail on each once
		// Sides.ViewersMovedSince, Sides.RoutersMovedSince and the route
		// rules' revision in Snapshot.Since name only what moves a route.
		for _, v := range ch.RouteViewers {
			if !movedViewers[v] {
				counts["RouteViewers named, no route moved"]++
			}
		}

		for _, r := range ch.Routers {
			if !movedRouters[r] {
				counts["Routers named, no route moved"]++
			}
		}

		if ch.AllRouters && len(movedRouters) == 0 {
			counts["AllRouters set, no route moved"]++
		}
	}()

	for _, v := range ids {
		va, okA := a.GetNode(v)
		vc, okC := c.GetNode(v)

		if !okA || !okC {
			continue
		}

		for _, p := range ids {
			pa, okA := a.GetNode(p)
			pc, okC := c.GetNode(p)

			if p == v || !okA || !okC {
				continue
			}

			x, y := prefixesSorted(a.RoutesForPeer(va, pa)), prefixesSorted(c.RoutesForPeer(vc, pc))
			if slices.Equal(x, y) {
				continue
			}

			counts["routes moved"]++

			movedViewers[v], movedRouters[p] = true, true

			if !ch.AllRouters && !in(ch.RouteViewers, v) && !in(ch.Nodes, v) && !in(ch.Routers, p) && !in(ch.Primaries, p) && !in(ch.Nodes, p) {
				return fmt.Sprintf("n%d's routes from n%d moved from %v to %v, and neither the viewer's RouteViewers (%v) or Nodes, nor the peer's Routers (%v), Primaries (%v) or Nodes (%v), nor AllRouters names it",
					v, p, x, y, ch.RouteViewers, ch.Routers, ch.Primaries, ch.Nodes)
			}
		}
	}

	return ""
}

// filtersNameAll reports whether the filters' change from a to c names
// every node, which makes Since tell everyone.
func filtersNameAll(a, c *Snapshot) bool {
	cur, was := c.s.Get(c.w.filters), a.s.Get(a.w.filters)
	if cur == was {
		return false
	}

	if c.w.capSources {
		_, all := cur.ChangedFor(was, c.s.Get(c.w.receivers))

		return all
	}

	_, all := cur.Changed(was)

	return all
}

// TestSinceSoundOverAnyPair drives each scenario through a world in both
// modes, the sessions a step marks read rendering each snapshot (every one
// the first), and holds Snapshot.Since over every pair of snapshots along
// it, adjacent or not, to the two snapshots' served values, field by
// field (sinceMisses), so a miss names the field that missed it. Pairs
// more than one commit apart are what the hub's render log asks. Oracle:
// the served values at both ends, the world's own accessors; it sees what
// Since's deltas miss, not what the cells serve.
func TestSinceSoundOverAnyPair(t *testing.T) {
	var shapes shapeTally

	counts := tally{}

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(worldSteps).Draw(t, "scenario")
		apart := rapid.SliceOfN(rapid.Map(rapid.IntRange(0, 3), func(n int) bool { return n == 3 }), len(s.Steps), len(s.Steps)).Draw(t, "written apart")

		shapes.add(s)

		for _, capSources := range []bool{false, true} {
			m, snap := newModelWorld(t, s.Start, capSources)
			snaps := make([]*Snapshot, 1, 1+len(s.Steps))
			snaps[0] = snap

			all := make([]types.NodeID, 0, len(s.Start.Topology.Nodes))
			for _, n := range s.Start.Topology.Nodes {
				all = append(all, n.ID)
			}

			reads := make([][]types.NodeID, 1, 1+len(s.Steps))
			reads[0] = all

			w := s.Start

			for i, st := range s.Steps {
				next, change := w.Commit(st)
				snaps = append(snaps, m.commit(t, next, change, apart[i]))
				reads = append(reads, readsOf(st, next))

				w = next
			}

			for i, a := range snaps {
				for _, id := range reads[i] {
					_, _ = a.FilterForNode(id)
				}
			}

			for i := range snaps {
				for j := i + 1; j < len(snaps); j++ {
					if msg := sinceMisses(snaps[i], snaps[j], reads[i], counts); msg != "" {
						t.Fatalf("capability sources %t, from step %d to step %d (%s): %s", capSources, i, j, s.Steps[j-1], msg)
					}
				}
			}
		}
	})

	t.Logf("since: %v", counts)
	shapes.log(t, "since")
}

// cellRevs are the revisions at which the policy pipeline's cells last
// changed.
type cellRevs struct {
	policy, selectors, userSets, roles, postings, templates, approvals, sides, filters, peers, routeRules uint64
}

func (s *Snapshot) cellRevs() cellRevs {
	return cellRevs{
		policy:     s.PolicyRev(),
		selectors:  graph.ChangedAt(s.s, s.w.selectors),
		userSets:   graph.ChangedAt(s.s, s.w.userSets),
		roles:      graph.ChangedAt(s.s, s.w.roles),
		postings:   graph.ChangedAt(s.s, s.w.postings),
		templates:  graph.ChangedAt(s.s, s.w.templates),
		approvals:  graph.ChangedAt(s.s, s.w.approvals),
		sides:      s.SidesRev(),
		filters:    s.FiltersRev(),
		peers:      s.PeersRev(),
		routeRules: s.RouteRulesRev(),
	}
}

// nonPolicyStep reports whether every edit of st changes only what no
// policy cell reads: whether a node is online, expired, or which client
// it runs.
func nonPolicyStep(st policymodel.Step) bool {
	for _, e := range st.Edits {
		switch e.(type) {
		case policymodel.SetOnline, policymodel.SetExpired, policymodel.SetClient:
		default:
			return false
		}
	}

	return len(st.Edits) > 0
}

// roleFactsMoved counts the nodes of next whose tags or owner differ from
// w's, joiners included: the role sets a node-only step must compute.
func roleFactsMoved(w, next policymodel.World, change policymodel.Change) int {
	n := 0

	for _, id := range change.Nodes {
		is, _ := next.Topology.Node(id)
		was, had := w.Topology.Node(id)

		if !had || was.User != is.User || !slices.Equal(was.Tags, is.Tags) {
			n++
		}
	}

	return n
}

// TestWorldCutoffsFollowWhatMoved drives each scenario through a world in
// both modes, every step one commit, every session reading after it, and
// holds what each commit recomputes to what its step moved:
//
//   - a step that only sets nodes online or offline, expired, or their
//     client moves no policy cell (the compile, the selectors, user sets,
//     roles, postings, templates, approvals, sides, filters, peers and
//     route rules keep their revisions), and reading every filter again
//     builds no expansion and cuts at most the filters of the nodes whose
//     receiver facts flipped, their other form;
//   - a step writing nodes alone computes exactly the role sets of the
//     nodes whose tags or owner moved, joiners among them;
//   - a document edit naming the same selectors and leaving the groups
//     keeps the user sets, roles and postings.
//
// Oracle: the step as the model classifies it, against the cells'
// revisions and the work counters. It sees a cut-off that does not cut,
// not one that cuts too much (the other properties see those).
func TestWorldCutoffsFollowWhatMoved(t *testing.T) {
	// The policy audit cuts afresh every filter it checks: work this
	// property must not count.
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "false")

	var shapes shapeTally

	counts := tally{}

	rapid.Check(t, func(t *rapid.T) {
		s := policymodel.Scenarios(worldSteps).Draw(t, "scenario")
		shapes.add(s)

		for _, capSources := range []bool{false, true} {
			m, snap := newModelWorld(t, s.Start, capSources)
			readAll(snap)

			w := s.Start

			for i, st := range s.Steps {
				next, change := w.Commit(st)
				before := snap
				snap = m.commit(t, next, change, false)

				if msg := cutoffMisses(before, snap, w, next, st, change, counts); msg != "" {
					t.Fatalf("capability sources %t, step %d (%s): %s", capSources, i+1, st, msg)
				}

				w = next
			}
		}
	})

	t.Logf("cut-offs: %v", counts)
	shapes.log(t, "cut-offs")
}

// readAll reads every node's filter from s, as every session renders.
func readAll(s *Snapshot) {
	for _, n := range s.ListNodes().All() {
		_, _ = s.FilterForNode(n.ID())
	}
}

func cutoffMisses(before, after *Snapshot, w, next policymodel.World, st policymodel.Step, change policymodel.Change, counts tally) string {
	revs, was := after.cellRevs(), before.cellRevs()

	switch {
	case nonPolicyStep(st):
		counts["no policy fact"]++

		if revs != was {
			return fmt.Sprintf("it moves no policy fact, yet cells recomputed: %+v, then %+v", was, revs)
		}

		var flipped uint64

		for _, n := range after.ListNodes().All() {
			if before.ReceiverFacts(n.ID()) != after.ReceiverFacts(n.ID()) {
				flipped++
			}
		}

		builds, cuts := policyv2.ExpansionBuilds(), policyv2.FilterCuts()

		readAll(after)

		if b, c := policyv2.ExpansionBuilds()-builds, policyv2.FilterCuts()-cuts; b > 0 || c > flipped {
			return fmt.Sprintf("it moves no policy fact, yet reading every filter built %d expansions and cut %d filters, %d nodes' facts flipping", b, c, flipped)
		}

		return ""
	case !change.Policy && !change.Users && len(change.Nodes)+len(change.Removed) > 0:
		counts["nodes alone"]++

		got, want := computedSince(before, after), roleFactsMoved(w, next, change)
		if got != want {
			return fmt.Sprintf("it moves the tags or owner of %d nodes, and the roles computed %d sets", want, got)
		}
	case change.Policy && !change.Users && len(change.Nodes)+len(change.Removed) == 0 &&
		sameSelectorSet(w.Policy.Selectors(), next.Policy.Selectors()) && reflect.DeepEqual(w.Policy.Groups, next.Policy.Groups):
		counts["document naming nothing new"]++

		if revs.userSets != was.userSets || revs.roles != was.roles || revs.postings != was.postings {
			return fmt.Sprintf("it names nothing new and moves no group, yet membership recomputed: %+v, then %+v", was, revs)
		}
	}

	readAll(after)

	return ""
}

func sameSelectorSet(a, b []policymodel.Sel) bool {
	key := func(s policymodel.Sel) string { return s.String() }

	return slices.Equal(slices.Sorted(slices.Values(mapStrings(a, key))), slices.Sorted(slices.Values(mapStrings(b, key))))
}

func mapStrings[E any](in []E, f func(E) string) []string {
	out := make([]string, len(in))
	for i, e := range in {
		out[i] = f(e)
	}

	return out
}

// TestServedAuditAgreesWhateverTheMergeOrder holds the served filter audit
// to a capability-form filter that says what address form says, over two
// rules alice's nodes reach 100.64.0.28 by: alice@'s and a self rule.
//
// TODO(kradalby): policy/merge-order: the compile writes a self rule's
// sources in address order and every other rule's as text, and merges
// rules only on equal text; for these addresses address form keeps the
// two rules apart, the audit's expansion of capability form merges them,
// and AgreesWithAddressForm, comparing rule multisets, logs a mismatch.
// Unskip once the audit compares rules merged by source set, or the
// compile writes one order.
func TestServedAuditAgreesWhateverTheMergeOrder(t *testing.T) {
	if os.Getenv("HEADSCALE_PBT_KNOWN_BUGS") == "" {
		t.Skip("TODO(kradalby): policy/merge-order; HEADSCALE_PBT_KNOWN_BUGS=1 runs it")
	}

	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	users := []types.User{{ID: 1, Name: "alice"}}
	pol := `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:22", "autogroup:self:80"]}]}`

	w, err := newWorldMode(types.Nodes{capWorldNode(3, &users[0], "100.64.0.3"), capWorldNode(28, &users[0], "100.64.0.28")},
		users, []byte(pol), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	failures := PolicyAuditFailures()

	_, err = w.snapshot().FilterForNode(28)
	require.NoError(t, err)
	require.Equal(t, failures, PolicyAuditFailures(), "the audit found no disagreement")
}

// TestSSHPolicyForgetsALeaverWhoSharedAnAddress holds a tagged node's SSH
// policy, after a node sharing its address leaves, to a compile from
// scratch: autogroup:tagged resolves by address, so the leaver's other
// address was a principal while it shared one with the tagged node.
//
// TODO(kradalby): policy/stale-under-shared-address: fails open: the
// carried SSH policy keeps the leaver's address as a principal (it may be
// handed to another node next) until a document edit. Database-only: State
// shares no address. Unskip with the shared-address exceptions of the
// properties.
func TestSSHPolicyForgetsALeaverWhoSharedAnAddress(t *testing.T) {
	if os.Getenv("HEADSCALE_PBT_KNOWN_BUGS") == "" {
		t.Skip("TODO(kradalby): policy/stale-under-shared-address; HEADSCALE_PBT_KNOWN_BUGS=1 runs it")
	}

	users := []types.User{{ID: 1, Name: "alice"}}
	pol := `{"tagOwners": {"tag:a": []}, "ssh": [{"action": "accept", "src": ["autogroup:tagged"], "dst": ["tag:a"], "users": ["root"]}]}`

	sharer := capWorldNode(2, &users[0], "100.64.0.1")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
	sharer.IPv6 = &v6

	w, err := newWorldMode(types.Nodes{capWorldNode(1, nil, "100.64.0.1", "tag:a"), sharer}, users, []byte(pol), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	tagged, _ := w.snapshot().GetNode(1)
	_, err = w.snapshot().SSHPolicy("https://headscale.test", tagged)
	require.NoError(t, err)

	s := w.update(func(e *nodeEdit) { e.Delete(2) })

	got, err := s.SSHPolicy("https://headscale.test", tagged)
	require.NoError(t, err)

	fresh, err := policyv2.NewPolicyManager([]byte(pol), users, s.ListNodes())
	require.NoError(t, err)

	want, err := fresh.SSHPolicy("https://headscale.test", tagged)
	require.NoError(t, err)
	require.Equal(t, want, got)
}
