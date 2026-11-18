// The reference semantics in policymodel held to what Tailscale's hosted
// service was captured doing, and then used as the judge of headscale's
// filters, peers, routes and stamps over generated policies and
// topologies. The reference shares no code with this package; the client
// oracle (the client's own packet filter) compares rules by what they let
// through, never by how they are written.

package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/wgengine/filter"
)

// refInputs is users and nodes as the reference reads them: their fields,
// not headscale's accessors.
func refInputs(users types.Users, nodes types.Nodes) ([]policymodel.User, []policymodel.RefNode) {
	us := make([]policymodel.User, len(users))
	for i, u := range users {
		us[i] = policymodel.User{ID: u.ID, Name: u.Name, Email: u.Email}
	}

	ns := make([]policymodel.RefNode, len(nodes))

	for i, n := range nodes {
		rn := policymodel.RefNode{ID: n.ID, Tags: n.Tags, Approved: n.ApprovedRoutes}

		if n.User != nil && slices.ContainsFunc(us, func(u policymodel.User) bool { return u.ID == n.User.ID }) {
			rn.User = n.User.ID
		}

		for _, a := range []*netip.Addr{n.IPv4, n.IPv6} {
			if a != nil && a.IsValid() {
				rn.Addrs = append(rn.Addrs, *a)
			}
		}

		if n.Hostinfo != nil {
			rn.Announced = n.Hostinfo.RoutableIPs
		}

		ns[i] = rn
	}

	return us, ns
}

type refGoldenTally struct {
	mu sync.Mutex

	files, refused, unreadable, captures int
	filters, filtersAgree, probes        int
	unrouted                             int
	peers, peersAgree                    int
	routes, routesAgree, routesVia       int
	known                                []string
}

// judgeGolden fails a check the reference answers otherwise than SaaS,
// unless refGoldenDivergences lists it, and a listed check it answers
// alike. It reports whether the check agreed.
func (g *refGoldenTally) judge(t *testing.T, key string, agree bool, detail func() string) bool {
	t.Helper()

	reason, listed := refGoldenDivergences[key]

	switch {
	case agree && listed:
		t.Errorf("%s: the reference agrees with SaaS; delete its divergence entry (%s)", key, reason)
	case !agree && listed:
		g.add(func(g *refGoldenTally) { g.known = append(g.known, key) })
	case !agree:
		t.Errorf("%s: the reference differs from SaaS: %s", key, detail())
	}

	return agree
}

func (g *refGoldenTally) add(f func(*refGoldenTally)) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f(g)
}

// TestReferenceAgreesWithCaptures holds the reference to the hosted
// service: for every captured node, the captured filter and the
// reference's rules must let the same packets through the node's own
// client, the captured peers must be the reference's, and each captured
// peer's routes the reference's route access over the routes the service
// made primary.
func TestReferenceAgreesWithCaptures(t *testing.T) {
	t.Parallel()

	tally := &refGoldenTally{}

	t.Cleanup(func() {
		g := tally
		t.Logf("capture files %d: %d refused by SaaS, %d unreadable by the reference, %d node captures",
			g.files, g.refused, g.unreadable, g.captures)
		t.Logf("filters: %d of %d agree (%d probes; %d accepted by SaaS for a route the node announces unapproved)", g.filtersAgree, g.filters, g.probes, g.unrouted)
		t.Logf("peers: %d of %d agree", g.peersAgree, g.peers)
		t.Logf("routes: %d of %d peers agree; %d node captures with via grants or in doubt not compared", g.routesAgree, g.routes, g.routesVia)
		slices.Sort(g.known)
		t.Logf("listed divergences %v", g.known)
	})

	for _, src := range goldenFilterSources() {
		files, err := filepath.Glob(filepath.Join("testdata", src.dir, src.glob))
		require.NoError(t, err)

		for _, file := range files {
			t.Run(filepath.Join(src.dir, filepath.Base(file)), func(t *testing.T) {
				t.Parallel()

				c, err := testcapture.Read(file)
				require.NoError(t, err)

				tally.add(func(g *refGoldenTally) { g.files++ })

				if c.Error || c.Input.APIResponseCode != 200 {
					tally.add(func(g *refGoldenTally) { g.refused++ })

					return
				}

				doc, err := policymodel.ParseDoc([]byte(c.Input.FullPolicy))
				if err != nil {
					tally.add(func(g *refGoldenTally) { g.unreadable++ })
					t.Logf("unreadable: %v", err)

					return
				}

				users, nodes := src.build(t, c)
				ru, rn := refInputs(users, nodes)
				ref := policymodel.NewRef(doc, ru, rn)

				refGoldenCapture(t, tally, c.TestID, c.Captures, ref, nodes, rn)
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		refGoldenSequence(t, tally, "policy-generation")
	})
}

// refGoldenDivergences lists, keyed <test_id>[/<step>]/<node>/<check>, the
// captured answers the reference gives otherwise, each for a reason
// headscale already records against SaaS. A listed answer the reference
// gives alike fails, so a fix must delete its entry.
var refGoldenDivergences = map[string]string{
	"users-short-name/server/filter":  shortUsername,
	"users-short-name/server/peers":   shortUsername,
	"users-short-name/user-tid/peers": shortUsername,
}

// refGoldenSequence replays a step capture: at each step the policy in
// force and the devices listed, against what each captured node held.
func refGoldenSequence(t *testing.T, tally *refGoldenTally, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)

	users := setupGrantsCompatUsers()
	ids := map[string]types.NodeID{}

	var policy []byte

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if _, ok := ids[a.Node]; a.Kind == "join" && !ok {
				ids[a.Node] = types.NodeID(len(ids) + 1) //nolint:gosec // a handful of nodes
			}
		}

		nodes, _ := sequenceNodes(t, users, step, ids)
		if pushed := stepPolicy(t, step); pushed != nil {
			policy = pushed
		}

		doc, err := policymodel.ParseDoc(policy)
		require.NoError(t, err)

		ru, rn := refInputs(users, nodes)
		refGoldenCapture(t, tally, id+"/"+step.Name, step.Captures, policymodel.NewRef(doc, ru, rn), nodes, rn)
	}
}

func refGoldenCapture(t *testing.T, tally *refGoldenTally, id string, captures map[string]testcapture.Node, ref *policymodel.Ref, nodes types.Nodes, rn []policymodel.RefNode) {
	t.Helper()

	refNode := func(id types.NodeID) policymodel.RefNode {
		return rn[slices.IndexFunc(rn, func(n policymodel.RefNode) bool { return n.ID == id })]
	}

	for _, alias := range slices.Sorted(maps.Keys(captures)) {
		capture := captures[alias]
		key := id + "/" + alias

		// SaaS's answer is in doubt there, see policySequenceNotCompared.
		if capture.Netmap == nil || notCompared(policySequenceNotCompared, key+"/filter") {
			continue
		}

		node := findNodeByGivenName(nodes, alias)
		require.NotNilf(t, node, "node %s not built", alias)

		view := policymodel.ViewFromNetmap(capture.Netmap)
		rep := policymodel.Compare(capture.PacketFilterRules, ref.Rules(node.ID), view)
		unrouted := 0

		rep.Verdicts = slices.DeleteFunc(rep.Verdicts, func(d policymodel.VerdictDiff) bool {
			if d.Ref == filter.Accept && !ref.Serves(node.ID, d.Probe.Dst) && view.LocalNets.Contains(d.Probe.Dst) {
				unrouted++

				return true
			}

			return false
		})

		var want, got []string

		for _, p := range capture.Netmap.Peers {
			name, _, _ := strings.Cut(p.Name(), ".")
			if findNodeByGivenName(nodes, name) != nil {
				want = append(want, name)
			}
		}

		for _, id := range ref.Peers(node.ID) {
			got = append(got, nameOf(nodes, id))
		}

		slices.Sort(want)
		slices.Sort(got)

		// SaaS's peers and routes are in doubt there, see routesNotCompared.
		comparePeers := !notCompared(routesNotCompared, key+"/peers")

		filterAgrees := tally.judge(t, key+"/filter", rep.Equivalent(), func() string {
			return fmt.Sprintf("filter (reference SaaS, candidate the reference): %s", rep)
		})
		peersAgree := comparePeers && tally.judge(t, key+"/peers", slices.Equal(want, got), func() string {
			return fmt.Sprintf("peers: SaaS %v, reference %v", want, got)
		})

		tally.add(func(g *refGoldenTally) {
			g.captures++
			g.filters++
			g.probes += rep.Probes
			g.unrouted += unrouted

			if filterAgrees {
				g.filtersAgree++
			}

			if comparePeers {
				g.peers++
			}

			if peersAgree {
				g.peersAgree++
			}
		})

		if ref.HasVia() || notCompared(routesNotCompared, key+"/peer-allowed-ips") {
			tally.add(func(g *refGoldenTally) { g.routesVia++ })

			continue
		}

		for _, nmPeer := range capture.Netmap.Peers {
			name, _, _ := strings.Cut(nmPeer.Name(), ".")

			peer := findNodeByGivenName(nodes, name)
			if peer == nil {
				continue
			}

			primaries := nmPeer.PrimaryRoutes().AsSlice()

			var wantR, gotR []netip.Prefix

			// A router is given the primary's route for a prefix it serves
			// itself, whatever the policy: elections, not route access.
			ownRoutes := refNode(node.ID).ServedRoutes()

			for _, p := range nmPeer.AllowedIPs().All() {
				ownAddr := p.IsSingleIP() && slices.Contains(refNode(peer.ID).Addrs, p.Addr())
				if !ownAddr && !slices.Contains(ownRoutes, p) {
					wantR = append(wantR, p)
				}
			}

			for _, p := range ref.Routes(node.ID, peer.ID) {
				if (p.Bits() == 0 || slices.Contains(primaries, p)) && !slices.Contains(ownRoutes, p) {
					gotR = append(gotR, p)
				}
			}

			slices.SortFunc(wantR, netip.Prefix.Compare)
			slices.SortFunc(gotR, netip.Prefix.Compare)

			agree := tally.judge(t, key+"/routes/"+name, slices.Equal(wantR, gotR), func() string {
				return fmt.Sprintf("routes of %s: SaaS %v, reference %v", name, wantR, gotR)
			})

			tally.add(func(g *refGoldenTally) {
				g.routes++

				if agree {
					g.routesAgree++
				}
			})
		}
	}
}

func nameOf(nodes types.Nodes, id types.NodeID) string {
	for _, n := range nodes {
		if n.ID == id {
			return n.GivenName
		}
	}

	return fmt.Sprintf("node%d", id)
}

// served is what headscale serves for one world, built from scratch from
// the cells the world serves from: filters in both modes, peers, route
// access, and the CapMaps it renders.
type served struct {
	w   policymodel.World
	ref *policymodel.Ref

	list  types.Nodes
	t     *Templates
	roles Roles
	sides Sides
	peers *PeerClasses
	caps  map[types.NodeID]tailcfg.NodeCapMap
	recv  Receivers

	ip, cap *Filters
}

func serve(w policymodel.World) (*served, error) {
	users, nodes := w.Topology.Build()

	pm, err := NewPolicyManager(w.Policy.HuJSON(), users, nodes.ViewSlice())
	if err != nil {
		return nil, err
	}

	sv := &served{w: w, ref: policymodel.RefOf(w), list: nodes, caps: pm.NodeCapMaps()}

	nm := nodeMapOf(nodes)
	sel := SelectorsFor(nil, pm)
	sv.roles = Roles{}.Update(NewUserSets(nil, sel, users), nm, nil)
	posts := Postings{}.Update(sv.roles)
	appr := SubnetApprovals{}.Update(nm)
	sv.t = BuildTemplates(nil, sel)
	sv.sides = UpdateSides(Sides{}, sv.t, sv.roles, posts, appr, nm)
	sv.peers = RolePeers(nil, sv.sides)
	sv.recv = capReceivers(nm, sv.caps)
	sv.ip = NewFilters(sv.t, posts, appr, nodes.ViewSlice())
	sv.cap = NewFiltersFor(CapabilitySources, sv.t, posts, appr, nodes.ViewSlice())

	return sv, nil
}

// render is node id as headscale renders it in capability mode, to
// itself or to a peer.
func (sv *served) render(id types.NodeID, self bool) tailcfg.NodeView {
	n := sv.list[slices.IndexFunc(sv.list, func(n *types.Node) bool { return n.ID == id })]
	rs, _ := sv.roles.Of(id)
	caps := WithStamps(sv.caps[id], sv.t.StampsOf(rs))

	tn := &tailcfg.Node{ID: tailcfg.NodeID(id), Addresses: n.Prefixes(), CapMap: PeerCapMap(n.View(), caps, true)} //nolint:gosec // test IDs are small
	if self {
		tn.CapMap = caps
	}

	return tn.View()
}

// peersOf is the nodes headscale shows node id.
func (sv *served) peersOf(id types.NodeID) []types.NodeID {
	return slices.DeleteFunc(slices.Clone(sv.peers.Peers(id)), func(p types.NodeID) bool { return p == id })
}

// view is what node n's client knows when it filters: local nets from
// what it announces and runs as, every node's addresses as sources worth
// probing, and capabilities from caps.
func viewOf(n policymodel.Node, w policymodel.World, caps *policymodel.NetmapCaps) policymodel.ClientView {
	own := make([]netip.Prefix, 0, 2)
	announced := make([]netip.Prefix, 0, len(n.Announced))

	for _, a := range n.Addrs() {
		own = append(own, netip.PrefixFrom(a, a.BitLen()))
	}

	for _, r := range n.Announced {
		announced = append(announced, policymodel.Prefixes[r])
	}

	v := policymodel.ClientView{Self: n.Addrs(), LocalNets: policymodel.LocalNets(own, announced, n.Client == policymodel.AppConnector, nil)}

	for _, m := range w.Topology.Nodes {
		v.Known = append(v.Known, m.Addrs()...)
	}

	if caps != nil {
		v.HasCap = caps.HasCap
	}

	return v
}

// verdictClasses are the differences from the reference a property
// allows, each counted; anything else fails it.
type verdictClasses struct {
	// unrouted: the client takes packets for a route its node announces
	// but is not approved for, or an app connector's unspecified address,
	// which the policy gives it none of; what it accepts there is the
	// rules' business, not the reference's.
	unrouted int
	// crossFamilyICMP: capability form refuses a packet carrying the
	// other family's ICMP protocol, which address form accepts: decided as malformed, failing closed.
	crossFamilyICMP int
	// repeatedValues: an app capability's values come once per
	// destination entry of a grant that names the receiver, where the
	// reference gives them once per grant. Reported, not encoded; no
	// capture holds an app grant with two destinations.
	repeatedValues int
	// contested counts the differences that are exactly a contested
	// clause of the reference: reported, not encoded (see
	// [policymodel.Contested]).
	contested map[policymodel.Contested]int
}

func (c *verdictClasses) addContested(k policymodel.Contested, n int) {
	if c.contested == nil {
		c.contested = map[policymodel.Contested]int{}
	}

	c.contested[k] += n
}

// contestedNames names the contested clauses for logs.
var contestedNames = map[policymodel.Contested]string{
	policymodel.OthersSelf:            "others' autogroup:self rules where they are routed",
	policymodel.ViaDestinations:       "via destinations as headscale writes them",
	policymodel.ExitDestinationRoutes: "exit nodes' routes as destinations",
	policymodel.AppWildcard:           "* as an app destination",
	policymodel.AllContested:          "several at once",
}

// contestedOrder is the order compareAt tries the clauses in: each alone,
// then all together.
var contestedOrder = []policymodel.Contested{
	policymodel.OthersSelf, policymodel.ViaDestinations, policymodel.ExitDestinationRoutes, policymodel.AppWildcard,
	policymodel.AllContested,
}

func (c *verdictClasses) String() string {
	var parts []string

	for _, k := range contestedOrder {
		if c.contested[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c.contested[k], contestedNames[k]))
		}
	}

	return fmt.Sprintf("allowed %d cross-family ICMP, %d on unapproved routes; suspected: %d app values repeated, contested %v",
		c.crossFamilyICMP, c.unrouted, c.repeatedValues, parts)
}

// judge holds rep, a comparison of the reference's rules (as Ref) with
// production's (as Cand) at node n, to the allowed classes, and returns
// the differences left.
func (c *verdictClasses) judge(rep policymodel.Report, ref *policymodel.Ref, n policymodel.Node, view policymodel.ClientView, capForm bool) policymodel.Report {
	if capForm {
		crossed, rest := rep.SplitCrossFamilyICMP()
		c.crossFamilyICMP += crossed
		rep = rest
	}

	rep.Caps = slices.DeleteFunc(rep.Caps, func(d policymodel.CapsDiff) bool {
		if sameUpToRepeats(d.Ref, d.Cand) {
			c.repeatedValues++

			return true
		}

		return false
	})

	rep.Caps = slices.DeleteFunc(rep.Caps, func(d policymodel.CapsDiff) bool {
		if sameUpToRepeats(d.Ref, d.Cand) {
			c.repeatedValues++

			return true
		}

		return false
	})

	rep.Verdicts = slices.DeleteFunc(rep.Verdicts, func(d policymodel.VerdictDiff) bool {
		if d.Ref == filter.Drop && d.Cand == filter.Accept && !ref.Serves(n.ID, d.Probe.Dst) && view.LocalNets.Contains(d.Probe.Dst) {
			c.unrouted++

			return true
		}

		return false
	})

	return rep
}

// sameUpToRepeats reports whether cand grants what ref does, in the same
// order, with some values repeated more often: the same runs of equal
// values, none shorter.
func sameUpToRepeats(ref, cand tailcfg.PeerCapMap) bool {
	if len(ref) != len(cand) {
		return false
	}

	type run struct {
		v tailcfg.RawMessage
		n int
	}

	runs := func(c peercap.Cap, vs []tailcfg.RawMessage) []run {
		var out []run

		for _, v := range vs {
			if len(out) > 0 && policymodel.SamePeerCaps(tailcfg.PeerCapMap{c: {out[len(out)-1].v}}, tailcfg.PeerCapMap{c: {v}}) {
				out[len(out)-1].n++

				continue
			}

			out = append(out, run{v: v, n: 1})
		}

		return out
	}

	for c, rv := range ref {
		cv, ok := cand[c]
		if !ok {
			return false
		}

		rr, cr := runs(c, rv), runs(c, cv)
		if len(rr) != len(cr) {
			return false
		}

		for i := range rr {
			if cr[i].n < rr[i].n || !policymodel.SamePeerCaps(tailcfg.PeerCapMap{c: {rr[i].v}}, tailcfg.PeerCapMap{c: {cr[i].v}}) {
				return false
			}
		}
	}

	return true
}

// compareAt holds production's rules got at node n to the reference
// through the client, and returns what is left once the allowed classes
// are taken out.
func (c *verdictClasses) compareAt(ref *policymodel.Ref, n policymodel.Node, got []tailcfg.FilterRule, view policymodel.ClientView, capForm bool) policymodel.Report {
	var trial verdictClasses

	rep := trial.judge(policymodel.Compare(ref.Rules(n.ID), got, view), ref, n, view, capForm)
	if !rep.Equivalent() {
		for _, k := range contestedOrder {
			var without verdictClasses

			rest := without.judge(policymodel.Compare(ref.Without(k).Rules(n.ID), got, view), ref, n, view, capForm)
			if rest.Equivalent() {
				c.addContested(k, len(rep.Verdicts)+len(rep.Caps))
				rep, trial = rest, without

				break
			}
		}
	}

	c.unrouted += trial.unrouted
	c.crossFamilyICMP += trial.crossFamilyICMP
	c.repeatedValues += trial.repeatedValues

	return rep
}

// refSteps is how long a drawn scenario may be: a failing case replays
// every step for each shrink candidate.
const refSteps = 10

// forEachServed calls f for the start of a drawn scenario and the world
// after each step, served.
func forEachServed(t *rapid.T, f func(step int, sv *served)) {
	s := policymodel.Scenarios(refSteps).Draw(t, "scenario")

	for i, w := range s.Worlds() {
		sv, err := serve(w)
		if err != nil {
			t.Fatalf("after step %d the policy is refused: %s", i, stableError(err))
		}

		f(i, sv)
	}
}

// requireJudged fails a property that judged fewer than floor cases, so
// that skipping cannot turn it green.
func requireJudged(t *testing.T, what string, judged, floor int) {
	t.Helper()

	if judged < floor {
		t.Errorf("%s: only %d cases judged, want at least %d", what, judged, floor)
	}
}

// TestServedFiltersFollowReference holds each node's address-form filter
// to the reference's rules for it, through the node's own client.
// Oracle: the reference (no production code) and the client's filter.
func TestServedFiltersFollowReference(t *testing.T) {
	t.Parallel()

	var judged, probes int

	var classes verdictClasses

	skipped := map[string]int{}

	rapid.Check(t, func(t *rapid.T) {
		forEachServed(t, func(step int, sv *served) {
			for _, n := range sv.w.Topology.Nodes {
				if why := sv.ref.ReceiverOutOfDomain(n.ID); why != "" {
					skipped[why]++

					continue
				}

				got, err := sv.ip.ForNode(n.ID, ReceiverFacts{})
				if err != nil {
					t.Fatalf("after step %d n%d: %v", step, n.ID, err)
				}

				view := viewOf(n, sv.w, nil)
				rep := classes.compareAt(sv.ref, n, got, view, false)

				judged++
				probes += rep.Probes

				if !rep.Equivalent() {
					t.Fatalf("after step %d n%d's address-form filter differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v",
						step, n.ID, rep, sv.ref.Rules(n.ID), got)
				}
			}
		})
	})

	t.Logf("judged %d node filters over %d probes, skipped receivers %v; %v", judged, probes, skipped, &classes)
	requireJudged(t, "address form", judged, 100)
}

// TestCapabilityFormFollowsReference holds each node's capability-form
// filter to the reference's rules for it, through its client, twice:
// with the netmap headscale renders (its peers and stamps), and with one
// built from the reference's peers and stamps, so that membership comes
// from somewhere other than the code under test. Allowed besides the
// address-form classes: cross-family ICMP, which capability form refuses.
func TestCapabilityFormFollowsReference(t *testing.T) {
	t.Parallel()

	var judged, probes int

	var rendered, referenced verdictClasses

	skipped := map[string]int{}

	rapid.Check(t, func(t *rapid.T) {
		forEachServed(t, func(step int, sv *served) {
			for _, n := range sv.w.Topology.Nodes {
				if why := sv.ref.ReceiverOutOfDomain(n.ID); why != "" {
					skipped[why]++

					continue
				}

				got, err := sv.cap.ForNode(n.ID, sv.recv.Of(n.ID))
				if err != nil {
					t.Fatalf("after step %d n%d: %v", step, n.ID, err)
				}

				var peers []tailcfg.NodeView
				for _, p := range sv.peersOf(n.ID) {
					peers = append(peers, sv.render(p, false))
				}

				caps := policymodel.NewNetmapCaps(sv.render(n.ID, true), peers)
				view := viewOf(n, sv.w, &caps)
				rep := rendered.compareAt(sv.ref, n, got, view, true)

				judged++
				probes += rep.Probes

				if !rep.Equivalent() {
					t.Fatalf("after step %d n%d's capability-form filter, with the netmap headscale renders, differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v",
						step, n.ID, rep, sv.ref.Rules(n.ID), got)
				}

				self, refPeers := sv.ref.Netmap(n.ID)
				refCaps := policymodel.NewNetmapCaps(self, refPeers)
				view = viewOf(n, sv.w, &refCaps)

				rep = referenced.compareAt(sv.ref, n, got, view, true)
				probes += rep.Probes

				if !rep.Equivalent() {
					t.Fatalf("after step %d n%d's capability-form filter, with the reference's peers and stamps, differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v",
						step, n.ID, rep, sv.ref.Rules(n.ID), got)
				}
			}
		})
	})

	t.Logf("with the rendered netmap: %v", &rendered)
	t.Logf("with the reference's netmap: %v", &referenced)

	t.Logf("judged %d node filters over %d probes, skipped receivers %v", judged, probes, skipped)
	requireJudged(t, "capability form", judged, 100)
}

// TestPeersAndRoutesFollowReference holds headscale's peers to the
// reference's visibility, and route access between peers to the
// reference's. Route access is compared on every route the peer serves,
// before elections; worlds with via grants are left out of it, since via
// grants routes through steering, which the reference does not model.
func TestPeersAndRoutesFollowReference(t *testing.T) {
	t.Parallel()

	var peerSets, routeSets, viaWorlds int

	skipped := map[string]int{}
	contested := map[policymodel.Contested]int{}

	rapid.Check(t, func(t *rapid.T) {
		forEachServed(t, func(step int, sv *served) {
			if why := sv.ref.OutOfDomain(); why != "" {
				skipped[why]++

				return
			}

			for _, n := range sv.w.Topology.Nodes {
				got, want := sv.peersOf(n.ID), sv.ref.Peers(n.ID)
				slices.Sort(got)

				peerSets++

				if !slices.Equal(got, want) {
					if k, ok := contestedPeers(sv.ref, n.ID, got); ok {
						contested[k]++

						continue
					}

					t.Fatalf("after step %d n%d is shown %v, the reference shows it %v", step, n.ID, got, want)
				}
			}

			if sv.ref.HasVia() {
				viaWorlds++

				return
			}

			for _, v := range sv.w.Topology.Nodes {
				if why := sv.ref.ReceiverOutOfDomain(v.ID); why != "" {
					skipped["viewer: "+why]++

					continue
				}

				for _, p := range sv.ref.Peers(v.ID) {
					peer, _ := sv.w.Topology.Node(p)

					var routes []netip.Prefix

					for _, r := range peer.Approved {
						if slices.Contains(peer.Announced, r) {
							routes = append(routes, policymodel.Prefixes[r])
						}
					}

					if len(routes) == 0 {
						continue
					}

					got, want := sv.sides.RouteAccess(v.ID, routes), sv.ref.Routes(v.ID, p)
					slices.SortFunc(got, netip.Prefix.Compare)
					slices.SortFunc(want, netip.Prefix.Compare)

					routeSets++

					if !slices.Equal(got, want) {
						if k, ok := contestedRoutes(sv.ref, v.ID, p, got); ok {
							contested[k]++

							continue
						}

						t.Fatalf("after step %d n%d is given %v of n%d's routes %v, the reference gives it %v", step, v.ID, got, p, routes, want)
					}
				}
			}
		})
	})

	var named []string

	for _, k := range contestedOrder {
		if contested[k] > 0 {
			named = append(named, fmt.Sprintf("%d %s", contested[k], contestedNames[k]))
		}
	}

	t.Logf("judged %d peer sets and %d route sets; skipped worlds %v, route access in %d worlds with via grants; contested sets %v",
		peerSets, routeSets, skipped, viaWorlds, named)
	requireJudged(t, "peers", peerSets, 100)
	requireJudged(t, "routes", routeSets, 20)
}

// contestedPeers reports which contested clause, left out of the
// reference, shows node id exactly got.
func contestedPeers(ref *policymodel.Ref, id types.NodeID, got []types.NodeID) (policymodel.Contested, bool) {
	for _, k := range contestedOrder {
		if slices.Equal(got, ref.Without(k).Peers(id)) {
			return k, true
		}
	}

	return 0, false
}

// contestedRoutes reports which contested clause, left out of the
// reference, gives viewer exactly got of peer's routes.
func contestedRoutes(ref *policymodel.Ref, viewer, peer types.NodeID, got []netip.Prefix) (policymodel.Contested, bool) {
	for _, k := range contestedOrder {
		want := ref.Without(k).Routes(viewer, peer)
		slices.SortFunc(want, netip.Prefix.Compare)

		if slices.Equal(got, want) {
			return k, true
		}
	}

	return 0, false
}

// TestStampsFollowReference holds the source capabilities headscale
// renders on a node, to itself and to its peers, to the reference: a stamp
// for every source selector the node is a member of that capability form
// can name, and nothing else in the reserved namespace. Membership, not
// holding a member's address, which no client verdict tells apart.
func TestStampsFollowReference(t *testing.T) {
	t.Parallel()

	var judged, stamped int

	rapid.Check(t, func(t *rapid.T) {
		forEachServed(t, func(step int, sv *served) {
			for _, n := range sv.w.Topology.Nodes {
				var want []string
				for _, s := range sv.ref.Stamps(n.ID) {
					want = append(want, policymodel.StampPrefix+s)
				}

				for _, self := range []bool{false, true} {
					var got []string

					for c := range sv.render(n.ID, self).CapMap().All() {
						if strings.Contains(string(c), strings.TrimPrefix(policymodel.StampPrefix, "https://")) {
							got = append(got, string(c))
						}
					}

					slices.Sort(got)

					judged++

					if !slices.Equal(got, want) {
						t.Fatalf("after step %d n%d is rendered (to itself %t) with stamps %v, the reference stamps it %v", step, n.ID, self, got, want)
					}
				}

				if len(want) > 0 {
					stamped++
				}
			}
		})
	})

	t.Logf("judged %d renders, %d nodes stamped", judged, stamped)
	requireJudged(t, "stamps", stamped, 50)
}
