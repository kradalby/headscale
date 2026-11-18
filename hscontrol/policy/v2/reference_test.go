// The reference semantics in policymodel held to what Tailscale's hosted
// service was captured doing, and then used as the judge of headscale's
// filters, peers, routes and stamps over generated scenarios, served the
// way the world serves them: every cell updated from its previous value
// step by step. The reference shares no code with this package; the client
// oracle (the client's own packet filter) compares rules by what they let
// through, never by how they are written.

package v2

import (
	"encoding/json"
	"flag"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// refInputs is users and nodes as the reference reads them: their fields,
// not headscale's accessors.
func refInputs(users types.Users, nodes types.Nodes) ([]policymodel.User, []policymodel.RefNode) {
	us := make([]policymodel.User, len(users))
	for i, u := range users {
		us[i] = policymodel.User{ID: u.ID, Name: u.Name, Email: u.Email}
		if u.ProviderIdentifier.Valid {
			us[i].Provider = u.ProviderIdentifier.String
		}
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

// acceptsThrough returns whether rules accept a probe through a
// destination entry keep admits, as the client would with view.
func acceptsThrough(rules []tailcfg.FilterRule, view policymodel.ClientView, keep func(tailcfg.NetPortRange) bool) func(policymodel.Probe) bool {
	var kept []tailcfg.FilterRule

	for _, r := range rules {
		var dsts []tailcfg.NetPortRange

		for _, d := range r.DstPorts {
			if keep(d) {
				dsts = append(dsts, d)
			}
		}

		if len(dsts) > 0 {
			r.DstPorts, r.CapGrant = dsts, nil
			kept = append(kept, r)
		}
	}

	ms, err := filter.MatchesFromFilterRules(kept)
	if err != nil || len(ms) == 0 {
		return func(policymodel.Probe) bool { return false }
	}

	f := filter.New(ms, view.HasCap, view.LocalNets, nil, nil, logger.Discard)

	return func(p policymodel.Probe) bool { return f.RunIn(p.Packet(), 0) == filter.Accept }
}

// starAccepts returns whether rules accept a probe through a destination
// written "*". That is the one way the captures show a node taking packets
// for a route it announces but is not approved for: every such captured
// accept comes from such a rule.
func starAccepts(rules []tailcfg.FilterRule, view policymodel.ClientView) func(policymodel.Probe) bool {
	return acceptsThrough(rules, view, func(d tailcfg.NetPortRange) bool { return d.IP == "*" })
}

// wholeAccepts returns whether rules accept a probe through a destination
// entry that also names something the node serves (served): a rule that
// reaches the node, written whole. "*" is one; the captures hold no other.
func wholeAccepts(rules []tailcfg.FilterRule, view policymodel.ClientView, served *netipx.IPSet) func(policymodel.Probe) bool {
	return acceptsThrough(rules, view, func(d tailcfg.NetPortRange) bool {
		if d.IP == "*" {
			return true
		}

		r, err := netipx.ParseIPRange(d.IP)
		if err != nil {
			p, perr := netip.ParsePrefix(d.IP)
			if perr != nil {
				a, aerr := netip.ParseAddr(d.IP)
				if aerr != nil {
					return false
				}

				p = netip.PrefixFrom(a, a.BitLen())
			}

			r = netipx.RangeOfPrefix(p)
		}

		return served.OverlapsRange(r)
	})
}

type refGoldenTally struct {
	mu sync.Mutex

	files, refused, unreadable, captures int
	filters, filtersAgree, probes        int
	// unrouted counts SaaS accepts through a * destination for a route
	// the node announces unapproved; unroutedAllowAll those of them in a
	// document with neither acls nor grants.
	unrouted, unroutedAllowAll int
	peers, peersAgree          int
	routes, routesAgree        int
	// routesSteered counts captured viewer and peer pairs via steering
	// decides; routesInDoubt node captures whose routes SaaS's answer is in
	// doubt for; routesUnseen the routes the reference gives that no
	// viewer's netmap shows as the peer's primary, which the captures
	// cannot confirm or refute.
	routesSteered, routesInDoubt, routesUnseen int
	known                                      []string
}

// judge fails a check the reference answers otherwise than SaaS, unless
// refGoldenDivergences lists it, and a listed check it answers alike. It
// reports whether the check agreed.
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
// made primary for anyone.
func TestReferenceAgreesWithCaptures(t *testing.T) {
	t.Parallel()

	tally := &refGoldenTally{}

	t.Cleanup(func() {
		g := tally
		t.Logf("capture files %d: %d refused by SaaS, %d unreadable by the reference, %d node captures",
			g.files, g.refused, g.unreadable, g.captures)
		t.Logf("filters: %d of %d agree (%d probes; %d accepted by SaaS through a * destination for a route the node announces unapproved, %d of them in allow-all documents)",
			g.filtersAgree, g.filters, g.probes, g.unrouted, g.unroutedAllowAll)
		t.Logf("peers: %d of %d agree", g.peersAgree, g.peers)
		t.Logf("routes: %d of %d viewer and peer pairs agree; not compared: %d pairs via steering decides, %d node captures in doubt; %d routes the reference gives no viewer sees as primary",
			g.routesAgree, g.routes, g.routesSteered, g.routesInDoubt, g.routesUnseen)
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

				refGoldenCapture(t, tally, c.TestID, c.Captures, ref, nodes, rn, allowAll(c.Input.FullPolicy))
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		refGoldenSequence(t, tally, "policy-generation")
	})
}

// allowAll reports whether a document has neither acls nor grants.
func allowAll(policy string) bool {
	var m map[string]json.RawMessage

	_ = json.Unmarshal([]byte(policy), &m)
	_, acls := m["acls"]
	_, grants := m["grants"]

	return !acls && !grants
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
		refGoldenCapture(t, tally, id+"/"+step.Name, step.Captures, policymodel.NewRef(doc, ru, rn), nodes, rn, allowAll(string(policy)))
	}
}

func refGoldenCapture(t *testing.T, tally *refGoldenTally, id string, captures map[string]testcapture.Node,
	ref *policymodel.Ref, nodes types.Nodes, rn []policymodel.RefNode, allAllowed bool,
) {
	t.Helper()

	primaries := unsteeredPrimaries(captures, ref, nodes)

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
		star := starAccepts(capture.PacketFilterRules, view)
		unrouted := 0

		rep.Verdicts = slices.DeleteFunc(rep.Verdicts, func(d policymodel.VerdictDiff) bool {
			if d.Ref == filter.Accept && !ref.Serves(node.ID, d.Probe.Dst) && view.LocalNets.Contains(d.Probe.Dst) && star(d.Probe) {
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

			if allAllowed {
				g.unroutedAllowAll += unrouted
			}

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

		if notCompared(routesNotCompared, key+"/peer-allowed-ips") {
			tally.add(func(g *refGoldenTally) { g.routesInDoubt++ })

			continue
		}

		refGoldenRoutes(t, tally, key, capture, ref, nodes, rn, node, primaries)
	}
}

// unsteeredPrimaries is each peer's primaries as every viewer via steering
// leaves alone saw them: a route the reference gives that is such a
// viewer's primary is comparable with every such viewer's AllowedIPs, an
// over-grant included. A steered viewer's primaries are steering's choice.
func unsteeredPrimaries(captures map[string]testcapture.Node, ref *policymodel.Ref, nodes types.Nodes) map[string][]netip.Prefix {
	primaries := map[string][]netip.Prefix{}

	for alias, capture := range captures {
		viewer := findNodeByGivenName(nodes, alias)
		if capture.Netmap == nil || viewer == nil {
			continue
		}

		for _, p := range capture.Netmap.Peers {
			name, _, _ := strings.Cut(p.Name(), ".")
			if peer := findNodeByGivenName(nodes, name); peer != nil && !ref.Steered(viewer.ID, peer.ID) {
				primaries[name] = append(primaries[name], p.PrimaryRoutes().AsSlice()...)
			}
		}
	}

	return primaries
}

// refGoldenRoutes holds each captured peer's routes in node's netmap to
// the reference's route access, both ways, over the routes some unsteered
// viewer sees as the peer's primary.
func refGoldenRoutes(t *testing.T, tally *refGoldenTally, key string, capture testcapture.Node, ref *policymodel.Ref,
	nodes types.Nodes, rn []policymodel.RefNode, node *types.Node, primaries map[string][]netip.Prefix,
) {
	t.Helper()

	refNode := func(id types.NodeID) policymodel.RefNode {
		return rn[slices.IndexFunc(rn, func(n policymodel.RefNode) bool { return n.ID == id })]
	}

	// A router is given the primary's route for a prefix it serves
	// itself, whatever the policy: elections, not route access.
	ownRoutes := refNode(node.ID).ServedRoutes()

	for _, nmPeer := range capture.Netmap.Peers {
		name, _, _ := strings.Cut(nmPeer.Name(), ".")

		peer := findNodeByGivenName(nodes, name)
		if peer == nil {
			continue
		}

		if ref.Steered(node.ID, peer.ID) {
			tally.add(func(g *refGoldenTally) { g.routesSteered++ })

			continue
		}

		var wantR, gotR []netip.Prefix

		unseen := 0

		for _, p := range nmPeer.AllowedIPs().All() {
			ownAddr := p.IsSingleIP() && slices.Contains(refNode(peer.ID).Addrs, p.Addr())
			if !ownAddr && !slices.Contains(ownRoutes, p) {
				wantR = append(wantR, p)
			}
		}

		for _, p := range ref.Routes(node.ID, peer.ID) {
			switch {
			case slices.Contains(ownRoutes, p):
			case p.Bits() == 0 || slices.Contains(primaries[name], p):
				gotR = append(gotR, p)
			default:
				unseen++
			}
		}

		slices.SortFunc(wantR, netip.Prefix.Compare)
		slices.SortFunc(gotR, netip.Prefix.Compare)

		agree := tally.judge(t, key+"/routes/"+name, slices.Equal(wantR, gotR), func() string {
			return fmt.Sprintf("routes of %s: SaaS %v, reference %v", name, wantR, gotR)
		})

		tally.add(func(g *refGoldenTally) {
			g.routes++
			g.routesUnseen += unseen

			if agree {
				g.routesAgree++
			}
		})
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

// served is what headscale serves for one world, from the cells the world
// serves from: filters in both modes, peers, route access, and the CapMaps
// it renders.
type served struct {
	w   policymodel.World
	ref *policymodel.Ref

	users types.Users
	// list is the nodes in ID order, each the pointer the step that last
	// changed it wrote; nm holds them as the world's node table.
	list types.Nodes
	nm   *NodeMap

	pm    *PolicyManager
	sel   *Selectors
	us    *UserSets
	t     *Templates
	roles Roles
	posts Postings
	appr  SubnetApprovals
	sides Sides
	peers *PeerClasses
	caps  *graph.Map[types.NodeID, tailcfg.NodeCapMap]
	recv  Receivers

	ip, cap *Filters
}

func sameCapMaps(a, b tailcfg.NodeCapMap) bool { return a.Equal(b) }

// serve returns what headscale serves for w, following prev across the
// step that led to w, which change describes, as the world's cells do:
// each updated from its previous value, a node the step did not change
// keeping its pointer. With prev nil it builds w from scratch.
func serve(prev *served, w policymodel.World, change policymodel.Change) (*served, error) {
	users, built := w.Topology.Build()

	sv := &served{w: w, ref: policymodel.RefOf(w), users: users}

	if prev == nil {
		prev = &served{nm: graph.NewMap[types.NodeID](graph.Same[*types.Node], nil), caps: graph.NewMap[types.NodeID](sameCapMaps, nil)}
		change = policymodel.Change{}

		for _, n := range built {
			change.Nodes = append(change.Nodes, n.ID)
		}
	}

	e := prev.nm.Edit()
	for _, id := range change.Removed {
		e.Delete(id)
	}

	for _, n := range built {
		if slices.Contains(change.Nodes, n.ID) {
			e.Set(n.ID, n)
		}
	}

	sv.nm = e.Done()

	for _, n := range built {
		cur, _ := sv.nm.Get(n.ID)
		sv.list = append(sv.list, cur)
	}

	var err error

	if prev.pm == nil {
		sv.pm, err = NewPolicyManager(w.Policy.HuJSON(), users, sv.list.ViewSlice())
	} else {
		sv.pm, err = NewPolicyManagerFrom(prev.pm, w.Policy.HuJSON(), users, sv.list.ViewSlice())
	}

	if err != nil {
		return nil, err
	}

	sv.sel = SelectorsFor(prev.sel, sv.pm)
	sv.us = NewUserSets(prev.us, sv.sel, users)
	sv.roles = prev.roles.Update(sv.us, sv.nm, nil)
	sv.posts = prev.posts.Update(sv.roles)
	sv.t = BuildTemplates(prev.t, sv.sel)
	sv.appr = prev.appr.Update(sv.nm)
	sv.sides = UpdateSides(prev.sides, sv.t, sv.roles, sv.posts, sv.appr, sv.nm)
	sv.peers = RolePeers(prev.peers, sv.sides)

	caps := sv.pm.NodeCapMaps()
	ce := prev.caps.Edit()

	for id, c := range caps {
		if old, ok := prev.caps.Get(id); !ok || !old.Equal(c) {
			ce.Set(id, c)
		}
	}

	for id := range prev.caps.All() {
		if _, ok := caps[id]; !ok {
			ce.Delete(id)
		}
	}

	sv.caps = ce.Done()
	sv.recv = prev.recv.Update(sv.nm, sv.caps)

	views := sv.list.ViewSlice()
	sv.ip = FollowFiltersFor(AddressSources, prev.ip, sv.t, sv.posts, sv.appr, views, sv.sides)
	sv.cap = FollowFiltersFor(CapabilitySources, prev.cap, sv.t, sv.posts, sv.appr, views, sv.sides)

	return sv, nil
}

// render is node id as headscale renders it in capability mode, to
// itself or to a peer.
func (sv *served) render(id types.NodeID, self bool) tailcfg.NodeView {
	n, _ := sv.nm.Get(id)
	rs, _ := sv.roles.Of(id)
	c, _ := sv.caps.Get(id)
	caps := WithStamps(c, sv.t.StampsOf(rs))

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

// viewOf is what node n's client knows when it filters: local nets from
// what it announces and runs as, every node's addresses as sources worth
// probing, and capabilities from caps. A client not known to match
// capability sources (one reporting no versions, tailscale-rs) matches
// none: it parses a cap: source and finds nobody holding it.
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

	if caps != nil && (n.Client == policymodel.Official || n.Client == policymodel.AppConnector) {
		v.HasCap = caps.HasCap
	}

	return v
}

// verdictClasses are the differences from the reference a property
// allows, each counted; anything else fails it.
type verdictClasses struct {
	// unrouted: the client takes packets for a route its node announces
	// but is not approved for, through a rule whose destination is "*";
	// the captures show exactly that.
	unrouted int
	// unroutedWhole: the same through any other destination entry that
	// also names something the node serves, written whole. No capture
	// holds one; reported as a question, not encoded.
	unroutedWhole int
	// crossFamilyICMP: capability form refuses a packet carrying the
	// other family's ICMP protocol, which address form accepts: decided as
	// malformed, failing closed.
	crossFamilyICMP int
	// repeatedValues: an app capability's values come once per
	// destination entry of a grant that names the receiver, where the
	// reference gives them once per grant. Reported, not encoded; no
	// capture holds an app grant with two destinations.
	repeatedValues int
	// contested counts the differences that are exactly some contested
	// clauses of the reference, by the set of clauses.
	contested map[policymodel.Contested]int
}

func (c *verdictClasses) addContested(k policymodel.Contested, n int) {
	if c.contested == nil {
		c.contested = map[policymodel.Contested]int{}
	}

	c.contested[k] += n
}

// contestedSets are the sets of contested clauses a difference is tried
// against, in order: each alone, each pair, then all of them.
var contestedSets = func() []policymodel.Contested {
	cs := policymodel.ContestedClauses
	out := slices.Clone(cs)

	var all policymodel.Contested

	for i, a := range cs {
		all |= a

		for _, b := range cs[i+1:] {
			out = append(out, a|b)
		}
	}

	return append(out, all)
}()

func (c *verdictClasses) String() string {
	var parts []string

	for _, k := range contestedSets {
		if c.contested[k] > 0 {
			open := ""
			if k.FailsOpen() {
				open = ", fails open"
			}

			parts = append(parts, fmt.Sprintf("%d %s%s", c.contested[k], k, open))
		}
	}

	return fmt.Sprintf("allowed %d cross-family ICMP, %d through * on unapproved routes; suspected: %d through other whole destinations on unapproved routes, %d app values repeated; contested %v",
		c.crossFamilyICMP, c.unrouted, c.unroutedWhole, c.repeatedValues, parts)
}

// judge holds rep, a comparison of the reference's rules (as Ref) with
// production's got (as Cand) at node n, to the allowed classes, and
// returns the differences left.
func (c *verdictClasses) judge(rep policymodel.Report, ref *policymodel.Ref, n policymodel.Node, view policymodel.ClientView,
	got []tailcfg.FilterRule, capForm bool,
) policymodel.Report {
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

	var star, whole func(policymodel.Probe) bool

	rep.Verdicts = slices.DeleteFunc(rep.Verdicts, func(d policymodel.VerdictDiff) bool {
		if d.Ref != filter.Drop || d.Cand != filter.Accept || ref.Serves(n.ID, d.Probe.Dst) || !view.LocalNets.Contains(d.Probe.Dst) {
			return false
		}

		if star == nil {
			star, whole = starAccepts(got, view), wholeAccepts(got, view, ref.Served(n.ID))
		}

		switch {
		case star(d.Probe):
			c.unrouted++
		case whole(d.Probe):
			c.unroutedWhole++
		default:
			return false
		}

		return true
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
// are taken out. A node whose whole difference is the reference less
// some contested clauses is counted under those clauses.
func (c *verdictClasses) compareAt(ref *policymodel.Ref, n policymodel.Node, got []tailcfg.FilterRule, view policymodel.ClientView, capForm bool) policymodel.Report {
	var trial verdictClasses

	rep := trial.judge(policymodel.Compare(ref.Rules(n.ID), got, view), ref, n, view, got, capForm)
	if !rep.Equivalent() {
		for _, k := range contestedSets {
			var without verdictClasses

			rest := without.judge(policymodel.Compare(ref.Without(k).Rules(n.ID), got, view), ref, n, view, got, capForm)
			if rest.Equivalent() {
				c.addContested(k, len(rep.Verdicts)+len(rep.Caps))
				rep, trial = rest, without

				break
			}
		}
	}

	c.unrouted += trial.unrouted
	c.unroutedWhole += trial.unroutedWhole
	c.crossFamilyICMP += trial.crossFamilyICMP
	c.repeatedValues += trial.repeatedValues

	return rep
}

// refSteps is how long a drawn scenario may be: a failing case replays
// every step for each shrink candidate.
const refSteps = 10

// drive draws a scenario and serves it step by step, incrementally, as the
// world does, calling f after each with the nodes whose sessions read
// then: every node at the start, the step's readers after it.
func drive(t *rapid.T, f func(step int, sv *served, reads []types.NodeID)) {
	s := policymodel.Scenarios(refSteps).Draw(t, "scenario")

	sv, err := serve(nil, s.Start, policymodel.Change{})
	if err != nil {
		t.Fatalf("the start's policy is refused: %s", stableError(err))
	}

	all := make([]types.NodeID, 0, len(s.Start.Topology.Nodes))
	for _, n := range s.Start.Topology.Nodes {
		all = append(all, n.ID)
	}

	f(0, sv, all)

	w := s.Start

	for i, st := range s.Steps {
		next, change := w.Commit(st)

		sv, err = serve(sv, next, change)
		if err != nil {
			t.Fatalf("after step %d the policy is refused: %s", i+1, stableError(err))
		}

		reads := slices.DeleteFunc(slices.Clone(st.Reads), func(id types.NodeID) bool {
			_, ok := next.Topology.Node(id)

			return !ok
		})

		f(i+1, sv, reads)

		w = next
	}
}

// judgedCounts are what a property judged: cases, cases with something
// at stake (a rule on either side, a peer, a route, a stamp), and cases
// skipped by why.
type judgedCounts struct {
	judged, atStake int
	skipped         map[string]int
}

func (j *judgedCounts) skip(why string) {
	if j.skipped == nil {
		j.skipped = map[string]int{}
	}

	j.skipped[why]++
}

func (j *judgedCounts) String() string {
	return fmt.Sprintf("judged %d (%d with something at stake), skipped %v", j.judged, j.atStake, j.skipped)
}

// judgedFloor is what a property must judge: shares of the cases it
// meets, each about half of what a default run measures, so that halving
// what is judged turns it red whatever the run drew; and a count of cases
// with something at stake well below any run's.
type judgedFloor struct {
	// share is judged over judged and skipped; atStake is the share of
	// judged cases with something at stake.
	share, atStake float64
	// cases is the least count with something at stake, at 100 checks.
	cases int
}

// requireJudged fails a property that judged less than floor.
func requireJudged(t *testing.T, what string, j judgedCounts, floor judgedFloor) {
	t.Helper()

	skipped := 0
	for _, n := range j.skipped {
		skipped += n
	}

	share := float64(j.judged) / float64(max(1, j.judged+skipped))
	atStake := float64(j.atStake) / float64(max(1, j.judged))
	checks := rapidChecks()
	cases := floor.cases * checks / 100

	t.Logf("%s: %v; judged share %.2f, at stake %.2f", what, &j, share, atStake)

	switch {
	case checks < 100:
		// Twenty checks swing too widely for a floor to mean anything.
	case share < floor.share:
		t.Errorf("%s: judged %.2f of the cases met, want at least %.2f", what, share, floor.share)
	case atStake < floor.atStake:
		t.Errorf("%s: %.2f of the judged cases had something at stake, want at least %.2f", what, atStake, floor.atStake)
	case j.atStake < cases:
		t.Errorf("%s: only %d cases with something at stake judged, want at least %d", what, j.atStake, cases)
	}
}

// Floors at about half of what default runs measure, over thirty seeds.
// Route sets vary most with what a run draws: their count floor sits
// below the least seen, and their shares carry the guard.
var (
	floorAddressForm = judgedFloor{share: 0.40, atStake: 0.30, cases: 250}
	floorCapForm     = judgedFloor{share: 0.40, atStake: 0.31, cases: 260}
	floorPeers       = judgedFloor{share: 0.40, atStake: 0.40, cases: 720}
	floorRoutes      = judgedFloor{share: 0.48, atStake: 0.32, cases: 300}
	floorStamps      = judgedFloor{share: 0.50, atStake: 0.23, cases: 1090}
)

// rapidChecks is the checks a property makes in this run.
func rapidChecks() int {
	checks := 100

	if f := flag.Lookup("rapid.checks"); f != nil {
		n, err := strconv.Atoi(f.Value.String())
		if err == nil {
			checks = n
		}
	}

	if testing.Short() {
		checks /= 5
	}

	return checks
}

// TestServedFiltersFollowReference holds each node's address-form filter,
// as the world serves it after each step to the sessions that read, to the
// reference's rules for it, through the node's own client. Oracle: the
// reference (no production code) and the client's filter.
func TestServedFiltersFollowReference(t *testing.T) {
	t.Parallel()

	var (
		counts  judgedCounts
		probes  int
		classes verdictClasses
	)

	rapid.Check(t, func(t *rapid.T) {
		drive(t, func(step int, sv *served, reads []types.NodeID) {
			for _, id := range reads {
				if why := sv.ref.OutOfDomain(); why != "" {
					counts.skip(why)

					continue
				}

				n, _ := sv.w.Topology.Node(id)

				got, err := sv.ip.ForNode(id, ReceiverFacts{})
				if err != nil {
					t.Fatalf("after step %d n%d: %v", step, id, err)
				}

				view := viewOf(n, sv.w, nil)
				rep := classes.compareAt(sv.ref, n, got, view, false)

				counts.judged++
				probes += rep.Probes

				if len(got) > 0 || len(sv.ref.Rules(id)) > 0 {
					counts.atStake++
				}

				if !rep.Equivalent() {
					t.Fatalf("after step %d n%d's address-form filter differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v",
						step, id, rep, sv.ref.Rules(id), got)
				}
			}
		})
	})

	t.Logf("%d probes; %v", probes, &classes)
	requireJudged(t, "address form", counts, floorAddressForm)
}

// TestCapabilityFormFollowsReference holds each node's capability-form
// filter, as served to the sessions that read, to the reference's rules
// for it, through its client, twice: with the netmap headscale renders
// (its peers and stamps), and with one built from the reference's peers
// and stamps, so that membership comes from somewhere other than the code
// under test. A client not known to match capabilities matches none.
// Allowed besides the address-form classes: cross-family ICMP, which
// capability form refuses.
func TestCapabilityFormFollowsReference(t *testing.T) {
	t.Parallel()

	var (
		counts               judgedCounts
		probes               int
		rendered, referenced verdictClasses
	)

	rapid.Check(t, func(t *rapid.T) {
		drive(t, func(step int, sv *served, reads []types.NodeID) {
			for _, id := range reads {
				if why := sv.ref.OutOfDomain(); why != "" {
					counts.skip(why)

					continue
				}

				n, _ := sv.w.Topology.Node(id)

				got, err := sv.cap.ForNode(id, sv.recv.Of(id))
				if err != nil {
					t.Fatalf("after step %d n%d: %v", step, id, err)
				}

				var peers []tailcfg.NodeView

				for _, p := range sv.peersOf(id) {
					if _, ok := sv.nm.Get(p); !ok {
						t.Fatalf("after step %d headscale shows n%d n%d, which is not in the tailnet", step, id, p)
					}

					peers = append(peers, sv.render(p, false))
				}

				caps := policymodel.NewNetmapCaps(sv.render(id, true), peers)
				view := viewOf(n, sv.w, &caps)
				rep := rendered.compareAt(sv.ref, n, got, view, true)

				counts.judged++
				probes += rep.Probes

				if len(got) > 0 || len(sv.ref.Rules(id)) > 0 {
					counts.atStake++
				}

				if !rep.Equivalent() {
					t.Fatalf("after step %d n%d's capability-form filter, with the netmap headscale renders, differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v",
						step, id, rep, sv.ref.Rules(id), got)
				}

				self, refPeers := sv.ref.Netmap(id)
				refCaps := policymodel.NewNetmapCaps(self, refPeers)
				view = viewOf(n, sv.w, &refCaps)

				rep = referenced.compareAt(sv.ref, n, got, view, true)
				probes += rep.Probes

				if !rep.Equivalent() {
					t.Fatalf("after step %d n%d's capability-form filter, with the reference's peers and stamps, differs from the reference (reference, candidate headscale): %s\nreference %v\nheadscale %v",
						step, id, rep, sv.ref.Rules(id), got)
				}
			}
		})
	})

	t.Logf("%d probes", probes)
	t.Logf("with the rendered netmap: %v", &rendered)
	t.Logf("with the reference's netmap: %v", &referenced)
	requireJudged(t, "capability form", counts, floorCapForm)
}

// TestPeersAndRoutesFollowReference holds headscale's peers, after every
// step, to the reference's visibility, and route access between peers to
// the reference's. Route access is compared on every route the peer
// serves, before elections. A pair where the viewer is a source of a via
// grant one of the peer's routes reaches is left out: via steering decides
// it, which the reference does not model. A via router's routes back to a
// via grant's sources are judged.
func TestPeersAndRoutesFollowReference(t *testing.T) {
	t.Parallel()

	var peerCounts, routeCounts judgedCounts

	contested := map[policymodel.Contested]int{}

	rapid.Check(t, func(t *rapid.T) {
		drive(t, func(step int, sv *served, _ []types.NodeID) {
			if why := sv.ref.OutOfDomain(); why != "" {
				for range sv.w.Topology.Nodes {
					peerCounts.skip(why)
				}

				return
			}

			for _, n := range sv.w.Topology.Nodes {
				got, want := sv.peersOf(n.ID), sv.ref.Peers(n.ID)
				slices.Sort(got)

				peerCounts.judged++

				if len(got)+len(want) > 0 {
					peerCounts.atStake++
				}

				if !slices.Equal(got, want) {
					if k, ok := contestedPeers(sv.ref, n.ID, got); ok {
						contested[k]++

						continue
					}

					t.Fatalf("after step %d n%d is shown %v, the reference shows it %v", step, n.ID, got, want)
				}
			}

			for _, v := range sv.w.Topology.Nodes {
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

					if sv.ref.Steered(v.ID, p) {
						routeCounts.skip("via steering decides")

						continue
					}

					got, want := sv.sides.RouteAccess(v.ID, routes), sv.ref.Routes(v.ID, p)
					slices.SortFunc(got, netip.Prefix.Compare)
					slices.SortFunc(want, netip.Prefix.Compare)

					routeCounts.judged++

					if len(got)+len(want) > 0 {
						routeCounts.atStake++
					}

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

	for _, k := range contestedSets {
		if contested[k] > 0 {
			named = append(named, fmt.Sprintf("%d %s", contested[k], k))
		}
	}

	t.Logf("contested %v", named)
	requireJudged(t, "peers", peerCounts, floorPeers)
	requireJudged(t, "routes", routeCounts, floorRoutes)
}

// contestedPeers reports which contested clauses, left out of the
// reference, show node id exactly got.
func contestedPeers(ref *policymodel.Ref, id types.NodeID, got []types.NodeID) (policymodel.Contested, bool) {
	for _, k := range contestedSets {
		if slices.Equal(got, ref.Without(k).Peers(id)) {
			return k, true
		}
	}

	return 0, false
}

// contestedRoutes reports which contested clauses, left out of the
// reference, give viewer exactly got of peer's routes.
func contestedRoutes(ref *policymodel.Ref, viewer, peer types.NodeID, got []netip.Prefix) (policymodel.Contested, bool) {
	for _, k := range contestedSets {
		want := ref.Without(k).Routes(viewer, peer)
		slices.SortFunc(want, netip.Prefix.Compare)

		if slices.Equal(got, want) {
			return k, true
		}
	}

	return 0, false
}

// TestStampsFollowReference holds the source capabilities headscale
// renders on a node after every step, to itself and to its peers, to the
// reference: a stamp for every source selector the node is a member of
// that capability form can name, and nothing else in the reserved
// namespace. Membership, not holding a member's address, which no client
// verdict tells apart.
func TestStampsFollowReference(t *testing.T) {
	t.Parallel()

	var counts judgedCounts

	rapid.Check(t, func(t *rapid.T) {
		drive(t, func(step int, sv *served, _ []types.NodeID) {
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

					counts.judged++

					if len(got)+len(want) > 0 {
						counts.atStake++
					}

					if !slices.Equal(got, want) {
						t.Fatalf("after step %d n%d is rendered (to itself %t) with stamps %v, the reference stamps it %v", step, n.ID, self, got, want)
					}
				}
			}
		})
	})

	requireJudged(t, "stamps", counts, floorStamps)
}
