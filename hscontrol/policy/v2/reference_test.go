// The reference semantics in policymodel held to what Tailscale's hosted
// service was captured doing, and then used as the judge of headscale's
// filters, peers, routes and stamps over generated scenarios, served the
// way the world serves them: every cell updated from its previous value
// step by step. The reference shares no code with this package; the client
// oracle (the client's own packet filter) compares rules by what they let
// through, never by how they are written.

package v2

import (
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
	"pgregory.net/rapid"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
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

type refGoldenTally struct {
	mu sync.Mutex

	files, refused, unreadable, captures int
	filters, filtersAgree, probes        int
	peers, peersAgree                    int
	routes, routesAgree                  int
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
		t.Logf("filters: %d of %d agree (%d probes)", g.filtersAgree, g.filters, g.probes)
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

func refGoldenCapture(t *testing.T, tally *refGoldenTally, id string, captures map[string]testcapture.Node,
	ref *policymodel.Ref, nodes types.Nodes, rn []policymodel.RefNode,
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

// refSteps is how long a drawn scenario may be: a failing case replays
// every step for each shrink candidate.
const refSteps = 10

// drive draws a scenario and serves it step by step, incrementally, as the
// world does, calling f after each with the nodes whose sessions read
// then: every node at the start, the step's readers after it.
func drive(t *rapid.T, f func(step int, sv *served, reads []types.NodeID)) {
	s := policymodel.Scenarios(refSteps).Draw(t, "scenario")

	slice, err := refSlice()
	if err != nil {
		t.Fatal(err)
	}

	if !slice.Holds(s) {
		return
	}

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
// meets, and a count of cases with something at stake.
type judgedFloor struct {
	// share is judged over judged and skipped; atStake is the share of
	// judged cases with something at stake.
	share, atStake float64
	// cases is the least count with something at stake, at 100 checks.
	cases int
}

// refSlice is the shapes a run of the reference properties is narrowed
// to; each property is one judge.
var refSlice = sync.OnceValues(func() (policymodel.Slice, error) { return policymodel.SliceOf() })

// requireJudged fails a property that judged less than floor.
func requireJudged(t *testing.T, what string, j judgedCounts, floor judgedFloor) {
	t.Helper()

	if slice, _ := refSlice(); !slice.Whole() {
		t.Logf("%s: %v over %v", what, &j, slice)

		return
	}

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

// Floors sit at least five standard deviations below what default runs
// measure, so that no random seed misses one: CI draws a seed per run.
// Shares stay near half the mean where that allows, so halving what is
// judged still fails; counts follow what a run draws, route sets most, and
// sit lower: the route count at half the least seen.
var (
	floorAddressForm = judgedFloor{share: 0.40, atStake: 0.30, cases: 170}
	floorCapForm     = judgedFloor{share: 0.40, atStake: 0.31, cases: 180}
	floorPeers       = judgedFloor{share: 0.40, atStake: 0.40, cases: 450}
	floorRoutes      = judgedFloor{share: 0.48, atStake: 0.16, cases: 150}
	floorStamps      = judgedFloor{share: 0.50, atStake: 0.18, cases: 500}
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
		classes policymodel.Verdicts
	)

	rapid.Check(t, func(t *rapid.T) {
		drive(t, func(step int, sv *served, reads []types.NodeID) {
			for _, id := range reads {
				n, _ := sv.w.Topology.Node(id)

				got, err := sv.ip.ForNode(id, ReceiverFacts{})
				if err != nil {
					t.Fatalf("after step %d n%d: %v", step, id, err)
				}

				view := policymodel.ModelView(n, sv.w, nil, nil)
				rep := classes.CompareAt(sv.ref, id, got, view, false)

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
		rendered, referenced policymodel.Verdicts
		form                 policymodel.FormJudge
	)

	rapid.Check(t, func(t *rapid.T) {
		drive(t, func(step int, sv *served, reads []types.NodeID) {
			for _, id := range reads {
				got, err := sv.cap.ForNode(id, sv.recv.Of(id))
				if err != nil {
					t.Fatalf("after step %d n%d: %v", step, id, err)
				}

				if msg := form.Check(sv.w, sv.ref, id, got, true); msg != "" {
					t.Fatalf("after step %d n%d's capability-form filter is in the wrong form: %s\nheadscale %v", step, id, msg, got)
				}

				n, _ := sv.w.Topology.Node(id)

				var peers []tailcfg.NodeView

				for _, p := range sv.peersOf(id) {
					if _, ok := sv.nm.Get(p); !ok {
						t.Fatalf("after step %d headscale shows n%d n%d, which is not in the tailnet", step, id, p)
					}

					peers = append(peers, sv.render(p, false))
				}

				caps := policymodel.NewNetmapCaps(sv.render(id, true), peers)
				view := policymodel.ModelView(n, sv.w, &caps, nil)
				rep := rendered.CompareAt(sv.ref, id, got, view, true)

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
				view = policymodel.ModelView(n, sv.w, &refCaps, nil)

				rep = referenced.CompareAt(sv.ref, id, got, view, true)
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
	t.Logf("form: %v", &form)
	requireJudged(t, "capability form", counts, floorCapForm)
	requireForm(t, form)
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
			for _, n := range sv.w.Topology.Nodes {
				got, want := sv.peersOf(n.ID), sv.ref.Peers(n.ID)
				slices.Sort(got)

				peerCounts.judged++

				if len(got)+len(want) > 0 {
					peerCounts.atStake++
				}

				if !slices.Equal(got, want) {
					if k, ok := policymodel.ContestedPeers(sv.ref, n.ID, got); ok {
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

					// The world offers exit routes as a pair only
					// ([types.Node.OfferedExitRoutes]).
					if slices.ContainsFunc(routes, tsaddr.IsExitRoute) && (!slices.Contains(routes, tsaddr.AllIPv4()) || !slices.Contains(routes, tsaddr.AllIPv6())) {
						routes = slices.DeleteFunc(routes, tsaddr.IsExitRoute)
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
						if k, ok := policymodel.ContestedRoutes(sv.ref, v.ID, p, got); ok {
							contested[k]++

							continue
						}

						t.Fatalf("after step %d n%d is given %v of n%d's routes %v, the reference gives it %v", step, v.ID, got, p, routes, want)
					}
				}
			}
		})
	})

	t.Logf("contested %v", policymodel.ContestedCounts(contested))
	requireJudged(t, "peers", peerCounts, floorPeers)
	requireJudged(t, "routes", routeCounts, floorRoutes)
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
