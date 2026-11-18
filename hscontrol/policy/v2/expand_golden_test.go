// The expander over the SaaS captures: for every policy headscale
// compiles and every node of its topology, templates and postings
// expanded must give exactly what the compile gives (check E), and for
// every captured node what SaaS sent, as the compat tests compare it
// (check A′ on the expander's output). The cap form cut for a captured
// node also expands to the same filter with its holders read from the
// captured netmap, its nodes stamped with the caps their role sets hold.

package v2

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
	"tailscale.com/types/views"
)

// expansionOf builds the expansion of src's compile pm over users and
// nodes from scratch, and returns it with its membership.
func expansionOf(t *testing.T, pm *PolicyManager, users types.Users, nodes *NodeMap) (*Expansion, Roles) {
	t.Helper()

	sel := SelectorsFor(nil, pm)
	us := NewUserSets(nil, sel, users)
	roles := Roles{}.Update(us, nodes, nil)
	posts := Postings{}.Update(roles)

	x, err := NewExpansion(BuildTemplates(nil, sel), posts, SubnetApprovals{}.Update(nodes).Strings(), lookupIn(nodes))
	require.NoError(t, err)

	x.diagnose = true

	return x, roles
}

func lookupIn(nodes *NodeMap) func(types.NodeID) (types.NodeView, bool) {
	return func(id types.NodeID) (types.NodeView, bool) {
		n, ok := nodes.Get(id)
		if !ok {
			return types.NodeView{}, false
		}

		return n.View(), true
	}
}

// requireSortedByID requires the list a compile is fed to be sorted by ID,
// as the world keeps it: the compile lists an owner's nodes in list order,
// the postings in ID order.
func requireSortedByID(t *testing.T, nodes types.Nodes) {
	t.Helper()

	ids := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}

	require.True(t, slices.IsSorted(ids), "the node list is not sorted by ID")
}

// requireExpandsLikeCompile requires x to give every node pm's filter,
// exactly, and returns the rules compared and the shapes cut.
func requireExpandsLikeCompile(t *testing.T, x *Expansion, pm *PolicyManager, nodes types.Nodes, msgAndArgs ...any) (int, FilterShapes) {
	t.Helper()

	var (
		rules  int
		shapes FilterShapes
	)

	for _, n := range nodes {
		want, err := pm.FilterForNode(n.View())
		require.NoError(t, err)

		got := expandFilter(x.capFilterFor(n.View(), &shapes), x.holders, reasonAddressMode)
		if !reflect.DeepEqual(want, got) {
			require.Failf(t, "expanded filter differs from the compile's", "node %s (%d) %s:\n%s",
				n.GivenName, n.ID, fmt.Sprint(msgAndArgs...), cmp.Diff(want, got, inOrderOpts...))
		}

		rules += len(got)
	}

	if got := x.Filter(); !reflect.DeepEqual(pm.filter, got) {
		require.Failf(t, "expanded global filter differs from the compile's", "%s:\n%s",
			fmt.Sprint(msgAndArgs...), cmp.Diff(pm.filter, got, inOrderOpts...))
	}

	// Filters look nodes up in a list sorted by ID, as the world keeps it.
	list := slices.Clone(nodes)
	slices.SortFunc(list, func(a, b *types.Node) int { return int(a.ID) - int(b.ID) }) //nolint:gosec // node IDs fit

	f := NewFilters(x.t, x.posts, SubnetApprovals{strs: x.routes}, list.ViewSlice())
	requireServedAgreesWithGlobal(t, f, list.ViewSlice(), msgAndArgs...)

	shapes.SelfByAddress = x.byAddress

	return rules, shapes
}

// globalAgreement counts, per top-level test, the nodes whose served filter
// requireServedAgreesWithGlobal held to the global filter's reduction and
// those with rules of their own, which it cannot be.
var globalAgreement = struct {
	sync.Mutex

	counts map[string][2]int
}{counts: map[string][2]int{}}

// agreementOf returns the counts of the top-level test t runs under.
func agreementOf(t *testing.T) (int, int) {
	t.Helper()

	globalAgreement.Lock()
	defer globalAgreement.Unlock()

	root, _, _ := strings.Cut(t.Name(), "/")
	c := globalAgreement.counts[root]

	return c[0], c[1]
}

// requireServedAgreesWithGlobal ties what nodes are served to the global
// filter the policy's tests, State.Filter and the debug dump read, which an
// independent construction writes ([Expansion.Filter] against the cut of
// [Expansion.capFilterFor]): for every node without rules of its own, the
// global filter reduced to it as the compile reduces it is exactly what it
// is served. A node with rules of its own — an owner under an
// autogroup:self grant, every exit node under one, a node carrying a via
// grant's tag — is sent rules the global filter does not hold, which can
// also merge with shared ones and move where merged rules sit, so it is
// only counted.
func requireServedAgreesWithGlobal(t *testing.T, f *Filters, nodes views.Slice[types.NodeView], msgAndArgs ...any) {
	t.Helper()

	global, err := f.Global()
	require.NoError(t, err)

	x, err := f.expansion()
	require.NoError(t, err)

	reducer := policyutil.NewReducer(global)

	var checked, own int

	for _, n := range nodes.All() {
		if hasOwnRules(x, n) {
			own++

			continue
		}

		served, err := f.ForNode(n.ID(), ReceiverFacts{})
		require.NoError(t, err)

		if want := reducer.Reduce(n); !reflect.DeepEqual(want, served) {
			require.Failf(t, "the global filter reduced to a node differs from what it is served", "node %d %s:\n%s",
				n.ID(), fmt.Sprint(msgAndArgs...), cmp.Diff(want, served, inOrderOpts...))
		}

		checked++
	}

	root, _, _ := strings.Cut(t.Name(), "/")

	globalAgreement.Lock()
	c := globalAgreement.counts[root]
	globalAgreement.counts[root] = [2]int{c[0] + checked, c[1] + own}
	globalAgreement.Unlock()
}

// hasOwnRules reports whether n gets, or places merged rules by, a rule
// only it receives: a self or via rule, reaching it or not.
func hasOwnRules(x *Expansion, n types.NodeView) bool {
	c := &cut{f: capFilter{anchors: []int64{}}, rc: newReceiver(n), count: true}

	for g, gt := range x.t.grants {
		switch {
		case gt.none:
		case gt.kind == grantSelf:
			x.cutSelf(c, g)
		case gt.kind == grantVia:
			x.cutVia(c, g, gt, x.grant(g))
		}
	}

	return len(c.f.rules) > 0 || len(c.own) > 0 || c.unreached > 0
}

type expandTally struct {
	mu sync.Mutex

	files, loads, refused, nodes, rules int
	saasCompared, saasExact             int
	saasListed                          []string
	netmapSame                          int
	netmapRouted, netmapDiffer          []string
	incremental                         int
	kinds                               map[string]int
	steps, stepFilters                  int
	shapes                              FilterShapes
	anchoredIn                          []string
}

func (g *expandTally) add(f func(*expandTally)) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f(g)
}

// TestGoldenExpander runs the expander over every policy the captures
// hold, with each directory's own users and nodes, the user captures under
// every overlay, and the step capture replayed incrementally.
func TestGoldenExpander(t *testing.T) {
	t.Parallel()

	tally := &expandTally{kinds: map[string]int{}}

	t.Cleanup(func() {
		t.Logf("capture files %d; %d policy loads expanded (%d refused by headscale) over %d nodes, %d rules, each equal to the compile",
			tally.files, tally.loads, tally.refused, tally.nodes, tally.rules)
		t.Logf("grant kinds expanded: %v", tally.kinds)
		t.Logf("shapes cut from scratch: %+v", tally.shapes)
		slices.Sort(tally.anchoredIn)
		t.Logf("policy loads with a rule merged at a rule that does not reach the receiver: %v", tally.anchoredIn)
		t.Logf("against SaaS: %d captured filters compared, %d exact as the compat tests compare, %d listed divergences: %v",
			tally.saasCompared, tally.saasExact, len(tally.saasListed), tally.saasListed)
		t.Logf("netmap holders: %d cap-form filters expand alike from the captured netmap; %d differ on receivers announcing routes, %d on listed divergences %v",
			tally.netmapSame, len(tally.netmapRouted), len(tally.netmapDiffer), tally.netmapDiffer)
		slices.Sort(tally.netmapRouted)
		t.Logf("  announcing routes: %v", tally.netmapRouted)

		checked, own := agreementOf(t)
		t.Logf("served ≡ global filter reduced: %d node filters held to it, %d nodes with rules of their own skipped", checked, own)
		t.Logf("incremental: %d policy loads replayed by joins and leaves; policy-generation: %d steps, %d captured filters against SaaS",
			tally.incremental, tally.steps, tally.stepFilters)
	})

	sources := goldenFilterSources()
	sources = append(sources, goldenFilterSource{
		dir: "policytest_results", glob: "*.hujson",
		build: func(_ *testing.T, c *testcapture.Capture) (types.Users, types.Nodes) {
			users := setupSSHDataCompatUsers()

			return users, buildGrantsNodesFromCapture(users, c)
		},
	})

	for _, src := range sources {
		files, err := filepath.Glob(filepath.Join("testdata", src.dir, src.glob))
		require.NoError(t, err)
		require.NotEmpty(t, files, "no captures in %s", src.dir)

		for _, file := range files {
			t.Run(filepath.Join(src.dir, filepath.Base(file)), func(t *testing.T) {
				t.Parallel()

				c, err := testcapture.Read(file)
				require.NoError(t, err)

				tally.add(func(g *expandTally) { g.files++ })

				policy := []byte(c.Input.FullPolicy)

				if src.dir != "users_results" {
					users, nodes := src.build(t, c)
					goldenExpansion(t, tally, c.TestID, policy, users, nodes, c)

					return
				}

				for _, o := range userTokenOverlays {
					name := o.name
					if name == "" {
						name = "capture"
					}

					t.Run(name, func(t *testing.T) {
						users, nodes, _ := userTokenUsersAndNodes(t, c, o)

						// Only the capture as taken is SaaS's answer.
						var captured *testcapture.Capture
						if o.name == "" {
							captured = c
						}

						goldenExpansion(t, tally, c.TestID, policy, users, nodes, captured)
					})
				}
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		goldenExpansionSequence(t, tally, "policy-generation")
	})
}

// goldenExpansion checks one policy load: every node of the topology from
// scratch, the captured nodes against SaaS and through their netmap, and
// the same tailnet built by joins and leaves.
func goldenExpansion(t *testing.T, tally *expandTally, id string, src []byte, users types.Users, nodes types.Nodes, c *testcapture.Capture) {
	t.Helper()

	requireSortedByID(t, nodes)

	pm, err := NewPolicyManager(src, users, nodes.ViewSlice())
	if err != nil {
		tally.add(func(g *expandTally) { g.refused++ })

		return
	}

	all := nodeMapOf(nodes)
	x, roles := expansionOf(t, pm, users, all)
	rules, shapes := requireExpandsLikeCompile(t, x, pm, nodes, "from scratch")

	kinds := map[string]int{}

	for _, gt := range x.t.grants {
		switch {
		case gt.none:
			kinds["none"]++
		case gt.kind == grantSelf:
			kinds["self"]++
		case gt.kind == grantVia:
			kinds["via"]++
		case gt.app != nil:
			kinds["app"]++
		default:
			kinds["regular"]++
		}
	}

	tally.add(func(g *expandTally) {
		g.loads++
		g.nodes += len(nodes)
		g.rules += rules
		g.shapes.Add(shapes)

		if shapes.Anchored > 0 {
			g.anchoredIn = append(g.anchoredIn, id)
		}

		for k, n := range kinds {
			g.kinds[k] += n
		}
	})

	if c != nil && !c.Error && c.Input.APIResponseCode == 200 {
		for _, alias := range slices.Sorted(maps.Keys(c.Captures)) {
			capture := c.Captures[alias]
			if capture.Netmap == nil {
				continue
			}

			node := findNodeByGivenName(nodes, alias)
			require.NotNilf(t, node, "%s: node %s not built", id, alias)

			got := x.FilterForNode(node.View())
			key := id + "/" + alias + "/manager"

			diff := cmp.Diff(capture.PacketFilterRules, got, append(cmpOptions(), cmpopts.EquateEmpty())...)

			_, listed := goldenProbeDivergences[key]
			if diff != "" && !listed {
				t.Errorf("%s: expanded filter differs from SaaS (-tailscale +expanded):\n%s", alias, diff)
			}

			// A receiver whose local nets are its own addresses sees as
			// peers every node its rules name: holders read off its netmap
			// must do. A router's or exit node's rules also cover others'
			// destinations, whose sources it need not see; those rules stay
			// in IP form (the local-nets fallback).
			// Sources and keys from the netmap's holders alone.
			cut := x.capFilterFor(node.View(), nil)
			cut.srcs, cut.keys = nil, nil
			viaNetmap := expandFilter(cut, netmapHolders(capture.Netmap, nodes, roles, x.table).holders, reasonAddressMode)
			same := reflect.DeepEqual(got, viaNetmap)
			announces := capture.Netmap.SelfNode.Hostinfo().RoutableIPs().Len() > 0

			if !same && !announces && !listed {
				t.Errorf("%s: cap form expanded from the netmap's holders differs (-postings +netmap):\n%s", alias, cmp.Diff(got, viaNetmap, inOrderOpts...))
			}

			tally.add(func(g *expandTally) {
				g.saasCompared++

				switch {
				case diff == "":
					g.saasExact++
				case listed:
					g.saasListed = append(g.saasListed, key)
				}

				switch {
				case same:
					g.netmapSame++
				case announces:
					g.netmapRouted = append(g.netmapRouted, id+"/"+alias)
				default:
					g.netmapDiffer = append(g.netmapDiffer, key)
				}
			})
		}
	}

	// The same tailnet reached incrementally: every node joining an empty
	// one in one commit, then every other node leaving.
	sel := x.t.sel
	us := NewUserSets(nil, sel, users)
	empty := graph.NewMap[types.NodeID, *types.Node](graph.Same[*types.Node], nil)
	incRoles := Roles{}.Update(us, empty, nil)
	incPosts := Postings{}.Update(incRoles)
	approvals := SubnetApprovals{}.Update(empty)

	step := func(nodes *NodeMap, listed types.Nodes, what string) {
		incRoles = incRoles.Update(us, nodes, nil)
		incPosts = incPosts.Update(incRoles)
		approvals = approvals.Update(nodes)

		want, err := NewPolicyManager(src, users, listed.ViewSlice())
		require.NoError(t, err)

		// The templates of the same document serve the new compile.
		ix, err := NewExpansion(x.t, incPosts, approvals.Strings(), lookupIn(nodes))
		require.NoError(t, err)

		requireExpandsLikeCompile(t, ix, want, listed, what)
	}

	e := empty.Edit()
	for _, n := range nodes {
		e.Set(n.ID, n)
	}

	joined := e.Done()
	step(joined, nodes, "after every node joined")

	e = joined.Edit()

	var kept types.Nodes

	for i, n := range nodes {
		if i%2 == 1 {
			e.Delete(n.ID)
		} else {
			kept = append(kept, n)
		}
	}

	step(e.Done(), kept, "after every other node left")

	tally.add(func(g *expandTally) { g.incremental++ })
}

// netmapHolders stamps the nodes of a captured netmap with the caps of
// the selectors the topology node with their addresses holds, as a
// cap-form render would, and reads holders back from them.
func netmapHolders(nm *netmap.NetworkMap, nodes types.Nodes, roles Roles, table *SelectorTable) netmapCaps {
	byAddr := map[netip.Addr]*types.Node{}

	for _, n := range nodes {
		for _, ip := range n.IPs() {
			byAddr[ip] = n
		}
	}

	stamp := func(v tailcfg.NodeView) tailcfg.NodeView {
		n := v.AsStruct()

		for _, p := range n.Addresses {
			hn, ok := byAddr[p.Addr()]
			if !p.IsSingleIP() || !ok {
				continue
			}

			rs, _ := roles.Of(hn.ID)
			for r := range rs.All() {
				if id, ok := r.Selector(); ok && table.Selector(id).Kind.HoldsNodes() {
					if n.CapMap == nil {
						n.CapMap = tailcfg.NodeCapMap{}
					}

					n.CapMap[selectorCap(table.Selector(id))] = nil
				}
			}

			break
		}

		return n.View()
	}

	peers := make([]tailcfg.NodeView, 0, len(nm.Peers))
	for _, p := range nm.Peers {
		peers = append(peers, stamp(p))
	}

	return newNetmapCaps(stamp(nm.SelfNode), peers)
}

// goldenExpansionSequence replays a step capture as the world runs it:
// one compile, templates, user sets, roles and postings carried from step
// to step, the expander checked against the compile at every step and,
// where SaaS's answer is settled, against SaaS.
func goldenExpansionSequence(t *testing.T, tally *expandTally, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)

	users := setupGrantsCompatUsers()
	ids := map[string]types.NodeID{}

	var (
		pm        *PolicyManager
		sel       *Selectors
		tmpl      *Templates
		us        *UserSets
		roles     Roles
		posts     Postings
		approvals SubnetApprovals
		nodes     = graph.NewMap[types.NodeID, *types.Node](graph.Same[*types.Node], nil)
		policy    []byte
	)

	for _, step := range c.Steps {
		for _, a := range step.Actions {
			if _, ok := ids[a.Node]; a.Kind == "join" && !ok {
				ids[a.Node] = types.NodeID(len(ids) + 1) //nolint:gosec // a handful of nodes
			}
		}

		listed, _ := sequenceNodes(t, users, step, ids)

		if pushed := stepPolicy(t, step); pushed != nil {
			policy = pushed
		}

		e := nodes.Edit()
		seen := map[types.NodeID]bool{}

		for _, n := range listed {
			seen[n.ID] = true
			e.Set(n.ID, n)
		}

		for nid := range nodes.All() {
			if !seen[nid] {
				e.Delete(nid)
			}
		}

		nodes = e.Done()

		pm, err = NewPolicyManagerFrom(pm, policy, users, nodeViews(nodes))
		require.NoError(t, err, step.Name)

		sel = SelectorsFor(sel, pm)
		tmpl = BuildTemplates(tmpl, sel)
		require.NoError(t, AuditTemplates(tmpl), step.Name)

		us = NewUserSets(us, sel, users)
		roles = roles.Update(us, nodes, nil)
		posts = posts.Update(roles)
		approvals = approvals.Update(nodes)

		x, err := NewExpansion(tmpl, posts, approvals.Strings(), lookupIn(nodes))
		require.NoError(t, err, step.Name)

		requireExpandsLikeCompile(t, x, pm, listed, step.Name)

		for _, alias := range slices.Sorted(maps.Keys(step.Captures)) {
			capture := step.Captures[alias]
			key := strings.Join([]string{id, step.Name, alias}, "/")

			if notCompared(policySequenceNotCompared, key+"/filter") {
				continue
			}

			node := findGrantsNode(listed, alias)
			require.NotNil(t, node)

			got := x.FilterForNode(node.View())
			if diff := cmp.Diff(capture.PacketFilterRules, got, append(cmpOptions(), cmpopts.EquateEmpty())...); diff != "" {
				t.Errorf("%s: expanded filter differs from SaaS (-tailscale +expanded):\n%s", key, diff)
			}

			tally.add(func(g *expandTally) { g.stepFilters++ })
		}

		tally.add(func(g *expandTally) { g.steps++ })
	}
}
