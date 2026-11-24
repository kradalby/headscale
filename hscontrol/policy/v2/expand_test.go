package v2

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// exampleTailnet is the worked-example tailnet as headscale stores it.
func exampleTailnet() (types.Users, types.Nodes) {
	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@example.com"},
		{ID: 2, Name: "bob", Email: "bob@example.com"},
	}

	node := func(id types.NodeID, name, v4, v6 string) *types.Node {
		return &types.Node{
			ID:             id,
			Hostname:       name,
			GivenName:      name,
			IPv4:           ptrAddr(v4),
			IPv6:           ptrAddr(v6),
			Hostinfo:       &tailcfg.Hostinfo{},
			ApprovedRoutes: []netip.Prefix{},
		}
	}

	alice := node(1, "alice-laptop", "100.64.0.1", "fd7a:115c:a1e0::1")
	alice.User, alice.UserID = &users[0], &users[0].ID

	bob := node(2, "bob-laptop", "100.64.0.2", "fd7a:115c:a1e0::2")
	bob.User, bob.UserID = &users[1], &users[1].ID

	web1 := node(3, "web1", "100.64.0.10", "fd7a:115c:a1e0::a")
	web1.Tags = []string{"tag:web"}

	db1 := node(4, "db1", "100.64.0.20", "fd7a:115c:a1e0::14")
	db1.Tags = []string{"tag:db"}

	r1 := node(5, "r1", "100.64.0.30", "fd7a:115c:a1e0::1e")
	r1.Tags = []string{"tag:router"}
	r1.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	r1.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	return users, types.Nodes{alice, bob, web1, db1, r1}
}

const examplePolicy = `{
	"groups": {
		"group:eng":   ["alice@example.com", "bob@example.com"],
		"group:empty": []
	},
	"tagOwners": {
		"tag:web":    ["alice@example.com"],
		"tag:db":     ["alice@example.com"],
		"tag:router": ["alice@example.com"]
	},
	"hosts": {"office": "192.168.1.0/24"},
	"grants": [
		{"src": ["group:eng"], "dst": ["tag:web"], "ip": ["tcp:443"]},
		{"src": ["group:eng", "office"], "dst": ["tag:web"], "ip": ["tcp:80"]},
		{"src": ["autogroup:member"], "dst": ["tag:web"], "ip": ["tcp:8080"]},
		{"src": ["group:empty"], "dst": ["tag:web"], "ip": ["tcp:9000"]},
		{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]}
	]
}`

func capRule(dsts []tailcfg.NetPortRange, proto []int, srcs ...string) tailcfg.FilterRule {
	return tailcfg.FilterRule{SrcIPs: srcs, DstPorts: dsts, IPProto: proto}
}

// TestExpandCapSourcesMatchesCompile writes the worked examples' filters in
// cap form by hand, as the encoder is meant to, and requires the expander,
// with holders read off the netmap, to give what the compile gives today,
// byte for byte.
func TestExpandCapSourcesMatchesCompile(t *testing.T) {
	t.Parallel()

	users, nodes := exampleTailnet()

	pm, err := NewPolicyManager([]byte(examplePolicy), users, nodes.ViewSlice())
	require.NoError(t, err)

	aliceAll := []tailcfg.NetPortRange{
		{IP: "100.64.0.1", Ports: tailcfg.PortRangeAny},
		{IP: "fd7a:115c:a1e0::1", Ports: tailcfg.PortRangeAny},
	}

	tests := []struct {
		name     string
		receiver string
		capForm  []tailcfg.FilterRule
	}{
		{
			// The eligible rule; mixed sources keep the prefix; two
			// selectors held by the same nodes merge as in the compile;
			// the empty group's rule goes.
			name:     "web1",
			receiver: "web1",
			capForm: []tailcfg.FilterRule{
				capRule(web1Dsts(443, 443), []int{6}, capSourcePrefix+capGroupEng),
				capRule(web1Dsts(80, 80), []int{6}, "192.168.1.0/24", capSourcePrefix+capGroupEng),
				capRule(web1Dsts(8080, 8080), []int{6}, capSourcePrefix+capMember),
				capRule(web1Dsts(9000, 9000), []int{6}, capSourcePrefix+capEmpty),
			},
		},
		{
			name:     "autogroup-self",
			receiver: "alice-laptop",
			capForm:  []tailcfg.FilterRule{capRule(aliceAll, nil, capSourcePrefix+capOwner1)},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, nc := exampleView(t, exampleNodes(), tc.receiver)

			want, err := pm.FilterForNode(findNodeByGivenName(nodes, tc.receiver).View())
			require.NoError(t, err)

			got := expandCapSources(tc.capForm, nil, nc.Holders)
			if diff := cmp.Diff(want, got, inOrderOpts...); diff != "" {
				t.Errorf("expanded cap form differs from the compile (-compile +expanded):\n%s", diff)
			}
		})
	}
}

func TestExpandCapSources(t *testing.T) {
	t.Parallel()

	_, nc := exampleView(t, exampleNodes(), "web1")
	dsts := web1Dsts(443, 443)
	alice := []string{"100.64.0.1", "fd7a:115c:a1e0::1"}

	grant := []tailcfg.CapGrant{{
		Dsts:   []netip.Prefix{netip.MustParsePrefix("100.64.0.10/32")},
		CapMap: tailcfg.PeerCapMap{capAppAdmin: nil},
	}}

	tests := []struct {
		name    string
		rules   []tailcfg.FilterRule
		classes []string
		want    []tailcfg.FilterRule
	}{
		{
			name:  "empty-holders-drop-rule",
			rules: []tailcfg.FilterRule{capRule(dsts, []int{6}, capSourcePrefix+capEmpty)},
			want:  []tailcfg.FilterRule{},
		},
		{
			name:  "empty-holders-keep-literal",
			rules: []tailcfg.FilterRule{capRule(dsts, []int{6}, capSourcePrefix+capEmpty, "10.0.0.0/8")},
			want:  []tailcfg.FilterRule{capRule(dsts, []int{6}, "10.0.0.0/8")},
		},
		{
			name:  "overlapping-selectors",
			rules: []tailcfg.FilterRule{capRule(dsts, []int{6}, capSourcePrefix+capAlice, capSourcePrefix+capGroupEng, capSourcePrefix+capAlice)},
			want:  []tailcfg.FilterRule{capRule(dsts, []int{6}, engSrcIPs...)},
		},
		{
			name:  "selector-and-its-addresses",
			rules: []tailcfg.FilterRule{capRule(dsts, []int{6}, "100.64.0.1", capSourcePrefix+capAlice)},
			want:  []tailcfg.FilterRule{capRule(dsts, []int{6}, alice...)},
		},
		{
			name:  "danger-all",
			rules: []tailcfg.FilterRule{capRule(dsts, nil, "*", capSourcePrefix+capAlice)},
			want:  []tailcfg.FilterRule{capRule(dsts, nil, "*")},
		},
		{
			// Two templates whose holders coincide are one rule in IP
			// form, at the first; a different protocol list keeps a rule
			// apart.
			name: "merge-at-first",
			rules: []tailcfg.FilterRule{
				capRule(web1Dsts(443, 443), []int{6}, capSourcePrefix+capGroupEng),
				capRule(web1Dsts(53, 53), []int{17}, capSourcePrefix+capMember),
				capRule(web1Dsts(80, 80), []int{6}, capSourcePrefix+capMember),
			},
			want: []tailcfg.FilterRule{
				capRule(append(web1Dsts(443, 443), web1Dsts(80, 80)...), []int{6}, engSrcIPs...),
				capRule(web1Dsts(53, 53), []int{17}, engSrcIPs...),
			},
		},
		{
			name: "classes-kept-apart",
			rules: []tailcfg.FilterRule{
				capRule(web1Dsts(443, 443), []int{6}, capSourcePrefix+capGroupEng),
				capRule(web1Dsts(80, 80), []int{6}, capSourcePrefix+capMember),
			},
			classes: []string{"", "via:[tag:router]"},
			want: []tailcfg.FilterRule{
				capRule(web1Dsts(443, 443), []int{6}, engSrcIPs...),
				capRule(web1Dsts(80, 80), []int{6}, engSrcIPs...),
			},
		},
		{
			name: "capgrant-not-merged",
			rules: []tailcfg.FilterRule{
				{SrcIPs: []string{capSourcePrefix + capAlice}, CapGrant: grant},
				{SrcIPs: []string{capSourcePrefix + capAlice}, CapGrant: grant},
			},
			want: []tailcfg.FilterRule{
				{SrcIPs: alice, CapGrant: grant},
				{SrcIPs: alice, CapGrant: grant},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := expandCapSources(tc.rules, tc.classes, nc.Holders)
			if diff := cmp.Diff(tc.want, got, inOrderOpts...); diff != "" {
				t.Errorf("(-want +got):\n%s", diff)
			}
		})
	}
}

// TestExpandCompareBlindToClientQuirks pins what check A cannot see: a cap
// rule the client misreads still expands to its IP-form reference. Only
// the probes (check B) catch those; A catches mapping mistakes.
func TestExpandCompareBlindToClientQuirks(t *testing.T) {
	t.Parallel()

	blind := map[string]bool{
		"cap-on-subnet-router":       true,
		"cap-on-portless-protocol":   true,
		"cap-on-capgrant":            true,
		"cap-rewrite-autogroup-self": true,
		"missing-cap-stamp":          false,
		"port-range-widened":         false,
		"dropped-source":             false,
	}

	for _, tc := range sensitivityCases() {
		want, ok := blind[tc.name]
		if !ok {
			continue
		}

		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, nc := exampleView(t, tc.nodes, tc.receiver)
			same := cmp.Equal(tc.ref, expandCapSources(tc.cand, nil, nc.Holders), inOrderOpts...)

			if same != want {
				t.Errorf("expanded candidate equals reference = %t, want %t", same, want)
			}
		})
	}
}

// BenchmarkExpansionAllFilters measures every node's filter from scratch
// both ways: the compile and its FilterForNode, and membership, templates
// and the expansion. The expander is to serve the filter, so the two
// must stay of the same order as the tailnet grows.
func BenchmarkExpansionAllFilters(b *testing.B) {
	for _, pol := range benchPolicies {
		for _, n := range []int{500, 2000} {
			users, nodes := benchNodes(n)

			b.Run(fmt.Sprintf("%s/compile/n=%d", pol.name, n), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					pm, err := NewPolicyManager([]byte(pol.policy), users, nodes.ViewSlice())
					require.NoError(b, err)

					for _, node := range nodes {
						_, err := pm.FilterForNode(node.View())
						require.NoError(b, err)
					}
				}
			})

			b.Run(fmt.Sprintf("%s/expand/n=%d", pol.name, n), func(b *testing.B) {
				b.ReportAllocs()

				for b.Loop() {
					sel, err := NewSelectors(nil, []byte(pol.policy))
					require.NoError(b, err)

					all := nodeMapOf(nodes)
					roles := Roles{}.Update(NewUserSets(nil, sel, users), all, nil)

					x, err := NewExpansion(BuildTemplates(nil, sel), Postings{}.Update(roles), SubnetApprovals{}.Update(all).Strings(), lookupIn(all))
					require.NoError(b, err)

					for _, node := range nodes {
						x.FilterForNode(node.View())
					}
				}
			})
		}
	}
}

// TestExpandCapSourcesKeepsCapabilityRuleFromNobody holds expanding a
// capability rule whose cap has no holders to what the compile writes for
// an app grant whose sources resolve to nothing: the rule, with empty
// sources, where a port rule would be dropped.
func TestExpandCapSourcesKeepsCapabilityRuleFromNobody(t *testing.T) {
	t.Parallel()

	users := types.Users{{ID: 1, Name: "alice"}}
	nodes := quirkNodes(quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}})

	pm, err := NewPolicyManager([]byte(`{"tagOwners": {"tag:a": ["alice@"]}, "grants": [
		{"src": ["nobody@"], "dst": ["tag:a"], "app": {"example.com/cap/x": [{}]}},
		{"src": ["nobody@"], "dst": ["tag:a"], "ip": ["tcp:22"]}]}`), users, nodes.ViewSlice())
	require.NoError(t, err)

	compiled, err := pm.FilterForNode(nodes[0].View())
	require.NoError(t, err)

	grant := []tailcfg.CapGrant{{Dsts: []netip.Prefix{host("100.64.0.10")}, CapMap: tailcfg.PeerCapMap{"example.com/cap/x": {"{}"}}}}
	capForm := []tailcfg.FilterRule{
		{SrcIPs: []string{capSourcePrefix + capEmpty}, CapGrant: grant},
		capRule(web1Dsts(22, 22), []int{ProtocolTCP}, capSourcePrefix+capEmpty),
	}

	got := expandCapSources(capForm, nil, func(nodecap.Cap) []netip.Addr { return nil })

	require.Equal(t, []tailcfg.FilterRule{{SrcIPs: []string{}, CapGrant: grant}}, compiled, "the compile keeps the capability rule, with empty sources")

	if !reflect.DeepEqual(compiled, got) {
		t.Errorf("expanded differs from the compile (-compile +expanded):\n%s", cmp.Diff(compiled, got, inOrderOpts...))
	}
}

// TestExpansionCostFollowsReceiver holds one receiver's filter to the rules
// that reach it: every receiver of a rule shares its sources expanded once,
// so a member's filter under a mesh costs the same at any tailnet size.
// Expanding them again per receiver made every filter cost the tailnet.
func TestExpansionCostFollowsReceiver(t *testing.T) {
	const mesh = `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`

	allocs := map[int]float64{}

	for _, n := range []int{100, 1000} {
		users, nodes := benchNodes(n)

		sel, err := NewSelectors(nil, []byte(mesh))
		require.NoError(t, err)

		all := nodeMapOf(nodes)
		roles := Roles{}.Update(NewUserSets(nil, sel, users), all, nil)

		x, err := NewExpansion(BuildTemplates(nil, sel), Postings{}.Update(roles), SubnetApprovals{}.Update(all).Strings(), lookupIn(all))
		require.NoError(t, err)

		member := nodes[1].View()
		require.False(t, member.IsTagged())
		require.Len(t, x.FilterForNode(member), 1)

		allocs[n] = testing.AllocsPerRun(20, func() { x.FilterForNode(member) })
	}

	t.Logf("allocations of one member's filter: %v", allocs)
	assert.LessOrEqual(t, allocs[1000], allocs[100]+2, "a receiver's filter grows with the tailnet")
}

// TestAuditFiltersRequiresSortedNodes holds the audit to the order the
// expansion assumes: the compile lists an owner's nodes in list order, the
// postings in ID order, so the two agree only on a list sorted by ID.
func TestAuditFiltersRequiresSortedNodes(t *testing.T) {
	t.Parallel()

	users := types.Users{{ID: 1, Name: "alice"}}
	alice := &users[0]
	nodes := quirkNodes(
		quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
		quirkNode{name: "a2", user: alice, v4: "100.64.0.2"},
	)
	reversed := types.Nodes{nodes[1], nodes[0]}

	const src = `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:22"]}]}`

	audit := func(list types.Nodes) error {
		pm, err := NewPolicyManager([]byte(src), users, list.ViewSlice())
		require.NoError(t, err)

		x, roles := expansionOf(t, pm, users, nodeMapOf(list))

		_, err = AuditFilters(FilterAudit{
			Templates: x.t, Postings: Postings{}.Update(roles), Approvals: SubnetApprovals{}.Update(nodeMapOf(list)),
			Nodes: list.ViewSlice(), Users: users, Policy: pm, Current: true,
		})

		return err
	}

	require.NoError(t, audit(nodes))
	require.ErrorIs(t, audit(reversed), errFilterAuditOrder)
}

// TestFiltersServeTheirOwnNodes pins the served filters' cache: a node's
// filter is cut once, from the list's own view of the node, and shared; a
// node the list lacks gets an error, not an empty filter.
func TestFiltersServeTheirOwnNodes(t *testing.T) {
	t.Parallel()

	users := types.Users{{ID: 1, Name: "alice"}}
	alice := &users[0]
	nodes := quirkNodes(
		quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
		quirkNode{name: "a2", user: alice, v4: "100.64.0.2"},
	)

	const src = `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:22"]}]}`

	pm, err := NewPolicyManager([]byte(src), users, nodes.ViewSlice())
	require.NoError(t, err)

	x, roles := expansionOf(t, pm, users, nodeMapOf(nodes))
	f := NewFilters(x.t, Postings{}.Update(roles), SubnetApprovals{}.Update(nodeMapOf(nodes)), nodes.ViewSlice())

	first, err := f.ForNode(nodes[0].ID, ReceiverFacts{})
	require.NoError(t, err)

	want, err := pm.FilterForNode(nodes[0].View())
	require.NoError(t, err)
	require.Equal(t, want, first)

	again, err := f.ForNode(nodes[0].ID, ReceiverFacts{})
	require.NoError(t, err)
	assert.Same(t, &first[0], &again[0], "readers of one node share its filter")

	_, err = f.ForNode(99, ReceiverFacts{})
	require.ErrorIs(t, err, errUnlisted)

	global, err := f.Global()
	require.NoError(t, err)
	assert.Equal(t, pm.addresses().filter, global)
}

// TestFiltersChangedCoversEveryMovedFilter holds [Filters.Changed] to the
// filters themselves, with no audit: over the random differential's
// policies and topologies, moved by joins, leaves and replacements, by
// single facts of one node, by user renames, by document edits that keep
// the selectors where they can (rules swapped, a source or destination
// moved to a selector named elsewhere, ports, protocols, apps, via tags,
// a host's prefix, a group's members) and by documents replaced, every
// node whose filter, cut afresh, differs between two states must be one
// Changed names, and one its routing names without the subnet routers it
// adds wholesale. And a filter served must be the one cut afresh: sessions
// read some filters at each commit and none at others, so what is served
// is carried across commits, some of it across several. HEADSCALE_SIDES_SEED
// replays a run.
func TestFiltersChangedCoversEveryMovedFilter(t *testing.T) {
	seed := uint64(time.Now().UnixNano()) //nolint:gosec // any seed

	if v := os.Getenv("HEADSCALE_SIDES_SEED"); v != "" {
		var err error

		seed, err = strconv.ParseUint(v, 10, 64)
		require.NoError(t, err)
	}

	t.Logf("HEADSCALE_SIDES_SEED=%d", seed)

	rounds := 450
	if testing.Short() {
		rounds = 40
	}

	edits := [][2]string{
		{`:22"`, `:*"`},
		{`"tcp:22"`, `"*"`},
		{`"group:g": ["alice@", "carol@example.com"]`, `"group:g": ["bob@"]`},
		{`"hnet": "10.0.0.0/24"`, `"hnet": "10.0.0.0/16"`},
	}

	// The capability variants serve capability form, with client facts
	// drawn and flipped; sparse ones send most nodes capabilities.
	variants := []struct {
		caps, sparse bool
		stream       uint64
	}{
		{stream: 2}, {caps: true, stream: 12}, {caps: true, sparse: true, stream: 13},
	}

	// The shapes only address-form naming reaches, over both capability
	// variants.
	addressOnly := map[string]int{}

	for _, v := range variants {
		t.Run(fmt.Sprintf("caps=%t/sparse=%t", v.caps, v.sparse), func(t *testing.T) {
			g := sideGen{r: rand.New(rand.NewPCG(seed, v.stream)), sparse: v.sparse} //nolint:gosec // reproducible
			if v.caps {
				g.facts = rand.New(rand.NewPCG(seed, v.stream+100)) //nolint:gosec // reproducible
			}

			// mode is how the filters name sources; recv each state's
			// receiver facts, which choose a receiver's form when read.
			mode := AddressSources
			if v.caps {
				mode = CapabilitySources
			}

			var moved, named, kept, carried, multiHop, unreadNodes, unread int

			reach := map[string]int{}

			for round := range rounds {
				pol := g.policy()

				nodes := make(types.Nodes, 0, 10)
				for i := range 3 + g.r.IntN(6) {
					nodes = append(nodes, g.node(types.NodeID(i+1), nodes)) //nolint:gosec // bounded
				}

				pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
				if err != nil {
					continue
				}

				m := newSideModel(t, pm, sideUsers, nodes)
				us := NewUserSets(nil, m.t.sel, sideUsers)
				prev := FollowFiltersFor(mode, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
				prevRecv := modelReceivers(v.caps, m)

				// gen counts the filters followed; read, by node, the last
				// one its filter was read from.
				gen := 0
				read := map[types.NodeID]int{}

				// Every node read, as sessions read theirs, so there is a
				// cache to carry over.
				for _, n := range m.list {
					_, err := prev.ForNode(n.ID, prevRecv.Of(n.ID))
					require.NoError(t, err)

					read[n.ID] = gen
				}

				for step := range 12 {
					was := m.list

					after, ok := g.move(t, m, us, edits, reach)
					if !ok {
						continue
					}

					requireStartable(t, m.list)

					us = after

					next := FollowFiltersFor(mode, prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
					nextRecv := modelReceivers(v.caps, m)
					gen++

					// A commit nobody routes or reads: the next filters carry
					// from what these would have.
					if g.r.IntN(4) == 0 {
						prev, prevRecv = next, nextRecv
						unread++

						continue
					}

					ids, all, narrow := routedAsSince(prev, next, prevRecv, nextRecv)

					fail := func(format string, args ...any) {
						t.Helper()
						t.Fatalf("HEADSCALE_SIDES_SEED=%d round %d step %d: %s\npolicy:\n%s\nbefore:\n%s\nafter:\n%s",
							seed, round, step, fmt.Sprintf(format, args...), m.pm.src, describeNodes(was), describeNodes(m.list))
					}

					freshOld, freshNew := prev.Uncached(), next.Uncached()

					every, _ := next.Changed(prev)
					capRoutingReach(v.caps, prevRecv, nextRecv, ids, all, every, m.list, reach)

					raw := capabilityStep(t, v.caps, g, prev, next, nextRecv, reach, fail)

					for _, n := range slices.Concat(was, m.list) {
						before, errBefore := freshOld.ForNode(n.ID, prevRecv.Of(n.ID))
						after, errAfter := freshNew.ForNode(n.ID, nextRecv.Of(n.ID))

						_, listed := slices.BinarySearch(ids, n.ID)

						if (errBefore == nil) != (errAfter == nil) || !reflect.DeepEqual(before, after) {
							moved++

							if !all && !listed {
								fail("node %d's filter moved from %v to %v, and Changed (%v) leaves it out", n.ID, before, after, ids)
							}

							if _, ok := slices.BinarySearch(narrow.ids, n.ID); !narrow.all && !ok {
								fail("node %d's filter moved from %v to %v, and routing without routers wholesale (%v) leaves it out", n.ID, before, after, narrow.ids)
							}

							addressOnlyReach(raw, n.ID, prevRecv.Of(n.ID), nextRecv.Of(n.ID), reach)

							named++
						} else if !listed {
							kept++
						}

						if errAfter != nil {
							continue
						}

						// Sessions read some filters only.
						if g.r.IntN(3) == 0 {
							unreadNodes++

							continue
						}

						served, err := next.ForNode(n.ID, nextRecv.Of(n.ID))
						require.NoError(t, err)

						if !reflect.DeepEqual(after, served) {
							fail("node %d is served %v, cut afresh %v", n.ID, served, after)
						}

						if !all && !listed {
							carried++

							if read[n.ID] < gen-1 {
								multiHop++
							}
						}

						read[n.ID] = gen
					}

					prev, prevRecv = next, nextRecv
				}
			}

			t.Logf("moved filters %d (named %d), unmoved left out %d, carried over %d (%d across several commits), unread filters %d, unread commits %d; %v",
				moved, named, kept, carried, multiHop, unreadNodes, unread, reach)
			require.Positive(t, moved, "filters moved")
			require.Positive(t, unread, "commits went unread")
			require.Positive(t, unreadNodes, "filters went unread")
			require.Positive(t, carried, "filters were carried over")
			require.Positive(t, multiHop, "filters were carried across several commits")
			require.Positive(t, reach["edits"], "documents were edited")
			require.Positive(t, reach["documents replaced"], "documents were replaced")

			// A short run is too few rounds to reach every kind.
			if testing.Short() {
				return
			}

			kinds := []string{
				"single node fact", "user renamed", "edit keeping the selectors",
				"edit: swap", "edit: src", "edit: dst", "edit: ports", "edit: proto", "edit: app", "edit: via", "edit: host", "edit: group",
			}
			if v.caps {
				kinds = append(kinds, "receiver form flipped", "capability receivers left out by routing", "census counted from an earlier one")
			}

			addKinds(addressOnly, reach, addressOnlyKinds)

			for _, kind := range kinds {
				assert.Positive(t, reach[kind], "%s reached", kind)
			}
		})
	}

	requireReached(t, addressOnly, addressOnlyKinds)
}

// addKinds adds reach's counts of kinds to into.
func addKinds(into, reach map[string]int, kinds []string) {
	for _, kind := range kinds {
		into[kind] += reach[kind]
	}
}

// requireReached requires every kind reached, but in a short run.
func requireReached(t *testing.T, reach map[string]int, kinds []string) {
	t.Helper()

	if testing.Short() {
		return
	}

	for _, kind := range kinds {
		assert.Positive(t, reach[kind], "%s reached", kind)
	}
}

// capabilityStep, in capability mode, returns routing's change from prev
// to next without the routers wholesale, and, now and then, reads next's
// census as a metrics scrape does: counted from the last one, across
// commits nobody read, it must be the one counted afresh, or it fails.
func capabilityStep(t *testing.T, caps bool, g sideGen, prev, next *Filters, recv Receivers, reach map[string]int,
	fail func(string, ...any),
) filterChange {
	t.Helper()

	if !caps {
		return filterChange{}
	}

	raw := routeFilters(prev, next, true)

	if g.r.IntN(3) == 0 {
		if msg := scrapeAgrees(t, next, recv, reach); msg != "" {
			fail("%s", msg)
		}
	}

	return raw
}

// addressOnlyKinds are what [addressOnlyReach] counts.
var addressOnlyKinds = []string{"owner named for a moved merge key alone", "service host named in address form alone"}

// modelReceivers is every node's facts in m's current state, none unless
// caps.
func modelReceivers(caps bool, m *sideModel) Receivers {
	if !caps {
		return Receivers{}
	}

	return capReceivers(m.nodes, m.pm.NodeCapMaps())
}

// routedAsSince returns what Since names from prev to next: what the
// filters say moved for each node in the form its facts send it, and the
// nodes whose facts moved, served their other form; and the same without
// subnet routers named wholesale.
func routedAsSince(prev, next *Filters, prevRecv, nextRecv Receivers) ([]types.NodeID, bool, filterChange) {
	var (
		ids []types.NodeID
		all bool
	)

	if next.Mode() == CapabilitySources {
		ids, all = next.ChangedFor(prev, nextRecv)
	} else {
		ids, all = next.Changed(prev)
	}

	flipped := nextRecv.ChangedSince(prevRecv)
	ids = slices.Compact(slices.Sorted(slices.Values(slices.Concat(ids, flipped))))
	narrow := routeFilters(prev, next, true)
	narrow.ids = slices.Compact(slices.Sorted(slices.Values(slices.Concat(narrow.namedFor(next.Mode(), nextRecv), flipped))))

	return ids, all, narrow
}

// scrapeAgrees reads f's census as a metrics scrape does and returns how it
// differs from one counted afresh, or nothing.
func scrapeAgrees(t *testing.T, f *Filters, recv Receivers, reach map[string]int) string {
	t.Helper()

	if f.censusFrom != nil {
		reach["census counted from an earlier one"]++
	}

	got, err := f.Census(recv)
	require.NoError(t, err)

	want, err := f.Uncached().Census(recv)
	require.NoError(t, err)

	if got != want {
		return fmt.Sprintf("the census is %+v, counted afresh %+v", got, want)
	}

	return ""
}

// addressOnlyReach counts the moved filters routing names only in address
// form, by the shapes that only that names: an owner whose self rules
// merged at a key that moved, and a service host, sent addresses for its
// local nets alone.
func addressOnlyReach(c filterChange, id types.NodeID, was, is ReceiverFacts, reach map[string]int) {
	if _, ok := slices.BinarySearch(c.ids, id); c.all || ok || !c.addr.has(id) {
		return
	}

	held := slices.ContainsFunc(c.addr.holders, func(ids []types.NodeID) bool {
		_, ok := slices.BinarySearch(ids, id)

		return ok
	})
	if !held {
		reach["owner named for a moved merge key alone"]++
	}

	host := ReceiverFacts{Client: true, ServiceHost: true}
	if was == host && is == host {
		reach["service host named in address form alone"]++
	}
}

// capRoutingReach counts, in capability mode, the receivers whose form
// flipped between prev and next, and the steps where routing left out
// receivers sent capabilities that a change naming every form names.
func capRoutingReach(caps bool, prev, next Receivers, ids []types.NodeID, all bool, every []types.NodeID, list types.Nodes, reach map[string]int) {
	if !caps {
		return
	}

	for _, id := range every {
		if _, found := slices.BinarySearch(ids, id); !all && !found {
			reach["capability receivers left out by routing"]++

			break
		}
	}

	for _, n := range list {
		was, is := prev.Of(n.ID), next.Of(n.ID)
		if receiverForm(CapabilitySources, was) != receiverForm(CapabilitySources, is) {
			reach["receiver form flipped"]++
		}
	}
}

// move moves m one step the way the Filters.Changed oracle draws them:
// joins, leaves and replacements; one node's fact; a document edit, a user
// renamed, a textual edit or another document. False when the step drew
// nothing that applies.
func (g sideGen) move(t *testing.T, m *sideModel, us *UserSets, edits [][2]string, reach map[string]int) (*UserSets, bool) {
	t.Helper()

	var (
		src   []byte
		label string
	)

	switch op := g.r.IntN(20); {
	case op < 5:
		m.step(t, us, g.step(m.list))

		return us, true
	case op < 9:
		m.step(t, us, g.tweak(m.list))

		reach["single node fact"]++

		return us, true
	case op < 15:
		var kind string

		src, kind = g.docEdit(m.pm.src)
		if src == nil {
			return us, false
		}

		table := m.t.table()

		next, ok := m.edit(t, us, src)
		if !ok {
			return us, false
		}

		reach["edits"]++
		reach["edit: "+kind]++

		if m.t.table() == table {
			reach["edit keeping the selectors"]++
		}

		return next, true
	case op < 17:
		reach["user renamed"]++

		return m.rename(t, us, g.r.IntN(len(m.users))), true
	case op < 19:
		e := edits[g.r.IntN(len(edits))]

		src = []byte(strings.Replace(string(m.pm.src), e[0], e[1], 1))
		if string(src) == string(m.pm.src) {
			return us, false
		}

		label = "edits"
	default:
		// Another document, most likely naming other selectors.
		src, label = g.policy(), "documents replaced"
	}

	next, ok := m.edit(t, us, src)
	if ok {
		reach[label]++
	}

	return next, ok
}

// docEdit returns src edited the way documents are, and what it edited:
// two rules swapped; a source or destination moved to a selector the
// document names; a port, protocol, app or via tag changed; a host's
// prefix or a group's members moved. Nil when src offers nothing to edit.
func (g sideGen) docEdit(src []byte) ([]byte, string) {
	var doc map[string]any

	err := json.Unmarshal(src, &doc)
	if err != nil {
		return nil, ""
	}

	acls, _ := doc["acls"].([]any)
	grants, _ := doc["grants"].([]any)
	rules := slices.Concat(acls, grants)

	if len(rules) == 0 {
		return nil, ""
	}

	named := docSelectors(rules)

	rule, _ := rules[g.r.IntN(len(rules))].(map[string]any)
	_, acl := rule["action"]

	kind := g.pick("swap", "src", "dst", "ports", "proto", "app", "via", "host", "group")
	switch kind {
	case "swap":
		list := acls
		if len(list) < 2 || len(grants) >= 2 && g.r.IntN(2) == 0 {
			list = grants
		}

		if len(list) < 2 {
			return nil, ""
		}

		i, j := g.r.IntN(len(list)), g.r.IntN(len(list))
		list[i], list[j] = list[j], list[i]
	case "src", "dst":
		vs, _ := rule[kind].([]any)
		i := g.r.IntN(len(vs))
		to := named[g.r.IntN(len(named))]

		if kind == "dst" && acl {
			d, _ := vs[i].(string)
			to += d[len(aclBase(d)):]
		}

		vs[i] = to
	case "ports":
		if acl {
			vs, _ := rule["dst"].([]any)
			i := g.r.IntN(len(vs))
			d, _ := vs[i].(string)
			vs[i] = aclBase(d) + ":" + g.pick("*", "22", "80,443")
		} else {
			rule["ip"] = []any{g.pick("*", "tcp:22", "udp:53", "tcp:80,443")}
		}
	case "proto":
		if !acl {
			return nil, ""
		}

		if _, ok := rule["proto"]; ok {
			delete(rule, "proto")
		} else {
			rule["proto"] = g.pick("tcp", "udp")
		}
	case "app":
		if acl {
			return nil, ""
		}

		rule["app"] = map[string]any{g.pick("tailscale.com/cap/relay", "example.com/cap/x", "example.com/cap/y"): []any{map[string]any{}}}
	case "via":
		if _, ok := rule["via"]; acl || !ok {
			return nil, ""
		}

		rule["via"] = []any{g.pick("tag:r", "tag:a", "tag:e")}
	case "host":
		hosts, _ := doc["hosts"].(map[string]any)
		hosts["hnet"] = g.pick("10.0.0.0/24", "10.0.0.0/16", "100.64.0.0/30", "100.64.0.4/32")
		hosts["hpub"] = g.pick("8.8.8.0/24", "8.8.8.9/32")
	case "group":
		var members []any

		for _, u := range []string{"alice@", "bob@", "carol@example.com"} {
			if g.r.IntN(2) == 0 {
				members = append(members, u)
			}
		}

		groups, _ := doc["groups"].(map[string]any)
		groups["group:g"] = members
	}

	out, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}

	return out, kind
}

// aclBase returns an ACL destination without the ports after its last
// colon.
func aclBase(d string) string {
	if before, _, ok := strings.CutLast(d, ":"); ok {
		return before
	}

	return d
}

// docSelectors returns the selectors rules name, but autogroup:self, which
// only a destination of its own can be.
func docSelectors(rules []any) []string {
	var named []string

	for _, r := range rules {
		rule, _ := r.(map[string]any)
		_, acl := rule["action"]

		for _, key := range []string{"src", "dst"} {
			vs, _ := rule[key].([]any)
			for _, v := range vs {
				name, _ := v.(string)
				if acl && key == "dst" {
					name = aclBase(name)
				}

				if name != "autogroup:self" {
					named = append(named, name)
				}
			}
		}
	}

	slices.Sort(named)

	return slices.Compact(named)
}

// tweak returns nodes with one fact of one node changed: an address, its
// tags, its owner, or one of its routes.
func (g sideGen) tweak(nodes types.Nodes) types.Nodes {
	next := slices.Clone(nodes)
	i := g.r.IntN(len(next))

	n := *next[i]
	n.Hostinfo = n.Hostinfo.Clone()

	kinds := 4
	if g.facts != nil {
		kinds = 6
	}

	switch g.r.IntN(kinds) {
	case 4:
		// What the client reports: another client, or an app connector.
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: n.Hostinfo.RoutableIPs}
		g.clientFacts(&n)
	case 5:
		// A route announced and not approved, or no longer announced.
		p := netip.MustParsePrefix(g.pick("10.0.0.0/24", "192.168.0.0/24"))
		if slices.Contains(n.Hostinfo.RoutableIPs, p) {
			n.Hostinfo.RoutableIPs = slices.DeleteFunc(slices.Clone(n.Hostinfo.RoutableIPs), func(q netip.Prefix) bool { return q == p })
		} else {
			n.Hostinfo.RoutableIPs = append(slices.Clone(n.Hostinfo.RoutableIPs), p)
		}
	case 0:
		// Never one another node holds: NewState refuses a shared address.
		v4, _ := g.addrs()
		v4 = slices.DeleteFunc(v4, func(a string) bool {
			return slices.ContainsFunc(nodes, func(o *types.Node) bool {
				return o.ID != n.ID && slices.Contains(o.IPs(), netip.MustParseAddr(a))
			})
		})

		if len(v4) > 0 {
			n.IPv4 = new(netip.MustParseAddr(g.pick(v4...)))
		}
	case 1:
		switch {
		case len(n.Tags) == 0:
			n.Tags = []string{g.pick("tag:a", "tag:r", "tag:e")}
		case n.User != nil:
			n.Tags = nil
		default:
			n.Tags = []string{g.pick("tag:a", "tag:r", "tag:e")}
		}
	case 2:
		if n.IsTagged() {
			n.Tags = append(slices.Clone(n.Tags), g.pick("tag:a", "tag:r", "tag:e"))
			slices.Sort(n.Tags)
			n.Tags = slices.Compact(n.Tags)
		} else {
			n.User = &sideUsers[g.r.IntN(len(sideUsers))]
			n.UserID = &n.User.ID
		}
	default:
		p := netip.MustParsePrefix(g.pick("10.0.0.0/24", "100.64.0.0/30", "100.64.0.4/32", "0.0.0.0/0", "192.168.0.0/24"))
		if slices.Contains(n.ApprovedRoutes, p) {
			n.ApprovedRoutes = slices.DeleteFunc(slices.Clone(n.ApprovedRoutes), func(q netip.Prefix) bool { return q == p })
		} else {
			n.ApprovedRoutes = append(slices.Clone(n.ApprovedRoutes), p)
			n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, p)
		}
	}

	next[i] = &n

	return next
}

// rename renames user i, or renames it back, and moves the model to it:
// its name, and an email where it has one.
func (m *sideModel) rename(t *testing.T, us *UserSets, i int) *UserSets {
	t.Helper()

	users := slices.Clone(m.users)
	u := &users[i]

	if base, ok := strings.CutSuffix(u.Name, "-renamed"); ok {
		u.Name = base
	} else {
		u.Name += "-renamed"
	}

	switch u.Email {
	case "carol@example.com":
		u.Email = "carol@other.example"
	case "carol@other.example":
		u.Email = "carol@example.com"
	}

	m.users = users
	us = NewUserSets(us, m.t.sel, users)
	m.roles = m.roles.Update(us, m.nodes, nil)
	m.posts = m.posts.Update(m.roles)
	m.sides = UpdateSides(m.sides, m.t, m.roles, m.posts, m.appr, m.nodes)
	m.peers = RolePeers(m.peers, m.sides)
	m.via = UpdateViaPlans(m.via, m.sides)

	var err error

	m.pm, err = NewPolicyManagerFrom(m.pm, m.pm.src, users, m.list.ViewSlice())
	require.NoError(t, err)

	return us
}

// edit moves the model to the document src, compiled against the same
// users and nodes, returning its user sets; false when src does not
// compile.
func (m *sideModel) edit(t *testing.T, us *UserSets, src []byte) (*UserSets, bool) {
	t.Helper()

	pm, err := NewPolicyManagerFrom(m.pm, src, m.users, m.list.ViewSlice())
	if err != nil {
		return us, false
	}

	sel := SelectorsFor(m.t.sel, pm)
	m.pm = pm
	us = NewUserSets(us, sel, m.users)
	m.t = BuildTemplates(m.t, sel)
	m.roles = m.roles.Update(us, m.nodes, nil)
	m.posts = m.posts.Update(m.roles)
	m.sides = UpdateSides(m.sides, m.t, m.roles, m.posts, m.appr, m.nodes)
	m.peers = RolePeers(m.peers, m.sides)
	m.via = UpdateViaPlans(m.via, m.sides)

	return us, true
}

// TestFiltersChangedFollowsSelfSourcesByAddress pins that an autogroup:self
// source names an owner's nodes by address: bob's node b1 holds alice's
// address, so group:g, alice alone, names b1, and bob gets a self rule on
// both his nodes. Alice's node moving to another address takes that rule
// from b2 too, though nothing of bob's moved.
func TestFiltersChangedFollowsSelfSourcesByAddress(t *testing.T) {
	pol := []byte(`{"groups": {"group:g": ["alice@"]},
		"acls": [{"action": "accept", "src": ["group:g"], "dst": ["autogroup:self:*"]}]}`)
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	// carol's node is in no rule, so the change does not name every node.
	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil),
		sideNode(2, bob, "100.64.0.1", "", nil),
		sideNode(3, bob, "100.64.0.2", "", nil),
		sideNode(4, carol, "100.64.0.3", "", nil),
	}

	pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	prev := FollowFilters(nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	was, err := prev.ForNode(3, ReceiverFacts{})
	require.NoError(t, err)
	require.NotEmpty(t, was, "test sanity: b2 gets bob's self rule, named through b1's address")

	moved := slices.Clone(nodes)
	moved[0] = sideNode(1, alice, "100.64.0.5", "", nil)
	m.step(t, us, moved)

	next := FollowFilters(prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	ids, all := next.Changed(prev)
	require.False(t, all)
	assert.Contains(t, ids, types.NodeID(3), "b2's self rule went with the address that named bob")

	is, err := next.ForNode(3, ReceiverFacts{})
	require.NoError(t, err)
	assert.Empty(t, is, "b2 is served its filter without the rule, not a carried one")
}

// TestFiltersChangedFollowsSelfRuleMergeKeys pins that an owner's self rule
// merges at the first shared rule with its key: alice's self rule has the
// sources group:g's rule has while group:g is alice alone, so on alice's
// node it sits first, before the tag:t rule. Bob joining group:g moves
// that rule's key away, and the self rule falls back behind, though
// nothing alice's node holds, or is named by, moved.
func TestFiltersChangedFollowsSelfRuleMergeKeys(t *testing.T) {
	doc := func(members string) []byte {
		return fmt.Appendf(nil, `{"groups": {"group:g": [%s]},
		"tagOwners": {"tag:x": [], "tag:t": []},
		"acls": [{"action": "accept", "src": ["group:g"], "dst": ["tag:x:22"]},
			{"action": "accept", "src": ["tag:t"], "dst": ["alice@:80"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:443"]}]}`, members)
	}
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil),
		sideNode(2, bob, "100.64.0.2", "", nil),
		sideNode(3, nil, "100.64.0.3", "", []string{"tag:x"}),
		sideNode(4, nil, "100.64.0.4", "", []string{"tag:t"}),
		sideNode(5, carol, "100.64.0.5", "", nil),
	}

	pm, err := NewPolicyManager(doc(`"alice@"`), sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	prev := FollowFilters(nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	ports := func(rules []tailcfg.FilterRule) []uint16 {
		out := make([]uint16, 0, len(rules))
		for _, r := range rules {
			out = append(out, r.DstPorts[0].Ports.First)
		}

		return out
	}

	was, err := prev.ForNode(1, ReceiverFacts{})
	require.NoError(t, err)
	require.Equal(t, []uint16{443, 80}, ports(was), "test sanity: the self rule sits where group:g's rule does")

	_, ok := m.edit(t, us, doc(`"alice@", "bob@"`))
	require.True(t, ok)

	next := FollowFilters(prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	ids, all := next.Changed(prev)
	require.False(t, all)
	assert.Contains(t, ids, types.NodeID(1), "the self rule's merged position moved")

	is, err := next.ForNode(1, ReceiverFacts{})
	require.NoError(t, err)
	assert.Equal(t, []uint16{80, 443}, ports(is), "alice's node is served the reordered filter, not a carried one")
}

// TestFiltersComparedInTheFormServed pins, across a document edit that
// changes the selector table, that each node is compared in the form it is
// served, not in the form the old filters happen to hold. Node 5 stops
// being an app connector: the carry keeps its address form alone. Node 4, a
// via router of tag:r, starts announcing its approved route in one commit
// with an edit that changes the table: the comparison recuts only the
// capability form the old filters hold. Each is then served the form it has
// no cut of, and a session that took those filters reads it from them after
// routing moved on, so the next edit must name each where only its served
// form moved: the via grant's literal source, which capability form cuts no
// via rule for, and a source renamed to a group of the same members, which
// address form writes alike. Node 6, served the capability form it holds,
// which no edit reaches, is left out.
func TestFiltersComparedInTheFormServed(t *testing.T) {
	doc := func(literal, group, extra string) []byte {
		return fmt.Appendf(nil, `{"groups": {"group:a": ["bob@"], "group:b": ["bob@"]},
		"tagOwners": {"tag:r": ["alice@"], "tag:s": [], "tag:x": []},
		"grants": [{"src": [%q, "autogroup:tagged"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]},
			{"src": [%q], "dst": ["tag:s"], "ip": ["tcp:22"]},
			{"src": ["alice@"], "dst": ["alice@"], "ip": ["tcp:80"]}%s]}`, literal, group, extra)
	}
	alice, bob := &sideUsers[0], &sideUsers[1]

	// A grant no node receives, whose selector is new to the table.
	const extra = `, {"src": ["tag:x"], "dst": ["tag:x"], "ip": ["tcp:1"]}`

	nodes := types.Nodes{
		sideNode(2, bob, "100.64.0.2", "", nil),
		sideNode(4, nil, "100.64.0.11", "", []string{"tag:r"}, "+10.0.0.0/24"),
		sideNode(5, nil, "100.64.0.5", "", []string{"tag:s"}),
		sideNode(6, alice, "100.64.0.6", "", nil),
	}
	asOfficial(nodes)
	nodes[2].Hostinfo.AppConnector.Set(true)

	pm, err := NewPolicyManager(doc("8.8.8.0/29", "group:a", ""), sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	recv := modelReceivers(true, m)
	prev := FollowFiltersFor(CapabilitySources, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	for _, n := range m.list {
		_, err := prev.ForNode(n.ID, recv.Of(n.ID))
		require.NoError(t, err)
	}

	// follow routes the filters of m's state from prev as Since does,
	// which works out what they carry.
	follow := func(prev *Filters) (*Filters, Receivers) {
		t.Helper()

		f := FollowFiltersFor(CapabilitySources, prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
		r := modelReceivers(true, m)
		_, all := f.ChangedFor(prev, r)
		require.False(t, all)

		return f, r
	}

	flip := func(id types.NodeID, set func(*tailcfg.Hostinfo)) {
		t.Helper()

		next := slices.Clone(m.list)
		i := slices.IndexFunc(next, func(n *types.Node) bool { return n.ID == id })
		n := *next[i]
		n.Hostinfo = n.Hostinfo.Clone()
		set(n.Hostinfo)
		next[i] = &n
		m.step(t, us, next)
	}

	flip(5, func(hi *tailcfg.Hostinfo) { hi.AppConnector.Set(false) })

	carried, _ := follow(prev)

	flip(4, func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")} })

	table := m.t.table()

	us, ok := m.edit(t, us, doc("8.8.8.0/29", "group:a", extra))
	require.True(t, ok)
	require.NotSame(t, table, m.t.table(), "test sanity: the edit changes the selector table")

	mid, midRecv := follow(carried)
	require.ElementsMatch(t, []types.NodeID{4, 5}, midRecv.ChangedSince(recv), "test sanity: both flipped their form")

	for id, served := range map[types.NodeID]filterForm{4: formAddress, 5: formCapability} {
		_, other := mid.heldIn(id, 1-served)
		_, own := mid.heldIn(id, served)
		require.True(t, other && !own, "test sanity: node %d holds only the form it is not served", id)
	}

	table = m.t.table()

	_, ok = m.edit(t, us, doc("8.8.4.0/29", "group:b", extra))
	require.True(t, ok)
	require.NotSame(t, table, m.t.table(), "test sanity: the edit changes the selector table")

	next := FollowFiltersFor(CapabilitySources, mid, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	nextRecv := modelReceivers(true, m)

	ids, all := next.ChangedFor(mid, nextRecv)
	require.False(t, all)

	every, _ := next.Changed(mid)

	for _, id := range []types.NodeID{4, 5} {
		was, err := mid.ForNode(id, midRecv.Of(id))
		require.NoError(t, err)

		is, err := next.ForNode(id, nextRecv.Of(id))
		require.NoError(t, err)
		require.NotEqual(t, was, is, "test sanity: node %d's served filter moved", id)

		assert.Contains(t, ids, id, "node %d is compared in the form it is served", id)
		assert.Contains(t, every, id, "Changed names node %d", id)
	}

	assert.NotContains(t, ids, types.NodeID(6), "a node served the form it holds, unmoved, is not named")
}

// TestFiltersChangeIsNotSharedWithCallers pins that the change the filters
// keep comes to each caller clipped: Since appends to it, and the hub and
// the sessions' renders ask for it at once, so an append into its spare
// room would write where another caller reads.
func TestFiltersChangeIsNotSharedWithCallers(t *testing.T) {
	// bob's node is no rule's: a join of alice's names some nodes, not all.
	alice, bob := &sideUsers[0], &sideUsers[1]
	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil), sideNode(2, alice, "100.64.0.2", "", nil),
		sideNode(9, bob, "100.64.0.9", "", nil),
	}

	pm, err := NewPolicyManager([]byte(`{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:*"]}]}`), sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	shared := 0

	for i, mode := range []SourceMode{AddressSources, CapabilitySources} {
		prev := FollowFiltersFor(mode, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

		id := types.NodeID(3 + i) //nolint:gosec // small
		joined := append(slices.Clone(m.list), sideNode(id, alice, fmt.Sprintf("100.64.0.%d", id), "", nil))
		slices.SortFunc(joined, func(a, b *types.Node) int { return int(a.ID) - int(b.ID) }) //nolint:gosec // small
		m.step(t, us, joined)

		next := FollowFiltersFor(mode, prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

		recv := modelReceivers(mode == CapabilitySources, m)

		for name, ask := range map[string]func() []types.NodeID{
			"Changed":    func() []types.NodeID { ids, _ := next.Changed(prev); return ids },
			"ChangedFor": func() []types.NodeID { ids, _ := next.ChangedFor(prev, recv); return ids },
		} {
			a, b := ask(), ask()
			require.NotEmpty(t, a, "test sanity: the join moves filters")

			// Two callers handed one array: neither may have room past
			// its end.
			if &a[0] == &b[0] {
				assert.Equal(t, len(a), cap(a), "%s in mode %d: a shared change has no room to append into", name, mode)

				shared++
			}
		}
	}

	require.Positive(t, shared, "test sanity: the change is shared between callers")
}

// TestFiltersChangedNamesOwnersAtMovedMergeKeys pins, in capability mode,
// that an owner sent addresses whose only rules are its own self rules is
// named when one of them was merged at another rule's key and that key
// moved: alice's 443 self rule sits where group:g's rule does, before her
// 80 self rule, until bob joins group:g. She receives no other grant, so
// nothing but the merge positions names her, and in capability mode
// routing does not work them out.
func TestFiltersChangedNamesOwnersAtMovedMergeKeys(t *testing.T) {
	doc := func(members string) []byte {
		return fmt.Appendf(nil, `{"groups": {"group:g": [%s]},
		"tagOwners": {"tag:x": []},
		"grants": [{"src": ["group:g"], "dst": ["tag:x"], "ip": ["tcp:22"]},
			{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["udp:80"]},
			{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["tcp:443"]}]}`, members)
	}
	alice, bob := &sideUsers[0], &sideUsers[1]

	// Every node reports no client: sent addresses in capability mode.
	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil),
		sideNode(2, bob, "100.64.0.2", "", nil),
		sideNode(3, nil, "100.64.0.3", "", []string{"tag:x"}),
	}

	pm, err := NewPolicyManager(doc(`"alice@"`), sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	recv := capReceivers(m.nodes, nil)
	require.Equal(t, "client", receiverForm(CapabilitySources, recv.Of(1)).String(), "test sanity: alice's node is sent addresses")

	prev := FollowFiltersFor(CapabilitySources, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	ports := func(rules []tailcfg.FilterRule) []uint16 {
		out := make([]uint16, 0, len(rules))
		for _, r := range rules {
			out = append(out, r.DstPorts[0].Ports.First)
		}

		return out
	}

	was, err := prev.ForNode(1, recv.Of(1))
	require.NoError(t, err)
	require.Equal(t, []uint16{443, 80}, ports(was), "test sanity: the 443 self rule sits where group:g's rule does")

	_, ok := m.edit(t, us, doc(`"alice@", "bob@"`))
	require.True(t, ok)

	next := FollowFiltersFor(CapabilitySources, prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	ids, all := next.ChangedFor(prev, recv)
	require.False(t, all)
	assert.Contains(t, ids, types.NodeID(1), "the self rule's merged position moved")

	is, err := next.ForNode(1, recv.Of(1))
	require.NoError(t, err)
	assert.Equal(t, []uint16{80, 443}, ports(is), "alice's node is served the reordered filter, not a carried one")
}

// TestFiltersChangedFollowsSelfNamedNodes pins that a self rule's sources
// are the owner's nodes a source names by address: b1, holding alice's
// address, is bob's only named node, and the source of the rule b2 gets.
// b1 moving to an address of its own takes that rule from b2, though no
// source's members moved and b2 did not.
func TestFiltersChangedFollowsSelfNamedNodes(t *testing.T) {
	pol := []byte(`{"groups": {"group:g": ["alice@"]},
		"acls": [{"action": "accept", "src": ["group:g"], "dst": ["autogroup:self:*"]}]}`)
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil),
		sideNode(2, bob, "100.64.0.1", "", nil),
		sideNode(3, bob, "100.64.0.2", "", nil),
		sideNode(4, carol, "100.64.0.3", "", nil),
	}

	pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	prev := FollowFilters(nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	was, err := prev.ForNode(3, ReceiverFacts{})
	require.NoError(t, err)
	require.NotEmpty(t, was, "test sanity: b2 gets bob's self rule, from b1")

	moved := slices.Clone(nodes)
	moved[1] = sideNode(2, bob, "100.64.0.6", "", nil)
	m.step(t, us, moved)

	next := FollowFilters(prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	ids, all := next.Changed(prev)
	require.False(t, all)
	assert.Contains(t, ids, types.NodeID(3), "b2's self rule went with b1's address")

	is, err := next.ForNode(3, ReceiverFacts{})
	require.NoError(t, err)
	assert.Empty(t, is, "b2 is served its filter without the rule, not a carried one")
}

// TestFiltersChangedFollowsMovedDestinations moves a rule's destination
// from tag:a to tag:b, both named elsewhere, so the selectors stay those of
// the document before: tag:a's holders lose the rule, though no source,
// member or merge position moved.
func TestFiltersChangedFollowsMovedDestinations(t *testing.T) {
	doc := func(dst string) []byte {
		return fmt.Appendf(nil, `{"tagOwners": {"tag:a": [], "tag:b": []},
		"acls": [{"action": "accept", "src": ["alice@"], "dst": ["%s:22"]},
			{"action": "accept", "src": ["bob@"], "dst": ["tag:b:80"]},
			{"action": "accept", "src": ["bob@"], "dst": ["tag:a:443"]}]}`, dst)
	}
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	nodes := types.Nodes{
		sideNode(1, alice, "100.64.0.1", "", nil),
		sideNode(2, bob, "100.64.0.2", "", nil),
		sideNode(3, nil, "100.64.0.3", "", []string{"tag:a"}),
		sideNode(4, nil, "100.64.0.4", "", []string{"tag:b"}),
		sideNode(5, carol, "100.64.0.5", "", nil),
	}

	pm, err := NewPolicyManager(doc("tag:a"), sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	prev := FollowFilters(nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	for _, n := range m.list {
		_, err := prev.ForNode(n.ID, ReceiverFacts{})
		require.NoError(t, err)
	}

	table := m.t.table()

	_, ok := m.edit(t, us, doc("tag:b"))
	require.True(t, ok)
	require.Same(t, table, m.t.table(), "test sanity: the document names the same selectors")

	next := FollowFilters(prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	ids, all := next.Changed(prev)
	require.False(t, all)
	assert.Contains(t, ids, types.NodeID(3), "tag:a's holder lost the rule")
	assert.Contains(t, ids, types.NodeID(4), "tag:b's holder gained it")

	for _, id := range []types.NodeID{3, 4} {
		served, err := next.ForNode(id, ReceiverFacts{})
		require.NoError(t, err)

		want, err := next.Uncached().ForNode(id, ReceiverFacts{})
		require.NoError(t, err)
		assert.Equal(t, want, served, "node %d is served its new filter, not a carried one", id)
	}
}

// TestFiltersChangedNamesOnlySelfOwnersSharingAKey joins a member under a
// grant from every member and a self grant: the member grant's sources,
// and so its merge key, move, but no owner holds every member's address,
// so no other owner's self rule can share it. Only what the join reaches
// is named: the grant's destinations, the joiner's owner and the joiner.
func TestFiltersChangedNamesOnlySelfOwnersSharingAKey(t *testing.T) {
	pol := []byte(`{"tagOwners": {"tag:server": []},
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:*"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`)
	alice, bob, carol := &sideUsers[0], &sideUsers[1], &sideUsers[2]

	nodes := types.Nodes{
		sideNode(1, nil, "100.64.0.1", "", []string{"tag:server"}),
		sideNode(2, nil, "100.64.0.2", "", []string{"tag:server"}),
		sideNode(3, alice, "100.64.0.3", "", nil),
		sideNode(4, alice, "100.64.0.4", "", nil),
		sideNode(5, bob, "100.64.0.5", "", nil),
		sideNode(6, bob, "100.64.0.6", "", nil),
		sideNode(7, carol, "100.64.0.7", "", nil),
		sideNode(8, carol, "100.64.0.8", "", nil),
	}

	pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, sideUsers, nodes)
	us := NewUserSets(nil, m.t.sel, sideUsers)
	prev := FollowFilters(nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	m.step(t, us, append(slices.Clone(nodes), sideNode(9, alice, "100.64.0.9", "", nil)))

	next := FollowFilters(prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
	ids, all := next.Changed(prev)
	require.False(t, all)
	assert.Equal(t, []types.NodeID{1, 2, 3, 4, 9}, ids)
}

// TestSSHPolicyAfreshFillsNoCache pins that an audit's SSH read leaves the
// compile as it was: SSH routing says every node may have moved until a
// session has asked the compile for SSH, so a read that prepared it would
// narrow what it measures.
func TestSSHPolicyAfreshFillsNoCache(t *testing.T) {
	pol := []byte(`{"tagOwners": {"tag:a": []},
		"ssh": [{"action": "accept", "src": ["alice@"], "dst": ["tag:a"], "users": ["root"]}]}`)
	nodes := types.Nodes{
		sideNode(1, &sideUsers[0], "100.64.0.1", "", nil),
		sideNode(2, nil, "100.64.0.2", "", []string{"tag:a"}),
	}

	pm, err := NewPolicyManager(pol, sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	afresh, err := pm.SSHPolicyAfresh("https://headscale.test", nodes[1].View())
	require.NoError(t, err)
	require.NotEmpty(t, afresh.Rules, "test sanity: the destination has SSH rules")

	assert.Zero(t, pm.sshPreps.Size(), "no rules prepared")
	assert.Zero(t, pm.sshPolicyMap.Size(), "no policy cached")

	next, err := NewPolicyManagerFrom(pm, pol, sideUsers, nodes.ViewSlice())
	require.NoError(t, err)

	_, all := next.SSHChangedNodes(pm)
	assert.True(t, all, "routing still cannot tell")

	cached, err := pm.SSHPolicy("https://headscale.test", nodes[1].View())
	require.NoError(t, err)
	assert.Equal(t, afresh, cached, "the same policy either way")
}

// joinWork is what the served pipeline did for one join or leave:
// allocations and bytes, and its own counters.
type joinWork struct {
	allocs, bytes                      uint64
	cuts, resolutions, members, routed uint64
	copied                             uint64
	named, viewers                     int
}

// measureChurn registers joins, or deletes nodes it joined, under
// capability mode in a tailnet of n nodes whose subject has the same
// viewers at any size, and returns the mean work of one through every cell
// the served path keeps for filters and peers, routing, and the reads of
// the sessions it wakes: the named receivers' filters, and the viewers',
// who render the subject.
func measureChurn(t *testing.T, n int, leave bool, routers int) joinWork {
	t.Helper()

	const pol = `{"groups": {"group:small": ["small@"]}, "tagOwners": {"tag:server": ["small@"]},
		"acls": [{"action": "accept", "src": ["group:small"], "dst": ["group:small:*"]},
		         {"action": "accept", "src": ["autogroup:member"], "dst": ["tag:server:22"]}]}`

	users := make(types.Users, 0, 11)
	users = append(users, types.User{Name: "small"})
	users[0].ID = 1

	for i := range 10 {
		users = append(users, types.User{Name: fmt.Sprintf("bulk%d", i)})
		users[len(users)-1].ID = uint(i + 2) //nolint:gosec // small
	}

	official := func(n *types.Node) *types.Node {
		n.Hostinfo = &tailcfg.Hostinfo{GoVersion: "go1.27.3", IPNVersion: "1.94.1"}

		return n
	}

	addr := func(i int) (string, string) {
		return fmt.Sprintf("100.%d.%d.%d", 64+i/65536, i/256%256, i%256), fmt.Sprintf("fd7a:115c:a1e0::%x", i)
	}

	nodes := make(types.Nodes, 0, n)

	for i := range n {
		v4, v6 := addr(i + 1)
		id := types.NodeID(i + 1) //nolint:gosec // bounded

		switch {
		case i < 10:
			nodes = append(nodes, official(sideNode(id, nil, v4, v6, []string{"tag:server"})))
		case i < 15:
			nodes = append(nodes, official(sideNode(id, &users[0], v4, v6, nil)))
		case i < 15+routers:
			// A subnet router: sent addresses, and recut at every rule
			// change.
			r := official(sideNode(id, &users[1+i%10], v4, v6, nil))
			r.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
			r.ApprovedRoutes = r.Hostinfo.RoutableIPs
			nodes = append(nodes, r)
		default:
			nodes = append(nodes, official(sideNode(id, &users[1+i%10], v4, v6, nil)))
		}
	}

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, users, nodes)
	us := NewUserSets(nil, m.t.sel, users)
	caps := graph.NewMap(func(a, b tailcfg.NodeCapMap) bool { return a.Equal(b) }, map[types.NodeID]tailcfg.NodeCapMap{})
	recv := Receivers{}.Update(m.nodes, caps)
	f := FollowFiltersFor(CapabilitySources, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

	// Every session has read its filter, as after a first map each.
	for _, nd := range m.list {
		_, err := f.ForNode(nd.ID, recv.Of(nd.ID))
		require.NoError(t, err)
	}

	read := func() [4]uint64 {
		return [4]uint64{FilterCuts(), resolutionsBuilt.Load(), membersExpanded.Load(), routedNodes.Load()}
	}

	// copied counts the entries the pipeline's group lists copied, each a
	// sorted slice an edit copies whole.
	var copied uint64

	// commit moves the pipeline to list, the policy's node list, which is
	// the world's to keep outside it (the compile reads it too), with the
	// node subject set or deleted; returns whom routing named and the
	// subject's viewers, before a leave and after a join, each having
	// read its filter.
	commit := func(subject *types.Node, list types.Nodes, del bool) (int, int) {
		viewers := m.peers.View(subject.ID)
		posts, sides, peers := m.posts, m.sides, m.peers

		e := m.nodes.Edit()
		if del {
			e.Delete(subject.ID)
		} else {
			e.Set(subject.ID, subject)
		}

		m.nodes, m.list = e.Done(), list
		m.roles = m.roles.Update(us, m.nodes, nil)
		m.posts = m.posts.Update(m.roles)
		m.appr = m.appr.Update(m.nodes)
		m.sides = UpdateSides(m.sides, m.t, m.roles, m.posts, m.appr, m.nodes)
		m.peers = RolePeers(m.peers, m.sides)
		m.via = UpdateViaPlans(m.via, m.sides)
		recv = recv.Update(m.nodes, caps)

		copied += groupCopies(posts.byRole.Groups, m.posts.byRole.Groups) + groupCopies(sides.held.Groups, m.sides.held.Groups) +
			groupCopies(sides.byAddr.Groups, m.sides.byAddr.Groups) + groupCopies(peers.keyed.members.Groups, m.peers.keyed.members.Groups)

		next := FollowFiltersFor(CapabilitySources, f, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

		named, all := next.ChangedFor(f, recv)
		require.False(t, all)

		if !del {
			viewers = m.peers.View(subject.ID)
		}

		for _, id := range slices.Concat(named, viewers) {
			if _, listed := next.node(id); listed {
				_, err := next.ForNode(id, recv.Of(id))
				require.NoError(t, err)
			}
		}

		f = next

		return len(named), len(viewers)
	}

	// The first commit carries every filter the sessions cut at the
	// filters before: what reading them all cost, once. Measured are the
	// commits in the steady state after it.
	const rounds = 5

	var w joinWork

	for j := range rounds + 1 {
		v4, v6 := addr(n + j + 1)
		subject := official(sideNode(types.NodeID(n+j+1), &users[0], v4, v6, nil)) //nolint:gosec // bounded
		joined := append(slices.Clone(m.list), subject)

		if leave {
			commit(subject, joined, false)
		}

		list := joined
		if leave {
			list = slices.Clone(m.list[:len(m.list)-1])
		}

		runtime.GC()

		var before, after runtime.MemStats

		runtime.ReadMemStats(&before)

		was, wasCopied := read(), copied
		named, viewers := commit(subject, list, leave)

		runtime.ReadMemStats(&after)

		is := read()

		if j == 0 {
			continue
		}

		w.allocs += after.Mallocs - before.Mallocs
		w.bytes += after.TotalAlloc - before.TotalAlloc
		w.cuts += is[0] - was[0]
		w.resolutions += is[1] - was[1]
		w.members += is[2] - was[2]
		w.routed += is[3] - was[3]
		w.copied += copied - wasCopied
		w.named, w.viewers = named, viewers
	}

	for _, v := range []*uint64{&w.allocs, &w.bytes, &w.cuts, &w.resolutions, &w.members, &w.routed, &w.copied} {
		*v /= rounds
	}

	return w
}

// TestJoinWorkWithRouters is [TestJoinWorkFollowsChange] with a subnet
// router: by D7 it is recut at every rule change, and its client builds
// its local nets from its routes, so it is cut in address form, which
// resolves every selector and the merge positions of every grant. So one
// join costs a router what the tailnet is: the members those resolutions
// list grow with it, and the bytes. The other work is the join's own.
func TestJoinWorkWithRouters(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 10,000 node tailnet")
	}

	small, large := measureChurn(t, 100, false, 1), measureChurn(t, 10_000, false, 1)

	t.Logf("at 100: %+v", small)
	t.Logf("at 10000: %+v", large)

	for _, w := range []joinWork{small, large} {
		assert.Equal(t, uint64(2), w.cuts, "the subject's filter and the router's are cut")
	}

	assert.Equal(t, small.resolutions, large.resolutions, "the router's cut resolves every selector, at any size")
	assert.Greater(t, large.members, 50*small.members, "the members those list are the tailnet")
}

// TestCensusAfterJoinCostsWhatMoved pins that a metrics scrape landing
// after a join, before any routing or read of the new filters, counts the
// census from the one scraped before: no owner's self rules but the
// joiner's are counted again, no selector resolved, and the scrape allocates alike at 100 and at 10,000
// nodes.
func TestCensusAfterJoinCostsWhatMoved(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 10,000 node tailnet")
	}

	type censusWork struct{ allocs, owners, resolutions uint64 }

	measure := func(n int) censusWork {
		const pol = `{"groups": {"group:small": ["small@"]},
			"grants": [{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["*"]},
			           {"src": ["group:small"], "dst": ["group:small"], "ip": ["tcp:22"]}]}`

		users := make(types.Users, 0, 11)
		users = append(users, types.User{Name: "small"})
		users[0].ID = 1

		for i := range 10 {
			users = append(users, types.User{Name: fmt.Sprintf("bulk%d", i)})
			users[len(users)-1].ID = uint(i + 2) //nolint:gosec // small
		}

		addr := func(i int) (string, string) {
			return fmt.Sprintf("100.%d.%d.%d", 64+i/65536, i/256%256, i%256), fmt.Sprintf("fd7a:115c:a1e0::%x", i)
		}

		node := func(i int, u *types.User) *types.Node {
			v4, v6 := addr(i)
			nd := sideNode(types.NodeID(i), u, v4, v6, nil) //nolint:gosec // bounded
			nd.Hostinfo = &tailcfg.Hostinfo{GoVersion: "go1.27.3", IPNVersion: "1.94.1"}

			return nd
		}

		nodes := make(types.Nodes, 0, n)
		for i := range n {
			nodes = append(nodes, node(i+1, &users[i%len(users)]))
		}

		pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
		require.NoError(t, err)

		m := newSideModel(t, pm, users, nodes)
		us := NewUserSets(nil, m.t.sel, users)
		caps := graph.NewMap(func(a, b tailcfg.NodeCapMap) bool { return a.Equal(b) }, map[types.NodeID]tailcfg.NodeCapMap{})
		recv := Receivers{}.Update(m.nodes, caps)
		f := FollowFiltersFor(CapabilitySources, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

		_, err = f.Census(recv)
		require.NoError(t, err)

		const rounds = 5

		var w censusWork

		for j := range rounds {
			subject := node(n+j+1, &users[0])

			e := m.nodes.Edit()
			e.Set(subject.ID, subject)
			m.nodes, m.list = e.Done(), append(slices.Clone(m.list), subject)
			m.roles = m.roles.Update(us, m.nodes, nil)
			m.posts = m.posts.Update(m.roles)
			m.appr = m.appr.Update(m.nodes)
			m.sides = UpdateSides(m.sides, m.t, m.roles, m.posts, m.appr, m.nodes)
			recv = recv.Update(m.nodes, caps)
			f = FollowFiltersFor(CapabilitySources, f, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

			counts := [2]uint64{ownerCounts.Load(), resolutionsBuilt.Load()}

			runtime.GC()

			var before, after runtime.MemStats

			runtime.ReadMemStats(&before)

			got, err := f.Census(recv)

			runtime.ReadMemStats(&after)
			require.NoError(t, err)

			w.allocs += after.Mallocs - before.Mallocs
			w.owners += ownerCounts.Load() - counts[0]
			w.resolutions += resolutionsBuilt.Load() - counts[1]

			want, err := f.Uncached().Census(recv)
			require.NoError(t, err)
			require.Equal(t, want, got, "the census counted from the last is the one counted afresh")
		}

		w.allocs /= rounds

		return w
	}

	small, large := measure(100), measure(10_000)
	t.Logf("at 100: %+v; at 10000: %+v", small, large)

	for _, w := range []censusWork{small, large} {
		assert.Zero(t, w.owners, "no census counts every owner")
		assert.Zero(t, w.resolutions, "no selector is resolved")
	}

	assert.LessOrEqual(t, float64(large.allocs), 1.2*float64(small.allocs)+16, "a scrape allocates what moved")
}

// groupCopies returns the entries the edits from a to b copied: each group
// list is a sorted slice, so an edit copies the whole list.
func groupCopies[G comparable](a, b *graph.Map[G, []types.NodeID]) uint64 {
	var n uint64

	for _, g := range graph.Changes(a, b) {
		was, _ := a.Get(g)
		is, _ := b.Get(g)
		n += uint64(max(len(was), len(is)))
	}

	return n
}

// TestJoinWorkFollowsChange is the churn invariant on work (plan check
// H): in capability mode one join, or one leave, under a policy whose
// subject has the same viewers at any size costs the served pipeline the
// same at 100 and at 10,000 nodes. It names the subject alone, cuts its
// filter alone (a leaver's is not cut) and builds no selector's
// resolution; its allocations do not grow with the tailnet.
// Its bytes do, by what the posting and holder lists the subject enters or
// leaves copy: each is a sorted slice, copied on edit.
func TestJoinWorkFollowsChange(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 10,000 node tailnet")
	}

	for _, leave := range []bool{false, true} {
		t.Run(fmt.Sprintf("leave=%t", leave), func(t *testing.T) {
			small, large := measureChurn(t, 100, leave, 0), measureChurn(t, 10_000, leave, 0)

			t.Logf("at 100: %+v", small)
			t.Logf("at 10000: %+v", large)

			cuts := uint64(1)
			if leave {
				cuts = 0
			}

			for _, w := range []joinWork{small, large} {
				assert.Equal(t, cuts, w.cuts, "the subject's filter alone is cut")
				assert.Equal(t, 1, w.named, "routing names the subject alone")
				assert.Equal(t, uint64(1), w.routed, "routing visits the subject alone")
				assert.Zero(t, w.resolutions, "no selector's members are expanded")
				assert.Zero(t, w.members)
			}

			assert.Equal(t, small.viewers, large.viewers, "test sanity: the subject has the same viewers at both sizes")
			assert.LessOrEqual(t, float64(large.allocs), 1.1*float64(small.allocs), "allocations do not grow with the tailnet")

			// What grows is the lists the subject enters or leaves:
			// autogroup:member's posting, its holders and the views built
			// from them.
			growth := float64(large.bytes) - float64(small.bytes)
			copies := 8 * float64(large.copied-small.copied)
			assert.InDelta(t, copies, growth, 0.15*copies+64<<10, "bytes grow by the group lists copied, %d and %d entries", small.copied, large.copied)
		})
	}
}

// TestFiltersFollowSelfMergeAnchors: a tag:a node joining moves where
// alice's self rule merges on node 2 (a rule whose sources are all of one
// owner's addresses gains a source). The change must name node 2 and serve
// it the fresh filter, in either form, and the address form must be the
// address compile's.
func TestFiltersFollowSelfMergeAnchors(t *testing.T) {
	pol := []byte(`{
		"tagOwners": {"tag:a": []},
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}],
		"grants": [
			{"src": ["alice@", "tag:a"], "dst": ["100.64.0.0/30"], "ip": ["*"]},
			{"src": ["autogroup:member"], "dst": ["autogroup:self"], "app": {"example.com/cap/x": [{}]}}
		]
	}`)
	users := sideUsers
	nodes := types.Nodes{
		sideNode(1, &users[0], "100.64.0.1", "", nil),
		sideNode(2, &users[0], "100.64.0.5", "", nil),
		sideNode(3, &users[1], "100.64.0.6", "", nil),
	}

	for _, mode := range []SourceMode{AddressSources, CapabilitySources} {
		pm, err := NewPolicyManager(pol, users, nodes.ViewSlice())
		require.NoError(t, err)

		m := newSideModel(t, pm, users, nodes)
		us := NewUserSets(nil, m.t.sel, users)
		recv := capReceivers(m.nodes, nil)

		prev := FollowFiltersFor(mode, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
		for _, n := range nodes {
			_, err := prev.ForNode(n.ID, recv.Of(n.ID))
			require.NoError(t, err)
		}

		next := append(slices.Clone(nodes), sideNode(4, nil, "100.64.0.7", "", []string{"tag:a"}))
		m.step(t, us, next)
		recv = capReceivers(m.nodes, nil)

		f := FollowFiltersFor(mode, prev, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)
		ids, all := f.ChangedFor(prev, recv)
		fresh := FollowFiltersFor(mode, nil, m.t, m.posts, m.appr, m.list.ViewSlice(), m.sides)

		for _, n := range next {
			got, err := f.ForNode(n.ID, recv.Of(n.ID))
			require.NoError(t, err)

			want, err := fresh.ForNode(n.ID, recv.Of(n.ID))
			require.NoError(t, err)
			require.Equal(t, want, got, "mode %v node %d", mode, n.ID)

			if old, _ := prev.ForNode(n.ID, recv.Of(n.ID)); !all && n.ID != 4 && !slices.Contains(ids, n.ID) {
				require.Equal(t, old, got, "mode %v node %d moved unnamed (named %v)", mode, n.ID, ids)
			}

			wantAddr, err := m.pm.FilterForNode(n.View())
			require.NoError(t, err)

			gotAddr, err := f.AddressForm(n.ID)
			require.NoError(t, err)
			require.Equal(t, wantAddr, gotAddr, "mode %v: address form of node %d against the address compile", mode, n.ID)
		}

		require.True(t, all || slices.Contains(ids, 2), "mode %v: node 2's self rule moved, named %v", mode, ids)
	}
}
