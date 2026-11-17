package v2

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

			got := expandCapSources(tc.capForm, nil, nc.holders)
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

			got := expandCapSources(tc.rules, tc.classes, nc.holders)
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
			same := cmp.Equal(tc.ref, expandCapSources(tc.cand, nil, nc.holders), inOrderOpts...)

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
	assert.Equal(t, pm.filter, global)
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
		public, caps, sparse bool
		stream               uint64
	}{
		{stream: 2}, {public: true, stream: 3}, {caps: true, stream: 12}, {caps: true, sparse: true, stream: 13},
	}

	for _, v := range variants {
		public := v.public

		t.Run(fmt.Sprintf("public=%t/caps=%t/sparse=%t", v.public, v.caps, v.sparse), func(t *testing.T) {
			g := sideGen{r: rand.New(rand.NewPCG(seed, v.stream)), public: public, sparse: v.sparse} //nolint:gosec // reproducible
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
					nodes = append(nodes, g.node(types.NodeID(i+1))) //nolint:gosec // bounded
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

					// As Since routes them: what the filters say moved, and
					// the nodes whose facts moved, served their other form.
					ids, all := next.Changed(prev)
					flipped := nextRecv.ChangedSince(prevRecv)
					ids = slices.Compact(slices.Sorted(slices.Values(slices.Concat(ids, flipped))))
					narrow := routeFilters(prev, next, func(end int, id types.NodeID) ReceiverFacts {
						return [2]Receivers{prevRecv, nextRecv}[end].Of(id)
					})
					narrow.ids = slices.Compact(slices.Sorted(slices.Values(slices.Concat(narrow.ids, flipped))))

					fail := func(format string, args ...any) {
						t.Helper()
						t.Fatalf("HEADSCALE_SIDES_SEED=%d public=%t round %d step %d: %s\npolicy:\n%s\nbefore:\n%s\nafter:\n%s",
							seed, public, round, step, fmt.Sprintf(format, args...), m.pm.src, describeNodes(was), describeNodes(m.list))
					}

					freshOld, freshNew := prev.Uncached(), next.Uncached()

					capRoutingReach(v.caps, prevRecv, nextRecv, ids, all, narrow, m.list, reach)

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
				kinds = append(kinds, "receiver form flipped", "capability pairs left out by narrow routing")
			}

			for _, kind := range kinds {
				assert.Positive(t, reach[kind], "%s reached", kind)
			}
		})
	}
}

// modelReceivers is every node's facts in m's current state, none unless
// caps.
func modelReceivers(caps bool, m *sideModel) Receivers {
	if !caps {
		return Receivers{}
	}

	return capReceivers(m.nodes, m.pm.NodeCapMaps())
}

// capRoutingReach counts, in capability mode, the receivers whose form
// flipped between prev and next, and the steps where narrow routing left
// out pairs sent capabilities that Changed names.
func capRoutingReach(caps bool, prev, next Receivers, ids []types.NodeID, all bool, narrow filterChange, list types.Nodes, reach map[string]int) {
	if !caps {
		return
	}

	if !all && !narrow.all && len(narrow.ids) < len(ids) {
		reach["capability pairs left out by narrow routing"]++
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
		v4, _ := g.addrs()
		n.IPv4 = new(netip.MustParseAddr(g.pick(v4...)))
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
