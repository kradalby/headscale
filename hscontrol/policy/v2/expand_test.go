package v2

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"

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

	first, err := f.ForNode(nodes[0].ID)
	require.NoError(t, err)

	want, err := pm.FilterForNode(nodes[0].View())
	require.NoError(t, err)
	require.Equal(t, want, first)

	again, err := f.ForNode(nodes[0].ID)
	require.NoError(t, err)
	assert.Same(t, &first[0], &again[0], "readers of one node share its filter")

	_, err = f.ForNode(99)
	require.ErrorIs(t, err, errUnlisted)

	global, err := f.Global()
	require.NoError(t, err)
	assert.Equal(t, pm.filter, global)
}
