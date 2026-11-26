package v2

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// quirkNode is a node in compact form: name, owner (nil for tagged),
// addresses (empty for none), tags, routes.
type quirkNode struct {
	name  string
	user  *types.User
	v4    string
	v6    string
	tags  []string
	route []string // announced and approved
	only  []string // approved, not announced
}

func quirkNodes(defs ...quirkNode) types.Nodes {
	nodes := make(types.Nodes, 0, len(defs))

	for i, d := range defs {
		n := &types.Node{
			ID:             types.NodeID(i + 1), //nolint:gosec // a handful
			Hostname:       d.name,
			GivenName:      d.name,
			Tags:           d.tags,
			Hostinfo:       &tailcfg.Hostinfo{},
			ApprovedRoutes: []netip.Prefix{},
		}

		if d.v4 != "" {
			n.IPv4 = ptrAddr(d.v4)
		}

		if d.v6 != "" {
			n.IPv6 = ptrAddr(d.v6)
		}

		if d.user != nil && len(d.tags) == 0 {
			n.User, n.UserID = d.user, &d.user.ID
		}

		for _, r := range d.route {
			p := netip.MustParsePrefix(r)
			n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, p)
			n.ApprovedRoutes = append(n.ApprovedRoutes, p)
		}

		for _, r := range d.only {
			n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix(r))
		}

		nodes = append(nodes, n)
	}

	return nodes
}

func dst(ip string, first, last uint16) tailcfg.NetPortRange {
	return tailcfg.NetPortRange{IP: ip, Ports: tailcfg.PortRange{First: first, Last: last}}
}

func port(ip string, p uint16) tailcfg.NetPortRange { return dst(ip, p, p) }

func anyPort(ip string) tailcfg.NetPortRange { return dst(ip, 0, 65535) }

func host(ip string) netip.Prefix {
	a := netip.MustParseAddr(ip)

	return netip.PrefixFrom(a, a.BitLen())
}

// TestExpanderQuirks pins, one case each, the parts of today's compile the
// expander has to reproduce that a plain substitution of members for
// selectors would not: each case writes the filter out by hand, and both
// the compile and the expansion must give exactly it.
func TestExpanderQuirks(t *testing.T) {
	t.Parallel()

	users := types.Users{
		{ID: 1, Name: "alice"},
		{ID: 2, Name: "bob"},
		{ID: 3, Name: "carol", Email: "carol@example.com"},
	}
	alice, carol := &users[0], &users[2]

	const owners = `"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]}`

	wildcard := []string{"100.115.94.0-100.127.255.255", "100.64.0.0-100.115.91.255", "fd7a:115c:a1e0::/48"}
	everything := tailcfg.FilterRule{SrcIPs: wildcard, DstPorts: []tailcfg.NetPortRange{anyPort("*")}}

	var internetV4 []tailcfg.NetPortRange

	for _, r := range internetStrings() {
		a, err := netip.ParseAddr(strings.Split(r, "-")[0])
		if err == nil && a.Is4() {
			internetV4 = append(internetV4, anyPort(r))
		}
	}

	tests := []struct {
		name     string
		policy   string
		nodes    types.Nodes
		receiver string
		want     []tailcfg.FilterRule
	}{
		{
			// Rules 0 and 2 name the same nodes: merged, the rule sits where
			// rule 0 does, ahead of rule 1, though rule 0 does not reach a1.
			name: "merged-at-first-rule-anywhere",
			policy: `{"groups": {"group:a": ["alice@", "carol@example.com"]}, ` + owners + `, "acls": [
				{"action": "accept", "src": ["group:a"], "dst": ["tag:a:22"]},
				{"action": "accept", "src": ["tag:b"], "dst": ["autogroup:member:80"]},
				{"action": "accept", "src": ["alice@", "carol@example.com"], "dst": ["autogroup:member:443"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "c1", user: carol, v4: "100.64.0.3"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
				quirkNode{name: "tb", v4: "100.64.0.11", tags: []string{"tag:b"}},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1", "100.64.0.3"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.1", 443)}},
				{SrcIPs: []string{"100.64.0.11"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.1", 80)}},
			},
		},
		{
			// A rule from nobody goes; a capability rule from nobody stays,
			// with sources empty, not missing.
			name: "empty-sources",
			policy: `{"groups": {"group:empty": []}, ` + owners + `, "grants": [
				{"src": ["group:empty"], "dst": ["tag:a"], "ip": ["tcp:22"]},
				{"src": ["nobody@"], "dst": ["tag:a"], "app": {"example.com/cap/x": [{}]}}]}`,
			nodes:    quirkNodes(quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}}),
			receiver: "ta",
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{},
				CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{host("100.64.0.10")}, CapMap: tailcfg.PeerCapMap{"example.com/cap/x": {"{}"}}}},
			}},
		},
		{
			name: "duplicates-keep-multiplicity",
			policy: `{` + owners + `, "grants": [
				{"src": ["alice@"], "dst": ["tag:a"], "ip": ["tcp:22"]},
				{"src": ["alice@"], "dst": ["tag:a"], "ip": ["tcp:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
			),
			receiver: "ta",
			want: []tailcfg.FilterRule{{
				SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.10", 22), port("100.64.0.10", 22)},
				IPProto: []int{ProtocolTCP},
			}},
		},
		{
			// The same sources, protocols and destination: a via rule and a
			// regular one stay apart.
			name: "via-apart-from-regular",
			policy: `{` + owners + `, "grants": [
				{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:b"]},
				{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "tb", v4: "100.64.0.11", tags: []string{"tag:b"}, route: []string{"10.0.0.0/24"}},
			),
			receiver: "tb",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{anyPort("10.0.0.0/24")}},
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{anyPort("10.0.0.0/24")}},
			},
		},
		{
			// * names an owner's nodes inside its ranges only.
			name:   "self-wildcard-by-address",
			policy: `{"acls": [{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "a2", user: alice, v4: "192.168.0.2"},
			),
			receiver: "a2",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{port("192.168.0.2", 22)}},
			},
		},
		{
			// * adds every approved subnet route, announced or not; exit
			// routes are not subnets.
			name:   "wildcard-adds-approved-routes",
			policy: `{` + owners + `, "acls": [{"action": "accept", "src": ["*"], "dst": ["tag:a:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
				quirkNode{name: "r", v4: "100.64.0.20", tags: []string{"tag:b"}, route: []string{"10.0.0.0/24", "0.0.0.0/0"}, only: []string{"10.1.0.0/24"}},
			),
			receiver: "ta",
			want: []tailcfg.FilterRule{{
				SrcIPs:   append([]string{"10.0.0.0/24", "10.1.0.0/24"}, wildcard...),
				DstPorts: []tailcfg.NetPortRange{port("100.64.0.10", 22)},
			}},
		},
		{
			name:   "receiver-among-its-sources",
			policy: `{"groups": {"group:a": ["alice@", "carol@example.com"]}, "acls": [{"action": "accept", "src": ["group:a"], "dst": ["group:a:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "c1", user: carol, v4: "100.64.0.3"},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1", "100.64.0.3"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.1", 22)}},
			},
		},
		{
			// An exit node holds every owner's self rules, by user ID, not by
			// node.
			name:   "exit-holds-every-owners-self-rules",
			policy: `{` + owners + `, "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "c1", user: carol, v4: "100.64.0.3"},
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ex", v4: "100.64.0.30", tags: []string{"tag:b"}, route: []string{"0.0.0.0/0", "::/0"}},
			),
			receiver: "ex",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.1", 22)}},
				{SrcIPs: []string{"100.64.0.3"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.3", 22)}},
			},
		},
		{
			// A route over others' addresses brings their destinations.
			name:   "router-over-tailnet-addresses",
			policy: `{` + owners + `, "acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
				quirkNode{name: "r", v4: "100.64.1.1", tags: []string{"tag:b"}, route: []string{"100.64.0.0/24"}},
			),
			receiver: "r",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.10", 22)}},
			},
		},
		{
			// A self rule merges into the shared rule of its key, which
			// sits ahead of * though it does not reach a1.
			name: "self-rule-at-shared-rule",
			policy: `{` + owners + `, "acls": [
				{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]},
				{"action": "accept", "src": ["*"], "dst": ["*:*"]},
				{"action": "accept", "src": ["alice@"], "dst": ["autogroup:self:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1", v6: "fd7a:115c:a1e0::1"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.1", 22), port("fd7a:115c:a1e0::1", 22)}},
				everything,
			},
		},
		{
			// A rule whose destination has no address anywhere is not
			// written, so it places nothing: the later rule of its key sits
			// after *.
			name: "no-address-no-place",
			policy: `{` + owners + `, "acls": [
				{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]},
				{"action": "accept", "src": ["*"], "dst": ["*:*"]},
				{"action": "accept", "src": ["alice@"], "dst": ["alice@:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{
				{SrcIPs: wildcard, DstPorts: []tailcfg.NetPortRange{anyPort("*")}},
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.1", 22)}},
			},
		},
		{
			// The internet through a via router only on an exit node: a
			// router of a public prefix gets the prefix, not the internet.
			name: "via-internet-exit-only",
			policy: `{` + owners + `, "grants": [
				{"src": ["alice@"], "dst": ["autogroup:internet", "8.8.8.0/24"], "ip": ["*"], "via": ["tag:b"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "tb", v4: "100.64.0.11", tags: []string{"tag:b"}, route: []string{"8.8.8.0/24"}},
			),
			receiver: "tb",
			want: []tailcfg.FilterRule{
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{anyPort("8.8.8.0/24")}},
			},
		},
		{
			// An exit router announcing IPv4 only keeps the IPv4 part of
			// the internet.
			name: "via-internet-reaches-announced-family",
			policy: `{` + owners + `, "grants": [
				{"src": ["alice@"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:b"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "tb", v4: "100.64.0.11", v6: "fd7a:115c:a1e0::b", tags: []string{"tag:b"}, route: []string{"0.0.0.0/0"}},
			),
			receiver: "tb",
			want:     []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.1"}, DstPorts: internetV4}},
		},
		{
			// Via matches announced and approved routes only: an
			// unannounced approval gives the router nothing.
			name: "via-ignores-unannounced-approval",
			policy: `{` + owners + `, "grants": [
				{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:b"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "tb", v4: "100.64.0.11", tags: []string{"tag:b"}, only: []string{"10.0.0.0/24"}},
			),
			receiver: "tb",
			want:     []tailcfg.FilterRule{},
		},
		{
			// Unannounced exit routes make no exit node: ex holds no owner's
			// self rule, which would otherwise place alice's rule ahead of *.
			name: "unannounced-exit-is-not-exit",
			policy: `{` + owners + `, "acls": [
				{"action": "accept", "src": ["alice@"], "dst": ["autogroup:self:22"]},
				{"action": "accept", "src": ["*"], "dst": ["*:*"]},
				{"action": "accept", "src": ["alice@"], "dst": ["tag:b:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ex", v4: "100.64.0.30", tags: []string{"tag:b"}, only: []string{"0.0.0.0/0", "::/0"}},
			),
			receiver: "ex",
			want: []tailcfg.FilterRule{
				everything,
				{SrcIPs: []string{"100.64.0.1"}, DstPorts: []tailcfg.NetPortRange{port("100.64.0.30", 22)}},
			},
		},
		{
			// * among identity sources adds the approved routes; the
			// identity's addresses stay strings of their own.
			name:   "wildcard-with-identity-adds-routes",
			policy: `{` + owners + `, "acls": [{"action": "accept", "src": ["*", "alice@"], "dst": ["tag:a:22"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
				quirkNode{name: "r", v4: "100.64.0.20", tags: []string{"tag:b"}, route: []string{"10.0.0.0/24"}},
			),
			receiver: "ta",
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"10.0.0.0/24", "100.115.94.0-100.127.255.255", "100.64.0.0-100.115.91.255", "100.64.0.1", "fd7a:115c:a1e0::/48"},
				DstPorts: []tailcfg.NetPortRange{port("100.64.0.10", 22)},
			}},
		},
		{
			// Self destinations nest by node, then port, then address; an
			// exit node shows all of them.
			name:   "self-destination-order",
			policy: `{` + owners + `, "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:22,80"]}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1", v6: "fd7a:115c:a1e0::1"},
				quirkNode{name: "a2", user: alice, v4: "100.64.0.2"},
				quirkNode{name: "ex", v4: "100.64.0.30", tags: []string{"tag:b"}, route: []string{"0.0.0.0/0", "::/0"}},
			),
			receiver: "ex",
			want: []tailcfg.FilterRule{{
				SrcIPs: []string{"100.64.0.1", "100.64.0.2", "fd7a:115c:a1e0::1"},
				DstPorts: []tailcfg.NetPortRange{
					port("100.64.0.1", 22), port("fd7a:115c:a1e0::1", 22), port("100.64.0.1", 80), port("fd7a:115c:a1e0::1", 80),
					port("100.64.0.2", 22), port("100.64.0.2", 80),
				},
			}},
		},
		{
			// The companion of * → tag:a has tag:a as sources, no routes: a
			// source of *, not a destination.
			name:   "companion-routes-only-from-wildcard-destination",
			policy: `{` + owners + `, "grants": [{"src": ["*"], "dst": ["tag:a"], "app": {"tailscale.com/cap/drive": [{}]}}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
				quirkNode{name: "r", v4: "100.64.0.20", tags: []string{"tag:b"}, route: []string{"10.0.0.0/24"}},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.10"},
				CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{host("100.64.0.1")}, CapMap: tailcfg.PeerCapMap{"tailscale.com/cap/drive-sharer": nil}}},
			}},
		},
		{
			// alice@ → *: the companion's sources are *'s ranges and the
			// approved routes, in that order, not sorted.
			name:   "companion-routes-from-wildcard-destination",
			policy: `{` + owners + `, "grants": [{"src": ["alice@"], "dst": ["*"], "app": {"tailscale.com/cap/relay": [{}]}}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "r", v4: "100.64.0.20", tags: []string{"tag:b"}, route: []string{"10.0.0.0/24"}},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{
				{
					SrcIPs:   []string{"100.64.0.1"},
					CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{host("100.64.0.1")}, CapMap: tailcfg.PeerCapMap{"tailscale.com/cap/relay": {"{}"}}}},
				},
				{
					SrcIPs:   []string{"100.64.0.0-100.115.91.255", "100.115.94.0-100.127.255.255", "fd7a:115c:a1e0::/48", "10.0.0.0/24"},
					CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{host("100.64.0.1")}, CapMap: tailcfg.PeerCapMap{"tailscale.com/cap/relay-target": nil}}},
				},
			},
		},
		{
			// A companion runs from the destinations to the sources.
			name:   "companion-reversed",
			policy: `{` + owners + `, "grants": [{"src": ["alice@"], "dst": ["tag:a"], "app": {"tailscale.com/cap/drive": [{}]}}]}`,
			nodes: quirkNodes(
				quirkNode{name: "a1", user: alice, v4: "100.64.0.1"},
				quirkNode{name: "ta", v4: "100.64.0.10", tags: []string{"tag:a"}},
			),
			receiver: "a1",
			want: []tailcfg.FilterRule{{
				SrcIPs:   []string{"100.64.0.10"},
				CapGrant: []tailcfg.CapGrant{{Dsts: []netip.Prefix{host("100.64.0.1")}, CapMap: tailcfg.PeerCapMap{"tailscale.com/cap/drive-sharer": nil}}},
			}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			requireSortedByID(t, tc.nodes)

			pm, err := NewPolicyManager([]byte(tc.policy), users, tc.nodes.ViewSlice())
			require.NoError(t, err)

			node := findNodeByGivenName(tc.nodes, tc.receiver)
			require.NotNil(t, node)

			compiled, err := pm.FilterForNode(node.View())
			require.NoError(t, err)

			if diff := cmp.Diff(tc.want, compiled, inOrderOpts...); diff != "" {
				t.Fatalf("the compile no longer does this (-want +compile):\n%s", diff)
			}

			x, _ := expansionOf(t, pm, users, nodeMapOf(tc.nodes))

			got := x.FilterForNode(node.View())
			if !reflect.DeepEqual(compiled, got) {
				t.Errorf("expanded differs from the compile (-compile +expanded):\n%s", cmp.Diff(compiled, got, inOrderOpts...))
			}

			requireExpandsLikeCompile(t, x, pm, tc.nodes)
		})
	}
}

// TestTemplatesKeptAcrossEdits checks what a document edit keeps: each
// grant it leaves alone, by identity, while the selector table stays; a
// host's prefix is not part of any grant's template; a new selector
// starts over.
func TestTemplatesKeptAcrossEdits(t *testing.T) {
	t.Parallel()

	const base = `{"hosts": {"lan": "10.0.0.0/24"}, "tagOwners": {"tag:a": ["alice@"]}, "acls": [
		{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]},
		{"action": "accept", "src": ["lan"], "dst": ["tag:a:80"]},
		{"action": "accept", "src": ["alice@"], "dst": ["tag:a:443"]}]}`

	selectors := func(prev *Selectors, src string) *Selectors {
		s, err := NewSelectors(prev, []byte(src))
		require.NoError(t, err)

		return s
	}

	s0 := selectors(nil, base)
	t0 := BuildTemplates(nil, s0)
	require.NoError(t, AuditTemplates(t0))
	assert.Same(t, t0, BuildTemplates(t0, s0), "the same selectors keep the templates")

	t.Run("port edit", func(t *testing.T) {
		t.Parallel()

		s1 := selectors(s0, replaceOnceString(base, "tag:a:443", "tag:a:8443"))
		require.Same(t, s0.Table(), s1.Table())

		t1 := BuildTemplates(t0, s1)
		require.NoError(t, AuditTemplates(t1))
		assert.Same(t, t0.grants[0], t1.grants[0])
		assert.Same(t, t0.grants[1], t1.grants[1])
		assert.NotSame(t, t0.grants[2], t1.grants[2])
	})

	t.Run("reorder", func(t *testing.T) {
		t.Parallel()

		s1 := selectors(s0, `{"hosts": {"lan": "10.0.0.0/24"}, "tagOwners": {"tag:a": ["alice@"]}, "acls": [
			{"action": "accept", "src": ["alice@"], "dst": ["tag:a:443"]},
			{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]},
			{"action": "accept", "src": ["lan"], "dst": ["tag:a:80"]}]}`)

		t1 := BuildTemplates(t0, s1)
		require.NoError(t, AuditTemplates(t1))
		assert.Same(t, t0.grants[2], t1.grants[0])
		assert.Same(t, t0.grants[0], t1.grants[1])
	})

	t.Run("host prefix", func(t *testing.T) {
		t.Parallel()

		s1 := selectors(s0, replaceOnceString(base, "10.0.0.0/24", "10.9.0.0/24"))
		require.Same(t, s0.Table(), s1.Table())

		t1 := BuildTemplates(t0, s1)
		require.NoError(t, AuditTemplates(t1))
		assert.Same(t, t0.grants[1], t1.grants[1], "the grant names the host, not its prefix")

		lan, _ := s1.Table().Lookup("lan")
		assert.Equal(t, []string{"10.9.0.0/24"}, t1.literals[lan.ID].res.Strings())
	})

	t.Run("new selector", func(t *testing.T) {
		t.Parallel()

		s1 := selectors(s0, replaceOnceString(base, `"src": ["lan"]`, `"src": ["lan", "bob@"]`))
		require.NotSame(t, s0.Table(), s1.Table())

		t1 := BuildTemplates(t0, s1)
		require.NoError(t, AuditTemplates(t1))
		assert.NotSame(t, t0.grants[0], t1.grants[0], "selector IDs of another table")
	})
}

// TestAuditTemplatesCatchesStaleReuse keeps a template across an edit that
// changed its grant, as a reuse rule looking at too little would, and
// requires the audit to see it.
func TestAuditTemplatesCatchesStaleReuse(t *testing.T) {
	t.Parallel()

	const base = `{"tagOwners": {"tag:a": ["alice@"]}, "acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]}]}`

	s0, err := NewSelectors(nil, []byte(base))
	require.NoError(t, err)

	s1, err := NewSelectors(s0, []byte(replaceOnceString(base, "tag:a:22", "tag:a:23")))
	require.NoError(t, err)

	stale := BuildTemplates(nil, s1)
	stale.grants[0] = BuildTemplates(nil, s0).grants[0]

	require.ErrorIs(t, AuditTemplates(stale), errTemplatesDiffer)
}

func replaceOnceString(s, old, replacement string) string {
	if strings.Count(s, old) != 1 {
		panic(old + " is not in the document once")
	}

	return strings.Replace(s, old, replacement, 1)
}
