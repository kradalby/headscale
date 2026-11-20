package v2

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// buildPeerMapPairScan is [PolicyManager.BuildPeerMap] as it was before the
// global-filter path stopped evaluating every matcher for every pair. It is
// kept as the reference the indexed build must reproduce exactly.
func buildPeerMapPairScan(pm *PolicyManager, nodes views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID {
	type nodeRoutes struct {
		subnet []netipx.IPRange
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{
			subnet: types.RouteRanges(n.SubnetRoutes()), isExit: n.IsExitNode(),
		}
	}

	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())

	if !pm.addresses().needsPerNodeFilter {
		for i := range nodes.Len() {
			for j := i + 1; j < nodes.Len(); j++ {
				if nodes.At(i).ID() == nodes.At(j).ID() {
					continue
				}

				ri, rj := routeInfo[nodes.At(i).ID()], routeInfo[nodes.At(j).ID()]

				linked := nodes.At(i).CanAccessWithRoutes(pm.addresses().matchers, nodes.At(j), ri.subnet, rj.subnet, rj.isExit) ||
					nodes.At(j).CanAccessWithRoutes(pm.addresses().matchers, nodes.At(i), rj.subnet, ri.subnet, ri.isExit)
				if linked || sameUser(nodes.At(i), nodes.At(j)) {
					ret[nodes.At(i).ID()] = append(ret[nodes.At(i).ID()], nodes.At(j).ID())
					ret[nodes.At(j).ID()] = append(ret[nodes.At(j).ID()], nodes.At(i).ID())
				}
			}
		}

		return ret
	}

	nodeMatchers := make(map[types.NodeID][]matcher.Match, nodes.Len())
	for _, node := range nodes.All() {
		nodeMatchers[node.ID()] = matcher.MatchesFromFilterRules(pm.peerRulesForNodeLocked(node))
	}

	for i := range nodes.Len() {
		nodeI := nodes.At(i)
		matchersI, hasFilterI := nodeMatchers[nodeI.ID()]
		riI := routeInfo[nodeI.ID()]

		for j := i + 1; j < nodes.Len(); j++ {
			nodeJ := nodes.At(j)
			matchersJ, hasFilterJ := nodeMatchers[nodeJ.ID()]
			riJ := routeInfo[nodeJ.ID()]

			canIAccessJ := hasFilterI && nodeI.CanAccessWithRoutes(matchersI, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)
			canJAccessI := hasFilterJ && nodeJ.CanAccessWithRoutes(matchersJ, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canJReachI := hasFilterI && nodeJ.CanAccessWithRoutes(matchersI, nodeI, riJ.subnet, riI.subnet, riI.isExit)
			canIReachJ := hasFilterJ && nodeI.CanAccessWithRoutes(matchersJ, nodeJ, riI.subnet, riJ.subnet, riJ.isExit)

			linked := canIAccessJ || canJAccessI || canJReachI || canIReachJ
			if linked || sameUser(nodeI, nodeJ) {
				ret[nodeI.ID()] = append(ret[nodeI.ID()], nodeJ.ID())
				ret[nodeJ.ID()] = append(ret[nodeJ.ID()], nodeI.ID())
			}
		}
	}

	return ret
}

var (
	scanUsers = []types.User{
		{ID: 1, Name: "u1"},
		{ID: 2, Name: "u2"},
		{ID: 3, Name: "u3"},
		{ID: 4, Name: "u4"},
	}
	scanTags   = []string{"tag:srv", "tag:db", "tag:router", "tag:exit"}
	scanRoutes = []string{"10.1.0.0/24", "10.1.1.0/24", "10.2.0.0/16", "192.168.5.0/24", "fd00:1::/64"}
	// Aliases usable on either side of a rule.
	scanAliases = []string{
		"*", "u1@", "u2@", "u3@", "u4@", "group:a", "group:b",
		"tag:srv", "tag:db", "tag:router", "tag:exit",
		"autogroup:member", "autogroup:tagged",
		"lan", "host1", "v6net",
		"10.1.0.0/24", "10.2.0.0/16", "192.168.5.0/24", "fd00:1::/64",
		"100.64.0.0/28", "100.64.0.3", "fd7a:115c:a1e0::/124", "fd7a:115c:a1e0::5",
	}
	// Destination-only extras: the internet, written both ways, and self.
	scanDstOnly = []string{"autogroup:internet", "autogroup:internet", "0.0.0.0/0", "::/0", "autogroup:self"}
)

// scanRandomNodes returns user-owned and tagged nodes on IPv4, IPv6 or both,
// some advertising subnet routes or exit routes that are approved only in
// part, so every identity [types.Node.CanAccess] looks at is present.
func scanRandomNodes(r *rand.Rand, n int) types.Nodes {
	nodes := make(types.Nodes, 0, n)

	for i := range n {
		nd := &types.Node{ID: types.NodeID(i + 1), Hostname: fmt.Sprintf("n%d", i+1)} //nolint:gosec

		v4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(i + 1)})                               //nolint:gosec
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 15: byte(i + 1)}) //nolint:gosec

		switch r.IntN(7) {
		case 0:
			nd.IPv4 = &v4
		case 1:
			nd.IPv6 = &v6
		default:
			nd.IPv4, nd.IPv6 = &v4, &v6
		}

		if r.IntN(10) < 6 {
			u := scanUsers[r.IntN(len(scanUsers))]
			nd.User, nd.UserID = &u, &u.ID
		} else {
			nd.Tags = []string{scanTags[r.IntN(len(scanTags))]}
			if r.IntN(3) == 0 {
				nd.Tags = append(nd.Tags, scanTags[r.IntN(len(scanTags))])
			}
		}

		var announced []netip.Prefix

		switch r.IntN(10) {
		case 0, 1, 2:
			for range 1 + r.IntN(2) {
				announced = append(announced, netip.MustParsePrefix(scanRoutes[r.IntN(len(scanRoutes))]))
			}
		case 3:
			announced = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
		case 4:
			announced = []netip.Prefix{
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
				netip.MustParsePrefix(scanRoutes[r.IntN(len(scanRoutes))]),
			}
		}

		if len(announced) > 0 {
			nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: announced}

			for _, p := range announced {
				if r.IntN(10) < 7 {
					nd.ApprovedRoutes = append(nd.ApprovedRoutes, p)
				}
			}
		}

		nodes = append(nodes, nd)
	}

	return nodes
}

// scanEmailUsers returns four users with e-mails on one of two domains, for
// SSH localpart users to match or not.
func scanEmailUsers(r *rand.Rand) []types.User {
	domains := []string{"example.com", "other.org"}
	users := make([]types.User, 4)

	for i := range users {
		users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i+1), Email: fmt.Sprintf("u%d@%s", i+1, domains[r.IntN(2)])} //nolint:gosec // bounded fixture
	}

	return users
}

// scanRandomSSHPolicy is [scanRandomPolicy] with SSH rules over every kind
// of source and destination SSH accepts, localpart users among them, and
// groups drawn anew, until the document parses.
func scanRandomSSHPolicy(r *rand.Rand) []byte {
	pick := func(pool ...string) string { return pool[r.IntN(len(pool))] }
	tagged := []string{"tag:srv", "tag:db", "tag:router", "autogroup:tagged"}

	for {
		var pol map[string]any
		if err := json.Unmarshal(scanRandomPolicy(r), &pol); err != nil { //nolint:noinlineerr
			panic(err)
		}

		pol["groups"] = map[string][]string{"group:a": {pick("u1@", "u2@", "u3@")}, "group:b": {pick("u3@", "u4@")}}

		n := 1 + r.IntN(4)
		rules := make([]any, 0, n)

		for range n {
			srcs := []string{pick("u1@", "u2@", "u3@", "group:a", "group:b", "autogroup:member", "tag:srv", "tag:db", "autogroup:tagged")}
			if r.IntN(3) == 0 {
				srcs = append(srcs, pick("u4@", "tag:router", "group:b"))
			}

			dsts := []string{pick("tag:srv", "tag:db", "autogroup:self", "u1@", "u2@", "autogroup:member", "autogroup:tagged")}
			if r.IntN(3) == 0 {
				dsts = append(dsts, pick("tag:exit", "autogroup:self", "u3@"))
			}

			users := []string{pick("root", "autogroup:nonroot", "ubuntu", "localpart:*@example.com", "localpart:*@other.org")}
			if r.IntN(3) == 0 {
				users = append(users, pick("root", "localpart:*@example.com"))
			}

			action := pick("accept", "check")
			// check refuses tagged sources.
			if slices.ContainsFunc(srcs, func(s string) bool { return slices.Contains(tagged, s) }) {
				action = "accept"
			}

			rule := map[string]any{"action": action, "src": srcs, "dst": dsts, "users": users}
			if r.IntN(3) == 0 {
				rule["acceptEnv"] = []string{"FOO_*"}
			}

			rules = append(rules, rule)
		}

		pol["ssh"] = rules

		b := must(json.Marshal(pol))
		if _, err := unmarshalPolicy(b); err == nil { //nolint:noinlineerr
			return b
		}
	}
}

// TestSSHCarryAndChangeSetMatchFresh holds the SSH half of the compile, the
// carried SSH policies and SSHChangedNodes, which carrying and waking both
// rest on, across random writes: SSH rules with localpart users, tag,
// autogroup:tagged, group, user and member sources, user, self, member and
// tagged destinations, check mode and acceptEnv; joins, leaves, retags,
// untags to a user, user reassignment, e-mail edits, address moves, route
// unapprovals and document changes. Every node's SSH policy, carried or
// prepared again, must equal a compile from scratch, and a node
// SSHChangedNodes leaves out against any of the last three compiles, as
// routing compares across coalesced commits, must keep its SSH policy.
func TestSSHCarryAndChangeSetMatchFresh(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 77)) //nolint:gosec // reproducible test input

	var checked, carried, history, unnamed, localpart, moved int

	for it := range 200 {
		users := scanEmailUsers(r)
		nodes := scanRandomNodes(r, 2+r.IntN(25))

		for _, n := range nodes {
			if n.User != nil {
				n.User = &users[n.User.ID-1]
			}
		}

		pol := scanRandomSSHPolicy(r)
		nextID, nextAddr := len(nodes)+1, 200

		var (
			chain      []*PolicyManager
			chainFresh []*PolicyManager
		)

		for step := range 10 {
			fresh, err := NewPolicyManager(pol, users, nodes.ViewSlice())
			require.NoError(t, err)

			var prev *PolicyManager
			if len(chain) > 0 {
				prev = chain[len(chain)-1]
			}

			inc, err := NewPolicyManagerFrom(prev, pol, users, nodes.ViewSlice())
			require.NoError(t, err)

			msg := fmt.Sprintf("iteration %d step %d, policy %s", it, step, pol)
			carried += inc.sshPolicyMap.Size()

			if bytes.Contains(pol, []byte("localpart:")) {
				localpart++
			}

			for _, n := range nodes {
				want, err := fresh.SSHPolicy(scanServerURL, n.View())
				require.NoError(t, err)

				got, err := inc.SSHPolicy(scanServerURL, n.View())
				require.NoError(t, err)
				require.Equal(t, want, got, "%s, node %d", msg, n.ID)

				checked++
			}

			for k, old := range chain {
				changed, all := inc.SSHChangedNodes(old)
				if all {
					continue
				}

				history++

				for _, n := range nodes {
					was, ok := old.nodesByID[n.ID]
					if !ok || slices.Contains(changed, n.ID) || was.HasPolicyChange(n.View()) {
						continue
					}

					a, err := chainFresh[k].SSHPolicy(scanServerURL, was)
					require.NoError(t, err)

					b, err := fresh.SSHPolicy(scanServerURL, n.View())
					require.NoError(t, err)
					require.Equal(t, a, b, "%s: node %d left out against compile %d back", msg, n.ID, len(chain)-k)

					unnamed++
				}
			}

			chain, chainFresh = append(chain, inc), append(chainFresh, fresh)
			if len(chain) > 3 {
				chain, chainFresh = chain[1:], chainFresh[1:]
			}

			switch r.IntN(9) {
			case 0:
				pol = scanRandomSSHPolicy(r)
			case 1:
				i := r.IntN(len(nodes))
				c := nodes[i].Clone()
				c.Tags = []string{scanTags[r.IntN(len(scanTags))]}
				c.User, c.UserID = nil, nil
				nodes[i] = c
			case 2:
				joined := scanRandomNodes(r, nextID)[nextID-1]
				if joined.User != nil {
					joined.User = &users[joined.User.ID-1]
				}

				nodes = append(slices.Clone(nodes), joined)
				nextID++
			case 3:
				if len(nodes) > 2 {
					i := r.IntN(len(nodes))
					nodes = slices.Delete(slices.Clone(nodes), i, i+1)
				}
			case 4:
				i := r.IntN(len(nodes))
				c := nodes[i].Clone()
				a := netip.AddrFrom4([4]byte{100, 64, 1, byte(nextAddr)}) //nolint:gosec // bounded fixture
				c.IPv4 = &a
				nodes[i] = c
				nextAddr++
				moved++
			case 5:
				// An untag to a user, or a node moved to another user.
				i := r.IntN(len(nodes))
				c := nodes[i].Clone()
				u := users[r.IntN(len(users))]
				c.Tags = nil
				c.User, c.UserID = &u, &u.ID
				nodes[i] = c
			case 6:
				users = slices.Clone(users)
				j := r.IntN(len(users))
				users[j].Email = fmt.Sprintf("u%d@%s", j+1, []string{"example.com", "other.org"}[r.IntN(2)])

				for k, n := range nodes {
					if n.User != nil && n.User.ID == users[j].ID {
						c := n.Clone()
						c.User = &users[j]
						nodes[k] = c
					}
				}
			case 7:
				i := r.IntN(len(nodes))
				c := nodes[i].Clone()
				c.ApprovedRoutes = nil
				nodes[i] = c
			default:
				i := r.IntN(len(nodes))
				if nodes[i].IsTagged() {
					c := nodes[i].Clone()
					c.Tags = slices.Compact(slices.Sorted(slices.Values(append(slices.Clone(c.Tags), scanTags[r.IntN(len(scanTags))]))))
					nodes[i] = c
				}
			}
		}
	}

	t.Logf("checked %d, carried %d, change sets %d, nodes left out %d, localpart compiles %d, address moves %d",
		checked, carried, history, unnamed, localpart, moved)
	require.Greater(t, carried, 1000, "SSH policies carried")
	require.Greater(t, unnamed, 1000, "nodes left out of a change set")
	require.Greater(t, localpart, 100, "compiles with localpart users")
	require.Greater(t, moved, 50, "address moves")
}

// scanRandomServedPolicy is [scanRandomPolicy] with what the compile still
// serves: SSH rules, node attributes and auto-approvers.
func scanRandomServedPolicy(r *rand.Rand) []byte {
	var pol map[string]any
	if err := json.Unmarshal(scanRandomPolicy(r), &pol); err != nil { //nolint:noinlineerr
		panic(err)
	}

	pick := func(pool ...string) string { return pool[r.IntN(len(pool))] }

	n := r.IntN(3)
	ssh := make([]any, 0, n)

	for range n {
		ssh = append(ssh, map[string]any{
			"action": pick("accept", "check"),
			"src":    []string{pick("u1@", "u2@", "group:a", "group:b", "autogroup:member")},
			"dst":    []string{pick("tag:srv", "tag:db", "autogroup:self")},
			"users":  []string{pick("root", "autogroup:nonroot", "ubuntu")},
		})
	}

	if n > 0 {
		pol["ssh"] = ssh
	}

	if r.IntN(2) == 0 {
		pol["nodeAttrs"] = []any{map[string]any{"target": []string{scanAliases[r.IntN(len(scanAliases))]}, "attr": []string{"custom:x"}}}
	}

	if r.IntN(2) == 0 {
		pol["autoApprovers"] = map[string]any{
			"routes":   map[string][]string{"10.1.0.0/16": {pick("u1@", "group:a", "tag:router")}},
			"exitNode": []string{pick("u2@", "tag:exit")},
		}
	}

	return must(json.Marshal(pol))
}

// scanRandomPolicy returns a policy of ACLs and grants over [scanAliases].
// Some of them the policy manager rejects; the caller skips those.
func scanRandomPolicy(r *rand.Rand) []byte {
	pick := func(pool []string, n int) []string {
		out := make([]string, 0, n)
		for range n {
			out = append(out, pool[r.IntN(len(pool))])
		}

		return out
	}

	pol := map[string]any{
		"groups":    map[string][]string{"group:a": {"u1@", "u2@"}, "group:b": {"u3@"}},
		"tagOwners": map[string][]string{"tag:srv": {"u1@"}, "tag:db": {"u1@"}, "tag:router": {"u1@"}, "tag:exit": {"u1@"}},
		"hosts":     map[string]string{"lan": "10.1.0.0/16", "host1": "100.64.0.5/32", "v6net": "fd7a:115c:a1e0::/122"},
	}

	// Neither section: allow-all. Empty grants: deny-all. Otherwise rules.
	switch r.IntN(20) {
	case 0:
		return must(json.Marshal(pol))
	case 1:
		pol["grants"] = []any{}

		return must(json.Marshal(pol))
	}

	var acls, grants []any

	for range 1 + r.IntN(8) {
		src := pick(scanAliases, 1+r.IntN(3))
		dst := pick(scanAliases, 1+r.IntN(3))

		if r.IntN(4) == 0 {
			dst = append(dst, scanDstOnly[r.IntN(len(scanDstOnly))])
		}

		if r.IntN(3) == 0 {
			// ACL destinations are "alias:ports"; bare IPv6 does not fit that form.
			var aclDst []string

			for _, d := range dst {
				if netip.MustParsePrefix("::/0").Contains(parseAddrOrZero(d)) {
					continue
				}

				aclDst = append(aclDst, d+":"+[]string{"*", "22", "80,443"}[r.IntN(3)])
			}

			if len(aclDst) > 0 {
				acls = append(acls, map[string]any{"action": "accept", "src": src, "dst": aclDst})
			}

			continue
		}

		g := map[string]any{"src": src, "dst": dst, "ip": [][]string{{"*"}, {"tcp:443"}, {"icmp:*"}, {"udp:53", "tcp:22"}}[r.IntN(4)]}
		if r.IntN(8) == 0 {
			g["via"] = []string{[]string{"tag:router", "tag:exit"}[r.IntN(2)]}

			// Capability only: via changes nothing, unlike a via grant with ports.
			if r.IntN(2) == 0 {
				delete(g, "ip")
				g["app"] = map[string]any{"example.com/cap/test": []map[string]any{{}}}
			}
		}

		grants = append(grants, g)
	}

	if acls != nil {
		pol["acls"] = acls
	}

	if grants != nil {
		pol["grants"] = grants
	}

	return must(json.Marshal(pol))
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}

	return v
}

// parseAddrOrZero returns the address of an IP or CIDR alias, or the IPv4
// zero address for anything else.
func parseAddrOrZero(alias string) netip.Addr {
	p, err := netip.ParsePrefix(alias)
	if err == nil {
		return p.Addr()
	}

	a, err := netip.ParseAddr(alias)
	if err == nil {
		return a
	}

	return netip.IPv4Unspecified()
}

// TestBuildPeerMapMatchesPairScan checks that the indexed peer-map build
// returns exactly what the pair scan it replaced returns, peer order
// included, over random tailnets and policies.
func TestBuildPeerMapMatchesPairScan(t *testing.T) {
	const iterations = 3000

	r := rand.New(rand.NewPCG(1, 2)) //nolint:gosec // reproducible test input

	var global, perNode, partial, full, empty, routeSrc, routeDst, exitDst, rejected int

	for it := range iterations {
		nodes := scanRandomNodes(r, 2+r.IntN(40))
		polB := scanRandomPolicy(r)

		pm, err := NewPolicyManager(polB, scanUsers, nodes.ViewSlice())
		if err != nil {
			rejected++
			continue
		}

		// The build takes any slice, not only the manager's own: also feed
		// it a shuffled subset, as a NodeStore snapshot would.
		subset := append(types.Nodes(nil), nodes...)
		r.Shuffle(len(subset), func(a, b int) { subset[a], subset[b] = subset[b], subset[a] })
		subset = subset[:1+r.IntN(len(subset))]

		for _, in := range []views.Slice[types.NodeView]{nodes.ViewSlice(), subset.ViewSlice()} {
			want := buildPeerMapPairScan(pm, in)
			got := pm.BuildPeerMap(in)
			require.Equalf(t, want, got, "iteration %d, policy %s", it, polB)
			require.Equalf(t, want, buildPeerMapSortedSlice(pm, in),
				"sorted slice: iteration %d, policy %s", it, polB)
			require.Equalf(t, want, buildPeerMapSliceMap(pm, in),
				"slice + map: iteration %d, policy %s", it, polB)
		}

		if pm.addresses().needsPerNodeFilter {
			perNode++
			continue
		}

		global++

		want := buildPeerMapPairScan(pm, nodes.ViewSlice())

		pairs := 0
		for _, peers := range want {
			pairs += len(peers)
		}

		switch pairs {
		case 0:
			empty++
		case len(nodes) * (len(nodes) - 1):
			full++
		default:
			partial++
		}

		// Count the inputs that reach the branches beyond plain node IPs.
		for _, n := range nodes {
			for i := range pm.addresses().matchers {
				m := &pm.addresses().matchers[i]
				if sr := n.SubnetRoutes(); len(sr) > 0 {
					if !m.SrcsContainsIPs(n.IPs()...) && m.SrcsOverlapsPrefixes(sr...) {
						routeSrc++
					}

					if !m.DestsContainsIP(n.IPs()...) && m.DestsOverlapsPrefixes(sr...) {
						routeDst++
					}
				}

				if n.IsExitNode() && !m.DestsContainsIP(n.IPs()...) && m.DestsIsTheInternet() {
					exitDst++
				}
			}
		}
	}

	t.Logf("%d policies: %d global (%d partial, %d full, %d empty peer maps), %d per-node, %d rejected; "+
		"matcher/node hits by subnet route as source %d, as destination %d, by exit node %d",
		iterations, global, partial, full, empty, perNode, rejected, routeSrc, routeDst, exitDst)

	// The comparison is only worth something if the inputs reached every branch.
	require.Greater(t, partial, iterations/10, "partial peer maps")
	require.Positive(t, full)
	require.Positive(t, empty)
	require.Positive(t, perNode)
	require.Positive(t, routeSrc)
	require.Positive(t, routeDst)
	require.Positive(t, exitDst)
}

// TestBuildPeerMapIdentities pins the pairs that only exist because of an
// identity other than the nodes' own IPs, so the indexed build cannot drop
// one of them without a named failure.
func TestBuildPeerMapIdentities(t *testing.T) {
	route := func(nd *types.Node, approved bool, prefixes ...string) *types.Node {
		ps := make([]netip.Prefix, 0, len(prefixes))
		for _, p := range prefixes {
			ps = append(ps, netip.MustParsePrefix(p))
		}

		nd.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: ps}
		if approved {
			nd.ApprovedRoutes = ps
		}

		return nd
	}
	tagged := func(id types.NodeID, v4, v6 string, tags ...string) *types.Node {
		nd := &types.Node{ID: id, Hostname: fmt.Sprintf("n%d", id), Tags: tags}
		if v4 != "" {
			nd.IPv4 = ap(v4)
		}

		if v6 != "" {
			nd.IPv6 = ap(v6)
		}

		return nd
	}

	const owners = `"tagOwners": {"tag:a": [], "tag:b": [], "tag:c": []},`

	tests := []struct {
		name   string
		policy string
		nodes  types.Nodes
		want   map[types.NodeID][]types.NodeID
	}{
		{
			name:   "subnet route as source and as destination",
			policy: `{` + owners + `"grants": [{"src": ["10.1.0.0/24"], "dst": ["10.2.0.0/16"], "ip": ["*"]}]}`,
			nodes: types.Nodes{
				route(tagged(1, "100.64.0.1", "", "tag:a"), true, "10.1.0.0/24"),
				route(tagged(2, "100.64.0.2", "", "tag:b"), true, "10.2.0.0/16"),
				route(tagged(3, "100.64.0.3", "", "tag:c"), false, "10.2.0.0/16"), // not approved
				tagged(4, "100.64.0.4", "", "tag:c"),
			},
			want: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
		},
		{
			name:   "exit node is the internet",
			policy: `{` + owners + `"grants": [{"src": ["tag:a"], "dst": ["autogroup:internet"], "ip": ["*"]}]}`,
			nodes: types.Nodes{
				tagged(1, "100.64.0.1", "fd7a:115c:a1e0::1", "tag:a"),
				route(tagged(2, "100.64.0.2", "fd7a:115c:a1e0::2", "tag:b"), true, "0.0.0.0/0", "::/0"),
				route(tagged(3, "100.64.0.3", "fd7a:115c:a1e0::3", "tag:b"), false, "0.0.0.0/0", "::/0"),
				tagged(4, "100.64.0.4", "fd7a:115c:a1e0::4", "tag:c"),
			},
			want: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
		},
		{
			name:   "ipv6-only and ipv4-only ends",
			policy: `{` + owners + `"grants": [{"src": ["tag:a"], "dst": ["tag:b"], "ip": ["tcp:443"]}]}`,
			nodes: types.Nodes{
				tagged(1, "", "fd7a:115c:a1e0::1", "tag:a"),
				tagged(2, "100.64.0.2", "", "tag:b"),
				tagged(3, "", "fd7a:115c:a1e0::3", "tag:c"),
			},
			want: map[types.NodeID][]types.NodeID{1: {2}, 2: {1}},
		},
		{
			name:   "one-way rule past the first 64 matchers",
			policy: scanManyRulesPolicy(100, 70),
			nodes:  scanManyRulesNodes(100),
			want:   nil, // compared against the pair scan only
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.policy), nil, tt.nodes.ViewSlice())
			require.NoError(t, err)
			require.False(t, pm.addresses().needsPerNodeFilter)

			got := pm.BuildPeerMap(tt.nodes.ViewSlice())
			require.Equal(t, buildPeerMapPairScan(pm, tt.nodes.ViewSlice()), got)
			require.Equal(t, got, buildPeerMapSortedSlice(pm, tt.nodes.ViewSlice()))
			require.Equal(t, got, buildPeerMapSliceMap(pm, tt.nodes.ViewSlice()))

			if tt.want != nil {
				require.Equal(t, tt.want, got)
			} else {
				require.Greater(t, len(pm.addresses().matchers), 64)
				require.NotEmpty(t, got)
			}
		})
	}
}

// scanManyRulesNodes and scanManyRulesPolicy describe a tailnet where every
// node has a tag of its own and access is granted pair by pair: n/20
// operators, one monitor, the rest units, and per lease one operator->unit
// grant plus an ICMP grant from each end to the monitor. The filter grows
// with the number of leases while each node appears in only a few rules.
func scanManyRulesNodes(n int) types.Nodes {
	nodes := make(types.Nodes, 0, n)

	for i := range n {
		v4 := netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)})                                      //nolint:gosec
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: byte(i >> 8), 15: byte(i)}) //nolint:gosec
		nodes = append(nodes, &types.Node{
			ID:       types.NodeID(i + 1), //nolint:gosec
			Hostname: fmt.Sprintf("n%d", i),
			IPv4:     &v4,
			IPv6:     &v6,
			Tags:     []string{fmt.Sprintf("tag:n%d", i)},
		})
	}

	return nodes
}

func scanManyRulesPolicy(n, leases int) string {
	ops := max(n/20, 1)
	owners := make(map[string][]string, n)

	for i := range n {
		owners[fmt.Sprintf("tag:n%d", i)] = []string{}
	}

	monitor := fmt.Sprintf("tag:n%d", n-1)
	grants := make([]map[string][]string, 0, leases*3)

	for l := range leases {
		op, unit := fmt.Sprintf("tag:n%d", l%ops), fmt.Sprintf("tag:n%d", ops+l)
		grants = append(grants,
			map[string][]string{"src": {op}, "dst": {unit}, "ip": {"tcp:445", "tcp:14000-16000", "udp:14000-16000", "icmp:*"}},
			map[string][]string{"src": {op}, "dst": {monitor}, "ip": {"icmp:*"}},
			map[string][]string{"src": {unit}, "dst": {monitor}, "ip": {"icmp:*"}},
		)
	}

	return string(must(json.Marshal(map[string]any{"tagOwners": owners, "grants": grants})))
}

// buildPeerMapSortedSlice benchmarks the global-filter path with sorted
// matcher IDs. Appending in matcher order keeps both indexes sorted.
func buildPeerMapSortedSlice(
	pm *PolicyManager,
	nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	if pm.addresses().needsPerNodeFilter {
		return pm.BuildPeerMap(nodes)
	}

	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())
	ids := make([]types.NodeID, nodes.Len())
	srcOf := make([][]int, nodes.Len())
	dstOf := make([][]int, nodes.Len())

	for i, n := range nodes.All() {
		ids[i] = n.ID()
		if !n.Valid() {
			continue
		}

		ips, ri := n.IPs(), routeInfo[n.ID()]
		routed := len(ri.subnet) > 0

		for k := range pm.addresses().matchers {
			m := &pm.addresses().matchers[k]

			if m.SrcsContainsIPs(ips...) ||
				(routed && m.SrcsOverlapsPrefixes(ri.subnet...)) {
				srcOf[i] = append(srcOf[i], k)
			}

			if m.DestsContainsIP(ips...) ||
				(routed && m.DestsOverlapsPrefixes(ri.subnet...)) ||
				(ri.isExit && m.DestsIsTheInternet()) {
				dstOf[i] = append(dstOf[i], k)
			}
		}
	}

	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] == ids[j] {
				continue
			}

			linked := sortedMatcherSetsIntersect(srcOf[i], dstOf[j]) || sortedMatcherSetsIntersect(srcOf[j], dstOf[i])
			if linked || sameUser(nodes.At(i), nodes.At(j)) {
				ret[ids[i]] = append(ret[ids[i]], ids[j])
				ret[ids[j]] = append(ret[ids[j]], ids[i])
			}
		}
	}

	return ret
}

func sortedMatcherSetsIntersect(src, dst []int) bool {
	i, j := 0, 0
	for i < len(src) && j < len(dst) {
		switch {
		case src[i] == dst[j]:
			return true
		case src[i] < dst[j]:
			i++
		default:
			j++
		}
	}

	return false
}

// buildPeerMapSliceMap benchmarks the global-filter path with source matcher
// IDs in slices and destination matcher IDs in maps.
func buildPeerMapSliceMap(
	pm *PolicyManager,
	nodes views.Slice[types.NodeView],
) map[types.NodeID][]types.NodeID {
	if pm == nil {
		return nil
	}

	if pm.addresses().needsPerNodeFilter {
		return pm.BuildPeerMap(nodes)
	}

	type nodeRoutes struct {
		subnet []netip.Prefix
		isExit bool
	}

	routeInfo := make(map[types.NodeID]nodeRoutes, nodes.Len())
	for _, n := range nodes.All() {
		routeInfo[n.ID()] = nodeRoutes{subnet: n.SubnetRoutes(), isExit: n.IsExitNode()}
	}

	ret := make(map[types.NodeID][]types.NodeID, nodes.Len())
	ids := make([]types.NodeID, nodes.Len())
	srcOf := make([][]int, nodes.Len())
	dstOf := make([]map[int]struct{}, nodes.Len())

	for i, n := range nodes.All() {
		ids[i] = n.ID()
		if !n.Valid() {
			continue
		}

		ips, ri := n.IPs(), routeInfo[n.ID()]
		routed := len(ri.subnet) > 0

		for k := range pm.addresses().matchers {
			m := &pm.addresses().matchers[k]

			if m.SrcsContainsIPs(ips...) ||
				(routed && m.SrcsOverlapsPrefixes(ri.subnet...)) {
				srcOf[i] = append(srcOf[i], k)
			}

			if m.DestsContainsIP(ips...) ||
				(routed && m.DestsOverlapsPrefixes(ri.subnet...)) ||
				(ri.isExit && m.DestsIsTheInternet()) {
				if dstOf[i] == nil {
					dstOf[i] = make(map[int]struct{})
				}

				dstOf[i][k] = struct{}{}
			}
		}
	}

	for i := range ids {
		for j := i + 1; j < len(ids); j++ {
			if ids[i] == ids[j] {
				continue
			}

			linked := sliceMapMatcherSetsIntersect(srcOf[i], dstOf[j]) || sliceMapMatcherSetsIntersect(srcOf[j], dstOf[i])
			if linked || sameUser(nodes.At(i), nodes.At(j)) {
				ret[ids[i]] = append(ret[ids[i]], ids[j])
				ret[ids[j]] = append(ret[ids[j]], ids[i])
			}
		}
	}

	return ret
}

func sliceMapMatcherSetsIntersect(src []int, dst map[int]struct{}) bool {
	if len(dst) == 0 {
		return false
	}

	for _, matcherID := range src {
		if _, ok := dst[matcherID]; ok {
			return true
		}
	}

	return false
}

// scanDenseRulesPolicy makes every node match many source and destination
// rules, with either immediate, last-rule-only, or no intersection. Unique
// off-tailnet source IPs prevent the compiler from merging the dense rules.
func scanDenseRulesPolicy(matchers int, shape string) string {
	const subnet = "100.64.0.0/10"

	grants := make([]map[string][]string, 0, matchers)
	for k := range matchers {
		marker := fmt.Sprintf("10.255.%d.%d", k/256, k%256)
		src, dst := []string{marker}, []string{subnet}

		if shape == "early-overlap" || (shape == "late-overlap" && k == matchers-1) {
			src = append(src, subnet)
		} else if k%2 == 0 {
			src = append(src, subnet)
			dst = []string{marker}
		}

		grants = append(grants, map[string][]string{
			"src": src, "dst": dst, "ip": {"*"},
		})
	}

	return string(must(json.Marshal(map[string]any{"grants": grants})))
}

// TestBuildPeerMapDenseRules pins the compiled rule count and memberships so
// policy compilation cannot silently turn a dense benchmark into a sparse one.
func TestBuildPeerMapDenseRules(t *testing.T) {
	nodes := scanManyRulesNodes(8)

	for _, tt := range []struct {
		shape                     string
		sources, destinations     int
		firstShared, peersPerNode int
	}{
		{"early-overlap", 70, 70, 0, 7},
		{"late-overlap", 36, 35, 69, 7},
		{"disjoint", 35, 35, -1, 0},
	} {
		t.Run(tt.shape, func(t *testing.T) {
			pm, err := NewPolicyManager(
				[]byte(scanDenseRulesPolicy(70, tt.shape)), nil, nodes.ViewSlice(),
			)
			require.NoError(t, err)
			require.False(t, pm.addresses().needsPerNodeFilter)
			require.Len(t, pm.addresses().matchers, 70)

			want := buildPeerMapPairScan(pm, nodes.ViewSlice())
			require.Equal(t, want, pm.BuildPeerMap(nodes.ViewSlice()))
			require.Equal(t, want, buildPeerMapSortedSlice(pm, nodes.ViewSlice()))
			require.Equal(t, want, buildPeerMapSliceMap(pm, nodes.ViewSlice()))

			for _, node := range nodes {
				sources, destinations, firstShared := 0, 0, -1

				for k, m := range pm.addresses().matchers {
					src := m.SrcsContainsIPs(node.IPs()...)
					dst := m.DestsContainsIP(node.IPs()...)

					if src {
						sources++
					}

					if dst {
						destinations++
					}

					if src && dst && firstShared == -1 {
						firstShared = k
					}
				}

				require.Equal(t, tt.sources, sources)
				require.Equal(t, tt.destinations, destinations)
				require.Equal(t, tt.firstShared, firstShared)
				require.Len(t, want[node.ID], tt.peersPerNode)
			}
		})
	}
}

// BenchmarkBuildPeerMapManyRules measures [PolicyManager.BuildPeerMap] on the
// many-rules shape, next to the pair scan it replaced.
// Each indexed variant includes index construction and peer-map allocation.
func BenchmarkBuildPeerMapManyRules(b *testing.B) {
	for _, c := range []struct{ nodes, leases int }{{200, 30}, {1000, 30}, {1000, 100}, {2000, 100}} {
		nodes := scanManyRulesNodes(c.nodes)

		pm, err := NewPolicyManager(
			[]byte(scanManyRulesPolicy(c.nodes, c.leases)),
			nil,
			nodes.ViewSlice(),
		)
		require.NoError(b, err)
		require.False(b, pm.addresses().needsPerNodeFilter)

		name := fmt.Sprintf(
			"n=%d/leases=%d/matchers=%d",
			c.nodes,
			c.leases,
			len(pm.addresses().matchers),
		)

		b.Run(name, func(b *testing.B) {
			benchmarkPeerMapBuilders(b, pm, nodes)
		})
	}
}

func BenchmarkBuildPeerMapDenseRules(b *testing.B) {
	for _, c := range []struct{ nodes, matchers int }{{200, 256}, {1000, 512}} {
		nodes := scanManyRulesNodes(c.nodes)

		for _, shape := range []string{"early-overlap", "late-overlap", "disjoint"} {
			pm, err := NewPolicyManager(
				[]byte(scanDenseRulesPolicy(c.matchers, shape)), nil, nodes.ViewSlice(),
			)
			require.NoError(b, err)
			require.False(b, pm.addresses().needsPerNodeFilter)
			require.Len(b, pm.addresses().matchers, c.matchers)

			name := fmt.Sprintf("%s/n=%d/matchers=%d", shape, c.nodes, c.matchers)
			b.Run(name, func(b *testing.B) {
				benchmarkPeerMapBuilders(b, pm, nodes)
			})
		}
	}
}

func benchmarkPeerMapBuilders(b *testing.B, pm *PolicyManager, nodes types.Nodes) {
	b.Helper()

	for _, builder := range []struct {
		name  string
		build func(*PolicyManager, views.Slice[types.NodeView]) map[types.NodeID][]types.NodeID
	}{
		{"bitset", (*PolicyManager).BuildPeerMap},
		{"sorted-slice", buildPeerMapSortedSlice},
		{"slice-map", buildPeerMapSliceMap},
		{"pairscan", buildPeerMapPairScan},
	} {
		b.Run(builder.name, func(b *testing.B) {
			if builder.name == "pairscan" && testing.Short() {
				b.Skip("the pair scan takes seconds per iteration")
			}

			b.ReportAllocs()

			for b.Loop() {
				builder.build(pm, nodes.ViewSlice())
			}
		})
	}
}

// peerRulesForNode returns the rules that decide a node's peers: its
// unreduced filter rules, with [viaPeerRule] in place of each via rule.
func peerRulesForNode(
	grants []compiledGrant,
	node types.NodeView,
	userIdx userNodeIndex,
) []tailcfg.FilterRule {
	return rulesForNode(grants, node, userIdx, ownSelfRules, viaPeerRule)
}

// peerRulesForNodeLocked returns the rules that decide a node's peers, see
// [peerRulesForNode].
func (pm *PolicyManager) peerRulesForNodeLocked(
	node types.NodeView,
) []tailcfg.FilterRule {
	return peerRulesForNode(pm.addresses().compiledGrants, node, pm.userNodeIdx)
}

func nilIfEmpty[T any](s []T) []T {
	if len(s) == 0 {
		return nil
	}

	return s
}

func diversePeerPolicy(n int, shape string) (types.Nodes, []types.User, []byte) {
	nodes := scanManyRulesNodes(n)

	var (
		users  []types.User
		grants []string
		owners []string
	)

	switch shape {
	case "pairs", "tag-pairs", "app-pairs", "overlapping-pairs", "cliques", "dense":
		for i := 0; i < n; i += 2 {
			src, dst := nodes[i].IPv4.String(), nodes[i+1].IPv4.String()
			if shape == "tag-pairs" {
				src, dst = nodes[i].Tags[0], nodes[i+1].Tags[0]
				owners = append(owners, fmt.Sprintf(`%q:[],%q:[]`, src, dst))
			}

			if shape == "dense" {
				dst = "*"
			}

			if shape == "cliques" {
				src = netip.PrefixFrom(*nodes[i].IPv4, 31).String()
				dst = src
			}

			access := `"ip":["*"]`
			if shape == "app-pairs" {
				access = `"app":{"example.com/cap/read":[{}]}`
			}

			grants = append(grants, fmt.Sprintf(`{"src":[%q],"dst":[%q],%s}`, src, dst, access))
			if shape == "overlapping-pairs" {
				grants = append(grants, fmt.Sprintf(`{"src":[%q],"dst":[%q],%s}`, nodes[i].IPv6.String(), nodes[i+1].IPv6.String(), access))
			}
		}
	case "self":
		users = make([]types.User, n/2)
		for i := range users {
			users[i] = types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i)} //nolint:gosec // bounded fixture
		}

		for i, node := range nodes {
			node.Tags = nil
			node.User = &users[i/2]
			node.UserID = &users[i/2].ID
		}

		grants = append(grants, `{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["*"]}`)
	case "allow-all":
		return nodes, nil, nil
	}

	return nodes, users, []byte(`{"tagOwners":{` + strings.Join(owners, ",") + `},"grants":[` + strings.Join(grants, ",") + `]}`)
}

// TestNewPolicyManagerFromMatchesFresh holds what the compile serves, compiled
// incrementally across random node and document changes, to a compile from
// scratch: tag owners, auto-approvers, node attributes and every node's SSH
// policy, carried or prepared again.
func TestNewPolicyManagerFromMatchesFresh(t *testing.T) {
	r := rand.New(rand.NewPCG(9, 10)) //nolint:gosec // reproducible test input

	reused, narrowed, narrowedDoc := 0, 0, 0

	for it := range 300 {
		nodes := scanRandomNodes(r, 2+r.IntN(30))
		polB := scanRandomServedPolicy(r)
		nextID := len(nodes) + 1

		var prev *PolicyManager

		for step := range 8 {
			fresh, err := NewPolicyManager(polB, scanUsers, nodes.ViewSlice())
			if err != nil {
				break
			}

			inc, err := NewPolicyManagerFrom(prev, polB, scanUsers, nodes.ViewSlice())
			require.NoError(t, err)

			msg := fmt.Sprintf("iteration %d step %d, policy %s", it, step, polB)
			require.Equal(t, fresh.tagOwnerMap, inc.tagOwnerMap, msg)
			require.Equal(t, fresh.autoApproveMap, inc.autoApproveMap, msg)
			require.Equal(t, fresh.exitSet, inc.exitSet, msg)
			require.Equal(t, fresh.nodeAttrsMap, inc.nodeAttrsMap, msg)

			for _, n := range nodes {
				wantSSH, err := fresh.SSHPolicy(scanServerURL, n.View())
				require.NoError(t, err)

				gotSSH, err := inc.SSHPolicy(scanServerURL, n.View())
				require.NoError(t, err)
				require.Equal(t, wantSSH, gotSSH, "%s, node %d SSH", msg, n.ID)
			}

			// Outside SSHChangedNodes, a node that did not change keeps
			// its SSH policy.
			if changed, all := inc.SSHChangedNodes(prev); prev != nil && !all && inc.HasSSH() {
				narrowed++

				if !bytes.Equal(prev.src, inc.src) {
					narrowedDoc++
				}

				for _, n := range nodes {
					old, ok := prev.nodesByID[n.ID]
					if !ok || old != n.View() || slices.Contains(changed, n.ID) {
						continue
					}

					wasSSH, err := prev.SSHPolicy(scanServerURL, old)
					require.NoError(t, err)

					isSSH, err := inc.SSHPolicy(scanServerURL, n.View())
					require.NoError(t, err)
					require.Equal(t, wasSSH, isSSH, "%s, unchanged node %d SSH", msg, n.ID)
				}
			}

			if prev != nil {
				for k, r := range inc.aliases {
					if was, ok := prev.aliases[k]; ok && reflect.DeepEqual(was, r) {
						reused++
					}
				}
			}

			prev = inc

			// Now and then the document changes instead of a node.
			if r.IntN(5) == 0 {
				polB = scanRandomServedPolicy(r)

				continue
			}

			switch r.IntN(4) {
			case 0:
				i := r.IntN(len(nodes))
				c := nodes[i].Clone()
				c.Tags = []string{scanTags[r.IntN(len(scanTags))]}
				c.User, c.UserID = nil, nil
				nodes[i] = c
			case 1:
				extra := scanRandomNodes(r, nextID)
				nodes = append(slices.Clone(nodes), extra[nextID-1])
				nextID++
			case 2:
				if len(nodes) > 2 {
					i := r.IntN(len(nodes))
					nodes = slices.Delete(slices.Clone(nodes), i, i+1)
				}
			default:
				i := r.IntN(len(nodes))
				c := nodes[i].Clone()
				c.ApprovedRoutes = nil
				nodes[i] = c
			}
		}
	}

	// The comparison is only worth something if resolutions were carried
	// and SSH recompiles narrowed.
	t.Logf("aliases reused %d, SSH narrowed %d (document changes %d)", reused, narrowed, narrowedDoc)
	require.Greater(t, reused, 100, "aliases reused")
	require.Greater(t, narrowed, 100, "SSH recompiles narrowed")
	require.Greater(t, narrowedDoc, 20, "document changes narrowed")
}

// TestInheritSSHNodeIdentity: a recompile carries a node's SSH policies
// over, for every server URL, while neither the node nor its rules moved;
// carried policies are the old ones, which stay as they were.
func TestInheritSSHNodeIdentity(t *testing.T) {
	pol := []byte(`{"tagOwners":{"tag:srv":["u1@"]},"acls":[{"action":"accept","src":["u2@"],"dst":["tag:srv:443"]}],
		"ssh":[{"action":"check","src":["u2@"],"dst":["tag:srv"],"users":["root"]}]}`)

	for _, change := range []string{"identical", "equal clone", "changed rules"} {
		t.Run(change, func(t *testing.T) {
			nodes := types.Nodes{ownRulesNode(1, nil, []string{"tag:srv"}), ownRulesNode(2, &scanUsers[1], nil), ownRulesNode(3, &scanUsers[2], nil)}
			prev, err := NewPolicyManager(pol, scanUsers, nodes.ViewSlice())
			require.NoError(t, err)

			urls := []string{scanServerURL, "https://other.example.com"}

			oldSSH := make([]*tailcfg.SSHPolicy, len(urls))
			for i, url := range urls {
				var err error

				oldSSH[i], err = prev.SSHPolicy(url, nodes[0].View())
				require.NoError(t, err)
				require.NotEmpty(t, oldSSH[i].Rules)
			}

			frozenSSH, err := json.Marshal(oldSSH)
			require.NoError(t, err)

			after, source := slices.Clone(nodes), pol

			switch change {
			case "equal clone":
				after[0] = nodes[0].Clone()
			case "changed rules":
				source = bytes.ReplaceAll(pol, []byte("u2@"), []byte("u3@"))
			}

			next, err := NewPolicyManagerFrom(prev, source, scanUsers, after.ViewSlice())
			require.NoError(t, err)

			for i, url := range urls {
				ssh, ok := next.sshPolicyMap.Load(sshKey{url, nodes[0].ID})
				require.Equal(t, change != "changed rules", ok)

				if ok {
					require.Same(t, oldSSH[i], ssh)
				}
			}

			require.NoError(t, next.Audit(source, scanUsers, after.ViewSlice()))
			require.NoError(t, prev.Audit(pol, scanUsers, nodes.ViewSlice()))

			stillSSH, err := json.Marshal(oldSSH)
			require.NoError(t, err)
			require.Equal(t, frozenSSH, stillSSH, "old SSH policies are immutable")
		})
	}
}

func ownRulesNode(id int, user *types.User, tags []string, routes ...string) *types.Node {
	v4 := netip.AddrFrom4([4]byte{100, 64, 0, byte(id)})                               //nolint:gosec
	v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 15: byte(id)}) //nolint:gosec

	n := &types.Node{ID: types.NodeID(id), Hostname: fmt.Sprintf("n%d", id), IPv4: &v4, IPv6: &v6, Tags: tags} //nolint:gosec
	if user != nil {
		n.User, n.UserID = user, &user.ID
	}

	for _, r := range routes {
		n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix(r))
	}

	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: n.ApprovedRoutes}

	return n
}

func TestSideIndexMissingAddresses(t *testing.T) {
	n := ownRulesNode(1, nil, []string{"tag:exit"}, "0.0.0.0/0", "::/0")
	n.IPv4, n.IPv6 = nil, nil

	pm := &PolicyManager{nodes: views.SliceOf([]types.NodeView{{}, n.View()})}
	idx := pm.sideIndex()
	require.Empty(t, idx.byIP)
}

func BenchmarkSideIndex(b *testing.B) {
	for _, n := range []int{100, 1000, 5000, 10000} {
		b.Run(fmt.Sprintf("nodes=%d", n), func(b *testing.B) {
			in := scanManyRulesNodes(n).ViewSlice()

			b.ReportAllocs()

			for b.Loop() {
				newSideIndex(in)
			}
		})
	}
}

func TestNewPolicyManagerFromTransitions(t *testing.T) {
	u1, u2 := scanUsers[0], scanUsers[1]

	policies := map[string]string{
		"users":  `{"acls":[{"action":"accept","src":["u1@"],"dst":["u1@:*"]},{"action":"accept","src":["u2@"],"dst":["u2@:22"]}]}`,
		"groups": `{"groups":{"group:a":["u1@"]},"acls":[{"action":"accept","src":["group:a"],"dst":["*:*"]}]}`,
		"member": `{"tagOwners":{"tag:srv":["u1@"]},"acls":[{"action":"accept","src":["autogroup:member"],"dst":["tag:srv:*"]}]}`,
		"self":   `{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
		"tagged": `{"tagOwners":{"tag:srv":["u1@"]},"acls":[{"action":"accept","src":["autogroup:tagged"],"dst":["u1@:*"]}]}`,
		"attrs": `{"tagOwners":{"tag:srv":["u1@"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],
			"nodeAttrs":[{"target":["u1@"],"attr":["custom:u1"]},{"target":["autogroup:member"],"attr":["custom:m"]}]}`,
		"ssh": `{"tagOwners":{"tag:srv":["u1@"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],
			"ssh":[{"action":"accept","src":["autogroup:member"],"dst":["tag:srv"],"users":["root"]},
			       {"action":"accept","src":["u1@"],"dst":["autogroup:self"],"users":["root"]}]}`,
		"subnet": `{"acls":[{"action":"accept","src":["u2@"],"dst":["10.1.0.0/24:*"]}]}`,
		"via": `{"tagOwners":{"tag:srv":["u1@"]},"grants":[{"src":["*"],"dst":["*"],"ip":["*"]},
			{"src":["u1@"],"dst":["10.1.0.0/24"],"ip":["*"],"via":["tag:srv"]}]}`,
	}

	owned := func(id int, u *types.User) *types.Node {
		n := ownRulesNode(id, nil, nil)
		uu := *u
		n.User, n.UserID = &uu, &uu.ID

		return n
	}

	transitions := map[string]func(n *types.Node){
		"owner reassigned": func(n *types.Node) {
			uu := u2
			n.User, n.UserID = &uu, &uu.ID
		},
		"address replaced": func(n *types.Node) {
			v4 := netip.MustParseAddr("100.64.0.99")
			n.IPv4 = &v4
		},
		"untagged": func(n *types.Node) {
			n.Tags = nil
			uu := u1
			n.User, n.UserID = &uu, &uu.ID
		},
		"retagged": func(n *types.Node) {
			n.Tags = []string{"tag:srv"}
		},
		"retagged without its User loaded": func(n *types.Node) {
			n.User = nil
			n.Tags = []string{"tag:srv"}
		},
		"user lost": func(n *types.Node) {
			n.User, n.UserID = nil, nil
		},
		// No matcher changes, only which ones the node is a side of.
		"route approved": func(n *types.Node) {
			n.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/24")}
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: n.ApprovedRoutes}
		},
	}

	for pname, pol := range policies {
		for tname, change := range transitions {
			t.Run(pname+"/"+tname, func(t *testing.T) {
				before := types.Nodes{
					owned(1, &u1), owned(2, &u1), owned(3, &u2),
					ownRulesNode(4, nil, []string{"tag:srv"}, "10.1.0.0/24"),
				}

				// The untagging case starts from the tagged node.
				target := 0
				if tname == "untagged" {
					target = 3
				}

				// A node whose User is not loaded: only UserID is set.
				if tname == "retagged without its User loaded" {
					before[target].User = nil
				}

				prev, err := NewPolicyManager([]byte(pol), scanUsers, before.ViewSlice())
				require.NoError(t, err)

				if pname == "via" {
					require.NotEmpty(t, prev.ViaRoutesForPeer(before[1].View(), before[3].View()).Include,
						"test sanity: the router serves u1 the via route")
				}

				// Prepare SSH policies, as live sessions do, so carried
				// ones are exercised.
				for _, n := range before {
					_, err := prev.SSHPolicy(scanServerURL, n.View())
					require.NoError(t, err)
				}

				after := slices.Clone(before)
				c := before[target].Clone()
				change(c)
				after[target] = c

				inc, err := NewPolicyManagerFrom(prev, []byte(pol), scanUsers, after.ViewSlice())
				require.NoError(t, err)
				require.NoError(t, inc.Audit([]byte(pol), scanUsers, after.ViewSlice()))
			})
		}
	}
}

const scanServerURL = "https://headscale.example.com"

// TestUserAliasIncrementalIdentities keeps stale embedded user records on nodes:
// token and domain membership must follow the current users, including collisions.
func TestUserAliasIncrementalIdentities(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "alice", Email: "alice@allowed.example"},
		{ID: 2, Name: "bob", Email: "bob@other.example", ProviderIdentifier: sql.NullString{String: "https://idp.example/bob", Valid: true}},
		{ID: 3, Name: "alice@allowed.example"},
		{ID: 4, Name: "duplicate"},
		{ID: 5, Name: "duplicate"},
		{ID: 6, Name: "https://idp.example/bob", Email: "duplicate-email@example.com"},
		{ID: 7, Name: "seventh", Email: "duplicate-email@example.com"},
		{ID: 8, Name: "folded", Email: "folded@ALLOWED.EXAMPLE"},
	}

	aliases := []string{"alice@", "alice@allowed.example", "bob@", "https://idp.example/bob@", "duplicate@", "duplicate-email@example.com", "missing@", "@", "user:*@allowed.example", "user:*@ALLOWED.EXAMPLE", "user:*@other.example", "group:a", "group:b", "group:overlap"}
	policy := func(reverse bool) []byte {
		grants := make([]string, 0, len(aliases))
		for i, alias := range aliases {
			grants = append(grants, fmt.Sprintf(`{"src":[%q],"dst":[%q],"ip":["tcp:%d"]}`, alias, alias, 443+i))
		}

		if reverse {
			slices.Reverse(grants)
		}

		return []byte(`{"groups":{"group:a":["alice@","missing@"],"group:b":["bob@"],"group:overlap":["alice@","bob@","user:*@allowed.example"]},"grants":[` + strings.Join(grants, ",") + `],"ssh":[{"action":"accept","src":["group:a"],"dst":["autogroup:self"],"users":["root"]},{"action":"accept","src":["bob@"],"dst":["autogroup:self"],"users":["root"]}]}`)
	}

	for _, transition := range []string{"join", "leave", "address", "owner", "tag", "untag", "association-only", "association-lost", "rename", "delete-user", "recreate-user", "email-domain", "reorder-grants", "fresh-policy"} {
		t.Run(transition, func(t *testing.T) {
			before := make(types.Nodes, len(users))
			for i, user := range users {
				stale := user
				stale.Name, stale.Email = "stale-name", "stale@invalid.example"
				before[i] = ownRulesNode(i+1, &stale, nil)
			}

			if transition == "association-only" {
				before[0].UserID = nil
			}

			if transition == "untag" {
				before[0].Tags = []string{"tag:retained-creator"}
			}

			pol := policy(false)
			prev, err := NewPolicyManagerFrom(nil, pol, users, before.ViewSlice())
			require.NoError(t, err)

			for _, n := range before {
				_, err := prev.SSHPolicy(scanServerURL, n.View())
				require.NoError(t, err)
			}

			after, nextUsers := slices.Clone(before), slices.Clone(users)
			after[0] = before[0].Clone()

			switch transition {
			case "join":
				joined := before[0].Clone()
				joined.ID, joined.IPv4 = 99, ap("100.64.0.99")
				after = append(after, joined)
			case "leave":
				after = after[1:]
			case "address", "association-only":
				after[0].IPv4 = ap("100.64.0.99")
			case "owner":
				after[0].User, after[0].UserID = &nextUsers[1], &nextUsers[1].ID
			case "tag":
				after[0].Tags = []string{"tag:retained-creator"}
			case "untag":
				after[0].Tags = nil
			case "association-lost":
				after[0].User = nil
			case "rename":
				nextUsers[0].Name = "renamed"
			case "delete-user":
				nextUsers = nextUsers[1:]
			case "recreate-user":
				nextUsers[0].ID = 99
				after[0].User, after[0].UserID = &nextUsers[0], &nextUsers[0].ID
			case "email-domain":
				nextUsers[0].Email = "alice@removed.example"
			case "reorder-grants":
				pol = policy(true)
			case "fresh-policy":
				pol = bytes.ReplaceAll(pol, []byte("tcp:443"), []byte("tcp:8443"))
			}

			inc, err := NewPolicyManagerFrom(prev, pol, nextUsers, after.ViewSlice())
			require.NoError(t, err)
			require.NoError(t, inc.Audit(pol, nextUsers, after.ViewSlice()))
			require.NoError(t, prev.Audit(policy(false), users, before.ViewSlice()))
		})
	}
}

// TestPeerClassesMixedSelfVia compares the served peer classes with the
// per-node reference, including user-owned routers with source-specific
// reachability.
func TestPeerClassesMixedSelfVia(t *testing.T) {
	for _, source := range []string{"autogroup:member", "u1@", "group:a"} {
		for _, appOnly := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/app=%t/reverse=%t", source, appOnly, reverse), func(t *testing.T) {
					traffic := `"ip":["tcp:443"]`
					if appOnly {
						traffic = `"app":{"example.com/via":[{}]}`
					}

					grants := []string{
						fmt.Sprintf(`{"src":[%q],"dst":["autogroup:self"],"ip":["tcp:443"]}`, source),
						`{"src":["u2@"],"dst":["autogroup:self"],"app":{"example.com/self":[{}]}}`,
						fmt.Sprintf(`{"src":["u1@"],"dst":["10.2.0.0/24","fd00:2::/64"],"via":["tag:router"],%s}`, traffic),
						`{"src":["100.64.0.2"],"dst":["10.2.0.0/25"],"via":["tag:router"],"ip":["tcp:80"]}`,
					}
					if reverse {
						slices.Reverse(grants)
					}

					pol := []byte(`{"groups":{"group:a":["u1@"]},"tagOwners":{"tag:router":[],"tag:source":[],"tag:exit":[]},"grants":[` + strings.Join(grants, ",") + `]}`)
					u1, u2 := &scanUsers[0], &scanUsers[1]
					nodes := types.Nodes{
						ownRulesNode(1, u1, nil, "100.64.0.3/32", "fd7a:115c:a1e0::3/128"),
						ownRulesNode(2, u1, nil, "10.1.0.0/24"),
						ownRulesNode(3, u2, nil),
						ownRulesNode(4, u2, nil),
						ownRulesNode(5, u1, []string{"tag:router"}, "10.2.0.0/24", "fd00:2::/64"),
						ownRulesNode(6, u1, []string{"tag:router"}, "10.2.0.0/24", "fd00:2::/64"),
						ownRulesNode(7, u2, []string{"tag:source"}, "100.64.0.2/32", "fd7a:115c:a1e0::2/128"),
						ownRulesNode(8, u1, []string{"tag:exit"}, "0.0.0.0/0", "::/0"),
						ownRulesNode(9, u1, nil),
					}
					nodes[8].User = nil // A creator ID alone does not carry self rules.

					var previous *PolicyManager

					for step := range 7 {
						pm, err := NewPolicyManagerFrom(previous, pol, scanUsers, nodes.ViewSlice())
						require.NoError(t, err)

						m := newSideModel(t, pm, scanUsers, nodes)

						want := buildPeerMapPairScan(pm, nodes.ViewSlice())
						for _, node := range nodes {
							require.Equalf(t, nilIfEmpty(slices.Sorted(slices.Values(want[node.ID]))), nilIfEmpty(m.peers.Peers(node.ID)), "step %d node %d", step, node.ID)
						}

						if step == 0 {
							require.Contains(t, m.peers.Peers(1), types.NodeID(3), "the source router reaches u2")
							require.NotContains(t, m.peers.Peers(2), types.NodeID(3), "its sibling must not inherit that source route")
							require.True(t, sameSlice(m.peers.View(3), m.peers.View(4)), "u2 devices share one peer view")
						}

						require.NoError(t, pm.Audit(pol, scanUsers, nodes.ViewSlice()))

						_, err = m.audit()
						require.NoError(t, err)

						previous = pm
						nodes = slices.Clone(nodes)

						switch step {
						case 0:
							nodes = append(nodes, ownRulesNode(10, u1, nil))
						case 1:
							nodes = slices.Delete(nodes, 1, 2)
						case 2:
							nodes[3] = nodes[3].Clone()
							nodes[3].Hostinfo = &tailcfg.Hostinfo{}
						case 3:
							nodes[0] = nodes[0].Clone()
							nodes[0].Hostinfo = &tailcfg.Hostinfo{}
						case 4:
							nodes[0] = nodes[0].Clone()
							nodes[0].Tags = []string{"tag:router"}
						case 5:
							nodes[1] = nodes[1].Clone()
							nodes[1].User, nodes[1].UserID = u1, &u1.ID
						}
					}
				})
			}
		}
	}
}

// TestPeerClassesListOwnCapabilitySourcesOnExit pins that an exit node
// lists the sources of a node's own capability to the internet, as the pair
// scan does: a self app grant whose owner holds a public address gives the
// owner's self rules a capability to the internet, and those rules are the
// owner's own, not the shared ones.
func TestPeerClassesListOwnCapabilitySourcesOnExit(t *testing.T) {
	alice := &scanUsers[0]
	exit := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	public, private := netip.MustParseAddr("8.8.8.1"), netip.MustParseAddr("100.64.0.2")
	nodes := types.Nodes{
		{ID: 1, IPv4: &public, User: alice, UserID: &alice.ID, Hostinfo: &tailcfg.Hostinfo{}},
		{ID: 2, IPv4: &private, User: alice, UserID: &alice.ID, Hostinfo: &tailcfg.Hostinfo{}},
		{ID: 3, IPv4: new(netip.MustParseAddr("100.64.0.3")), Tags: []string{"tag:exit"}, Hostinfo: &tailcfg.Hostinfo{RoutableIPs: exit}, ApprovedRoutes: exit},
	}

	pol := []byte(`{"tagOwners": {"tag:exit": []}, "grants": [
		{"src": ["autogroup:member"], "dst": ["autogroup:self"], "app": {"example.com/cap/x": [{}]}}]}`)

	pm, err := NewPolicyManager(pol, scanUsers, nodes.ViewSlice())
	require.NoError(t, err)

	m := newSideModel(t, pm, scanUsers, nodes)
	require.Equal(t, []types.NodeID{1, 2}, m.peers.Peers(3), "the exit node lists the owner nodes its own rule's capability reaches the internet from")
	require.Equal(t, []types.NodeID{2}, m.peers.Peers(1), "the listing is one-way")
	require.Equal(t, []types.NodeID{1, 2}, pm.BuildPeerMap(nodes.ViewSlice())[3], "as the pair scan does")

	_, err = m.audit()
	require.NoError(t, err)
}
