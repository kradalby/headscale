package v2

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

var incrementalURLs = []string{"https://a.example.com", "https://b.example.com"}

// Every field and operation is drawn through Rapid, so failures shrink policy
// rules and history, rather than merely shrinking a seed for another generator.
func incrementalDocument(t *rapid.T) []byte {
	aliases := []string{
		"*", "u1@", "u2@", "group:a", "tag:srv", "tag:router",
		"autogroup:member", "autogroup:tagged", "lan", "100.64.0.1", "fd7a:115c:a1e0::2",
	}
	pick := func(pool []string) []string {
		return rapid.SliceOfN(rapid.SampledFrom(pool), 1, 3).Draw(t, "aliases")
	}
	pol := map[string]any{
		"groups":        map[string][]string{"group:a": pick([]string{"u1@", "u2@", "u3@"})},
		"tagOwners":     map[string][]string{"tag:srv": {"u1@"}, "tag:router": {"u2@"}},
		"hosts":         map[string]string{"lan": rapid.SampledFrom([]string{"10.0.0.0/24", "2001:db8::/64"}).Draw(t, "host")},
		"autoApprovers": map[string]any{"routes": map[string][]string{"10.0.0.0/24": {"tag:router"}}},
	}
	grants, acls := []any{}, []any{}

	for range rapid.IntRange(0, 5).Draw(t, "rules") {
		src := pick(aliases)

		dst := pick(append(slices.Clone(aliases), "autogroup:self", "autogroup:internet"))
		if slices.Contains(dst, "autogroup:self") {
			src = pick([]string{"u1@", "u2@", "group:a", "autogroup:member"})
		}

		switch rapid.IntRange(0, 3).Draw(t, "rule kind") {
		case 0:
			// IPv6 literals need bracket syntax in ACL destinations; grants cover them.
			dst = pick([]string{"*", "u1@", "group:a", "tag:srv", "autogroup:self", "lan"})
			if slices.Contains(dst, "autogroup:self") {
				src = pick([]string{"u1@", "u2@", "group:a", "autogroup:member"})
			}

			for i := range dst {
				dst[i] += ":" + rapid.SampledFrom([]string{"*", "22", "80,443"}).Draw(t, "ports")
			}

			acls = append(acls, map[string]any{"action": "accept", "src": src, "dst": dst})
		case 1:
			grants = append(grants, map[string]any{
				"src": src, "dst": dst,
				"ip": pick([]string{"*", "tcp:443", "udp:53", "icmp:*"}),
			})
		case 2:
			for i := range dst {
				if dst[i] == "autogroup:internet" {
					dst[i] = "8.8.8.0/24"
				}
			}

			grants = append(grants, map[string]any{
				"src": src, "dst": dst,
				"app": map[string]any{"example.com/cap/test": []any{map[string]any{"role": rapid.SampledFrom([]string{"read", "write"}).Draw(t, "role")}}},
			})
		case 3:
			grants = append(grants, map[string]any{
				"src": src, "dst": []string{"lan"},
				"via": []string{"tag:router"}, "ip": []string{"tcp:443"},
			})
		}
	}

	pol["grants"], pol["acls"] = grants, acls
	if rapid.Bool().Draw(t, "default allow") && len(grants)+len(acls) == 0 {
		delete(pol, "grants")
		delete(pol, "acls")
	}

	ssh := make([]any, 0, 2)

	for range rapid.IntRange(0, 2).Draw(t, "ssh rules") {
		action := rapid.SampledFrom([]string{"accept", "check"}).Draw(t, "ssh action")

		dst := []string{"autogroup:self"}
		if action == "accept" {
			dst = pick([]string{"autogroup:self", "tag:srv", "tag:router"})
		}

		ssh = append(ssh, map[string]any{
			"action": action, "src": pick([]string{"u1@", "group:a", "autogroup:member"}),
			"dst": dst, "users": pick([]string{"root", "autogroup:nonroot"}),
		})
	}

	pol["ssh"] = ssh
	pol["nodeAttrs"] = []any{map[string]any{"target": pick(aliases), "attr": pick([]string{"foo", "bar", "randomize-client-port"})}}
	pol["randomizeClientPort"] = rapid.Bool().Draw(t, "randomize port")

	return incrementalJSON(t, pol)
}

func incrementalJSON(t *rapid.T, v any) []byte {
	t.Helper()

	b, err := json.Marshal(v)
	require.NoError(t, err)

	return b
}

func incrementalNode(t *rapid.T, id types.NodeID, users []types.User) *types.Node {
	u := users[rapid.IntRange(0, len(users)-1).Draw(t, "owner")]
	n := node(fmt.Sprintf("n%d", id), fmt.Sprintf("100.64.0.%d", id), fmt.Sprintf("fd7a:115c:a1e0::%x", id), u)
	n.ID = id
	incrementalIdentity(t, n, users)
	incrementalFamily(t, n)

	return n
}

func incrementalIdentity(t *rapid.T, n *types.Node, users []types.User) {
	u := users[rapid.IntRange(0, len(users)-1).Draw(t, "owner")]
	n.User, n.UserID = &u, &u.ID

	n.Tags = rapid.SampledFrom([][]string{nil, {"tag:srv"}, {"tag:router"}, {"tag:srv", "tag:srv"}}).Draw(t, "tags")
	if n.IsTagged() && rapid.Bool().Draw(t, "clear creator") {
		n.User, n.UserID = nil, nil
	}
}

func incrementalFamily(t *rapid.T, n *types.Node) {
	n.IPv4 = new(netip.MustParseAddr(fmt.Sprintf("100.64.0.%d", n.ID)))
	n.IPv6 = new(netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%x", n.ID)))

	switch rapid.IntRange(0, 2).Draw(t, "family") {
	case 1:
		n.IPv4 = nil
	case 2:
		n.IPv6 = nil
	}
}

type incrementalInput struct {
	doc   []byte
	users []types.User
	nodes types.Nodes
}

func (in incrementalInput) edit(t *rapid.T, op string) incrementalInput {
	in.users, in.nodes = slices.Clone(in.users), slices.Clone(in.nodes)

	switch op {
	case "policy":
		in.doc = incrementalDocument(t)
	case "users":
		i := rapid.IntRange(0, len(in.users)-1).Draw(t, "user index")
		in.users[i].Name = rapid.SampledFrom([]string{"u1", "u2", "renamed"}).Draw(t, "name")
		in.users[i].Email = rapid.SampledFrom([]string{"u1@example.com", "u2@example.net", ""}).Draw(t, "email")
		in.users[i].ProviderIdentifier = sql.NullString{String: "subject", Valid: rapid.Bool().Draw(t, "provider")}
	case "membership":
		id := types.NodeID(rapid.IntRange(1, 8).Draw(t, "member id")) //nolint:gosec // bounded positive ID

		i := slices.IndexFunc(in.nodes, func(n *types.Node) bool { return n.ID == id })
		if i < 0 {
			in.nodes = append(in.nodes, incrementalNode(t, id, in.users))
		} else {
			in.nodes = slices.Delete(in.nodes, i, i+1)
		}
	case "order", "duplicate":
		var pol map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(in.doc, &pol))

		for _, key := range []string{"grants", "acls"} {
			var rules []json.RawMessage
			if b, ok := pol[key]; ok {
				require.NoError(t, json.Unmarshal(b, &rules))
				slices.Reverse(rules)

				if op == "duplicate" && len(rules) > 0 {
					rules = append(rules, rules[0])
				}

				pol[key] = incrementalJSON(t, rules)
			}
		}

		in.doc = incrementalJSON(t, pol)
		slices.Reverse(in.nodes)
	case "noop":
	default:
		if len(in.nodes) == 0 {
			return in
		}

		i := rapid.IntRange(0, len(in.nodes)-1).Draw(t, "node index")
		n := in.nodes[i].Clone()
		in.nodes[i] = n

		switch op {
		case "identity":
			incrementalIdentity(t, n, in.users)
		case "family":
			incrementalFamily(t, n)
		case "endpoints":
			n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}
		case "approved", "advertised":
			routes := rapid.SliceOfN(rapid.SampledFrom([]netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::/64"),
				netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
			}), 0, 4).Draw(t, "routes")
			if op == "approved" {
				n.ApprovedRoutes = routes
			} else {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
			}
		}
	}

	return in
}

// Keep returned slices/maps as well as serialized values: re-reading a manager
// alone would miss mutations of output a reader already holds.
type incrementalOutput struct {
	Global   []tailcfg.FilterRule
	Filters  map[types.NodeID][]tailcfg.FilterRule
	SSH      map[string]map[types.NodeID]*tailcfg.SSHPolicy
	Caps     map[types.NodeID]tailcfg.NodeCapMap
	Peers    map[types.NodeID][]types.NodeID
	Matchers map[types.NodeID][]string
}

func incrementalObserve(t *rapid.T, pm *PolicyManager, classes *PeerClasses) incrementalOutput {
	t.Helper()

	out := incrementalOutput{
		Filters: map[types.NodeID][]tailcfg.FilterRule{}, SSH: map[string]map[types.NodeID]*tailcfg.SSHPolicy{},
		Caps: pm.NodeCapMaps(), Peers: map[types.NodeID][]types.NodeID{}, Matchers: map[types.NodeID][]string{},
	}

	out.Global, _ = pm.Filter()
	for _, url := range incrementalURLs {
		out.SSH[url] = map[types.NodeID]*tailcfg.SSHPolicy{}
	}

	for _, n := range pm.nodes.All() {
		var err error

		out.Filters[n.ID()], err = pm.FilterForNode(n)
		require.NoError(t, err)

		for _, url := range incrementalURLs {
			out.SSH[url][n.ID()], err = pm.SSHPolicy(url, n)
			require.NoError(t, err)
		}

		out.Peers[n.ID()] = classes.Peers(n.ID())
		ms, err := pm.MatchersForNode(n)
		require.NoError(t, err)

		for _, m := range ms {
			out.Matchers[n.ID()] = append(out.Matchers[n.ID()], fmt.Sprintf("%s internet=%t capInternet=%t", m.DebugString(), m.DestsIsTheInternet(), m.CapDestsIsTheInternet()))
		}
	}

	return out
}

type incrementalSnapshot struct {
	incrementalInput

	warm, cold          *PolicyManager
	classes             *PeerClasses
	held                incrementalOutput
	frozen, frozenViews []byte
}

func incrementalCompile(t *rapid.T, in incrementalInput, prev *incrementalSnapshot) *incrementalSnapshot {
	t.Helper()

	var (
		warm, cold *PolicyManager
		classes    *PeerClasses
	)
	if prev != nil {
		warm, cold, classes = prev.warm, prev.cold, prev.classes
	}

	fresh, err := NewPolicyManager(in.doc, in.users, in.nodes.ViewSlice())
	require.NoError(t, err, "document: %s", in.doc)
	warm, err = NewPolicyManagerFrom(warm, in.doc, in.users, in.nodes.ViewSlice())
	require.NoError(t, err)
	cold, err = NewPolicyManagerFrom(cold, in.doc, in.users, in.nodes.ViewSlice())
	require.NoError(t, err)

	classes = warm.BuildPeerClasses(in.nodes.ViewSlice(), classes)
	if prev != nil {
		classes.Reuse(prev.classes)
	}

	wantClasses := fresh.BuildPeerClasses(in.nodes.ViewSlice(), nil)
	want := incrementalObserve(t, fresh, wantClasses)
	got := incrementalObserve(t, warm, classes)
	require.Equal(t, want, got)
	require.Equal(t, fresh.tagOwnerMap, warm.tagOwnerMap)
	require.Equal(t, fresh.autoApproveMap, warm.autoApproveMap)
	require.Equal(t, fresh.exitSet, warm.exitSet)

	pairScan := fresh.BuildPeerMap(in.nodes.ViewSlice())
	for _, n := range in.nodes {
		require.ElementsMatch(t, pairScan[n.ID], got.Peers[n.ID])
	}

	if prev != nil {
		incrementalNotifications(t, prev, prev.warm, warm, want, classes)
		incrementalNotifications(t, prev, prev.cold, cold, want, classes)
	}

	return &incrementalSnapshot{
		incrementalInput: in, warm: warm, cold: cold, classes: classes,
		held: got, frozen: incrementalJSON(t, want), frozenViews: incrementalJSON(t, classes.Views()),
	}
}

func incrementalNotifications(t *rapid.T, old *incrementalSnapshot, previous, next *PolicyManager, want incrementalOutput, classes *PeerClasses) {
	t.Helper()

	changed, all := next.FilterChangedNodes(previous)

	peerChanged := classes.Changed(old.classes)
	for _, n := range next.nodes.All() {
		before, exists := old.warm.nodesByID[n.ID()]
		if !exists || !slices.Equal(old.held.Peers[n.ID()], want.Peers[n.ID()]) {
			require.Contains(t, peerChanged, n.ID(), "peer notification")
		}
		// The world wakes a changed node itself. This delta must also wake
		// untouched destinations, even if they are not peers of the changed node.
		if !exists || before != n || all || slices.Contains(changed, n.ID()) {
			continue
		}

		require.Equal(t, old.held.Filters[n.ID()], want.Filters[n.ID()], "missed filter notification for %d", n.ID())

		for _, url := range incrementalURLs {
			require.Equal(t, old.held.SSH[url][n.ID()], want.SSH[url][n.ID()], "missed SSH notification for %d", n.ID())
		}
	}

	for id := range old.warm.nodesByID {
		if _, exists := next.nodesByID[id]; !exists {
			require.Contains(t, peerChanged, id, "removed node notification")
		}
	}
}

func (s *incrementalSnapshot) check(t *rapid.T) {
	t.Helper()
	require.Equal(t, s.frozen, incrementalJSON(t, s.held), "retained output mutated")
	require.Equal(t, s.frozenViews, incrementalJSON(t, s.classes.Views()), "retained peer views mutated")
	require.Equal(t, s.frozen, incrementalJSON(t, incrementalObserve(t, s.warm, s.classes)), "old warm snapshot changed")
	classes := s.cold.BuildPeerClasses(s.nodes.ViewSlice(), nil)
	require.Equal(t, s.frozen, incrementalJSON(t, incrementalObserve(t, s.cold, classes)), "old cold snapshot changed")
}

func TestIncrementalPolicyRapidHistory(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		in := incrementalInput{doc: incrementalDocument(t), users: []types.User{
			{ID: 1, Name: "u1"}, {ID: 2, Name: "u2"}, {ID: 3, Name: "u3"},
		}}
		for i := range rapid.IntRange(0, 6).Draw(t, "nodes") {
			in.nodes = append(in.nodes, incrementalNode(t, types.NodeID(i+1), in.users)) //nolint:gosec
		}

		history := []*incrementalSnapshot{incrementalCompile(t, in, nil)}

		ops := []string{"policy", "users", "identity", "family", "approved", "advertised", "endpoints", "membership", "order", "duplicate", "noop"}
		for _, op := range rapid.SliceOfN(rapid.SampledFrom(append(slices.Clone(ops), "restore", "temporary", "batch")), 1, 12).Draw(t, "operations") {
			base := history[len(history)-1]
			if rapid.Bool().Draw(t, "sibling") {
				base = history[rapid.IntRange(0, len(history)-1).Draw(t, "ancestor")]
			}

			in = base.incrementalInput

			switch op {
			case "restore":
				in = history[rapid.IntRange(0, len(history)-1).Draw(t, "restore snapshot")].incrementalInput
			case "temporary":
				// Remove all grants, then restore from a descendant, not from the saved manager.
				in.doc = []byte(`{"grants":[]}`)
				removed := incrementalCompile(t, in, base)
				history = append(history, removed)
				in, base = base.incrementalInput, removed
			case "batch":
				for range rapid.IntRange(2, 4).Draw(t, "batch size") {
					in = in.edit(t, rapid.SampledFrom(ops).Draw(t, "batch operation"))
				}
			default:
				in = in.edit(t, op)
			}

			next := incrementalCompile(t, in, base)
			if op == "order" || op == "duplicate" || op == "endpoints" || op == "noop" {
				require.Equal(t, base.held.Peers, next.held.Peers, "semantics-preserving operation %s", op)
			}

			history = append(history, next)
			// The newest manager stays cold until a child has compiled from it.
			for _, old := range history[:len(history)-1] {
				old.check(t)
			}
		}

		history[len(history)-1].check(t)
	})
}

// This oracle knows only literal IPs and directed edges. It never calls a
// production alias resolver, matcher, reducer or CanAccess implementation.
func TestIncrementalPolicyRapidDirectIPs(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 8).Draw(t, "nodes")

		nodes := make(types.Nodes, n)
		for i := range nodes {
			nodes[i] = node(fmt.Sprint("n", i), fmt.Sprintf("100.64.0.%d", i+1), fmt.Sprintf("fd7a:115c:a1e0::%x", i+1), types.User{ID: uint(i + 1), Name: fmt.Sprint("u", i)}) //nolint:gosec
			nodes[i].ID = types.NodeID(i + 1)                                                                                                                                   //nolint:gosec
		}

		type edge struct{ from, to int }

		edges := rapid.SliceOfN(rapid.Custom(func(t *rapid.T) edge {
			return edge{rapid.IntRange(0, n-1).Draw(t, "from"), rapid.IntRange(0, n-1).Draw(t, "to")}
		}), 0, 16).Draw(t, "edges")
		v6 := rapid.Bool().Draw(t, "ipv6")
		ip := func(i int) string {
			if v6 {
				return nodes[i].IPv6.String()
			}

			return nodes[i].IPv4.String()
		}

		var prev *incrementalSnapshot
		// Duplicate, reorder, remove and restore rules without changing their model.
		for _, es := range [][]edge{edges, slices.Concat(edges, edges), {}, edges} {
			grants := []any{}
			for _, e := range es {
				grants = append(grants, map[string]any{"src": []string{ip(e.from)}, "dst": []string{ip(e.to)}, "ip": []string{"tcp:443"}})
			}

			slices.Reverse(grants)

			next := incrementalCompile(t, incrementalInput{doc: incrementalJSON(t, map[string]any{"grants": grants}), nodes: nodes}, prev)
			for i, a := range nodes {
				var peers []types.NodeID

				for j, b := range nodes {
					forward := slices.Contains(es, edge{i, j})
					if i != j && (forward || slices.Contains(es, edge{j, i})) {
						peers = append(peers, b.ID)
					}
					// All generated rules have one literal source and TCP port 443.
					allowed := false

					for _, rule := range next.held.Filters[b.ID] {
						if !slices.Contains(rule.SrcIPs, ip(i)) {
							continue
						}

						for _, dst := range rule.DstPorts {
							if dst.IP == ip(j) && dst.Ports.First <= 443 && dst.Ports.Last >= 443 && slices.Contains(rule.IPProto, 6) {
								allowed = true
							}
						}
					}

					require.Equal(t, forward, allowed, "directed packet access %d -> %d", i, j)
				}

				require.ElementsMatch(t, peers, next.held.Peers[a.ID])
			}

			if prev != nil {
				prev.check(t)
			}

			prev = next
		}

		prev.check(t)
	})
}

func TestIncrementalPolicyRapidMatcherWords(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		count := rapid.SampledFrom([]int{0, 1, 63, 64, 65, 127, 128, 129}).Draw(t, "matcher count")
		nodes := scanManyRulesNodes(6).ViewSlice()

		rules := make([]tailcfg.FilterRule, count)
		for i := range rules {
			src := rapid.IntRange(0, nodes.Len()-1).Draw(t, "source")
			dst := rapid.IntRange(0, nodes.Len()-1).Draw(t, "destination")
			rules[i] = tailcfg.FilterRule{
				SrcIPs:   []string{nodes.At(src).IPv4().String()},
				DstPorts: []tailcfg.NetPortRange{{IP: nodes.At(dst).IPv4().String(), Ports: tailcfg.PortRangeAny}},
			}
		}

		ms := matcher.MatchesFromFilterRules(rules)
		_, _, old := cachedMatcherSides(ms, nodes, nil)

		type masks struct{ Src, Dst []uint64 }

		frozen := map[types.NodeID]masks{}
		for id, s := range old.nodes {
			frozen[id] = masks{slices.Clone(s.src), slices.Clone(s.dst)}
		}

		reordered := slices.Clone(ms)
		slices.Reverse(reordered)

		removed := reordered[:rapid.IntRange(0, len(reordered)).Draw(t, "retain")]
		for _, next := range [][]matcher.Match{reordered, slices.Concat(ms, ms), removed, nil, ms} {
			src, dst, _ := cachedMatcherSides(next, nodes, old)
			// Compare every bit with a scalar membership test, including high words.
			for i, node := range nodes.All() {
				for k, m := range next {
					has := func(words []uint64) bool { return k/64 < len(words) && words[k/64]&(uint64(1)<<uint(k%64)) != 0 } //nolint:gosec
					require.Equal(t, m.SrcsContainsIPs(node.IPs()...), has(src[i]))
					require.Equal(t, m.DestsContainsIP(node.IPs()...), has(dst[i]))
				}

				// Cached masks may keep zero words, but no bit may name a removed rule.
				for _, words := range [][]uint64{src[i], dst[i]} {
					for w, word := range words {
						valid := min(max(len(next)-64*w, 0), 64)
						unused := ^uint64(0) << valid
						require.Zero(t, word&unused, "bits beyond %d matchers in word %d", len(next), w)
					}
				}
			}

			for id, s := range old.nodes {
				require.Equal(t, masks{s.src, s.dst}, frozen[id], "old masks mutated")
			}
		}
	})
}

func TestIncrementalPolicyRapidSSHAndOwnership(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		users := []types.User{{ID: 1, Name: "u1"}}

		nodes := types.Nodes{
			node("source", "100.64.0.1", "fd7a:115c:a1e0::1", users[0]),
			node("sibling", "100.64.0.2", "fd7a:115c:a1e0::2", users[0]),
			node("server", "100.64.0.3", "fd7a:115c:a1e0::3", users[0]),
		}
		for i, n := range nodes {
			n.ID = types.NodeID(i + 1)
		} //nolint:gosec

		nodes[2].Tags = []string{"tag:srv"} // Retain creator: tags still exclude self access.
		self := rapid.Bool().Draw(t, "self packet grant")

		pol := map[string]any{"grants": []any{}, "ssh": []any{}, "tagOwners": map[string][]string{"tag:srv": {"u1@"}}}
		if self {
			pol["grants"] = []any{map[string]any{"src": []string{"u1@"}, "dst": []string{"autogroup:self"}, "ip": []string{"*"}}}
		}

		base := incrementalCompile(t, incrementalInput{doc: incrementalJSON(t, pol), users: users, nodes: nodes}, nil)
		prev := base

		for _, enabled := range []bool{true, false, true} {
			pol["ssh"] = []any{}
			if enabled {
				pol["ssh"] = []any{map[string]any{"action": "accept", "src": []string{"u1@"}, "dst": []string{"tag:srv"}, "users": []string{"root"}}}
			}

			next := incrementalCompile(t, incrementalInput{doc: incrementalJSON(t, pol), users: users, nodes: nodes}, prev)
			for _, url := range incrementalURLs {
				ssh := next.held.SSH[url][3]
				require.Equal(t, enabled, ssh != nil && len(ssh.Rules) > 0)
			}

			require.Empty(t, next.held.Peers[3], "SSH alone must not grant packet visibility")
			require.Empty(t, next.held.Filters[3], "creator ID must not give tagged nodes self access")
			// Move a source's identity while the destination is untouched and is
			// not its peer. FilterChangedNodes must still cover the SSH change.
			moved := slices.Clone(nodes)
			moved[0] = moved[0].Clone()

			moved[0].Tags = []string{"tag:srv"}
			if rapid.Bool().Draw(t, "retain creator") {
				moved[0].User, moved[0].UserID = nil, nil
			}

			child := incrementalCompile(t, incrementalInput{doc: next.doc, users: users, nodes: moved}, next)
			require.Empty(t, child.held.Filters[1], "tagged source must lose its self filter")
			require.Empty(t, child.held.Peers[1])

			if enabled {
				require.NotEqual(t, next.held.SSH[incrementalURLs[0]][3], child.held.SSH[incrementalURLs[0]][3])
			}

			next.check(t)
			prev = incrementalCompile(t, next.incrementalInput, child)
			child.check(t)
			base.check(t)
		}

		prev.check(t)
	})
}

func TestIncrementalPolicyRapidRawApprovals(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		route := rapid.SampledFrom([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("2001:db8::/64")}).Draw(t, "route")
		nodes := scanManyRulesNodes(2)
		// Wildcard source includes manual approvals even before advertisement.
		wildcard := []byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["*"]}]}`)
		// A subnet source connects a router only while it serves that subnet.
		subnet := incrementalJSON(t, map[string]any{"grants": []any{map[string]any{
			"src": []string{route.String()}, "dst": []string{nodes[1].IPv4.String()}, "ip": []string{"*"},
		}}})

		var prev *incrementalSnapshot

		for _, doc := range [][]byte{wildcard, subnet} {
			for _, state := range [][2]bool{{false, false}, {true, false}, {true, true}, {false, true}, {false, false}, {true, true}} {
				nodes = slices.Clone(nodes)
				nodes[0] = nodes[0].Clone()
				nodes[0].ApprovedRoutes = nil

				nodes[0].Hostinfo = &tailcfg.Hostinfo{}
				if state[0] {
					nodes[0].ApprovedRoutes = []netip.Prefix{route}
				}

				if state[1] {
					nodes[0].Hostinfo.RoutableIPs = []netip.Prefix{route}
				}

				next := incrementalCompile(t, incrementalInput{doc: doc, nodes: nodes}, prev)
				if string(doc) == string(wildcard) {
					present := slices.ContainsFunc(next.held.Global, func(r tailcfg.FilterRule) bool { return slices.Contains(r.SrcIPs, route.String()) })
					require.Equal(t, state[0], present, "wildcard must use raw approval")
				} else {
					require.Equal(t, state[0] && state[1], slices.Contains(next.held.Peers[1], types.NodeID(2)), "subnet source needs approval and advertisement")
				}

				if prev != nil {
					prev.check(t)
				}

				prev = next
			}
		}

		prev.check(t)
	})
}

func TestIncrementalPolicyRapidCapabilityKeys(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		nodes := scanManyRulesNodes(2)
		suffix := rapid.SampledFrom([]string{"a", "a,b", "a=b", "a|b"}).Draw(t, "capability suffix")
		key := "example.com/" + suffix
		caps := []map[string]any{
			{key: []any{}, "example.com/b": []any{}},
			{key + "=example.com/b": []any{}},
			{key: []any{map[string]any{"value": rapid.IntRange(0, 3).Draw(t, "value")}}},
		}

		var prev *incrementalSnapshot

		for _, capMap := range []map[string]any{caps[0], caps[1], caps[2], caps[0]} {
			doc := incrementalJSON(t, map[string]any{"grants": []any{map[string]any{
				"src": []string{nodes[0].IPv4.String()}, "dst": []string{nodes[1].IPv4.String()}, "app": capMap,
			}}})
			next := incrementalCompile(t, incrementalInput{doc: doc, nodes: nodes}, prev)
			rules := next.held.Filters[2]
			require.Len(t, rules, 1)
			require.Len(t, rules[0].CapGrant, 1)
			require.JSONEq(t, string(incrementalJSON(t, capMap)), string(incrementalJSON(t, rules[0].CapGrant[0].CapMap)))

			if prev != nil {
				prev.check(t)
			}

			prev = next
		}

		prev.check(t)

		// Same source/destination sets, different meaning for an exit node.
		nodes = slices.Clone(nodes)
		nodes[1] = nodes[1].Clone()
		nodes[1].ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
		nodes[1].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: slices.Clone(nodes[1].ApprovedRoutes)}
		prev = nil

		for _, app := range []bool{false, true, false, true} {
			grant := map[string]any{"src": []string{nodes[0].IPv4.String()}, "dst": []string{"8.8.8.0/24"}}
			if app {
				grant["app"] = caps[0]
			} else {
				grant["ip"] = []string{"*"}
			}

			next := incrementalCompile(t, incrementalInput{doc: incrementalJSON(t, map[string]any{"grants": []any{grant}}), nodes: nodes}, prev)
			require.Equal(t, !app, slices.Contains(next.held.Peers[1], types.NodeID(2)), "capabilities alone do not grant exit traffic")
			require.Equal(t, []types.NodeID{1}, next.held.Peers[2], "exit must know capability source")

			if prev != nil {
				prev.check(t)
			}

			prev = next
		}

		prev.check(t)
	})
}
