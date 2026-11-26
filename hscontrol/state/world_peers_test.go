package state

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/graph"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func (s *Snapshot) sides() policyv2.Sides        { return s.s.Get(s.w.sides) }
func (s *Snapshot) peers() *policyv2.PeerClasses { return s.s.Get(s.w.peers) }
func (s *Snapshot) viaPlans() policyv2.ViaPlans  { return s.s.Get(s.w.viaPlan) }

type sidesRevs struct{ sides, peers, via uint64 }

func (s *Snapshot) sidesRevs() sidesRevs {
	return sidesRevs{
		sides: graph.ChangedAt(s.s, s.w.sides),
		peers: graph.ChangedAt(s.s, s.w.peers),
		via:   graph.ChangedAt(s.s, s.w.viaPlan),
	}
}

// sidesAuditOf is what the world's sides audit checks in s.
func sidesAuditOf(s *Snapshot) policyv2.SidesAudit {
	cp := s.s.Get(s.w.policy)
	pm, _ := cp.pm.(*policyv2.PolicyManager)

	return policyv2.SidesAudit{
		Templates: s.templates(), Roles: s.roles(), Postings: s.postings(), Approvals: s.approvals(),
		Nodes: s.nodes(), Sides: s.sides(), Peers: s.peers(), Via: s.viaPlans().Plan,
		List: s.s.Get(s.w.policyNodes).list, Users: s.s.Get(s.w.policyUsers), Policy: pm, Current: cp.err == nil,
	}
}

// requireSides runs the sides audit on s directly, so a failure names the
// difference, and returns what it compared.
func requireSides(t *testing.T, s *Snapshot, msgAndArgs ...any) policyv2.SidesReport {
	t.Helper()

	rep, err := policyv2.AuditSides(sidesAuditOf(s))
	require.NoError(t, err, msgAndArgs...)

	return rep
}

// requireAuditedSides is requireSides, and requires the world's audit to
// have checked s: its pairs, and its elections while the document in force
// compiles.
func requireAuditedSides(t *testing.T, s *Snapshot, msg string, args ...any) policyv2.SidesReport {
	t.Helper()

	rep := requireSides(t, s, append([]any{msg}, args...)...)

	require.True(t, s.SidesAudited(), append([]any{msg + ": the last change was audited"}, args...)...)
	require.True(t, s.ViaElectionAudited() || s.PolicyErr() != nil, append([]any{msg + ": the elections were audited"}, args...)...)

	return rep
}

const sidesCostPolicy = `{
	"groups": {"group:eng": ["alice@"]},
	"tagOwners": {"tag:web": ["alice@"], "tag:router": ["alice@"]},
	"acls": [
		{"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]},
		{"action": "accept", "src": ["tag:web"], "dst": ["tag:web:80"]}],
	"grants": [{"src": ["bob@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:router"]}]}`

// TestWorldSidesCostFollowsChange pins, per write kind, which role-based
// cells move and how much they compute: a write that moves no address,
// route, tag or user computes no side set and keeps every view; a join
// computes the joiner's side set and the views of the classes its atoms
// are adjacent to, keeping the rest by identity. Peers and counts are
// written out from the policy, not read back from the code.
func TestWorldSidesCostFollowsChange(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}
	alice, bob := &users[0], &users[1]

	tagged := func(n *types.Node, tag string) *types.Node {
		n.Tags, n.UserID, n.User = []string{tag}, nil, nil

		return n
	}

	route := netip.MustParsePrefix("10.0.0.0/24")
	router := tagged(worldNode(6, alice, "100.64.0.6"), "tag:router")
	router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	router.ApprovedRoutes = []netip.Prefix{route}

	w, err := newWorld(types.Nodes{
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
		worldNode(3, bob, "100.64.0.3"),
		tagged(worldNode(4, alice, "100.64.0.4"), "tag:web"),
		tagged(worldNode(5, alice, "100.64.0.5"), "tag:web"),
		router,
	}, users, []byte(sidesCostPolicy), types.DNSView{})
	require.NoError(t, err)

	requirePeers := func(s *Snapshot, want map[types.NodeID][]types.NodeID) {
		t.Helper()

		for id, peers := range want {
			if got := s.peers().Peers(id); len(peers) > 0 || len(got) > 0 {
				assert.Equal(t, peers, got, "peers of %d", id)
			}
		}
	}

	// alice's nodes reach the web servers, which reach each other; bob's
	// via grant links him with the router serving its route.
	requirePeers(w.snapshot(), map[types.NodeID][]types.NodeID{
		1: {2, 4, 5}, 2: {1, 4, 5}, 3: {6}, 4: {1, 2, 5}, 5: {1, 2, 4}, 6: {3},
	})

	type moves struct {
		sides, peers, via bool
		// computed side sets, class views; viaBuilt: the plan was rebuilt.
		computed, views int
		viaBuilt        bool
		// kept are nodes whose view keeps its identity.
		kept []types.NodeID
	}

	steps := []struct {
		name  string
		write func()
		want  moves
		peers map[types.NodeID][]types.NodeID
	}{
		{"endpoint", func() {
			w.UpdateNode(1, func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")} })
		}, moves{kept: []types.NodeID{1, 2, 3, 4, 5, 6}}, nil},
		{"hostinfo", func() {
			w.UpdateNode(4, func(n *types.Node) { n.Hostinfo = &tailcfg.Hostinfo{OS: "linux"} })
		}, moves{kept: []types.NodeID{1, 2, 3, 4, 5, 6}}, nil},
		{"health", func() { w.UpdateNode(6, func(n *types.Node) { n.Unhealthy = true }) }, moves{kept: []types.NodeID{1, 2, 3, 4, 5, 6}}, nil},
		// The joiner's set, alice's; the views of alice's class (her clique)
		// and of the web servers' (group:eng's other side) move.
		{
			"join", func() { w.PutNode(*worldNode(7, alice, "100.64.0.7")) },
			moves{sides: true, peers: true, computed: 1, views: 2, kept: []types.NodeID{3, 6}},
			map[types.NodeID][]types.NodeID{1: {2, 4, 5, 7}, 4: {1, 2, 5, 7}, 7: {1, 2, 4, 5}, 3: {6}},
		},
		{
			"leave", func() { w.DeleteNode(7) },
			moves{sides: true, peers: true, views: 2, kept: []types.NodeID{3, 6}},
			map[types.NodeID][]types.NodeID{1: {2, 4, 5}, 4: {1, 2, 5}},
		},
		// bob joins the web servers' class; the router loses its via source,
		// alice's class gains a web server. The ACLs' destinations gain bob,
		// which steering asks the roles about: the plan stays.
		{
			"tag", func() {
				w.UpdateNode(3, func(n *types.Node) { n.Tags, n.UserID, n.User = []string{"tag:web"}, nil, nil })
			},
			moves{sides: true, peers: true, computed: 1, views: 3},
			map[types.NodeID][]types.NodeID{1: {2, 3, 4, 5}, 3: {1, 2, 4, 5}, 6: nil},
		},
		// bob's class is new again.
		{
			"untag", func() { w.UpdateNode(3, func(n *types.Node) { n.Tags, n.User, n.UserID = nil, bob, &bob.ID }) },
			moves{sides: true, peers: true, computed: 1, views: 4},
			map[types.NodeID][]types.NodeID{1: {2, 4, 5}, 3: {6}, 6: {3}},
		},
		// Without the route the router is nobody's via router.
		{
			"withdraw approval", func() { w.UpdateNode(6, func(n *types.Node) { n.ApprovedRoutes = nil }) },
			moves{sides: true, peers: true, via: true, computed: 1, views: 2, viaBuilt: true, kept: []types.NodeID{1, 2, 4, 5}},
			map[types.NodeID][]types.NodeID{3: nil, 6: nil},
		},
		{
			"approve", func() { w.UpdateNode(6, func(n *types.Node) { n.ApprovedRoutes = []netip.Prefix{route} }) },
			moves{sides: true, peers: true, via: true, computed: 1, views: 2, viaBuilt: true, kept: []types.NodeID{1, 2, 4, 5}},
			map[types.NodeID][]types.NodeID{3: {6}, 6: {3}},
		},
		// The same selectors: every side set again, every view equal and
		// kept.
		{"port edit", func() {
			_, err := w.SetPolicy([]byte(replaceOnce(sidesCostPolicy, "tag:web:443", "tag:web:8443")), noCheck)
			require.NoError(t, err)
		}, moves{sides: true, peers: true, via: true, computed: 6, views: 4, viaBuilt: true, kept: []types.NodeID{1, 2, 3, 4, 5, 6}}, nil},
		// A new selector re-identifies every side set: everything again.
		{"new selector", func() {
			_, err := w.SetPolicy([]byte(replaceOnce(sidesCostPolicy, `"tag:web:80"]`, `"tag:web:80", "100.64.0.99:22"]`)), noCheck)
			require.NoError(t, err)
		}, moves{sides: true, peers: true, via: true, computed: 6, views: 4, viaBuilt: true}, nil},
	}

	for _, step := range steps {
		before := w.snapshot()

		step.write()

		after := w.snapshot()

		t.Run(step.name, func(t *testing.T) {
			require.Equal(t, before.Rev()+1, after.Rev(), "the write is one commit")

			b, a := before.sidesRevs(), after.sidesRevs()
			assert.Equal(t, step.want.sides, a.sides != b.sides, "sides moved")
			assert.Equal(t, step.want.peers, a.peers != b.peers, "classes moved")
			assert.Equal(t, step.want.via, a.via != b.via, "via plan moved")

			_, wasComputed := before.sides().Computed()
			_, isComputed := after.sides().Computed()
			assert.Equal(t, step.want.computed, isComputed-wasComputed, "side sets computed")

			wasViews, _ := before.peers().ViewsComputed()
			isViews, _ := after.peers().ViewsComputed()
			assert.Equal(t, step.want.views, isViews-wasViews, "class views computed")
			assert.Equal(t, step.want.viaBuilt, after.viaPlans().Builds > before.viaPlans().Builds, "via plan built")

			for _, id := range step.want.kept {
				v, o := after.peers().View(id), before.peers().View(id)
				assert.True(t, len(v) == len(o) && (len(v) == 0 || &v[0] == &o[0]), "node %d keeps its view", id)
			}

			requirePeers(after, step.peers)
			requireSides(t, after, step.name)
			require.True(t, after.SidesAudited(), "the audit covers the commit")
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}

// TestWorldSidesFollowMembershipUnderRefusal pins what the role-based cells
// serve while the document in force is refused: the current membership
// under the last good policy, as the selectors do. Nodes joining then are
// seen through the last good rules; the audit holds the pairs against the
// last good document compiled afresh over the current nodes, and holds the
// routes and elections back until a document is in force again, then checks
// them at that commit.
func TestWorldSidesFollowMembershipUnderRefusal(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}
	alice, bob := &users[0], &users[1]

	route := netip.MustParsePrefix("10.0.0.0/24")
	router := func(id types.NodeID) *types.Node {
		n := worldNode(id, alice, fmt.Sprintf("100.64.0.%d", id))
		n.Tags, n.UserID, n.User = []string{"tag:r"}, nil, nil
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}

		return n
	}

	good := `{"tagOwners": {"tag:r": []},
	  "acls": [{"action": "accept", "src": ["alice@"], "dst": ["bob@:*"]}],
	  "grants": [{"src": ["alice@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`

	w, err := newWorld(types.Nodes{worldNode(1, alice, "100.64.0.1"), worldNode(2, bob, "100.64.0.2"), router(4)}, users, []byte(good), types.DNSView{})
	require.NoError(t, err)

	_, err = w.SetPolicy([]byte(`{"acls": [{"action": "accept", "src": ["tag:undefined"], "dst": ["*:*"]}]}`), noCheck)
	require.NoError(t, err)
	require.Error(t, w.snapshot().PolicyErr(), "the document is refused")

	w.PutNode(*worldNode(3, bob, "100.64.0.3"))
	w.PutNode(*router(5))

	s := w.snapshot()
	require.Error(t, s.PolicyErr())

	// The last good rules: alice reaches bob's nodes and the via routers,
	// bob's nodes are one clique.
	for id, want := range map[types.NodeID][]types.NodeID{1: {2, 3, 4, 5}, 2: {1, 3}, 3: {1, 2}, 5: {1}} {
		assert.Equal(t, want, s.peers().Peers(id), "peers of %d", id)
	}

	rep := requireSides(t, s)
	assert.Equal(t, 1, rep.Fresh, "held against the last good document compiled afresh")
	assert.True(t, s.SidesAudited(), "the pairs are checked under refusal")
	assert.False(t, s.ViaElectionAudited(), "the elections wait for a document in force")

	_, err = w.SetPolicy([]byte(good), noCheck)
	require.NoError(t, err)

	s = w.snapshot()
	require.NoError(t, s.PolicyErr())
	assert.True(t, s.SidesAudited(), "the routes are checked")
	assert.True(t, s.ViaElectionAudited(), "the elections are checked")
	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}

// sidesChurnPolicies add, to the filter churn's documents, what decides
// visibility, route access and via beyond the filter: self capabilities,
// via with an identity destination and the internet, a public prefix, and
// identity destinations a router's routes can cover.
var sidesChurnPolicies = slices.Concat(filterChurnPolicies, []string{
	// Self rules with capabilities, which a public owner address takes to
	// the internet; exit nodes.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["autogroup:member"], "dst": ["autogroup:self"], "app": {"tailscale.com/cap/relay": [{}]}},
		{"src": ["alice@", "bob@"], "dst": ["autogroup:self"], "ip": ["tcp:22"]},
		{"src": ["tag:a"], "dst": ["autogroup:internet"], "ip": ["*"]},
		{"src": ["tag:b"], "dst": ["8.8.4.0/24"], "app": {"tailscale.com/cap/relay": [{}]}}]}`,
	// Via to a subnet and to the internet; a regular grant over the same
	// routes.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["alice@", "tag:a"], "dst": ["10.0.1.0/24"], "ip": ["*"], "via": ["tag:b"]},
		{"src": ["bob@"], "dst": ["autogroup:internet", "10.0.0.0/16"], "ip": ["tcp:443"], "via": ["tag:b"]},
		{"src": ["*"], "dst": ["10.0.0.0/24"], "ip": ["*"]},
		{"src": ["autogroup:member"], "dst": ["tag:b:*", "100.64.1.0/24"], "ip": ["*"]}]}`,
	// A via router among its own sources by a route, self from one user:
	// what only another node's change reaches.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["100.64.1.96/28", "alice@"], "dst": ["10.0.1.0/24", "10.0.0.0/16"], "ip": ["*"], "via": ["tag:b"]},
		{"src": ["bob@"], "dst": ["autogroup:self"], "ip": ["tcp:22"]}]}`,
	// Everything reaching everything through routes: the subnet-to-subnet
	// reverse rule.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["10.0.0.0/16"], "dst": ["tag:a:*"]},
		{"action": "accept", "src": ["tag:b"], "dst": ["10.0.0.0/24:*", "fd7a:115c:a1e0::/120:*"]},
		{"action": "accept", "src": ["alice@"], "dst": ["autogroup:member:*"]}]}`,
})

// TestWorldSidesUnderRandomChurn drives random writes of every kind the
// role-based visibility, route access and via read, many in one commit, and
// requires them equal to the compile's and to builds from scratch after
// each, with every shape that matters reached: routers covering others'
// addresses, public routes and addresses, single-family nodes and exits,
// tagged nodes keeping a user, via tags gained and lost, approvals added
// and withdrawn, policy edits.
func TestWorldSidesUnderRandomChurn(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	var rep policyv2.SidesReport

	kinds := map[string]int{}

	for seed := range uint64(4) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			sidesChurn(t, rand.New(rand.NewPCG(seed, 31)), sidesChurnPolicies, false, &rep, kinds) //nolint:gosec // deterministic test input
		})
	}

	// The shapes the mix reaches rarely — a node whose side set moves
	// through another's: a router over another address, an owner turning
	// public — with the writes and documents building them.
	for seed := range uint64(4) {
		t.Run(fmt.Sprintf("focused/seed=%d", seed), func(t *testing.T) {
			sidesChurn(t, rand.New(rand.NewPCG(seed, 37)), sidesChurnPolicies[len(filterChurnPolicies):], true, &rep, kinds) //nolint:gosec // deterministic test input
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")

	t.Logf("writes: %v", kinds)
	t.Logf("compared: %+v", rep)

	for name, n := range map[string]int{
		"routers covering others' addresses": rep.Covering, "single-family nodes": rep.SingleFamily,
		"exit nodes of one family": rep.ExitOneFamily, "public routes": rep.PublicRoute,
		"tagged nodes keeping a user": rep.TaggedWithUser,
		"via routers":                 rep.ViaTargets,
		"steered pairs":               rep.Steered,
		"one-way peers":               rep.AsymmetricPeers, "routes kept": rep.RoutesKept,
		"audits against a compile afresh, as a refused document makes": rep.Fresh,
	} {
		assert.Positive(t, n, name)
	}

	for _, k := range []string{
		"via tag gained", "via tag lost", "approval added", "approval withdrawn", "cover",
		"policy, same selectors", "policy, new selectors", "coalesced", "concurrent", "refused policy",
	} {
		assert.Positive(t, kinds[k], "no %s write", k)
	}
}

// sortedIDs returns the IDs of the nodes e holds, sorted.
func sortedIDs(e *nodeEdit) []types.NodeID {
	ids := make([]types.NodeID, 0, e.Len())
	for id := range e.All() {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
}

// coverOp makes a node route over other nodes' addresses, a via router of
// tag:b sometimes.
func (c *churnRun) coverOp(e *nodeEdit) {
	ids := sortedIDs(e)

	if len(ids) == 0 {
		return
	}

	n := mustGet(c.t, e, ids[c.r.IntN(len(ids))]).Clone()
	routes := [][]netip.Prefix{
		{netip.MustParsePrefix("100.64.1.0/24")},
		{netip.MustParsePrefix("100.64.1.96/28"), netip.MustParsePrefix("fd7a:115c:a1e0::1000/120")},
		{netip.MustParsePrefix("8.8.4.0/24")},
	}[c.r.IntN(3)]

	n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
	n.ApprovedRoutes = routes

	if c.r.IntN(2) == 0 {
		n.Tags, n.User, n.UserID = []string{"tag:b"}, nil, nil
	}

	e.Set(n.ID, n)
}

// viaTagOp gives the first router tag:b, the via tag of the churn's
// documents, or takes it away.
func (c *churnRun) viaTagOp(e *nodeEdit) string {
	for _, id := range sortedIDs(e) {
		n := mustGet(c.t, e, id)
		if len(n.SubnetRoutes()) == 0 {
			continue
		}

		n = n.Clone()

		kind := "via tag gained"
		if n.HasTag("tag:b") {
			kind = "via tag lost"
			n.Tags = slices.DeleteFunc(slices.Clone(n.Tags), func(s string) bool { return s == "tag:b" })
		} else {
			n.Tags = append(slices.Clone(n.Tags), "tag:b")
			n.User, n.UserID = nil, nil
		}

		e.Set(id, n)

		return kind
	}

	return "via tag"
}

// approvalOp approves the first announcing node's routes, or withdraws one
// approval of it, the announcement kept.
func (c *churnRun) approvalOp(e *nodeEdit) string {
	for _, id := range sortedIDs(e) {
		n := mustGet(c.t, e, id)
		if n.Hostinfo == nil || len(n.Hostinfo.RoutableIPs) == 0 {
			continue
		}

		n = n.Clone()

		kind := "approval added"
		if len(n.ApprovedRoutes) > 0 {
			kind = "approval withdrawn"
			n.ApprovedRoutes = n.ApprovedRoutes[1:]
		} else {
			n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
		}

		e.Set(id, n)

		return kind
	}

	return "approval"
}

// policyEdit commits one of policies, or a port edit of the document in
// force, which names the same selectors, and says which it was.
func (c *churnRun) policyEdit(before *Snapshot, policies []string) string {
	src := policies[c.r.IntN(len(policies))]

	if cur := string(before.PolicySource()); c.r.IntN(3) == 0 && strings.Contains(cur, `22"`) {
		src = strings.Replace(cur, `22"`, `2222"`, 1)
	} else if c.r.IntN(3) == 0 && strings.Contains(cur, `2222"`) {
		src = strings.Replace(cur, `2222"`, `22"`, 1)
	}

	_, err := c.w.SetPolicy([]byte(src), noCheck)
	require.NoError(c.t, err, src)

	switch was, is := before.templates(), c.w.snapshot().templates(); {
	case was == is:
		return "policy unchanged"
	case was.Selectors().Table() == is.Selectors().Table():
		return "policy, same selectors"
	default:
		return "policy, new selectors"
	}
}

// focusedOps are the churn's op draws the focused variant makes: node,
// route, family or public, cover, via tag, coalesced and policy writes.
var focusedOps = []int{0, 0, 7, 7, 10, 10, 10, 11, 11, 12, 12, 14, 16, 20}

func sidesChurn(t *testing.T, r *rand.Rand, policies []string, focused bool, rep *policyv2.SidesReport, kinds map[string]int) {
	t.Helper()

	c := &churnRun{t: t, r: r, uid: 3, aligned: true}

	c.users = []types.User{{Name: "alice"}, {Name: "bob"}, {Name: "carol", Email: "carol@example.com"}}
	for i := range c.users {
		c.users[i].ID = uint(i + 1) //nolint:gosec // three users
	}

	w, err := newWorld(nil, slices.Clone(c.users), []byte(policies[0]), types.DNSView{})
	require.NoError(t, err)

	c.w = w

	for range 8 {
		n := c.randomNode()
		w.PutNode(*n)
	}

	// An election kept across steps, incremental over the via plan, and the
	// nodes it last saw.
	var (
		shadow *policyv2.ViaWinners
		seenAt *nodeMap
	)

	for step := range 300 {
		runs := SidesAuditRuns()
		before := w.snapshot()

		// A generator step that built what the server refuses to start
		// on fails here, not in a count only a refused world can move.
		c.requireStartable()

		var kind string

		op := r.IntN(27)
		if focused {
			op = focusedOps[r.IntN(len(focusedOps))]
		}

		switch {
		case op < 7:
			w.update(func(e *nodeEdit) { kind = c.nodeOp(e) })
		case op < 10:
			kind = "routes"

			w.update(c.routeOp)
		case op < 11:
			kind = "family"

			w.update(c.familyOp)
		case op < 14:
			kind = "cover"

			w.update(c.coverOp)
		case op < 15:
			w.update(func(e *nodeEdit) { kind = c.viaTagOp(e) })
		case op < 16:
			w.update(func(e *nodeEdit) { kind = c.approvalOp(e) })
		case op < 18:
			w.update(func(e *nodeEdit) {
				kind = "coalesced"

				for range 2 + r.IntN(3) {
					switch r.IntN(3) {
					case 0:
						c.routeOp(e)
					case 1:
						c.coverOp(e)
					default:
						c.nodeOp(e)
					}
				}
			})
		case op < 19:
			kind = "concurrent"

			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() { w.update(func(e *nodeEdit) { c.nodeOp(e) }) })
			}

			wg.Wait()
		case op < 20:
			kind = "users"

			c.uid++
			u := types.User{ID: c.uid}
			c.randomUserFields(&u)
			c.users = append(c.users, u)
			c.setUsers()
		case op < 24:
			kind = c.policyEdit(before, policies)
		case op < 25:
			kind = "refused policy"
			src := membershipChurnRefused[r.IntN(len(membershipChurnRefused))]
			_, err := w.SetPolicy([]byte(src), noCheck)
			require.NoError(t, err, "step %d: %s", step, src)
		default:
			// Writes no side reads: nothing is computed.
			kind = "quiet"
			ids := before.ListNodes()

			if ids.Len() > 0 {
				id := ids.At(r.IntN(ids.Len())).ID()
				w.UpdateNode(id, func(n *types.Node) {
					n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(r.IntN(65535)))} //nolint:gosec // small
					n.Unhealthy = !n.Unhealthy
				})
			}

			assert.Equal(t, runs, SidesAuditRuns(), "step %d: a quiet write ran the all-pairs audit", step)
			assert.Equal(t, before.sidesRevs().sides, w.snapshot().sidesRevs().sides, "step %d: sides moved", step)
		}

		kinds[kind]++

		after := w.snapshot()
		rep.Add(requireAuditedSides(t, after, "step %d (%s)", step, kind))

		// The incremental election over the via plan agrees with the
		// world's, while the compile in force is current.
		plan := after.viaPlans().Plan
		nodes := after.nodes()

		var touched map[netip.Prefix]struct{}
		if seenAt != nil {
			touched = electionPrefixes(seenAt, nodes)
		}

		shadow = policyv2.ElectVia(shadow, plan, touched, func(candidates views.Slice[types.NodeID], incumbent types.NodeID) (types.NodeID, bool) {
			return electViaPrimary(nodes, candidates, incumbent)
		})
		seenAt = nodes

		if after.PolicyErr() == nil {
			require.True(t, shadow.SameWinners(after.ViaElection()), "step %d (%s): incremental election over the plan", step, kind)
		}
	}
}

// TestWorldSidesShapes drives, through the world's own cells and writes,
// the shapes an update reaches only through another node, which the random
// churn reaches rarely: each world is audited as built and after the one
// write that moves the shape, incremental against a build from scratch and
// against the compile.
func TestWorldSidesShapes(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}, {ID: 3, Name: "carol"}}
	alice, bob, carol := &users[0], &users[1], &users[2]

	tests := []struct {
		name   string
		policy string
		nodes  types.Nodes
		write  func(e *nodeEdit)
	}{
		{
			name: "route-comes-to-cover-a-via-source",
			policy: `{"tagOwners": {"tag:r": []}, "grants": [
				{"src": ["alice@", "carol@"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:r"]}]}`,
			nodes: types.Nodes{
				shapeNode(1, alice, "100.64.0.1", "", nil, nil, nil),
				shapeNode(5, nil, "100.64.0.5", "", []string{"tag:r"}, []string{"10.0.0.0/24"}, nil),
				shapeNode(6, bob, "100.64.0.6", "", nil, nil, nil),
				shapeNode(8, carol, "100.64.0.8", "", nil, nil, nil),
			},
			write: func(e *nodeEdit) { e.Set(6, shapeNode(6, bob, "100.64.0.6", "", nil, []string{"100.64.0.8/30"}, nil)) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w, err := newWorld(tt.nodes, users, []byte(tt.policy), types.DNSView{})
			require.NoError(t, err)

			requireSides(t, w.snapshot(), "as built")

			before := w.snapshot()
			w.update(tt.write)
			after := w.snapshot()

			require.Greater(t, after.Rev(), before.Rev())
			require.True(t, after.SidesAudited())
			requireSides(t, after, "after the write")
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}
