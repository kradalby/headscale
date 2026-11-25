package state

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
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
	"tailscale.com/tailcfg/nodecap"
)

// pinSources returns the options of a world whose capability sources a test
// pins: filter chunks follow their switch, and the default, as everywhere.
func pinSources(capSources bool) worldOptions {
	o := optionsOf(types.PolicyConfig{})
	o.capSources = capSources

	return o
}

func (s *Snapshot) templates() *policyv2.Templates      { return s.s.Get(s.w.templates) }
func (s *Snapshot) approvals() policyv2.SubnetApprovals { return s.s.Get(s.w.approvals) }

// filterAuditOf returns s's templates, membership and compile as the
// filter audit reads them.
func filterAuditOf(s *Snapshot) policyv2.FilterAudit {
	cp := s.s.Get(s.w.policy)
	pm, _ := cp.pm.(*policyv2.PolicyManager)

	return policyv2.FilterAudit{
		Templates: s.templates(),
		Postings:  s.postings(),
		Approvals: s.approvals(),
		Nodes:     s.s.Get(s.w.policyNodes).list,
		Users:     s.s.Get(s.w.policyUsers),
		Policy:    pm,
		Current:   cp.err == nil,
	}
}

// requireFilters requires every node's filter expanded from s's templates
// and postings to equal the compile's, which the audit also checks at
// every commit; calling it here names the mismatch.
func requireFilters(t *testing.T, s *Snapshot, msgAndArgs ...any) policyv2.FilterReport {
	t.Helper()

	rep, err := policyv2.AuditFilters(filterAuditOf(s))
	require.NoError(t, err, msgAndArgs...)

	return rep
}

// filterRevs are the revisions at which the cells the filter audit reads
// last changed.
type filterRevs struct{ templates, approvals, postings, policy uint64 }

func (s *Snapshot) filterRevs() filterRevs {
	return filterRevs{
		templates: graph.ChangedAt(s.s, s.w.templates),
		approvals: graph.ChangedAt(s.s, s.w.approvals),
		postings:  graph.ChangedAt(s.s, s.w.postings),
		policy:    graph.ChangedAt(s.s, s.w.policy),
	}
}

const filterCostPolicy = `{
	"groups": {"group:eng": ["alice@", "carol@"]},
	"tagOwners": {"tag:web": ["alice@"], "tag:db": ["alice@"], "tag:r": ["alice@"]},
	"acls": [
		{"action": "accept", "src": ["group:eng"], "dst": ["tag:web:443"]},
		{"action": "accept", "src": ["*"], "dst": ["tag:db:5432"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
	]}`

// TestWorldFilterCostFollowsChange pins what each kind of write reaches
// among the template and route cells, and when the filter audit runs: an
// endpoint, Hostinfo or health write reaches neither and expands nothing;
// a join reaches the postings, not the templates; an approval reaches the
// approved routes; a port edit keeps the templates of the grants it does
// not touch.
func TestWorldFilterCostFollowsChange(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}, {ID: 3, Name: "carol"}}
	alice, carol := &users[0], &users[2]

	web := worldNode(4, alice, "100.64.0.4")
	web.Tags, web.UserID, web.User = []string{"tag:web"}, nil, nil

	router := worldNode(5, alice, "100.64.0.5")
	router.Tags, router.UserID, router.User = []string{"tag:r"}, nil, nil

	w, err := newWorld(types.Nodes{
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
		worldNode(3, carol, "100.64.0.3"),
		web, router,
	}, users, []byte(filterCostPolicy), types.DNSView{})
	require.NoError(t, err)

	start := w.snapshot()
	requireFilters(t, start)
	require.True(t, start.FilterAudited())

	route := netip.MustParsePrefix("10.0.0.0/24")

	type moves struct{ templates, approvals, postings, audited bool }

	steps := []struct {
		name  string
		write func()
		want  moves
	}{
		{"endpoint", func() {
			w.UpdateNode(1, func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")} })
		}, moves{}},
		{"health", func() { w.UpdateNode(5, func(n *types.Node) { n.Unhealthy = true }) }, moves{}},
		{"announce without approval", func() {
			w.UpdateNode(5, func(n *types.Node) { n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}} })
		}, moves{}},
		{"approve", func() { w.UpdateNode(5, func(n *types.Node) { n.ApprovedRoutes = []netip.Prefix{route} }) }, moves{approvals: true, audited: true}},
		{"withdraw, still approved", func() {
			w.UpdateNode(5, func(n *types.Node) { n.Hostinfo = &tailcfg.Hostinfo{} })
		}, moves{audited: true}},
		// An exit route counts only announced as well.
		{"approve exit routes", func() {
			w.UpdateNode(5, func(n *types.Node) {
				n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"))
			})
		}, moves{}},
		{"announce exit routes", func() {
			w.UpdateNode(5, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}
			})
		}, moves{audited: true}},
		{"join", func() { w.PutNode(*worldNode(6, carol, "100.64.0.6")) }, moves{postings: true, audited: true}},
		{"leave", func() { w.DeleteNode(6) }, moves{postings: true, audited: true}},
		{"address", func() { w.UpdateNode(2, func(n *types.Node) { n.IPv4 = new(netip.MustParseAddr("100.64.0.92")) }) }, moves{audited: true}},
		{"tag", func() {
			w.UpdateNode(3, func(n *types.Node) { n.Tags, n.UserID, n.User = []string{"tag:db"}, nil, nil })
		}, moves{postings: true, audited: true}},
		{"display name", func() {
			users[0].DisplayName = "Alice"
			require.NoError(t, w.SetUsers(users))
		}, moves{}},
		{"port edit", func() {
			_, err := w.SetPolicy([]byte(replaceOnce(filterCostPolicy, "tag:web:443", "tag:web:8443")), noCheck)
			require.NoError(t, err)
		}, moves{templates: true, audited: true}},
	}

	for _, step := range steps {
		before := w.snapshot()
		runs := FilterAuditRuns()

		step.write()

		after := w.snapshot()

		t.Run(step.name, func(t *testing.T) {
			require.Equal(t, before.Rev()+1, after.Rev(), "the write is one commit")

			b, a := before.filterRevs(), after.filterRevs()
			assert.Equal(t, step.want.templates, a.templates != b.templates, "templates moved")
			assert.Equal(t, step.want.approvals, a.approvals != b.approvals, "approved routes moved")
			assert.Equal(t, step.want.postings, a.postings != b.postings, "postings moved")

			audits := uint64(0)
			if step.want.audited {
				audits = 1
			}

			assert.Equal(t, audits, FilterAuditRuns()-runs, "filter audits")
			require.True(t, after.FilterAudited(), "the verdict covers the commit")
			requireFilters(t, after)
		})
	}

	// The port edit kept the templates of the grants it did not touch.
	last := w.snapshot()
	prev := start.templates()
	cur := last.templates()
	require.Len(t, cur.Grants(), len(prev.Grants()))
	assert.NotSame(t, prev.Grants()[0], cur.Grants()[0], "the edited grant")

	for i := 1; i < len(cur.Grants()); i++ {
		assert.Same(t, prev.Grants()[i], cur.Grants()[i], "grant %d kept", i)
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}

// filterChurnOwnRules place merged rules at a receiver's own rules, which
// takes one of a few owners holding a self rule that reaches nothing on a
// node: the focused churn runs them alone, with users fixed.
var filterChurnOwnRules = []string{
	// A receiver's own self rule that reaches nothing there (an exit node
	// routing one family) still places the merged rule of its key.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["bob@"], "dst": ["autogroup:self"], "ip": ["tcp:22"]},
		{"src": ["alice@"], "dst": ["autogroup:self"], "ip": ["tcp:22"]},
		{"src": ["*"], "dst": ["*"], "ip": ["*"]},
		{"src": ["bob@"], "dst": ["tag:a", "tag:b"], "ip": ["tcp:22"]},
		{"src": ["alice@"], "dst": ["10.0.0.0/8", "tag:b"], "ip": ["tcp:22"]}]}`,
	// Self rules merged at a shared rule; a rule whose destinations have
	// no address places nothing; self over several ports.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]},
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
		{"action": "accept", "src": ["alice@"], "dst": ["autogroup:self:22"]},
		{"action": "accept", "src": ["bob@"], "dst": ["tag:b:22"]},
		{"action": "accept", "src": ["bob@"], "dst": ["bob@:22"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:22,80"]}]}`,
}

// filterChurnPolicies are the documents the filter churn switches between:
// every way today's compile places, merges or drops a rule. Variants of
// one document name the same selectors, so templates carry across them.
var filterChurnPolicies = slices.Concat(filterChurnOwnRules, []string{
	``,
	`{"acls": []}`,
	// Equal sources at several positions, a duplicate rule, a rule that
	// reaches no node.
	`{"groups": {"group:a": ["alice@", "carol@example.com"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["group:a"], "dst": ["tag:a:22"]},
		{"action": "accept", "src": ["tag:b"], "dst": ["autogroup:member:80"]},
		{"action": "accept", "src": ["alice@", "carol@example.com"], "dst": ["tag:b:443", "autogroup:member:443"]},
		{"action": "accept", "src": ["group:a"], "dst": ["tag:b:22", "group:a:22"]},
		{"action": "accept", "src": ["group:a"], "dst": ["tag:b:22"]}]}`,
	`{"groups": {"group:a": ["alice@", "carol@example.com"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["alice@", "carol@example.com"], "dst": ["tag:b:443", "autogroup:member:443"]},
		{"action": "accept", "src": ["group:a"], "dst": ["tag:a:2222"]},
		{"action": "accept", "src": ["tag:b"], "dst": ["autogroup:member:80"]},
		{"action": "accept", "src": ["group:a"], "dst": ["tag:b:22", "group:a:22"]},
		{"action": "accept", "src": ["group:a"], "dst": ["tag:b:22"]}]}`,
	// autogroup:self from identities and from *, mixed with other
	// destinations.
	`{"groups": {"group:a": ["alice@", "bob@"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "hosts": {"lan": "100.64.0.0/24"},
	  "acls": [
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:self:22", "lan:22"]},
		{"action": "accept", "src": ["bob@", "group:a"], "dst": ["autogroup:self:443", "tag:a:443"]},
		{"action": "accept", "src": ["alice@"], "dst": ["alice@:443"]}]}`,
	// autogroup:self from single users, which a node sharing a member's
	// address meets.
	`{"acls": [
		{"action": "accept", "src": ["bob@"], "dst": ["autogroup:self:22"]},
		{"action": "accept", "src": ["alice@", "carol@example.com"], "dst": ["autogroup:self:80", "bob@:80"]}]}`,
	// Via, with and without the internet, and a regular rule from the
	// same sources.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["alice@", "tag:a"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:b"]},
		{"src": ["alice@", "tag:a"], "dst": ["10.0.0.0/24", "autogroup:internet"], "ip": ["tcp:22"], "via": ["tag:b"]},
		{"src": ["alice@", "tag:a"], "dst": ["autogroup:internet"], "ip": ["*"], "via": ["tag:a", "tag:b"]},
		{"src": ["alice@", "tag:a"], "dst": ["10.0.0.0/24"], "ip": ["*"]},
		{"src": ["autogroup:member"], "dst": ["tag:b"], "ip": ["*"], "via": ["tag:b"], "app": {"example.com/cap/x": [{}]}}]}`,
	// App capabilities: companions both ways, a source naming nobody,
	// with and without ip.
	`{"groups": {"group:a": ["alice@", "carol@example.com"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["group:a"], "dst": ["tag:a", "tag:b"], "app": {"tailscale.com/cap/drive": [{"shares": ["*"], "access": "rw"}]}},
		{"src": ["*"], "dst": ["*"], "app": {"tailscale.com/cap/relay": [{}]}},
		{"src": ["autogroup:member"], "dst": ["autogroup:self"], "ip": ["tcp:22"], "app": {"tailscale.com/cap/drive": [{"shares": ["*"]}]}},
		{"src": ["nobody@"], "dst": ["tag:a"], "app": {"example.com/cap/x": [{}]}},
		{"src": ["group:a"], "dst": ["tag:a"], "ip": ["tcp:443", "udp:53"], "app": {"example.com/cap/y": [{"v": 1}]}}]}`,
	// Address sources and destinations, protocols.
	`{"groups": {"group:a": ["alice@"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["autogroup:danger-all"], "dst": ["tag:a:*"]},
		{"action": "accept", "src": ["*"], "dst": ["autogroup:internet:*", "10.0.0.0/8:*"]},
		{"action": "accept", "src": ["group:a", "autogroup:tagged"], "dst": ["*:22"]},
		{"action": "accept", "proto": "udp", "src": ["group:a"], "dst": ["tag:b:53"]},
		{"action": "accept", "src": ["*", "group:a"], "dst": ["tag:b:80"]}]}`,
	`{"groups": {"group:a": ["alice@", "bob@"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["group:a"], "dst": ["tag:a"], "ip": ["tcp:22", "udp:53", "icmp:*", "gre:*"]},
		{"src": ["autogroup:member"], "dst": ["tag:a", "autogroup:self"], "ip": ["tcp:22"]},
		{"src": ["group:a"], "dst": ["tag:b"], "ip": ["tcp:22"]}]}`,
	// Companions of * to a tag and of identities to *.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["*"], "dst": ["tag:a"], "app": {"tailscale.com/cap/drive": [{}]}},
		{"src": ["alice@", "tag:b"], "dst": ["*"], "app": {"tailscale.com/cap/relay": [{}]}}]}`,
	// The internet and a public prefix through a via router, which only
	// an exit node serves the internet for.
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["alice@", "tag:a"], "dst": ["autogroup:internet", "8.8.8.0/24"], "ip": ["*"], "via": ["tag:b"]},
		{"src": ["alice@", "tag:a"], "dst": ["8.8.8.0/24", "10.0.0.0/8"], "ip": ["tcp:443"]}]}`,
	// One table, two prefixes for a host: kept templates, new literals.
	`{"hosts": {"lan": "10.0.0.0/24"}, "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["lan", "alice@"], "dst": ["tag:a:22", "lan:80"]},
		{"action": "accept", "src": ["*"], "dst": ["lan:443"]}]}`,
	`{"hosts": {"lan": "100.64.0.0/16"}, "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "acls": [
		{"action": "accept", "src": ["lan", "alice@"], "dst": ["tag:a:22", "lan:80"]},
		{"action": "accept", "src": ["*"], "dst": ["lan:443"]}]}`,
})

// TestWorldFiltersUnderRandomChurn drives random writes of every kind the
// filter reads, many in one commit, and requires every node's filter
// expanded from the incrementally maintained templates and postings to
// equal the compile's after each, the templates to equal a build from
// scratch, and the audit to run at every commit that can change either
// side and at no other.
func TestWorldFiltersUnderRandomChurn(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	var shapes policyv2.FilterShapes

	for seed := range uint64(4) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			shapes.Add(filterChurn(t, rand.New(rand.NewPCG(seed, 23)), filterChurnPolicies, true)) //nolint:gosec // deterministic test input
		})
	}

	for seed := range uint64(2) {
		t.Run(fmt.Sprintf("own-rules/seed=%d", seed), func(t *testing.T) {
			shapes.Add(filterChurn(t, rand.New(rand.NewPCG(seed, 29)), filterChurnOwnRules, false)) //nolint:gosec // deterministic test input
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")

	t.Logf("shapes cut: %+v", shapes)

	// A shape no seed reaches tests nothing.
	for name, n := range map[string]int{
		"exit receivers": shapes.Exit, "routed receivers": shapes.Routed, "self rules": shapes.Self,
		"via rules": shapes.Via, "capability rules": shapes.CapGrant, "companion rules": shapes.Companion,
		"rules with cap sources": shapes.Capped, "rules merged at a rule that does not reach the receiver": shapes.Anchored,
		"rules merged at a receiver's own rule that reaches nothing": shapes.OwnAnchored,
	} {
		assert.Positive(t, n, name)
	}
}

// familyOp gives a node one family only, or moves both its addresses.
func (c *churnRun) familyOp(e *nodeEdit) {
	ids := make([]types.NodeID, 0, e.Len())
	for id := range e.All() {
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return
	}

	slices.Sort(ids)

	n := mustGet(c.t, e, ids[c.r.IntN(len(ids))]).Clone()

	// The whole id, so no two nodes the churn can build share an
	// address: a shared one is a world the server refuses to start on.
	hi, lo := byte(n.ID>>8), byte(n.ID) //nolint:gosec // a few hundred nodes

	switch c.r.IntN(3) {
	case 0:
		n.IPv4 = nil
		n.IPv6 = new(netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: 0x40 | hi, 15: lo}))
	case 1:
		n.IPv4 = new(netip.AddrFrom4([4]byte{100, 66, hi, lo}))
		n.IPv6 = nil
	default:
		n.IPv4 = new(netip.AddrFrom4([4]byte{100, 66, hi, lo}))
		n.IPv6 = new(netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: 0x40 | hi, 15: lo}))
	}

	e.Set(n.ID, n)
}

// routeOp is one random change to a node's routes, staged on e: approved
// and announced, approved only, announced only, an exit node, or none.
// The routes overlap each other and the tailnet's own addresses.
func (c *churnRun) routeOp(e *nodeEdit) {
	ids := make([]types.NodeID, 0, e.Len())
	for id := range e.All() {
		ids = append(ids, id)
	}

	if len(ids) == 0 {
		return
	}

	slices.Sort(ids)

	n := mustGet(c.t, e, ids[c.r.IntN(len(ids))]).Clone()

	pool := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("100.64.0.0/24"),
		netip.MustParsePrefix("fd7a:115c:a1e0::/120"),
		netip.MustParsePrefix("8.8.8.0/24"),
	}
	exits := [][]netip.Prefix{
		{netip.MustParsePrefix("0.0.0.0/0")},
		{netip.MustParsePrefix("::/0")},
		{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
	}

	pick := func() []netip.Prefix {
		var out []netip.Prefix

		for _, p := range pool {
			if c.r.IntN(3) == 0 {
				out = append(out, p)
			}
		}

		if c.r.IntN(3) == 0 {
			out = append(out, exits[c.r.IntN(len(exits))]...)
		}

		return out
	}

	announced, approved := pick(), pick()

	switch c.r.IntN(4) {
	case 0:
		approved = announced
	case 1:
		announced = nil
	case 2:
		approved = nil
	}

	if n.Hostinfo == nil {
		n.Hostinfo = &tailcfg.Hostinfo{}
	} else {
		n.Hostinfo = n.Hostinfo.Clone()
	}

	n.Hostinfo.RoutableIPs = announced
	n.ApprovedRoutes = approved
	e.Set(n.ID, n)
}

// filterChurn drives one seed over policies; with users unset, the user
// list stays as it starts, so the policies' user tokens keep their owners.
func filterChurn(t *testing.T, r *rand.Rand, policies []string, users bool) policyv2.FilterShapes {
	t.Helper()

	// Addresses of one width make merges across paths come up; the family
	// op and M1's churn, which runs this audit too, give the rest.
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

	kinds := map[string]int{}
	fresh := 0

	var shapes policyv2.FilterShapes

	for step := range 400 {
		runs := FilterAuditRuns()

		// A generator step that built what the server refuses to start
		// on fails here, not in a count only a refused world can move.
		c.requireStartable()

		var kind string

		switch op := r.IntN(24); {
		case op < 8:
			w.update(func(e *nodeEdit) { kind = c.nodeOp(e) })
		case op < 10:
			kind = "routes"

			w.update(c.routeOp)
		case op < 11:
			kind = "family"

			w.update(c.familyOp)
		case op < 13:
			// Writes landing in one commit.
			w.update(func(e *nodeEdit) {
				kind = "coalesced"

				for range 2 + r.IntN(3) {
					if r.IntN(2) == 0 {
						c.routeOp(e)
					} else {
						c.nodeOp(e)
					}
				}
			})
		case op < 14:
			kind = "concurrent"

			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() { w.update(func(e *nodeEdit) { c.nodeOp(e) }) })
			}

			wg.Wait()
		case op < 16 && !users:
			w.update(func(e *nodeEdit) { kind = c.nodeOp(e) })
		case op < 16:
			kind = "users"

			switch r.IntN(3) {
			case 0:
				c.uid++
				u := types.User{ID: c.uid}
				c.randomUserFields(&u)
				c.users = append(c.users, u)
			case 1:
				if len(c.users) > 0 {
					c.randomUserFields(&c.users[r.IntN(len(c.users))])
				}
			default:
				r.Shuffle(len(c.users), func(i, j int) { c.users[i], c.users[j] = c.users[j], c.users[i] })
			}

			c.setUsers()
		case op < 21:
			kind = "policy"
			src := policies[r.IntN(len(policies))]
			_, err := w.SetPolicy([]byte(src), noCheck)
			require.NoError(t, err, "step %d: %s", step, src)
		case op < 22:
			kind = "refused policy"
			src := membershipChurnRefused[r.IntN(len(membershipChurnRefused))]
			_, err := w.SetPolicy([]byte(src), noCheck)
			require.NoError(t, err, "step %d: %s", step, src)
		default:
			// Writes no filter reads: nothing may be expanded.
			kind = "quiet"
			before := w.snapshot()
			ids := before.ListNodes()

			if ids.Len() > 0 {
				id := ids.At(r.IntN(ids.Len())).ID()
				w.UpdateNode(id, func(n *types.Node) {
					n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(r.IntN(65535)))} //nolint:gosec // small
					n.Unhealthy = !n.Unhealthy
				})
			}

			assert.Equal(t, runs, FilterAuditRuns(), "step %d: a quiet write ran the filter audit", step)
			assert.Equal(t, before.filterRevs().templates, w.snapshot().filterRevs().templates, "step %d: templates moved", step)
		}

		kinds[kind]++

		after := w.snapshot()
		rep := requireFilters(t, after, "step %d (%s)", step, kind)
		shapes.Add(rep.Shapes)

		if rep.Fresh {
			fresh++
		}

		require.True(t, after.FilterAudited(), "step %d (%s): the last change was audited", step, kind)

		if kind == "join" || kind == "leave" || kind == "tag" || kind == "routes" {
			assert.LessOrEqual(t, FilterAuditRuns()-runs, uint64(1), "step %d: one commit, one audit", step)
		}
	}

	for _, k := range []string{"join", "leave", "tag", "owner", "address", "routes", "family", "coalesced", "concurrent", "policy", "refused policy", "quiet"} {
		assert.Positive(t, kinds[k], "no %s write", k)
	}

	if users {
		assert.Positive(t, kinds["users"], "no users write")
	}

	assert.Positive(t, fresh, "no step audited against a compile afresh, as a refused document makes")

	t.Logf("writes: %v; shapes: %+v", kinds, shapes)

	return shapes
}

// TestWorldFilterFollowsMembershipUnderRefusedPolicy pins what the
// expansion does while a refused document stands: the last good compile
// keeps serving, compiled against the nodes of its time, so a node joining
// since reaches no filter it serves; the expansion follows the join under
// the same last good policy. That is the behaviour decided for the switch:
// freezing filters there is a quirk of the compile, not intent. The audit
// checks the expansion against that policy compiled afresh.
func TestWorldFilterFollowsMembershipUnderRefusedPolicy(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	const good = `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:22"]}]}`

	users := []types.User{{ID: 1, Name: "alice"}}

	w, err := newWorld(types.Nodes{worldNode(1, &users[0], "100.64.0.1")}, users, []byte(good), types.DNSView{})
	require.NoError(t, err)

	_, err = w.SetPolicy([]byte(`{"acls": [`), noCheck)
	require.NoError(t, err)
	require.Error(t, w.snapshot().PolicyErr(), "the document does not compile")

	w.PutNode(*worldNode(2, &users[0], "100.64.0.2"))

	s := w.snapshot()
	require.Error(t, s.PolicyErr(), "still refused")

	node1, ok := s.GetNode(1)
	require.True(t, ok)

	pm, ok := s.Policy().(*policyv2.PolicyManager)
	require.True(t, ok, "test sanity: a v2 policy")

	compiled, err := pm.FilterForNode(node1)
	require.NoError(t, err)
	assert.Equal(t, []string{"100.64.0.1"}, compiled[0].SrcIPs, "the compile in force is frozen at its own nodes")

	rep := requireFilters(t, s)
	assert.True(t, rep.Fresh, "audited against the last good document compiled afresh")
	require.True(t, s.FilterAudited())

	x, err := policyv2.NewExpansion(s.templates(), s.postings(), s.approvals().Strings(), s.GetNode)
	require.NoError(t, err)

	expanded := x.FilterForNode(node1)
	assert.Equal(t, []string{"100.64.0.1", "100.64.0.2"}, expanded[0].SrcIPs, "the expansion follows the join under the last good policy")

	assert.Zero(t, PolicyAuditFailures()-failures)
}

// TestWorldServedFilterFollowsMembership reads each node's served filter
// as a session would, before and after each write, and holds it to what
// the writes give, worked out by hand: a filter read before a join, a
// leave or an address change must not be served after it.
func TestWorldServedFilterFollowsMembership(t *testing.T) {
	// Pinned to address form: it pins the sources a join writes into a filter; in capability form the filter names the selector and the stamps follow membership (TestWorldStampsFollowMembership).
	t.Setenv(TestCapabilitySourcesEnv, "false")

	const src = `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:22"]}]}`

	users := []types.User{{ID: 1, Name: "alice"}}

	w, err := newWorld(types.Nodes{worldNode(1, &users[0], "100.64.0.1"), worldNode(2, &users[0], "100.64.0.2")}, users, []byte(src), types.DNSView{})
	require.NoError(t, err)

	sources := func(id types.NodeID) []string {
		t.Helper()

		snap := w.snapshot()

		rules, err := snap.FilterForNode(id)
		require.NoError(t, err)
		require.Len(t, rules, 1)

		// Read twice, as two sessions of one snapshot do: one slice.
		again, err := snap.FilterForNode(id)
		require.NoError(t, err)
		require.Same(t, &rules[0], &again[0])

		return rules[0].SrcIPs
	}

	assert.Equal(t, []string{"100.64.0.1", "100.64.0.2"}, sources(1))

	w.PutNode(*worldNode(3, &users[0], "100.64.0.3"))
	assert.Equal(t, []string{"100.64.0.1", "100.64.0.2", "100.64.0.3"}, sources(1), "a join reaches a filter read before it")

	_, ok := w.UpdateNode(2, func(n *types.Node) { n.IPv4 = new(netip.MustParseAddr("100.64.0.9")) })
	require.True(t, ok)
	assert.Equal(t, []string{"100.64.0.1", "100.64.0.3", "100.64.0.9"}, sources(1), "an address change too")

	w.DeleteNode(3)
	assert.Equal(t, []string{"100.64.0.1", "100.64.0.9"}, sources(1), "and a leave")

	_, ok = w.UpdateNode(1, func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")} })
	require.True(t, ok)
	assert.Equal(t, []string{"100.64.0.1", "100.64.0.9"}, sources(1), "a write no policy reads keeps the filter")
}

// TestWorldServesMembershipUnderRefusedPolicy pins what is served and
// routed while a refused document stands: the served filter follows a join
// under the last good policy while the compile does not, and change
// routing, which reads what is served, follows it too: the join wakes the
// nodes whose filter it changed, and the refusal and the first compile
// after it, which move nothing served, wake nobody.
func TestWorldServesMembershipUnderRefusedPolicy(t *testing.T) {
	// Pinned to address form: it pins the sources a join writes into a filter under a refused document; in capability form the filter names the selector.
	t.Setenv(TestCapabilitySourcesEnv, "false")

	const good = `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:22"]}]}`

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}

	// bob's node is in no rule: a change to alice's rules does not reach it.
	w, err := newWorld(types.Nodes{worldNode(1, &users[0], "100.64.0.1"), worldNode(3, &users[1], "100.64.0.3")},
		users, []byte(good), types.DNSView{})
	require.NoError(t, err)

	accepted := w.snapshot()

	_, err = w.SetPolicy([]byte(`{"acls": [`), noCheck)
	require.NoError(t, err)

	refused := w.snapshot()
	require.Error(t, refused.PolicyErr())

	c := refused.Since(accepted)
	assert.False(t, c.Global, "a refusal serves nothing new")
	assert.Empty(t, c.Filters, "a refusal serves nothing new")

	w.PutNode(*worldNode(2, &users[0], "100.64.0.2"))

	joined := w.snapshot()
	node1, ok := joined.GetNode(1)
	require.True(t, ok)

	served, err := joined.FilterForNode(1)
	require.NoError(t, err)
	assert.Equal(t, []string{"100.64.0.1", "100.64.0.2"}, served[0].SrcIPs, "the served filter follows the join under the last good policy")

	pm, ok := joined.Policy().(*policyv2.PolicyManager)
	require.True(t, ok, "test sanity: a v2 policy")

	frozen, err := pm.FilterForNode(node1)
	require.NoError(t, err)
	assert.Equal(t, []string{"100.64.0.1"}, frozen[0].SrcIPs, "the compile is frozen, and routing does not read it")

	c = joined.Since(refused)
	assert.False(t, c.Global, "routing follows what is served")
	assert.Equal(t, []types.NodeID{1, 2}, c.Filters, "the join reaches the filter it changed")

	_, ok = w.UpdateNode(2, func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")} })
	require.True(t, ok)

	quiet := w.snapshot()
	c = quiet.Since(joined)
	assert.False(t, c.Global, "a write no policy reads recompiles nothing")
	assert.Empty(t, c.Filters, "a write no policy reads recompiles nothing")

	_, err = w.SetPolicy([]byte(good), noCheck)
	require.NoError(t, err)

	fixed := w.snapshot()
	require.NoError(t, fixed.PolicyErr())

	c = fixed.Since(quiet)
	assert.False(t, c.Global, "the first compile after a refusal serves what was served")
	assert.Empty(t, c.Filters, "the first compile after a refusal serves what was served")
}

// shapeNode is a node of the shapes test: owner (nil for tagged), one or
// both addresses, tags, routes announced and approved, routes approved only.
func shapeNode(id types.NodeID, user *types.User, v4, v6 string, tags []string, routes, only []string) *types.Node {
	n := worldNode(id, &types.User{}, "100.64.0.1")
	n.IPv4, n.UserID, n.User, n.Tags = nil, nil, nil, tags
	n.GivenName = fmt.Sprintf("n%d", id)

	if user != nil {
		n.User, n.UserID = user, &user.ID
	}

	if v4 != "" {
		n.IPv4 = new(netip.MustParseAddr(v4))
	}

	if v6 != "" {
		n.IPv6 = new(netip.MustParseAddr(v6))
	}

	for _, r := range routes {
		p := netip.MustParsePrefix(r)
		n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, p)
		n.ApprovedRoutes = append(n.ApprovedRoutes, p)
	}

	for _, r := range only {
		n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix(r))
	}

	return n
}

// TestWorldFilterShapes runs, through the world's own cells and writes,
// the shapes whose mistakes the random churn reaches rarely or not at all:
// each world is audited as built and after one write that moves the shape.
// The audit holds the expansion to the compile; the shapes are those of
// TestExpanderQuirks, reached here incrementally.
func TestWorldFilterShapes(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}
	alice, bob := &users[0], &users[1]

	const owners = `"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]}`

	tests := []struct {
		name   string
		policy string
		nodes  types.Nodes
		write  func(w *world)
	}{
		{
			// A tag without members places nothing.
			name: "no-address-no-place",
			policy: `{` + owners + `, "acls": [
				{"action": "accept", "src": ["alice@"], "dst": ["tag:a:22"]},
				{"action": "accept", "src": ["*"], "dst": ["*:*"]},
				{"action": "accept", "src": ["alice@"], "dst": ["alice@:22"]}]}`,
			nodes: types.Nodes{
				shapeNode(1, alice, "100.64.0.1", "", nil, nil, nil),
			},
			write: func(w *world) { w.PutNode(*shapeNode(3, alice, "100.64.0.3", "", nil, nil, nil)) },
		},
		{
			// Unannounced exit routes make no exit node.
			name: "unannounced-exit",
			policy: `{` + owners + `, "acls": [
				{"action": "accept", "src": ["alice@"], "dst": ["autogroup:self:22"]},
				{"action": "accept", "src": ["*"], "dst": ["*:*"]},
				{"action": "accept", "src": ["alice@"], "dst": ["tag:b:22"]}]}`,
			nodes: types.Nodes{
				shapeNode(1, alice, "100.64.0.1", "", nil, nil, nil),
				shapeNode(2, nil, "100.64.0.30", "", []string{"tag:b"}, nil, []string{"0.0.0.0/0", "::/0"}),
			},
			write: func(w *world) { w.PutNode(*shapeNode(3, alice, "100.64.0.3", "", nil, nil, nil)) },
		},
		{
			// Via takes announced approvals only.
			name: "via-unannounced",
			policy: `{` + owners + `, "grants": [
				{"src": ["alice@"], "dst": ["100.64.0.0/24"], "ip": ["*"], "via": ["tag:b"]}]}`,
			nodes: types.Nodes{
				shapeNode(1, alice, "100.64.0.1", "", nil, nil, nil),
				shapeNode(2, nil, "100.64.0.11", "", []string{"tag:b"}, nil, []string{"100.64.0.0/24"}),
			},
			write: func(w *world) { w.PutNode(*shapeNode(3, alice, "100.64.0.3", "", nil, nil, nil)) },
		},
		{
			// * next to an identity source adds the approved routes.
			name:   "wildcard-with-identity",
			policy: `{` + owners + `, "acls": [{"action": "accept", "src": ["*", "alice@"], "dst": ["tag:a:22"]}]}`,
			nodes: types.Nodes{
				shapeNode(1, alice, "100.64.0.1", "", nil, nil, nil),
				shapeNode(2, nil, "100.64.0.10", "", []string{"tag:a"}, nil, nil),
				shapeNode(3, nil, "100.64.0.20", "", []string{"tag:b"}, []string{"10.0.0.0/24"}, nil),
			},
			write: func(w *world) {
				w.UpdateNode(3, func(n *types.Node) { n.ApprovedRoutes = append(n.ApprovedRoutes, netip.MustParsePrefix("10.1.0.0/24")) })
			},
		},
		{
			// An exit node routing one family: bob's self rule reaches
			// nothing there and still places the merged rule.
			name: "own-rule-on-exit",
			policy: `{` + owners + `, "grants": [
				{"src": ["bob@"], "dst": ["autogroup:self"], "ip": ["tcp:22"]},
				{"src": ["*"], "dst": ["*"], "ip": ["*"]},
				{"src": ["bob@"], "dst": ["tag:b"], "ip": ["tcp:22"]}]}`,
			nodes: types.Nodes{
				shapeNode(1, bob, "", "fd7a:115c:a1e0::2", nil, nil, nil),
				shapeNode(2, nil, "100.64.0.30", "fd7a:115c:a1e0::1e", []string{"tag:b"}, []string{"0.0.0.0/0"}, nil),
			},
			write: func(w *world) {
				w.UpdateNode(2, func(n *types.Node) {
					n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
				})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w, err := newWorld(tc.nodes, users, []byte(tc.policy), types.DNSView{})
			require.NoError(t, err)

			requireFilters(t, w.snapshot(), "as built")
			require.True(t, w.snapshot().FilterAudited())

			tc.write(w)

			requireFilters(t, w.snapshot(), "after the write")
			require.True(t, w.snapshot().FilterAudited())
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}

// TestPolicyAuditLeavesServedFiltersAlone pins that the policy audit
// observes the served filters as production serves them rather than
// serving them its own way: a commit cuts no served filter and works out
// no change, so filters are carried across commits nobody read; a filter
// read is held to one cut afresh.
func TestPolicyAuditLeavesServedFiltersAlone(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}, {ID: 3, Name: "carol"}}
	alice, carol := &users[0], &users[2]

	w, err := newWorld(types.Nodes{
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
		worldNode(3, carol, "100.64.0.3"),
	}, users, []byte(filterCostPolicy), types.DNSView{})
	require.NoError(t, err)

	for _, id := range []types.NodeID{1, 2, 3} {
		_, err := w.snapshot().FilterForNode(id)
		require.NoError(t, err)
	}

	audits, cuts := FilterAuditRuns(), FilterCuts()

	w.PutNode(*worldNode(4, carol, "100.64.0.4"))
	w.PutNode(*worldNode(5, alice, "100.64.0.5"))

	require.Equal(t, audits+2, FilterAuditRuns(), "test sanity: both joins were audited")
	assert.Equal(t, cuts, FilterCuts(), "the audit cut no filter at the commits")

	served := ServedAuditRuns()

	for _, id := range []types.NodeID{1, 2, 3, 4, 5} {
		_, err := w.snapshot().FilterForNode(id)
		require.NoError(t, err)
	}

	assert.Equal(t, served+5, ServedAuditRuns(), "every filter read was held to a fresh cut")
	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}

// capWorldNode is worldNode, tagged when tags are given.
func capWorldNode(id types.NodeID, user *types.User, ip string, tags ...string) *types.Node {
	if user == nil {
		user = &types.User{}
	}

	n := worldNode(id, user, ip)

	if len(tags) > 0 {
		n.Tags, n.UserID, n.User = tags, nil, nil
	}

	return n
}

const capGroupPolicy = `{
	"groups": {"group:eng": ["alice@"]},
	"tagOwners": {"tag:web": ["alice@"]},
	"grants": [{"src": ["group:eng"], "dst": ["tag:web"], "ip": ["tcp:443"]}]
}`

// TestWorldStampsFollowMembership pins the stamps in capability mode: a
// member is stamped with the selectors some rule can name, as a peer and as
// itself; a join stamps the joiner and leaves the receiver's filter as it
// was; a group edit takes the stamps away and names the nodes whose stamps
// moved in Change.Caps, which wakes their viewers. Without capability
// sources nothing is stamped.
func TestWorldStampsFollowMembership(t *testing.T) {
	const eng = "https://headscale.net/cap/src/group:eng"

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}

	nodes := func() types.Nodes {
		return types.Nodes{capWorldNode(1, nil, "100.64.0.10", "tag:web"), capWorldNode(2, &users[0], "100.64.0.1"), capWorldNode(3, &users[1], "100.64.0.2")}
	}

	off, err := newWorldMode(nodes(), users, []byte(capGroupPolicy), types.DNSView{}, pinSources(false))
	require.NoError(t, err)

	if !off.capSources {
		require.Empty(t, off.snapshot().Stamps(2), "address mode stamps nothing")
		require.NotContains(t, off.snapshot().NodeCaps(2), nodecap.Cap(eng))
	}

	w, err := newWorldMode(nodes(), users, []byte(capGroupPolicy), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	snap := w.snapshot()
	require.Equal(t, policyv2.Stamps{eng}, snap.Stamps(2))
	require.Contains(t, snap.NodeCaps(2), nodecap.Cap(eng), "rendered with its stamps")
	require.Empty(t, snap.Stamps(3), "bob holds no selector a rule names")
	require.Empty(t, snap.Stamps(1), "tag:web is named by no source")

	web, err := snap.FilterForNode(1)
	require.NoError(t, err)
	require.Len(t, web, 1)
	require.Equal(t, []string{"cap:" + eng}, web[0].SrcIPs)

	before := w.snapshot()
	w.PutNode(*capWorldNode(4, &users[0], "100.64.0.4"))

	after := w.snapshot()
	require.Equal(t, policyv2.Stamps{eng}, after.Stamps(4), "the joiner is stamped")

	again, err := after.FilterForNode(1)
	require.NoError(t, err)
	require.Equal(t, web, again, "a join leaves the receiver's capability form as it was")

	c := after.Since(before)
	require.Contains(t, c.Caps, types.NodeID(4))

	before = after

	_, err = w.SetPolicy([]byte(strings.Replace(capGroupPolicy, `["alice@"]`, `["bob@"]`, 1)), noCheck)
	require.NoError(t, err)

	after = w.snapshot()
	require.Empty(t, after.Stamps(2), "alice left group:eng")
	require.NotContains(t, after.NodeCaps(2), nodecap.Cap(eng))
	require.Equal(t, policyv2.Stamps{eng}, after.Stamps(3), "bob joined it")

	c = after.Since(before)
	for _, id := range []types.NodeID{2, 3, 4} {
		require.Containsf(t, c.Caps, id, "node %d's stamps moved: its viewers render it again", id)
	}
}

// TestWorldReceiverFactsFlipFilterForm pins that what a node announces and
// what its client is, no policy facts, flip the form of its filter, are
// routed to it and are not served stale from the carried cache: announcing
// a route it is not approved for sends it addresses, as does reporting
// TestServedAuditHoldsWideLocalNetsToAddresses: the audit of a served
// filter refuses a capability source on a node that announces a route, is
// an app connector or hosts a service IP, from the node itself and not
// fallback.go's decision, and leaves a node handling its own addresses
// alone; the filters served to both pass it.
func TestServedAuditHoldsWideLocalNetsToAddresses(t *testing.T) {
	users := []types.User{{ID: 1, Name: "alice"}}
	pol := `{"groups": {"group:eng": ["alice@"]},
		"tagOwners": {"tag:web": ["alice@"], "tag:svc": ["alice@"]},
		"nodeAttrs": [{"target": ["tag:svc"], "attr": ["service-host"]}],
		"grants": [{"src": ["group:eng"], "dst": ["tag:web", "tag:svc"], "ip": ["tcp:443"]}]}`

	router := capWorldNode(1, nil, "100.64.0.10", "tag:web")
	router.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}
	connector := capWorldNode(3, nil, "100.64.0.11", "tag:web")
	connector.Hostinfo.AppConnector.Set(true)

	w, err := newWorldMode(types.Nodes{
		router, capWorldNode(2, &users[0], "100.64.0.1"), connector,
		capWorldNode(4, nil, "100.64.0.12", "tag:svc"), capWorldNode(5, nil, "100.64.0.13", "tag:web"),
	}, users, []byte(pol), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	s := w.snapshot()
	sent := []tailcfg.FilterRule{{SrcIPs: []string{"cap:https://headscale.net/cap/src/group:eng"}}}

	for _, id := range []types.NodeID{1, 3, 4} {
		require.ErrorIs(t, s.auditLocalNetsForm(id, sent), errServedForm, "node %d", id)

		served, err := s.FilterForNode(id)
		require.NoError(t, err)
		require.NoError(t, s.auditLocalNetsForm(id, served), "node %d is served addresses", id)
	}

	require.NoError(t, s.auditLocalNetsForm(5, sent), "a node handling its own addresses may be sent capabilities")
}

// another client; undoing either sends it capabilities again.
func TestWorldReceiverFactsFlipFilterForm(t *testing.T) {
	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}

	w, err := newWorldMode(types.Nodes{capWorldNode(1, nil, "100.64.0.10", "tag:web"), capWorldNode(2, &users[0], "100.64.0.1")},
		users, []byte(capGroupPolicy), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	sources := func() []string {
		t.Helper()

		rules, err := w.snapshot().FilterForNode(1)
		require.NoError(t, err)
		require.Len(t, rules, 1)

		return rules[0].SrcIPs
	}

	capForm := []string{"cap:https://headscale.net/cap/src/group:eng"}
	require.Equal(t, capForm, sources())

	flip := func(what string, fn func(*types.Node), want []string) {
		t.Helper()

		before := w.snapshot()

		_, ok := w.UpdateNode(1, func(n *types.Node) {
			n.Hostinfo = n.Hostinfo.Clone()
			fn(n)
		})
		require.True(t, ok)

		after := w.snapshot()
		require.Equalf(t, after.PolicyRev(), before.PolicyRev(), "%s: no policy fact moved", what)
		require.Containsf(t, after.Since(before).Filters, types.NodeID(1), "%s: routed to the node", what)
		require.Equalf(t, want, sources(), "%s", what)
	}

	flip("announcing a route", func(n *types.Node) { n.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")} },
		[]string{"100.64.0.1"})
	flip("announcing none", func(n *types.Node) { n.Hostinfo.RoutableIPs = nil }, capForm)
	flip("another client", func(n *types.Node) { n.Hostinfo.GoVersion, n.Hostinfo.App = "", "tailscale-rs" }, []string{"100.64.0.1"})
	flip("the official client", func(n *types.Node) { n.Hostinfo.GoVersion, n.Hostinfo.App = "go1.27.3", "" }, capForm)
	flip("an app connector", func(n *types.Node) { n.Hostinfo.AppConnector.Set(true) }, []string{"100.64.0.1"})
}

// TestWorldAddressModeDoesNoNewWork pins that address mode registers and
// builds nothing capability sources need: a census read, as each metrics
// scrape makes, builds no expansion.
func TestWorldAddressModeDoesNoNewWork(t *testing.T) {
	t.Setenv(TestCapabilitySourcesEnv, "false")
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "")

	users := []types.User{{ID: 1, Name: "alice"}}

	w, err := newWorldMode(types.Nodes{capWorldNode(1, nil, "100.64.0.10", "tag:web"), capWorldNode(2, &users[0], "100.64.0.1")},
		users, []byte(capGroupPolicy), types.DNSView{}, pinSources(false))
	require.NoError(t, err)

	snap := w.snapshot()
	builds := ExpansionBuilds()

	census, err := snap.FallbackCensus()
	require.NoError(t, err)
	require.Equal(t, policyv2.FallbackCensus{}, census)
	require.Equal(t, builds, ExpansionBuilds(), "a census read builds no expansion")

	require.False(t, snap.AddressHolders().Valid())
	require.Equal(t, policyv2.ReceiverFacts{}, snap.ReceiverFacts(2))
	require.Empty(t, snap.Stamps(2))
	require.False(t, w.capSources, "the capability cells are not registered")
}

// TestWorldCarriedFormAfterFlip pins that a filter carried over a commit
// is carried in the form it was cut in: after a join that moves the
// address form, a node flipping to address form is sent the joiner's
// address; after one moving neither, each form is carried as itself.
func TestWorldCarriedFormAfterFlip(t *testing.T) {
	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}

	w, err := newWorldMode(types.Nodes{capWorldNode(1, nil, "100.64.0.10", "tag:web"), capWorldNode(2, &users[0], "100.64.0.1")},
		users, []byte(capGroupPolicy), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	sources := func() []string {
		t.Helper()

		rules, err := w.snapshot().FilterForNode(1)
		require.NoError(t, err)
		require.Len(t, rules, 1)

		return rules[0].SrcIPs
	}

	announce := func(routes ...netip.Prefix) {
		_, ok := w.UpdateNode(1, func(n *types.Node) {
			n.Hostinfo = n.Hostinfo.Clone()
			n.Hostinfo.RoutableIPs = routes
		})
		require.True(t, ok)
	}

	route := netip.MustParsePrefix("10.9.0.0/24")
	capForm := []string{"cap:https://headscale.net/cap/src/group:eng"}

	// Both forms cut under one filters.
	announce(route)
	require.Equal(t, []string{"100.64.0.1"}, sources())
	announce()
	require.Equal(t, capForm, sources())

	w.PutNode(*capWorldNode(3, &users[0], "100.64.0.3"))
	require.Equal(t, capForm, sources(), "the capability form is carried")

	announce(route)
	require.Equal(t, []string{"100.64.0.1", "100.64.0.3"}, sources(), "the address form is cut again")

	// A join moving neither form carries each as it was cut.
	announce()
	require.Equal(t, capForm, sources())

	w.PutNode(*capWorldNode(4, &users[1], "100.64.0.4"))
	require.Equal(t, capForm, sources())

	announce(route)
	require.Equal(t, []string{"100.64.0.1", "100.64.0.3"}, sources(), "the address form is carried as address form")
}

// TestWorldStampsFollowRetag pins that a node's stamps follow its role
// set: a retag away from the tag a rule names takes its stamp, and an
// owned node tagged trades its user's selectors for the tag's.
func TestWorldStampsFollowRetag(t *testing.T) {
	const (
		pol = `{
			"groups": {"group:eng": ["alice@"]},
			"tagOwners": {"tag:web": ["alice@"], "tag:dev": ["alice@"], "tag:idle": ["alice@"]},
			"grants": [{"src": ["group:eng", "tag:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}]
		}`
		eng = "https://headscale.net/cap/src/group:eng"
		dev = "https://headscale.net/cap/src/tag:dev"
	)

	users := []types.User{{ID: 1, Name: "alice"}}

	w, err := newWorldMode(types.Nodes{
		capWorldNode(1, nil, "100.64.0.10", "tag:web"),
		capWorldNode(2, &users[0], "100.64.0.1"),
		capWorldNode(3, nil, "100.64.0.3", "tag:dev"),
	}, users, []byte(pol), types.DNSView{}, pinSources(true))
	require.NoError(t, err)

	require.Equal(t, policyv2.Stamps{dev}, w.snapshot().Stamps(3))

	retag := func(id types.NodeID, tags []string, want policyv2.Stamps, gone ...string) {
		t.Helper()

		before := w.snapshot()

		_, ok := w.UpdateNode(id, func(n *types.Node) {
			if n.UserID != nil {
				n.UserID, n.User = nil, nil
			}

			n.Tags = tags
		})
		require.True(t, ok)

		after := w.snapshot()
		require.Equal(t, want, after.Stamps(id))
		require.Contains(t, after.Since(before).Caps, id, "its viewers render it again")

		for _, c := range gone {
			require.NotContains(t, after.NodeCaps(id), nodecap.Cap(c))
		}
	}

	retag(3, []string{"tag:idle"}, nil, dev)
	retag(3, []string{"tag:dev"}, policyv2.Stamps{dev})
	retag(2, []string{"tag:dev"}, policyv2.Stamps{dev}, eng)
}

// BenchmarkWorldReceiverFlip measures one node flipping the client it
// reports, under a mesh: the commit, routing it, and the flipped node's
// filter read again. It concerns that node's filter form only.
func BenchmarkWorldReceiverFlip(b *testing.B) {
	const mesh = `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`

	for _, capSources := range []bool{false, true} {
		for _, n := range []int{300, 3000} {
			b.Run(fmt.Sprintf("capability=%t/nodes=%d", capSources, n), func(b *testing.B) {
				alice := &types.User{ID: 1, Name: "alice"}

				nodes := make(types.Nodes, n)
				for i := range nodes {
					nodes[i] = capWorldNode(types.NodeID(i+1), alice, netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}).String())
				}

				w, err := newWorldMode(nodes, []types.User{*alice}, []byte(mesh), types.DNSView{}, pinSources(capSources))
				require.NoError(b, err)

				for _, nd := range nodes {
					_, err := w.snapshot().FilterForNode(nd.ID)
					require.NoError(b, err)
				}

				cuts := FilterCuts()
				flips := 0

				b.ReportAllocs()

				for b.Loop() {
					before := w.snapshot()

					_, ok := w.UpdateNode(1, func(nd *types.Node) {
						nd.Hostinfo = nd.Hostinfo.Clone()
						if nd.Hostinfo.GoVersion == "" {
							nd.Hostinfo.GoVersion = "go1.27.3"
						} else {
							nd.Hostinfo.GoVersion = ""
						}
					})
					require.True(b, ok)

					after := w.snapshot()
					_ = after.Since(before)

					_, err := after.FilterForNode(1)
					require.NoError(b, err)

					flips++
				}

				b.ReportMetric(float64(FilterCuts()-cuts)/float64(flips), "filter-cuts/op")
			})
		}
	}
}

// TestWorldReceiverFlipCostFollowsNode pins that a node flipping what
// decides its filter's form costs that node only, at any tailnet size: no
// new filters, no expansion, one cut at most, routing naming it alone.
func TestWorldReceiverFlipCostFollowsNode(t *testing.T) {
	// The audit cuts afresh at every read; this counts the served path.
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "")

	const mesh = `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}]}`

	for _, n := range []int{50, 500} {
		t.Run(fmt.Sprintf("nodes=%d", n), func(t *testing.T) {
			alice := &types.User{ID: 1, Name: "alice"}

			nodes := make(types.Nodes, n)
			for i := range nodes {
				nodes[i] = capWorldNode(types.NodeID(i+1), alice, netip.AddrFrom4([4]byte{100, 64, byte(i >> 8), byte(i)}).String())
			}

			w, err := newWorldMode(nodes, []types.User{*alice}, []byte(mesh), types.DNSView{}, pinSources(true))
			require.NoError(t, err)

			for _, nd := range nodes {
				_, err := w.snapshot().FilterForNode(nd.ID)
				require.NoError(t, err)
			}

			for _, flip := range []func(*types.Node){
				func(nd *types.Node) { nd.Hostinfo.GoVersion = "" },
				func(nd *types.Node) { nd.Hostinfo.GoVersion = "go1.27.3" },
				func(nd *types.Node) { nd.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")} },
				func(nd *types.Node) { nd.Hostinfo.RoutableIPs = nil },
			} {
				before := w.snapshot()
				cuts, builds := FilterCuts(), ExpansionBuilds()

				_, ok := w.UpdateNode(1, func(nd *types.Node) {
					nd.Hostinfo = nd.Hostinfo.Clone()
					flip(nd)
				})
				require.True(t, ok)

				after := w.snapshot()
				c := after.Since(before)

				require.False(t, c.Global)
				require.Equal(t, []types.NodeID{1}, c.Filters, "routing names the node alone")
				require.Same(t, before.s.Get(before.w.filters), after.s.Get(after.w.filters), "the filters stay")

				_, err := after.FilterForNode(1)
				require.NoError(t, err)

				_, err = after.FilterForNode(2)
				require.NoError(t, err)

				require.LessOrEqual(t, FilterCuts()-cuts, uint64(1), "one cut at most: the node's other form")
				require.Equal(t, builds, ExpansionBuilds(), "no expansion is built")
			}
		})
	}
}

// TestWorldNarrowRoutingFollowsEachFallback flips each reason a source is
// sent as addresses on and off around membership changes, and holds
// routing to fresh cuts at every commit: a receiver whose served filter
// moved is named; every filter served, cut or carried in either form,
// equals a fresh cut; and, in capability mode, a receiver sent
// capabilities at both ends whose filter did not move is not named, which
// is the narrowing. The receiver's address form is cut before a flip and
// carried across commits it is sent capabilities in, then read again.
func TestWorldNarrowRoutingFollowsEachFallback(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "")

	users := []types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}

	const receiver = types.NodeID(1)

	policy := func(grant, extra string) string {
		return `{"groups": {"group:eng": ["alice@"]}, "tagOwners": {"tag:web": ["alice@"]}` + extra +
			`, "grants": [{"src": ["group:eng"], "dst": ["tag:web"], "ip": ["tcp:443"]}` + grant + `]}`
	}

	hostinfoOf := func(id types.NodeID, fn func(*tailcfg.Hostinfo)) func(*world) {
		return func(w *world) {
			_, ok := w.UpdateNode(id, func(n *types.Node) {
				n.Hostinfo = n.Hostinfo.Clone()
				fn(n.Hostinfo)
			})
			require.True(t, ok)
		}
	}

	hostinfo := func(fn func(*tailcfg.Hostinfo)) func(*world) { return hostinfoOf(receiver, fn) }

	const self = `{"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`

	setPolicy := func(src string) func(*world) {
		return func(w *world) {
			_, err := w.SetPolicy([]byte(src), noCheck)
			require.NoError(t, err)
		}
	}

	route := netip.MustParsePrefix("10.1.0.0/24")

	cases := []struct {
		name   string
		policy string
		// into and out move the fallback onto the pair and off it; nil
		// where the rule itself is the fallback.
		into, out func(*world)
		// owner is the receiver, an owner node of alice's, for self rules.
		owner bool
	}{
		{
			name: "self/local-nets", policy: self, owner: true,
			into: hostinfoOf(2, func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")} }),
			out:  hostinfoOf(2, func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = nil }),
		},
		{
			name: "client",
			into: hostinfo(func(hi *tailcfg.Hostinfo) { hi.GoVersion, hi.App = "", "tailscale-rs" }),
			out:  hostinfo(func(hi *tailcfg.Hostinfo) { hi.GoVersion, hi.App = "go1.27.3", "" }),
		},
		{
			name: "local-nets/announces",
			into: hostinfo(func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")} }),
			out:  hostinfo(func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = nil }),
		},
		{
			name: "local-nets/app-connector",
			into: hostinfo(func(hi *tailcfg.Hostinfo) { hi.AppConnector.Set(true) }),
			out:  hostinfo(func(hi *tailcfg.Hostinfo) { hi.AppConnector.Set(false) }),
		},
		{
			name:   "local-nets/service-host",
			policy: policy("", ""),
			into:   setPolicy(policy("", `, "nodeAttrs": [{"target": ["tag:web"], "attr": ["service-host"]}]`)),
			out:    setPolicy(policy("", "")),
		},
		{
			name:   "cap-grant",
			policy: policy(`, {"src": ["group:eng"], "dst": ["tag:web"], "app": {"example.com/cap/admin": [{}]}}`, ""),
		},
		{
			name:   "portless",
			policy: policy(`, {"src": ["group:eng"], "dst": ["tag:web"], "ip": ["gre:*"]}`, ""),
		},
		{
			name:   "literal",
			policy: policy(`, {"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:80"]}`, ""),
			into: func(w *world) {
				_, ok := w.UpdateNode(2, func(n *types.Node) {
					n.Hostinfo = n.Hostinfo.Clone()
					n.Hostinfo.RoutableIPs, n.ApprovedRoutes = []netip.Prefix{route}, []netip.Prefix{route}
				})
				require.True(t, ok)
			},
			out: func(w *world) {
				_, ok := w.UpdateNode(2, func(n *types.Node) { n.ApprovedRoutes = nil })
				require.True(t, ok)
			},
		},
	}

	for _, capSources := range []bool{false, true} {
		for _, tc := range cases {
			t.Run(fmt.Sprintf("capability=%t/%s", capSources, tc.name), func(t *testing.T) {
				t.Setenv(TestCapabilitySourcesEnv, strconv.FormatBool(capSources))

				src := tc.policy
				if src == "" {
					src = policy("", "")
				}

				w, err := newWorldMode(types.Nodes{
					capWorldNode(receiver, nil, "100.64.0.10", "tag:web"),
					capWorldNode(2, &users[0], "100.64.0.1"),
					capWorldNode(5, &users[1], "100.64.0.5"),
				}, users, []byte(src), types.DNSView{}, pinSources(capSources))
				require.NoError(t, err)

				// Every node read, as its session would, so filters are
				// cut and carried.
				readAll := func(snap *Snapshot) {
					for _, n := range snap.ListNodes().All() {
						_, err := snap.FilterForNode(n.ID())
						require.NoError(t, err)
					}
				}

				before := w.snapshot()
				readAll(before)

				narrowed := 0

				watched := receiver
				if tc.owner {
					watched = 2
				}

				step := func(label string, write func(*world)) {
					t.Helper()

					write(w)

					after := w.snapshot()
					change := after.Since(before)
					freshOld, freshNew := before.Uncached(), after.Uncached()

					ids := map[types.NodeID]bool{}
					for _, n := range slices.Concat(before.ListNodes().AsSlice(), after.ListNodes().AsSlice()) {
						ids[n.ID()] = true
					}

					for id := range ids {
						was, errWas := freshOld.FilterForNode(id)
						is, errIs := freshNew.FilterForNode(id)
						moved := (errWas == nil) != (errIs == nil) || !reflect.DeepEqual(was, is)
						named := change.Global || slices.Contains(change.Filters, id)

						if moved {
							require.Truef(t, named, "%s: node %d's filter moved from %v to %v and routing leaves it out", label, id, was, is)
						}

						if errIs != nil {
							continue
						}

						served, err := after.FilterForNode(id)
						require.NoError(t, err)
						require.Equalf(t, is, served, "%s: node %d is served a filter other than a fresh cut", label, id)

						capBoth := capSources && capabilityForm(before.ReceiverFacts(id)) && capabilityForm(after.ReceiverFacts(id))
						if id == watched && capBoth && !moved && !change.Global {
							require.Falsef(t, named, "%s: the receiver is sent capabilities at both ends, its filter did not move, and routing names it", label)

							narrowed++
						}
					}

					readAll(after)

					before = after
				}

				join := func(id types.NodeID, ip string) func(*world) {
					return func(w *world) { w.PutNode(*capWorldNode(id, &users[0], ip)) }
				}

				step("join a member", join(3, "100.64.0.3"))

				if tc.into != nil {
					step("into the fallback", tc.into)
				}

				step("join a member in the fallback", join(4, "100.64.0.4"))

				if tc.out != nil {
					step("out of the fallback", tc.out)
				}

				step("a member leaves", func(w *world) { w.DeleteNode(3) })
				step("join a member again", join(6, "100.64.0.6"))

				if tc.into != nil {
					// The address form cut before is read again: what it
					// was carried across the joins above must be current.
					step("into the fallback again", tc.into)
					step("join a member in the fallback again", join(7, "100.64.0.7"))
				}

				if capSources && tc.into != nil {
					require.Positive(t, narrowed, "the receiver was left out of a membership change it reads nothing of")
				}
			})
		}
	}
}

// capabilityForm reports whether a receiver with facts f is sent
// capability sources: written here from the receiver rule, not read from
// the code it checks.
func capabilityForm(f policyv2.ReceiverFacts) bool {
	return f.Client && !f.Announces && !f.AppConnector && !f.ServiceHost
}
