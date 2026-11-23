package state

import (
	"database/sql"
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
)

func (s *Snapshot) roles() policyv2.Roles       { return s.s.Get(s.w.roles) }
func (s *Snapshot) postings() policyv2.Postings { return s.s.Get(s.w.postings) }

// membershipOf returns s's membership as the audit reads it.
func membershipOf(s *Snapshot) policyv2.Membership {
	cp := s.s.Get(s.w.policy)
	pm, _ := cp.pm.(*policyv2.PolicyManager)

	return policyv2.Membership{
		Selectors: s.s.Get(s.w.selectors),
		UserSets:  s.s.Get(s.w.userSets),
		Roles:     s.roles(),
		Postings:  s.postings(),
		Users:     s.s.Get(s.w.policyUsers),
		Nodes:     s.nodes(),
		Policy:    pm,
		Current:   cp.err == nil,
	}
}

// requireMembership requires s's membership cells to pass the audit, which
// also runs at every commit under HEADSCALE_DEBUG_POLICY_AUDIT; calling it
// here names the mismatch.
func requireMembership(t *testing.T, s *Snapshot, msgAndArgs ...any) policyv2.MembershipReport {
	t.Helper()

	rep, err := policyv2.AuditMembership(membershipOf(s))
	require.NoError(t, err, msgAndArgs...)

	return rep
}

// membershipRevs are the revisions at which each membership cell last
// changed.
type membershipRevs struct{ selectors, userSets, roles, postings uint64 }

func (s *Snapshot) membershipRevs() membershipRevs {
	return membershipRevs{
		selectors: graph.ChangedAt(s.s, s.w.selectors),
		userSets:  graph.ChangedAt(s.s, s.w.userSets),
		roles:     graph.ChangedAt(s.s, s.w.roles),
		postings:  graph.ChangedAt(s.s, s.w.postings),
	}
}

// computedSince returns how many role sets the commits from before to
// after computed, when they are one commit apart: a roles cell that did not
// recompute still holds its last computation's count.
func computedSince(before, after *Snapshot) int {
	if after.roles() == before.roles() {
		return 0
	}

	return after.roles().Computed()
}

// named returns the roles of the selectors spelled names in s's table,
// and of the owners uids, sorted.
func named(t *testing.T, s *Snapshot, names []string, uids ...uint) []policyv2.Role {
	t.Helper()

	roles := make([]policyv2.Role, 0, len(names)+len(uids))

	for _, name := range names {
		sel, ok := s.s.Get(s.w.selectors).Table().Lookup(name)
		require.True(t, ok, "no selector %q", name)

		roles = append(roles, policyv2.SelectorRole(sel.ID))
	}

	for _, uid := range uids {
		roles = append(roles, policyv2.OwnerRole(uid))
	}

	return sortedRoles(roles)
}

func sortedRoles(rs []policyv2.Role) []policyv2.Role {
	rs = slices.Clone(rs)
	slices.SortFunc(rs, func(a, b policyv2.Role) int { return strings.Compare(a.String(), b.String()) })

	return rs
}

// requireRoles requires node id to hold exactly want in s.
func requireRoles(t *testing.T, s *Snapshot, id types.NodeID, want []policyv2.Role) {
	t.Helper()

	rs, ok := s.roles().Of(id)
	require.True(t, ok, "node %d has no role set", id)
	assert.Equal(t, want, sortedRoles(rs.Roles()), "roles of node %d", id)
}

const membershipPolicy = `{
	"groups": {"group:eng": ["alice@", "carol@"]},
	"tagOwners": {"tag:web": ["alice@"], "tag:db": ["alice@"], "tag:ci": ["alice@"]},
	"acls": [
		{"action": "accept", "src": ["group:eng", "bob@example.com"], "dst": ["tag:web:443"]},
		{"action": "accept", "src": ["user:*@example.com"], "dst": ["tag:db:5432"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
	]}`

const (
	member = "autogroup:member"
	eng    = "group:eng"
	bobTok = "bob@example.com"
	domain = "user:*@example.com"
)

// TestWorldMembershipCostFollowsChange pins what each kind of write
// recomputes in the membership cells: nothing for a write the roles do not
// read, the touched node's role set and the posting lists of the roles it
// entered or left for a join, leave or tag change, nothing for a user
// change no selector sees, and only the moved users' nodes for one it does.
// The roles expected are written out from the policy, not read back.
func TestWorldMembershipCostFollowsChange(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{
		{ID: 1, Name: "alice"},
		{ID: 2, Name: "bob", Email: "bob@example.com"},
		{ID: 3, Name: "carol", Email: "carol@example.com"},
	}

	alice, bob, carol := &users[0], &users[1], &users[2]

	web := worldNode(5, alice, "100.64.0.5")
	web.Tags, web.UserID, web.User = []string{"tag:web"}, nil, nil

	// Tagged, keeping the user who created it.
	db := worldNode(6, alice, "100.64.0.6")
	db.Tags = []string{"tag:db"}

	w, err := newWorld(types.Nodes{
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
		worldNode(3, bob, "100.64.0.3"),
		worldNode(4, carol, "100.64.0.4"),
		web, db,
	}, users, []byte(membershipPolicy), types.DNSView{})
	require.NoError(t, err)

	start := w.snapshot()
	runs, misses := MembershipAuditRuns(), graph.MapLogMisses()

	requireMembership(t, start)
	require.True(t, start.MembershipAudited())

	for id, want := range map[types.NodeID][]policyv2.Role{
		1: named(t, start, []string{member, eng}, 1),
		2: named(t, start, []string{member, eng}, 1),
		3: named(t, start, []string{member, bobTok, domain}, 2),
		4: named(t, start, []string{member, eng, domain}, 3),
		5: named(t, start, []string{"tag:web"}),
		6: named(t, start, []string{"tag:db"}),
	} {
		requireRoles(t, start, id, want)
	}

	// unmoved requires a write to have reached no membership cell.
	unmoved := func(t *testing.T, before, after *Snapshot) {
		t.Helper()

		assert.Equal(t, before.membershipRevs().userSets, after.membershipRevs().userSets, "user sets")
		assert.Equal(t, before.membershipRevs().roles, after.membershipRevs().roles, "roles")
		assert.Equal(t, before.membershipRevs().postings, after.membershipRevs().postings, "postings")
		assert.Zero(t, computedSince(before, after), "role sets computed")
	}

	// moved requires the write to have computed that many role sets and
	// edited exactly the postings of roles, leaving every other list the
	// list it was.
	moved := func(t *testing.T, before, after *Snapshot, computed int, roles []policyv2.Role) {
		t.Helper()

		assert.Equal(t, computed, computedSince(before, after), "role sets computed")

		changed, all := after.postings().Changed(before.postings())
		require.False(t, all, "same table")
		assert.Equal(t, roles, sortedRoles(changed), "postings edited")

		for r, ids := range before.postings().All() {
			if !slices.Contains(roles, r) {
				got := after.postings().Nodes(r)
				require.NotEmpty(t, got, "role %s kept", r)
				assert.Same(t, &ids[0], &got[0], "role %s keeps its list", r)
			}
		}
	}

	steps := []struct {
		name  string
		write func()
		check func(t *testing.T, before, after *Snapshot)
	}{
		{"endpoint", func() {
			w.UpdateNode(1, func(n *types.Node) { n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")} })
		}, unmoved},
		{"hostinfo", func() {
			w.UpdateNode(1, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{OS: "linux", RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
			})
		}, unmoved},
		{"address", func() {
			w.UpdateNode(1, func(n *types.Node) { n.IPv4 = new(netip.MustParseAddr("100.64.0.91")) })
		}, unmoved},
		{"join", func() { w.PutNode(*worldNode(7, alice, "100.64.0.7")) }, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			requireRoles(t, after, 7, named(t, after, []string{member, eng}, 1))
			moved(t, before, after, 1, named(t, after, []string{member, eng}, 1))
		}},
		{"leave", func() { w.DeleteNode(7) }, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			moved(t, before, after, 0, named(t, after, []string{member, eng}, 1))
		}},
		{"tag", func() {
			w.UpdateNode(3, func(n *types.Node) { n.Tags, n.UserID, n.User = []string{"tag:web"}, nil, nil })
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			requireRoles(t, after, 3, named(t, after, []string{"tag:web"}))
			moved(t, before, after, 1, named(t, after, []string{member, bobTok, domain, "tag:web"}, 2))
		}},
		{"user outside every selector", func() {
			users = append(users, types.User{ID: 4, Name: "dave", Email: "dave@other.org"})
			require.NoError(t, w.SetUsers(users))
		}, unmoved},
		{"display name", func() {
			users[0].DisplayName = "Alice"
			require.NoError(t, w.SetUsers(users))
		}, unmoved},
		{"user named by a selector, without nodes", func() {
			users = append(users, types.User{ID: 5, Name: "erin", Email: "erin@example.com"})
			require.NoError(t, w.SetUsers(users))
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			assert.NotEqual(t, before.membershipRevs().userSets, after.membershipRevs().userSets, "the domain names erin")
			assert.Equal(t, before.membershipRevs().roles, after.membershipRevs().roles, "erin has no nodes")
			assert.Equal(t, before.membershipRevs().postings, after.membershipRevs().postings)
		}},
		{"rename out of a group", func() {
			users[2].Name = "caroline"
			require.NoError(t, w.SetUsers(users))
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			// carol@ names nobody now; the domain still names her.
			requireRoles(t, after, 4, named(t, after, []string{member, domain}, 3))
			moved(t, before, after, 1, named(t, after, []string{eng}))
		}},
		{"port edit", func() {
			_, err := w.SetPolicy([]byte(replaceOnce(membershipPolicy, "tag:web:443", "tag:web:8443")), noCheck)
			require.NoError(t, err)
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			assert.Same(t, before.s.Get(before.w.selectors).Table(), after.s.Get(after.w.selectors).Table())
			unmoved(t, before, after)
		}},
		{"group edit", func() {
			_, err := w.SetPolicy([]byte(replaceOnce(replaceOnce(membershipPolicy, "tag:web:443", "tag:web:8443"),
				`["alice@", "carol@"]`, `["bob@example.com"]`)), noCheck)
			require.NoError(t, err)
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			assert.Same(t, before.s.Get(before.w.selectors).Table(), after.s.Get(after.w.selectors).Table())
			// alice's untagged nodes leave; bob's only node is tagged now.
			requireRoles(t, after, 1, named(t, after, []string{member}, 1))
			moved(t, before, after, 2, named(t, after, []string{eng}))
		}},
		{"coalesced join, leave and tag", func() {
			w.update(func(e *nodeEdit) {
				e.Set(8, worldNode(8, carol, "100.64.0.8"))
				e.Delete(2)

				n := *mustGet(t, e, 4)
				n.Tags, n.UserID, n.User = []string{"tag:db"}, nil, nil
				e.Set(4, &n)
			})
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			requireRoles(t, after, 8, named(t, after, []string{member, domain}, 3))
			requireRoles(t, after, 4, named(t, after, []string{"tag:db"}))
			// member and the domain trade 4 for 8, carol's ownership too;
			// alice keeps one node; tag:db gains 4.
			moved(t, before, after, 2, named(t, after, []string{member, domain, "tag:db"}, 1, 3))
		}},
		{"new selector", func() {
			_, err := w.SetPolicy([]byte(replaceOnce(membershipPolicy, `"bob@example.com"]`, `"bob@example.com", "tag:ci"]`)), noCheck)
			require.NoError(t, err)
		}, func(t *testing.T, before, after *Snapshot) {
			t.Helper()
			assert.NotSame(t, before.s.Get(before.w.selectors).Table(), after.s.Get(after.w.selectors).Table())
			assert.Equal(t, after.nodes().Len(), computedSince(before, after), "a new table recomputes every node")

			_, all := after.postings().Changed(before.postings())
			assert.True(t, all, "postings of another table compare as all changed")
		}},
	}

	for _, step := range steps {
		before := w.snapshot()

		step.write()

		after := w.snapshot()

		t.Run(step.name, func(t *testing.T) {
			require.Equal(t, before.Rev()+1, after.Rev(), "the write is one commit")
			step.check(t, before, after)
			requireMembership(t, after)
			require.True(t, after.MembershipAudited(), "the commit was audited")
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
	assert.Equal(t, w.snapshot().Rev()-start.Rev(), MembershipAuditRuns()-runs, "one audit per commit")
	assert.Equal(t, misses, graph.MapLogMisses(), "the audit compares unrelated maps without the edit log")
}

// TestWorldMembershipFollowsServedPolicy commits a document the compile
// refuses, as only the world's own SetPolicy lets through: the compile
// keeps serving the last good policy, and membership keeps describing it.
func TestWorldMembershipFollowsServedPolicy(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	users := []types.User{{ID: 1, Name: "alice"}}
	w, err := newWorld(types.Nodes{worldNode(1, &users[0], "100.64.0.1")}, users, []byte(membershipPolicy), types.DNSView{})
	require.NoError(t, err)

	before := w.snapshot()

	_, err = w.SetPolicy([]byte(`{"acls": [`), noCheck)
	require.NoError(t, err)

	after := w.snapshot()
	require.Error(t, after.PolicyErr(), "the document does not compile")

	pm, _ := after.Policy().(*policyv2.PolicyManager)
	assert.True(t, after.s.Get(after.w.selectors).Describes(pm), "membership describes the policy served")
	assert.Same(t, before.s.Get(before.w.selectors), after.s.Get(after.w.selectors))

	// A node writing while the refused document stands recompiles it, fails
	// again, and keeps both on the last good policy.
	w.PutNode(*worldNode(2, &users[0], "100.64.0.2"))

	last := w.snapshot()
	pm, _ = last.Policy().(*policyv2.PolicyManager)
	assert.True(t, last.s.Get(last.w.selectors).Describes(pm))
	requireMembership(t, last)

	_, err = w.SetPolicy([]byte(`{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["alice@:*"]}]}`), noCheck)
	require.NoError(t, err)

	fixed := w.snapshot()
	require.NoError(t, fixed.PolicyErr())

	pm, _ = fixed.Policy().(*policyv2.PolicyManager)
	assert.True(t, fixed.s.Get(fixed.w.selectors).Describes(pm), "and follows the next good one")
	_, ok := fixed.s.Get(fixed.w.selectors).Table().Lookup("alice@")
	assert.True(t, ok)
	requireMembership(t, fixed)

	assert.Zero(t, PolicyAuditFailures()-failures)
}

func mustGet(t *testing.T, e *nodeEdit, id types.NodeID) *types.Node {
	t.Helper()

	n, ok := e.Get(id)
	require.True(t, ok, "node %d", id)

	return n
}

func noCheck(*Snapshot) error { return nil }

// replaceOnce returns s with its one old replaced by new.
func replaceOnce(s, old, replacement string) string {
	if strings.Count(s, old) != 1 {
		panic(fmt.Sprintf("%q is not in the policy once", old))
	}

	return strings.Replace(s, old, replacement, 1)
}

// TestWorldRoleSetsInterned checks that nodes holding equal roles hold the
// same role set, in one snapshot and across snapshots of one table.
func TestWorldRoleSetsInterned(t *testing.T) {
	users := []types.User{{Name: "alice"}, {Name: "bob", Email: "bob@example.com"}, {Name: "carol", Email: "carol@example.com"}}
	for i := range users {
		users[i].ID = uint(i + 1) //nolint:gosec // three users
	}

	w, err := newWorld(types.Nodes{
		worldNode(1, &users[1], "100.64.0.1"),
		worldNode(2, &users[1], "100.64.0.2"),
		worldNode(3, &users[2], "100.64.0.3"),
	}, users, []byte(replaceOnce(membershipPolicy, `{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}`,
		`{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}`)), types.DNSView{})
	require.NoError(t, err)

	s := w.snapshot()
	one, _ := s.roles().Of(1)
	two, _ := s.roles().Of(2)
	three, _ := s.roles().Of(3)

	assert.Equal(t, one, two, "two of bob's nodes")
	assert.NotEqual(t, one, three, "bob@example.com names bob only")

	w.PutNode(*worldNode(4, &users[1], "100.64.0.4"))

	four, _ := w.snapshot().roles().Of(4)
	assert.Equal(t, one, four, "a later node of bob's")
}

// membershipChurnPolicies are the documents the churn test switches
// between: every selector kind, users and groups that resolve by name,
// e-mail, provider identity and domain, and documents that name none.
var membershipChurnPolicies = []string{
	``,
	`{}`,
	`{"acls": []}`,
	`{"groups": {"group:a": ["alice@", "dup@", "user:*@other.org"], "group:b": ["bob@", "carol@example.com", "pid@"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["group:b"]},
	  "acls": [
		{"action": "accept", "src": ["group:a", "tag:a"], "dst": ["group:b:*", "tag:b:22"]},
		{"action": "accept", "src": ["user:*@example.com", "dup@", "pid@"], "dst": ["autogroup:tagged:*"]},
		{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`,
	`{"groups": {"group:a": ["bob@", "carol@example.com"]},
	  "tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "hosts": {"lan": "10.0.0.0/24"},
	  "acls": [
		{"action": "accept", "src": ["*"], "dst": ["lan:*", "tag:a:*"]},
		{"action": "accept", "src": ["group:a", "10.0.0.0/8"], "dst": ["autogroup:internet:*", "tag:b:443"]}],
	  "ssh": [{"action": "accept", "src": ["group:a"], "dst": ["tag:a"], "users": ["root"]},
	          {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}]}`,
	`{"tagOwners": {"tag:a": ["alice@"], "tag:b": ["alice@"]},
	  "grants": [
		{"src": ["alice@", "user:*@example.com"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:b"]},
		{"src": ["autogroup:member", "autogroup:tagged"], "dst": ["autogroup:member"], "ip": ["tcp:22"]},
		{"src": ["autogroup:danger-all"], "dst": ["tag:a"], "ip": ["*"]}]}`,
	`{"tagOwners": {"tag:a": ["alice@"]},
	  "acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*", "tag:a:*"]},
	           {"action": "accept", "src": ["alice@", "bob@"], "dst": ["alice@:*"]}]}`,
}

// membershipChurnRefused are documents the compile refuses, which only the
// world's own SetPolicy commits: the last good policy keeps serving.
var membershipChurnRefused = []string{
	`{"acls": [`,
	`{"acls": [{"action": "accept", "src": ["tag:undefined"], "dst": ["*:*"]}]}`,
}

// TestWorldMembershipUnderRandomChurn drives random writes of every kind
// the membership reads, many of them in one commit, and requires the
// incremental cells to match a build from scratch and the compile's
// resolution after each, and the cells to stay put for writes they do not
// read.
func TestWorldMembershipUnderRandomChurn(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")

	failures := PolicyAuditFailures()

	for seed := range uint64(4) {
		t.Run(fmt.Sprintf("seed=%d", seed), func(t *testing.T) {
			membershipChurn(t, rand.New(rand.NewPCG(seed, 11))) //nolint:gosec // deterministic test input
		})
	}

	assert.Zero(t, PolicyAuditFailures()-failures, "audit failures")
}

// churnRun is the state one churn test acts on.
type churnRun struct {
	t     *testing.T
	r     *rand.Rand
	w     *world
	users []types.User
	next  types.NodeID
	uid   uint

	// aligned gives new nodes addresses of one width, so a list of them
	// sorts alike as text and as addresses and rules from different paths
	// share merge keys.
	aligned bool
}

// setUsers stores the user list. While a refused document stands every
// recompile fails, and SetUsers reports that failure; it must be the
// snapshot's.
func (c *churnRun) setUsers() {
	err := c.w.SetUsers(slices.Clone(c.users))
	require.Equal(c.t, c.w.snapshot().PolicyErr(), err)
}

func (c *churnRun) randomUser() *types.User {
	if len(c.users) == 0 {
		return nil
	}

	u := c.users[c.r.IntN(len(c.users))]

	return &u
}

// randomUserFields returns a name, an e-mail and a provider identity drawn
// from a small pool, so tokens collide and become ambiguous.
func (c *churnRun) randomUserFields(u *types.User) {
	names := []string{"alice", "bob", "carol", "dup", "pid", "zed"}
	emails := []string{"", "carol@example.com", "x@example.com", "y@Other.Org", "dup", "alice"}

	u.Name = names[c.r.IntN(len(names))]
	u.Email = emails[c.r.IntN(len(emails))]
	u.ProviderIdentifier = sql.NullString{}

	if c.r.IntN(4) == 0 {
		u.ProviderIdentifier = sql.NullString{String: []string{"pid", "alice", "bob"}[c.r.IntN(3)], Valid: true}
	}
}

// randomNode returns a new node: owned by a listed user, a user the list
// lacks, or nobody, tagged or not, and with a user and UserID that may
// disagree.
func (c *churnRun) randomNode() *types.Node {
	c.next++
	id := c.next

	n := &types.Node{
		ID:        id,
		GivenName: fmt.Sprintf("n%d", id),
		Hostname:  fmt.Sprintf("n%d", id),
		IPv4:      new(netip.AddrFrom4([4]byte{100, 64, byte(id >> 8), byte(id)})),                                      //nolint:gosec // a few hundred nodes
		IPv6:      new(netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: byte(id >> 8), 15: byte(id)})), //nolint:gosec // a few hundred nodes
		IsOnline:  new(true),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	if c.aligned {
		n.IPv4 = new(netip.AddrFrom4([4]byte{100, 64, 1, byte(100 + id)}))                                   //nolint:gosec // fewer than 156 nodes
		n.IPv6 = new(netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 14: 0x10, 15: byte(id)})) //nolint:gosec // fewer than 156 nodes
	}

	c.reown(n)
	c.retag(n)

	return n
}

func (c *churnRun) reown(n *types.Node) {
	switch c.r.IntN(8) {
	case 0:
		n.User, n.UserID = nil, nil
	case 1:
		// The user is not loaded.
		n.User, n.UserID = nil, new(uint(1+c.r.IntN(4))) //nolint:gosec // small
	case 2:
		u := &types.User{Name: "gone"}
		u.ID = 99
		n.User, n.UserID = u, new(u.ID)
	case 3:
		// The loaded user and the UserID disagree.
		if u := c.randomUser(); u != nil {
			n.User, n.UserID = u, []*uint{nil, new(u.ID + 1)}[c.r.IntN(2)]
		}
	default:
		if u := c.randomUser(); u != nil {
			n.User, n.UserID = u, new(u.ID)
		}
	}
}

func (c *churnRun) retag(n *types.Node) {
	tags := [][]string{nil, nil, {"tag:a"}, {"tag:b"}, {"tag:a", "tag:b"}, {"tag:other"}}
	n.Tags = tags[c.r.IntN(len(tags))]

	// A tagged node usually drops its user; sometimes it keeps it.
	if len(n.Tags) > 0 && c.r.IntN(3) > 0 {
		n.User, n.UserID = nil, nil
	}
}

// nodeOp is one random change to the node table, staged on e.
func (c *churnRun) nodeOp(e *nodeEdit) string {
	ids := make([]types.NodeID, 0, e.Len())
	for id := range e.All() {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	if len(ids) < 3 || c.r.IntN(5) == 0 {
		n := c.randomNode()
		e.Set(n.ID, n)

		return "join"
	}

	id := ids[c.r.IntN(len(ids))]
	n := mustGet(c.t, e, id).Clone()

	switch c.r.IntN(6) {
	case 0:
		e.Delete(id)

		return "leave"
	case 1:
		c.retag(n)
		e.Set(id, n)

		return "tag"
	case 2:
		c.reown(n)
		e.Set(id, n)

		return "owner"
	case 3:
		// A new address, none other holds: membership must not read
		// addresses.
		a := netip.AddrFrom4([4]byte{100, 65, byte(c.r.Uint32()), byte(c.r.Uint32())}) //nolint:gosec // any byte
		if !slices.ContainsFunc(ids, func(o types.NodeID) bool { return mustGet(c.t, e, o).HasIP(a) }) {
			n.IPv4 = &a
		}

		e.Set(id, n)

		return "address"
	case 4:
		n.Hostinfo = &tailcfg.Hostinfo{OS: "linux", RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}}
		e.Set(id, n)

		return "hostinfo"
	default:
		n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(c.r.IntN(65535)))} //nolint:gosec // small
		e.Set(id, n)

		return "endpoint"
	}
}

func membershipChurn(t *testing.T, r *rand.Rand) {
	t.Helper()

	c := &churnRun{t: t, r: r, uid: 3}

	c.users = []types.User{{Name: "alice"}, {Name: "bob"}, {Name: "carol", Email: "carol@example.com"}}
	for i := range c.users {
		c.users[i].ID = uint(i + 1) //nolint:gosec // three users
	}

	w, err := newWorld(nil, slices.Clone(c.users), []byte(membershipChurnPolicies[3]), types.DNSView{})
	require.NoError(t, err)

	c.w = w

	for range 6 {
		n := c.randomNode()
		w.PutNode(*n)
	}

	start, runs := w.snapshot(), MembershipAuditRuns()
	kinds := map[string]int{}

	for step := range 500 {
		before := w.snapshot()

		var kind string

		switch op := r.IntN(20); {
		case op < 10:
			w.update(func(e *nodeEdit) { kind = c.nodeOp(e) })
		case op < 12:
			// Writes landing in one commit.
			w.update(func(e *nodeEdit) {
				kind = "coalesced"

				for range 2 + r.IntN(3) {
					c.nodeOp(e)
				}
			})
		case op < 13:
			// Concurrent writers, which the world batches as it can.
			kind = "concurrent"

			var wg sync.WaitGroup
			for range 4 {
				wg.Go(func() {
					// The writer runs batched writes one after another.
					w.update(func(e *nodeEdit) { c.nodeOp(e) })
				})
			}

			wg.Wait()
		case op < 14:
			kind = "user add"
			c.uid++
			u := types.User{ID: c.uid}
			c.randomUserFields(&u)
			c.users = append(c.users, u)
			c.setUsers()
		case op < 15:
			kind = "user rename"

			if len(c.users) > 0 {
				c.randomUserFields(&c.users[r.IntN(len(c.users))])
				c.setUsers()
			}
		case op < 16:
			kind = "user delete"

			if len(c.users) > 1 {
				i := r.IntN(len(c.users))
				c.users = slices.Delete(c.users, i, i+1)
				c.setUsers()
			}
		case op < 17:
			// The order decides which of two equal provider identities wins.
			kind = "user reorder"

			r.Shuffle(len(c.users), func(i, j int) { c.users[i], c.users[j] = c.users[j], c.users[i] })
			c.setUsers()
		case op < 19:
			kind = "policy"
			src := membershipChurnPolicies[r.IntN(len(membershipChurnPolicies))]
			_, err := w.SetPolicy([]byte(src), noCheck)
			require.NoError(t, err, "step %d: %s", step, src)
		default:
			kind = "refused policy"
			src := membershipChurnRefused[r.IntN(len(membershipChurnRefused))]
			_, err := w.SetPolicy([]byte(src), noCheck)
			require.NoError(t, err, "step %d: %s", step, src)
		}

		kinds[kind]++

		after := w.snapshot()
		requireMembership(t, after, "step %d (%s)", step, kind)

		require.True(t, after.MembershipAudited(), "step %d (%s): the last change was audited", step, kind)

		pm, _ := after.Policy().(*policyv2.PolicyManager)
		require.True(t, after.s.Get(after.w.selectors).Describes(pm), "step %d (%s): membership describes the policy served", step, kind)

		// A write the roles do not read moves none.
		if kind == "endpoint" || kind == "hostinfo" || kind == "address" {
			assert.Equal(t, before.membershipRevs().roles, after.membershipRevs().roles, "step %d: %s moved roles", step, kind)
			assert.Zero(t, computedSince(before, after), "step %d: %s computed role sets", step, kind)
		}

		if kind == "join" {
			assert.Equal(t, 1, computedSince(before, after), "step %d: a join computes its node's role set", step)
		}
	}

	for _, k := range []string{"join", "leave", "tag", "owner", "coalesced", "concurrent", "user add", "user rename", "user delete", "user reorder", "policy", "refused policy"} {
		assert.Positive(t, kinds[k], "no %s write", k)
	}

	// Every commit here changes the nodes, the users or the policy.
	audits, commits := MembershipAuditRuns()-runs, w.snapshot().Rev()-start.Rev()
	assert.Equal(t, commits, audits, "one audit per commit")

	t.Logf("writes: %v; %d commits, %d audits", kinds, commits, audits)
}
