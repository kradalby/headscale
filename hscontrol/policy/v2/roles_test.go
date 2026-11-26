package v2

import (
	"database/sql"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// membership is a policy's membership cells built from scratch, with the
// compile they describe.
type membership struct {
	pm    *PolicyManager
	sel   *Selectors
	us    *UserSets
	roles Roles
	posts Postings
	users types.Users
	nodes *NodeMap
}

func nodeMapOf(nodes types.Nodes) *NodeMap {
	byID := make(map[types.NodeID]*types.Node, len(nodes))
	for _, n := range nodes {
		byID[n.ID] = n
	}

	return graph.NewMap(graph.Same[*types.Node], byID)
}

// newMembership builds the membership of src over users and nodes, from
// its compile when it compiles, from its parse otherwise.
func newMembership(t *testing.T, src string, users types.Users, nodes types.Nodes) membership {
	t.Helper()

	m := membership{users: users, nodes: nodeMapOf(nodes)}

	pm, err := NewPolicyManagerFrom(nil, []byte(src), users, nodes.ViewSlice())
	if err == nil {
		m.pm, m.sel = pm, SelectorsFor(nil, pm)
	} else {
		m.sel, err = NewSelectors(nil, []byte(src))
		require.NoError(t, err)
	}

	m.us = NewUserSets(nil, m.sel, users)
	m.roles = Roles{}.Update(m.us, m.nodes, nil)
	m.posts = Postings{}.Update(m.roles)

	return m
}

// buildMembership is [newMembership], required to pass the audit.
func buildMembership(t *testing.T, src string, users types.Users, nodes types.Nodes) membership {
	t.Helper()

	m := newMembership(t, src, users, nodes)

	_, err := m.audit()
	require.NoError(t, err)

	return m
}

func (m membership) audit() (MembershipReport, error) {
	return AuditMembership(Membership{
		Selectors: m.sel, UserSets: m.us, Roles: m.roles, Postings: m.posts,
		Users: m.users, Nodes: m.nodes, Policy: m.pm, Current: m.pm != nil,
	})
}

// members returns the nodes the selector spelled name lists.
func (m membership) members(t *testing.T, name string) []types.NodeID {
	t.Helper()

	s, ok := m.sel.Table().Lookup(name)
	require.True(t, ok, "no selector %q", name)

	return m.posts.Nodes(SelectorRole(s.ID))
}

// TestMembershipQuirks pins how membership follows today's resolution in
// the cases that are not plain: which user a token picks, ambiguity,
// tagged nodes that keep a user, nodes whose user and UserID disagree.
// Every case also passes the audit, which resolves each alias as the
// compile does.
func TestMembershipQuirks(t *testing.T) {
	user := func(id uint, name, email, provider string) types.User {
		u := types.User{ID: id, Name: name, Email: email}

		if provider != "" {
			u.ProviderIdentifier = sql.NullString{String: provider, Valid: true}
		}

		return u
	}

	users := types.Users{
		user(1, "alice", "", ""),
		user(2, "bob", "bob@example.com", ""),
		user(3, "dup", "", ""),
		user(4, "dup", "", ""),
		// Named like user 5's provider identity, and listed first: the
		// provider identity still wins.
		user(6, "pid", "", ""),
		user(5, "zed", "", "pid"),
		user(7, "carol", "carol@EXAMPLE.org", ""),
		user(8, "dave", "dave@sub@example.org", ""),
		user(9, "eve", "eve@example.org.evil", ""),
		// Named what user 11's e-mail is: the e-mail wins.
		user(10, "frank@example.com", "", ""),
		user(11, "frank", "frank@example.com", ""),
	}

	var ip byte

	node := func(id types.NodeID, uid uint, tags ...string) *types.Node {
		ip++

		v4 := netip.AddrFrom4([4]byte{100, 64, 0, ip})
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0, 15: ip})
		n := &types.Node{ID: id, IPv4: &v4, IPv6: &v6, Tags: tags}

		if uid != 0 {
			i := slices.IndexFunc(users, func(u types.User) bool { return u.ID == uid })
			require.GreaterOrEqual(t, i, 0)

			n.User, n.UserID = &users[i], &users[i].ID
		}

		return n
	}

	// Untagged, UserID set, user not loaded.
	idOnly := node(10, 0)
	idOnly.UserID = new(uint(1))

	// Untagged, user loaded, no UserID.
	userOnly := node(11, 1)
	userOnly.UserID = nil

	// Owned by a user the list no longer has.
	gone := node(15, 0)
	gone.User = &types.User{Name: "gone"}
	gone.User.ID = 99

	nodes := types.Nodes{
		node(1, 1),
		// Tagged, keeping the user who created it.
		node(2, 1, "tag:web"),
		node(3, 2),
		node(4, 3),
		node(5, 5),
		node(6, 6),
		node(7, 7),
		node(8, 8),
		node(9, 9),
		idOnly,
		userOnly,
		node(12, 0),
		node(13, 0, "tag:db"),
		node(14, 11),
		gone,
	}

	m := buildMembership(t, `{
		"groups": {"group:eng": ["alice@", "dup@", "nobody@"]},
		"hosts": {"lan": "192.168.0.0/16"},
		"tagOwners": {"tag:web": ["alice@"], "tag:db": ["alice@"]},
		"acls": [
			{"action": "accept",
			 "src": ["alice@", "bob@example.com", "dup@", "nobody@", "pid@", "frank@example.com",
			         "user:*@Example.ORG", "group:eng", "tag:web", "autogroup:tagged", "*", "10.0.0.0/8", "lan"],
			 "dst": ["tag:db:22", "autogroup:internet:*", "lan:*", "100.64.0.1:*"]},
			{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
		]}`, users, nodes)

	ids := func(ids ...types.NodeID) []types.NodeID { return ids }

	for name, want := range map[string][]types.NodeID{
		// Untagged nodes of the loaded user, whatever UserID says.
		"alice@":            ids(1, 11),
		"bob@example.com":   ids(3),
		"dup@":              nil,
		"nobody@":           nil,
		"pid@":              ids(5),
		"frank@example.com": ids(14),
		// Case-insensitive domain, after the last @.
		"user:*@Example.ORG": ids(7, 8),
		// Ambiguous and unknown members name nobody; the rest still count.
		"group:eng": ids(1, 11),
		// Tags own a tagged node, whoever created it.
		"tag:web":          ids(2),
		"tag:db":           ids(13),
		"autogroup:tagged": ids(2, 13),
		// Every untagged node, with a user or not.
		"autogroup:member": ids(1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15),
		// Addresses, not memberships.
		"*":                  nil,
		"10.0.0.0/8":         nil,
		"lan":                nil,
		"autogroup:internet": nil,
		"100.64.0.1/32":      nil,
	} {
		assert.Equal(t, want, m.members(t, name), name)
	}

	// Owners are the loaded user's untagged nodes, listed or not.
	for uid, want := range map[uint][]types.NodeID{1: ids(1, 11), 99: ids(15), 2: ids(3)} {
		assert.Equal(t, want, m.posts.Nodes(OwnerRole(uid)), "owner %d", uid)
	}

	assert.Empty(t, m.posts.Nodes(OwnerRole(0)), "a node without a loaded user owns nothing")

	for name, kind := range map[string]SelectorKind{
		"alice@": SelectorUser, "user:*@Example.ORG": SelectorDomain, "group:eng": SelectorGroup,
		"tag:web": SelectorTag, "autogroup:member": SelectorMember, "autogroup:tagged": SelectorTagged,
		"autogroup:self": SelectorSelf, "*": SelectorWildcard, "lan": SelectorHost, "10.0.0.0/8": SelectorPrefix,
		"autogroup:internet": SelectorInternet,
	} {
		s, ok := m.sel.Table().Lookup(name)
		require.True(t, ok, name)
		assert.Equal(t, kind, s.Kind, name)
	}
}

// TestRoleSetIdentity pins interning: equal sets of one table are the same
// value, sets of different tables never are.
func TestRoleSetIdentity(t *testing.T) {
	a := newRoleSet(1, []Role{SelectorRole(3), OwnerRole(7), SelectorRole(1), SelectorRole(3)})
	b := newRoleSet(1, []Role{OwnerRole(7), SelectorRole(1), SelectorRole(3)})

	assert.Equal(t, a, b)
	assert.NotEqual(t, a, newRoleSet(2, []Role{OwnerRole(7), SelectorRole(1), SelectorRole(3)}))
	assert.NotEqual(t, a, newRoleSet(1, []Role{SelectorRole(1), SelectorRole(3)}))

	assert.Equal(t, 3, a.Len())
	assert.Equal(t, []Role{SelectorRole(1), SelectorRole(3), OwnerRole(7)}, a.Roles())
	assert.True(t, a.Has(OwnerRole(7)))
	assert.False(t, a.Has(SelectorRole(7)))
	assert.False(t, a.Has(OwnerRole(1)))
	assert.Equal(t, "{selector:1 selector:3 owner:7}", a.String())

	var zero RoleSet
	assert.Zero(t, zero.Len())
	assert.False(t, zero.Has(SelectorRole(0)))

	id, ok := SelectorRole(5).Selector()
	assert.True(t, ok)
	assert.Equal(t, SelectorID(5), id)

	_, ok = SelectorRole(5).Owner()
	assert.False(t, ok)

	uid, ok := OwnerRole(5).Owner()
	assert.True(t, ok)
	assert.Equal(t, uint(5), uid)

	// User IDs keep every bit: no two users share an owner role.
	big := uint(1)<<56 + 5
	assert.NotEqual(t, OwnerRole(5), OwnerRole(big))

	uid, _ = OwnerRole(big).Owner()
	assert.Equal(t, big, uid)
	assert.NotEqual(t, newRoleSet(1, []Role{OwnerRole(5)}), newRoleSet(1, []Role{OwnerRole(big)}))
}

// TestSelectorsKeepTableAcrossRuleEdits checks the table's cutoff: an edit
// that names the same selectors keeps the table, so nothing built from it
// moves, while a group's members are definitions, read by the user sets.
func TestSelectorsKeepTableAcrossRuleEdits(t *testing.T) {
	sel, err := NewSelectors(nil, []byte(`{"groups":{"group:eng":["alice@"]},"tagOwners":{"tag:web":["alice@"],"tag:ci":["alice@"]},"acls":[{"action":"accept","src":["group:eng"],"dst":["tag:web:22"]}]}`))
	require.NoError(t, err)

	ports, err := NewSelectors(sel, []byte(`{"groups":{"group:eng":["alice@"]},"tagOwners":{"tag:web":["alice@"],"tag:ci":["alice@"]},"acls":[{"action":"accept","src":["group:eng"],"dst":["tag:web:443"]}]}`))
	require.NoError(t, err)
	assert.Same(t, sel.Table(), ports.Table(), "a port edit keeps the table")

	members, err := NewSelectors(ports, []byte(`{"groups":{"group:eng":["bob@"]},"tagOwners":{"tag:web":["alice@"],"tag:ci":["alice@"]},"acls":[{"action":"accept","src":["group:eng"],"dst":["tag:web:443"]}]}`))
	require.NoError(t, err)
	assert.Same(t, sel.Table(), members.Table(), "a group's members do not name selectors")

	more, err := NewSelectors(members, []byte(`{"groups":{"group:eng":["bob@"]},"tagOwners":{"tag:web":["alice@"],"tag:ci":["alice@"]},"acls":[{"action":"accept","src":["group:eng","tag:ci"],"dst":["tag:web:443"]}]}`))
	require.NoError(t, err)
	assert.NotSame(t, sel.Table(), more.Table())

	bad, err := NewSelectors(more, []byte(`{`))
	require.Error(t, err)
	assert.Same(t, more, bad, "a document that does not parse keeps the last")

	users := types.Users{{Name: "alice"}, {Name: "bob"}}
	users[0].ID, users[1].ID = 1, 2

	before := NewUserSets(nil, sel, users)
	assert.Same(t, before, NewUserSets(before, ports, users), "same table, same users")

	after := NewUserSets(before, members, users)
	require.NotSame(t, before, after)
	assert.ElementsMatch(t, []uint{1, 2}, graph.Changes(before.byUser, after.byUser), "only alice and bob moved")

	// A user no selector names is no change.
	more3 := append(slices.Clone(users), types.User{Name: "zed"})
	more3[2].ID = 3
	assert.Same(t, after, NewUserSets(after, members, more3))
}

// TestAuditMembershipCatchesMistakes seeds the mistakes membership can
// make and requires the audit to report each: in the incremental build,
// which the build from scratch catches, and in both, which only the
// resolution of the policy can.
func TestAuditMembershipCatchesMistakes(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}

	addr := func(i byte) *netip.Addr { a := netip.AddrFrom4([4]byte{100, 64, 0, i}); return &a }

	nodes := types.Nodes{
		{ID: 1, IPv4: addr(1), User: &users[0], UserID: &users[0].ID},
		{ID: 2, IPv4: addr(2), User: &users[1], UserID: &users[1].ID},
		{ID: 3, IPv4: addr(3), Tags: []string{"tag:web"}},
	}

	const src = `{"tagOwners":{"tag:web":["alice@"]},
		"acls":[{"action":"accept","src":["alice@"],"dst":["autogroup:self:*"]},
		{"action":"accept","src":["autogroup:member","tag:web"],"dst":["autogroup:member:*"]}]}`

	m := buildMembership(t, src, users, nodes)

	role := func(name string) Role {
		s, ok := m.sel.Table().Lookup(name)
		require.True(t, ok, name)

		return SelectorRole(s.ID)
	}

	// setPostings replaces role's list, as a wrong membership rule would
	// in both builds: only the resolution can tell.
	setPostings := func(lists map[Role][]types.NodeID) membership {
		bad := m
		e := m.posts.byRole.Groups.Edit()

		for r, ids := range lists {
			if ids == nil {
				e.Delete(r)
			} else {
				e.Set(r, ids)
			}
		}

		bad.posts.byRole.Groups = e.Done()

		return bad
	}

	resolveOnly := func(bad membership) error {
		_, err := auditResolve(Membership{
			Selectors: bad.sel, UserSets: bad.us, Roles: bad.roles, Postings: bad.posts,
			Users: users, Nodes: bad.nodes, Policy: bad.pm, Current: true,
		})

		return err
	}

	t.Run("posting missing a node", func(t *testing.T) {
		_, err := setPostings(map[Role][]types.NodeID{role("alice@"): nil}).audit()
		require.ErrorContains(t, err, "postings")
	})

	t.Run("role missing from a set", func(t *testing.T) {
		bad := m
		e := m.roles.sets.Edit()
		e.Set(1, newRoleSet(m.sel.Table().id, nil))
		bad.roles.sets = e.Done()

		_, err := bad.audit()
		require.ErrorContains(t, err, "role sets of nodes [1]")
	})

	t.Run("user sets of older users", func(t *testing.T) {
		renamed := slices.Clone(users)
		renamed[0].Name = "alicia"

		bad := m
		bad.users = renamed
		bad.pm = nil // the compile resolved the older users

		_, err := bad.audit()
		require.ErrorContains(t, err, "user sets")
	})

	t.Run("roles not moved by a tag change", func(t *testing.T) {
		tagged := slices.Clone(nodes)
		n := *tagged[1]
		n.Tags = []string{"tag:web"}
		tagged[1] = &n

		bad := m
		bad.nodes, bad.pm = nodeMapOf(tagged), nil

		_, err := bad.audit()
		require.ErrorContains(t, err, "role sets of nodes [2]")
	})

	t.Run("a node in the wrong posting", func(t *testing.T) {
		err := resolveOnly(setPostings(map[Role][]types.NodeID{role("alice@"): {1, 2}}))
		require.ErrorContains(t, err, "node 2 listed true, resolved false")
	})

	t.Run("owner lists another user's node", func(t *testing.T) {
		err := resolveOnly(setPostings(map[Role][]types.NodeID{OwnerRole(1): {1, 2}}))
		require.ErrorContains(t, err, "owner 1 lists")
	})

	t.Run("selectors of another policy", func(t *testing.T) {
		other := buildMembership(t, `{"acls":[{"action":"accept","src":["alice@"],"dst":["alice@:*"]}]}`, users, nodes)

		bad := m
		bad.pm = other.pm

		_, err := bad.audit()
		require.ErrorContains(t, err, "another policy")
	})

	t.Run("a section not collected", func(t *testing.T) {
		bad := m
		bad.sel = &Selectors{table: newSelectorTable(&Policy{ACLs: m.sel.pol.ACLs[:1]}), pol: m.sel.pol}

		_, err := bad.audit()
		require.ErrorContains(t, err, "the selector table lacks it")
	})

	_, err := m.audit()
	require.NoError(t, err)
}

// TestSelectorTableCollectsEverySection requires each section in scope to
// reach the table, an alias written only there included, and each section
// out of scope not to; the independent walk agrees in every case.
func TestSelectorTableCollectsEverySection(t *testing.T) {
	const owners = `"tagOwners":{"tag:only":["alice@"],"tag:other":["alice@"]}`

	for _, tt := range []struct {
		section, policy string
		collected       bool
	}{
		{"acl source", `{` + owners + `,"acls":[{"action":"accept","src":["tag:only"],"dst":["tag:other:*"]}]}`, true},
		{"acl destination", `{` + owners + `,"acls":[{"action":"accept","src":["tag:other"],"dst":["tag:only:22"]}]}`, true},
		{"grant source", `{` + owners + `,"grants":[{"src":["tag:only"],"dst":["tag:other"],"ip":["*"]}]}`, true},
		{"grant destination", `{` + owners + `,"grants":[{"src":["tag:other"],"dst":["tag:only"],"ip":["*"]}]}`, true},
		{"grant via", `{` + owners + `,"grants":[{"src":["tag:other"],"dst":["10.0.0.0/8"],"ip":["*"],"via":["tag:only"]}]}`, true},
		{"ssh source", `{` + owners + `,"acls":[],"ssh":[{"action":"accept","src":["tag:only"],"dst":["tag:other"],"users":["root"]}]}`, true},
		{"ssh destination", `{` + owners + `,"acls":[],"ssh":[{"action":"accept","src":["tag:other"],"dst":["tag:only"],"users":["root"]}]}`, true},
		{"node attribute target", `{` + owners + `,"acls":[],"nodeAttrs":[{"target":["tag:only"],"attr":["disable-ipv4"]}]}`, false},
		{"tag owner", `{"tagOwners":{"tag:a":["tag:only"],"tag:only":["alice@"]},"acls":[]}`, false},
		{"auto-approver", `{` + owners + `,"acls":[],"autoApprovers":{"routes":{"10.0.0.0/8":["tag:only"]}}}`, false},
		{"ssh test", `{` + owners + `,"acls":[],"ssh":[{"action":"accept","src":["alice@"],"dst":["tag:other"],"users":["root"]}],
			"sshTests":[{"src":"alice@","dst":["tag:only"],"accept":["root"]}]}`, false},
	} {
		t.Run(tt.section, func(t *testing.T) {
			sel, err := NewSelectors(nil, []byte(tt.policy))
			require.NoError(t, err)

			_, ok := sel.Table().Lookup("tag:only")
			assert.Equal(t, tt.collected, ok, "tag:only in the table")
			require.NoError(t, auditSelectorTable(sel))

			found := false

			for _, aliases := range policyAliases(sel.pol) {
				for _, a := range aliases {
					found = found || a.String() == "tag:only"
				}
			}

			assert.True(t, found, "the walk finds tag:only")
		})
	}

	t.Run("every policy field is decided", func(t *testing.T) {
		for name := range policyAliases(&Policy{}) {
			_, ok := selectorSections[name]
			assert.True(t, ok, "policy field %s is neither in nor out of scope", name)
		}
	})
}

// TestPostingsChangedAcrossTables checks that postings of two tables
// never compare role by role: the same ID names another selector in each.
func TestPostingsChangedAcrossTables(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}}
	addr := netip.MustParseAddr("100.64.0.1")
	nodes := types.Nodes{{ID: 1, IPv4: &addr, Tags: []string{"tag:a", "tag:b"}}}

	const owners = `"tagOwners":{"tag:a":["alice@"],"tag:b":["alice@"]}`

	before := buildMembership(t, `{`+owners+`,"acls":[{"action":"accept","src":["tag:b"],"dst":["*:*"]}]}`, users, nodes)
	after := buildMembership(t, `{`+owners+`,"acls":[{"action":"accept","src":["tag:a","tag:b"],"dst":["*:*"]}]}`, users, nodes)

	roles, all := after.posts.Changed(before.posts)
	assert.True(t, all, "a new table changes every role")
	assert.Nil(t, roles)

	same, all := after.posts.Changed(after.posts)
	assert.False(t, all)
	assert.Empty(t, same)
}

// TestPostingsUpdateIncrementally checks that a write moves only the lists
// of the roles its node entered or left: the others are the same lists.
func TestPostingsUpdateIncrementally(t *testing.T) {
	users := types.Users{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}
	addr := func(i byte) *netip.Addr { a := netip.AddrFrom4([4]byte{100, 64, 0, i}); return &a }

	nodes := types.Nodes{
		{ID: 1, IPv4: addr(1), User: &users[0]},
		{ID: 2, IPv4: addr(2), User: &users[1]},
		{ID: 3, IPv4: addr(3), Tags: []string{"tag:web"}},
	}

	m := buildMembership(t, `{"tagOwners":{"tag:web":["alice@"]},
		"acls":[{"action":"accept","src":["alice@","bob@","tag:web"],"dst":["autogroup:member:*"]}]}`, users, nodes)

	e := m.nodes.Edit()
	e.Set(4, &types.Node{ID: 4, IPv4: addr(4), User: &users[0]})
	joined := e.Done()

	roles := m.roles.Update(m.us, joined, nil)
	posts := m.posts.Update(roles)

	changed, all := posts.Changed(m.posts)
	require.False(t, all)

	rs, _ := roles.Of(4)
	assert.ElementsMatch(t, rs.Roles(), changed, "the joiner's roles, and only those, moved")

	for r, ids := range m.posts.All() {
		if slices.Contains(changed, r) {
			continue
		}

		got := posts.Nodes(r)
		assert.Same(t, &ids[0], &got[0], "role %s untouched by the join keeps its list", r)
	}
}

// membershipTally collects what the golden membership check saw.
type membershipTally struct {
	mu sync.Mutex

	files, parsed, policies, compiled, nodes, owners int
	refused                                          []string
	kinds, listed                                    map[SelectorKind]int
	sections                                         map[string]int
	report                                           MembershipReport
}

func (g *membershipTally) add(f func(*membershipTally)) {
	g.mu.Lock()
	defer g.mu.Unlock()

	f(g)
}

// goldenMembership checks one policy's membership over users and nodes:
// built from scratch, it must pass the audit, held against the compile's
// own resolutions; built by joining every node to an empty tailnet and
// then removing every other one, it must pass the audit at each step.
func goldenMembership(t *testing.T, tally *membershipTally, src []byte, users types.Users, nodes types.Nodes) {
	t.Helper()

	m := newMembership(t, string(src), users, nodes)

	rep, err := m.audit()
	require.NoError(t, err)

	empty := graph.NewMap[types.NodeID, *types.Node](graph.Same[*types.Node], nil)
	inc := m
	inc.nodes = empty
	inc.roles = Roles{}.Update(m.us, empty, nil)
	inc.posts = Postings{}.Update(inc.roles)
	inc.pm = nil // the compile saw every node

	e := empty.Edit()
	for _, n := range nodes {
		e.Set(n.ID, n)
	}

	inc.nodes = e.Done()
	inc.roles = inc.roles.Update(m.us, inc.nodes, nil)
	inc.posts = inc.posts.Update(inc.roles)
	inc.pm = m.pm

	_, err = inc.audit()
	require.NoError(t, err, "after every node joined")

	e = inc.nodes.Edit()

	for i, n := range nodes {
		if i%2 == 1 {
			e.Delete(n.ID)
		}
	}

	inc.nodes = e.Done()
	inc.roles = inc.roles.Update(m.us, inc.nodes, nil)
	inc.posts = inc.posts.Update(inc.roles)
	inc.pm = nil // the compile saw every node, not half

	_, err = inc.audit()
	require.NoError(t, err, "after every other node left")

	tally.add(func(g *membershipTally) {
		g.policies++
		g.nodes += len(nodes)

		if m.pm != nil {
			g.compiled++
		}

		for _, s := range m.sel.Table().Selectors() {
			g.kinds[s.Kind]++

			if len(m.posts.Nodes(SelectorRole(s.ID))) > 0 {
				g.listed[s.Kind]++
			}
		}

		for r := range m.posts.All() {
			if _, ok := r.Owner(); ok {
				g.owners++
			}
		}

		for section, aliases := range policyAliases(m.sel.pol) {
			g.sections[section] += len(aliases)
		}

		g.report.Compiled += rep.Compiled
		g.report.Indexed += rep.Indexed
		g.report.Fresh += rep.Fresh
		g.report.Judged += rep.Judged
		g.report.Relabelled += rep.Relabelled
	})
}

// TestGoldenMembership runs the membership check over every policy the
// captures hold, with each directory's own users and nodes, and the user
// captures under every overlay, where user resolution has its quirks.
func TestGoldenMembership(t *testing.T) {
	t.Parallel()

	tally := &membershipTally{kinds: map[SelectorKind]int{}, listed: map[SelectorKind]int{}, sections: map[string]int{}}

	t.Cleanup(func() {
		t.Logf("capture files %d, policies parsed %d, refused %d; checked %d policy loads (%d compiled) over %d nodes, %d owner postings",
			tally.files, tally.parsed, len(tally.refused), tally.policies, tally.compiled, tally.nodes, tally.owners)

		for _, k := range slices.Sorted(maps.Keys(tally.kinds)) {
			t.Logf("  %-12s %5d selectors, %5d listing nodes", k, tally.kinds[k], tally.listed[k])
		}

		for _, section := range slices.Sorted(maps.Keys(tally.sections)) {
			t.Logf("  aliases under %-20s %6d (selectors: %t)", section, tally.sections[section], selectorSections[section])
		}

		r := tally.report
		t.Logf("oracle: %d identity selectors held against the compile's alias cache, %d through its indexes, %d resolved afresh",
			r.Compiled, r.Indexed, r.Fresh)
		t.Logf("per node: %d node×selector pairs judged by own addresses, %d by relabelling",
			r.Judged, r.Relabelled)
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

				tally.add(func(g *membershipTally) { g.files++ })

				policy := []byte(c.Input.FullPolicy)

				// SaaS refusals count too: an alias means the same in a
				// document SaaS refused, as long as headscale parses it.
				_, err = unmarshalPolicy(policy)
				if err != nil {
					tally.add(func(g *membershipTally) { g.refused = append(g.refused, c.TestID) })

					return
				}

				tally.add(func(g *membershipTally) { g.parsed++ })

				if src.dir != "users_results" {
					users, nodes := src.build(t, c)
					goldenMembership(t, tally, policy, users, nodes)

					return
				}

				for _, o := range userTokenOverlays {
					name := o.name
					if name == "" {
						name = "capture"
					}

					t.Run(name, func(t *testing.T) {
						users, nodes, _ := userTokenUsersAndNodes(t, c, o)
						goldenMembership(t, tally, policy, users, nodes)

						// At runtime the overlay's users log in to a server
						// running the policy over the capture's users.
						saasUsers, _, _ := userTokenUsersAndNodes(t, c, userTokenOverlay{})
						m := newMembership(t, string(policy), saasUsers, nodes)

						m.us = NewUserSets(m.us, m.sel, users)
						m.roles = m.roles.Update(m.us, m.nodes, nil)
						m.posts = m.posts.Update(m.roles)
						m.users, m.pm = users, nil

						_, err := m.audit()
						require.NoError(t, err)
					})
				}
			})
		}
	}

	t.Run("steps/policy-generation", func(t *testing.T) {
		t.Parallel()
		goldenMembershipSequence(t, "policy-generation")
	})
}

// goldenMembershipSequence replays a step capture through the incremental
// updates, as the world runs them, auditing every step against the compile
// of that step.
func goldenMembershipSequence(t *testing.T, id string) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "..", "servertest", "testdata", "steps", id+".hujson"))
	require.NoError(t, err)

	users := setupGrantsCompatUsers()
	ids := map[string]types.NodeID{}

	var (
		pm     *PolicyManager
		sel    *Selectors
		us     *UserSets
		roles  Roles
		posts  Postings
		nodes  = graph.NewMap[types.NodeID, *types.Node](graph.Same[*types.Node], nil)
		policy []byte
		steps  int
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

		// Every listed node is written, as one commit writing them all.
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
		us = NewUserSets(us, sel, users)
		roles = roles.Update(us, nodes, nil)
		posts = posts.Update(roles)

		_, err = AuditMembership(Membership{
			Selectors: sel, UserSets: us, Roles: roles, Postings: posts,
			Users: users, Nodes: nodes, Policy: pm, Current: true,
		})
		require.NoError(t, err, step.Name)

		steps++
	}

	t.Logf("%s: %d steps audited", id, steps)
}
