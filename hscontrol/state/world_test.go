package state

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func worldNode(id types.NodeID, user *types.User, ip string) *types.Node {
	addr := netip.MustParseAddr(ip)
	uid := user.ID

	return &types.Node{
		ID:         id,
		GivenName:  "node",
		Hostname:   "node",
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		IPv4:       &addr,
		UserID:     &uid,
		User:       user,
		IsOnline:   new(true),
		Hostinfo:   &tailcfg.Hostinfo{},
	}
}

const ownUserPolicy = `{"acls":[{"action":"accept","src":["alice@"],"dst":["alice@:*"]}]}`

func testWorld(t *testing.T, nodes ...*types.Node) (*world, []types.User) {
	t.Helper()

	users := []types.User{{Name: "alice"}, {Name: "bob"}}
	users[0].ID, users[1].ID = 1, 2

	w, err := newWorld(nodes, users, []byte(ownUserPolicy))
	require.NoError(t, err)

	return w, users
}

func TestWorldPayloadWriteKeepsPolicy(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t,
		worldNode(1, alice, "100.64.0.1"),
		worldNode(2, alice, "100.64.0.2"),
	)

	before := w.snapshot()

	w.UpdateNode(1, func(n *types.Node) {
		n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
	})

	after := w.snapshot()
	require.Greater(t, after.Rev(), before.Rev())
	assert.Equal(t, before.PolicyRev(), after.PolicyRev(), "an endpoint update must not recompile the policy")
	assert.Same(t, before.Policy(), after.Policy())
	assert.Equal(t, []types.NodeID{2}, after.ListPeerIDs(1))

	nv, _ := after.GetNode(1)
	assert.Len(t, nv.Endpoints().AsSlice(), 1, "readers see the write")
}

func TestWorldNodeJoinUpdatesPeers(t *testing.T) {
	alice, bob := &types.User{Name: "alice"}, &types.User{Name: "bob"}
	alice.ID, bob.ID = 1, 2

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"))
	before := w.snapshot()

	w.PutNode(*worldNode(2, alice, "100.64.0.2"))
	w.PutNode(*worldNode(3, bob, "100.64.0.3"))

	after := w.snapshot()
	assert.NotEqual(t, before.PolicyRev(), after.PolicyRev(), "a join recompiles the policy")
	assert.Equal(t, []types.NodeID{2}, after.ListPeerIDs(1))
	assert.Empty(t, after.ListPeerIDs(3), "bob's node is outside alice's ACL")

	// The old snapshot is untouched.
	assert.Empty(t, before.ListPeerIDs(1))
}

func TestWorldGivenNamesStayUnique(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t)

	a := w.PutNode(*worldNode(1, alice, "100.64.0.1"))
	b := w.PutNode(*worldNode(2, alice, "100.64.0.2"))

	assert.Equal(t, "node", a.GivenName())
	assert.Equal(t, "node-1", b.GivenName())

	_, err := w.SetGivenName(2, "NODE")
	require.ErrorIs(t, err, ErrGivenNameTaken)

	_, err = w.SetGivenName(2, "not a label")
	require.ErrorIs(t, err, ErrGivenNameInvalid)

	_, err = w.SetGivenName(9, "x")
	require.ErrorIs(t, err, ErrNodeNotFound)

	nv, err := w.SetGivenName(2, "laptop")
	require.NoError(t, err)
	assert.Equal(t, "laptop", nv.GivenName())
}

func TestWorldPrimaryKeepsHealthyIncumbent(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	route := netip.MustParsePrefix("10.0.0.0/24")
	router := func(id types.NodeID, ip string) *types.Node {
		n := worldNode(id, alice, ip)
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}

		return n
	}

	w, _ := testWorld(t, router(1, "100.64.0.1"), router(2, "100.64.0.2"))

	primary, _ := w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(1), primary, "lowest ID wins first")

	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(false) })
	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(2), primary, "failover")

	w.UpdateNode(1, func(n *types.Node) { n.IsOnline = new(true) })
	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(2), primary, "a returning router does not take the prefix back")

	w.UpdateNode(2, func(n *types.Node) { n.Unhealthy = true })
	primary, _ = w.snapshot().PrimaryRouteFor(route)
	assert.Equal(t, types.NodeID(1), primary, "an unhealthy primary hands over")
}

func TestWorldSetUsersRefreshesNodeOwner(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, users := testWorld(t, worldNode(1, alice, "100.64.0.1"))

	users[0].DisplayName = "Alice A."
	w.SetUsers(users)

	nv, _ := w.snapshot().GetNode(1)
	assert.Equal(t, "Alice A.", nv.User().DisplayName())
}

func TestWorldFailedCompileKeepsLastPolicy(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"), worldNode(2, alice, "100.64.0.2"))
	good := w.snapshot().Policy()

	// Two users named alice make the policy's "alice@" ambiguous.
	dup := []types.User{{Name: "alice"}, {Name: "alice"}}
	dup[0].ID, dup[1].ID = 1, 3
	w.SetUsers(dup)

	snap := w.snapshot()
	require.Error(t, snap.PolicyErr())
	assert.Same(t, good, snap.Policy())
}

// createTestNode returns a user-owned node with keys and an IPv4 address
// unique to id.
func createTestNode(id types.NodeID, userID uint, username, hostname string) types.Node {
	ip := netip.MustParseAddr(fmt.Sprintf("100.64.%d.%d", id/256, id%256))
	user := &types.User{Name: username, DisplayName: username}
	user.ID = userID

	return types.Node{
		ID:             id,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       hostname,
		GivenName:      hostname,
		UserID:         new(userID),
		User:           user,
		RegisterMethod: "test",
		IPv4:           &ip,
		Hostinfo:       &tailcfg.Hostinfo{},
	}
}

// newTestWorld returns a world without a policy, so every node sees every
// other, holding nodes as PutNode stores them.
func newTestWorld(t *testing.T, nodes ...types.Node) *world {
	t.Helper()

	w, err := newWorld(nil, nil, nil)
	require.NoError(t, err)

	for _, n := range nodes {
		w.PutNode(n)
	}

	return w
}

// fatalfer is what *testing.T and *rapid.T share, so property tests can use
// the checks below.
type fatalfer interface {
	Helper()
	Fatalf(format string, args ...any)
}

// checkPeersMatchFullBuild compares the snapshot's derived peer map against
// a policy compiled from scratch over the same nodes and users. Divergence
// means a cutoff kept a peer map the inputs no longer produce.
func checkPeersMatchFullBuild(t fatalfer, snap *Snapshot) {
	t.Helper()

	nodes := snap.ListNodes()

	fresh, err := policy.NewPolicyManager(snap.PolicySource(), snap.Users(), nodes)
	if err != nil {
		t.Fatalf("fresh policy: %v", err)
	}

	want := fresh.BuildPeerMap(nodes)

	for _, nv := range nodes.All() {
		got := snap.ListPeerIDs(nv.ID())

		exp := slices.Sorted(slices.Values(want[nv.ID()]))
		if !slices.Equal(got, exp) {
			t.Fatalf("node %d: peers %v, full build %v", nv.ID(), got, exp)
		}
	}
}

// TestPutNodeGivenNameCollisionBumps is the reproduction for #3188: two
// nodes written with one GivenName get -1, -2, … appended instead of
// sharing it.
func TestPutNodeGivenNameCollisionBumps(t *testing.T) {
	w := newTestWorld(t)

	got1 := w.PutNode(createTestNode(1, 1, "alice", "laptop"))
	got2 := w.PutNode(createTestNode(2, 1, "alice", "laptop"))
	got3 := w.PutNode(createTestNode(3, 1, "alice", "laptop"))

	require.Equal(t, "laptop", got1.GivenName(), "first registration keeps base label")
	require.Equal(t, "laptop-1", got2.GivenName(), "second registration bumps to -1")
	require.Equal(t, "laptop-2", got3.GivenName(), "third registration bumps to -2")
}

// TestPutNodeEmptyGivenNameFallsBackToNode covers the SaaS rule that an
// empty sanitised label becomes the literal "node".
func TestPutNodeEmptyGivenNameFallsBackToNode(t *testing.T) {
	w := newTestWorld(t)

	got1 := w.PutNode(createTestNode(1, 1, "alice", ""))
	got2 := w.PutNode(createTestNode(2, 1, "alice", ""))

	require.Equal(t, "node", got1.GivenName())
	require.Equal(t, "node-1", got2.GivenName())
}

// TestPutNodeIdempotentKeepsLabel asserts re-putting a node does not bump
// its own label.
func TestPutNodeIdempotentKeepsLabel(t *testing.T) {
	w := newTestWorld(t)

	n := createTestNode(1, 1, "alice", "laptop")
	require.Equal(t, "laptop", w.PutNode(n).GivenName())
	require.Equal(t, "laptop", w.PutNode(n).GivenName(), "re-put of same node must not bump its own label")
}

// TestUpdateNodeBumpsOnCollision asserts an update that rewrites GivenName
// to a label another node holds is bumped too.
func TestUpdateNodeBumpsOnCollision(t *testing.T) {
	w := newTestWorld(t,
		createTestNode(1, 1, "alice", "laptop"),
		createTestNode(2, 1, "alice", "phone"),
	)

	view, ok := w.UpdateNode(2, func(n *types.Node) { n.GivenName = "laptop" })
	require.True(t, ok)
	require.Equal(t, "laptop-1", view.GivenName(), "UpdateNode must bump on collision")
}

// TestConcurrentPutNodeSameGivenNameAllUnique writes one GivenName from many
// goroutines; every stored label must still be unique.
func TestConcurrentPutNodeSameGivenNameAllUnique(t *testing.T) {
	const n = 20

	w := newTestWorld(t)

	var wg sync.WaitGroup

	results := make(chan string, n)
	for id := range n {
		wg.Go(func() {
			results <- w.PutNode(createTestNode(types.NodeID(id+1), 1, "alice", "laptop")).GivenName() //nolint:gosec // test ids
		})
	}

	wg.Wait()
	close(results)

	seen := make(map[string]struct{}, n)
	for label := range results {
		require.NotContains(t, seen, label, "duplicate label across concurrent PutNode")

		seen[label] = struct{}{}
	}

	for i := range n {
		want := "laptop"
		if i > 0 {
			want = fmt.Sprintf("laptop-%d", i)
		}

		assert.Contains(t, seen, want)
	}
}

func TestSetGivenName(t *testing.T) {
	w := newTestWorld(t,
		createTestNode(1, 1, "alice", "Laptop"),
		createTestNode(2, 1, "alice", "phone"),
	)

	t.Run("free label", func(t *testing.T) {
		view, err := w.SetGivenName(2, "workhorse")
		require.NoError(t, err)
		require.Equal(t, "workhorse", view.GivenName())
	})

	t.Run("own label", func(t *testing.T) {
		view, err := w.SetGivenName(2, "workhorse")
		require.NoError(t, err, "a node's own label is not a collision")
		require.Equal(t, "workhorse", view.GivenName())
	})

	// "Laptop" and "laptop" are one DNS name, so a certificate for one
	// would be valid for the other.
	t.Run("taken ignoring case", func(t *testing.T) {
		_, err := w.SetGivenName(2, "laptop")
		require.ErrorIs(t, err, ErrGivenNameTaken)

		view, _ := w.snapshot().GetNode(2)
		require.Equal(t, "workhorse", view.GivenName(), "rejected rename must not mutate state")

		got := w.PutNode(createTestNode(3, 1, "alice", "laptop"))
		require.Equal(t, "laptop-1", got.GivenName())
	})

	t.Run("invalid", func(t *testing.T) {
		for _, bad := range []string{"Joe's Mac", "has space", "-leading", "trailing-", "", "dot.in.label"} {
			_, err := w.SetGivenName(1, bad)
			require.ErrorIsf(t, err, ErrGivenNameInvalid, "label %q must reject as invalid", bad)
		}
	})

	t.Run("missing node", func(t *testing.T) {
		_, err := w.SetGivenName(999, "something")
		require.ErrorIs(t, err, ErrNodeNotFound)
	})
}

// TestWorldIndex covers the lookups every reader relies on: peers never
// include the node itself, and tagged nodes belong to no user.
func TestWorldIndex(t *testing.T) {
	tagged := createTestNode(4, 1, "user1", "tagged")
	tagged.UserID, tagged.User = nil, nil
	tagged.Tags = []string{"tag:srv"}

	snap := newTestWorld(t,
		createTestNode(1, 1, "user1", "node1"),
		createTestNode(2, 2, "user2", "node2"),
		createTestNode(3, 1, "user1", "node3"),
		tagged,
	).snapshot()

	assert.Equal(t, 4, snap.ListNodes().Len())
	assert.Equal(t, 2, snap.ListNodesByUser(1).Len())
	assert.Equal(t, 1, snap.ListNodesByUser(2).Len())
	assert.Zero(t, snap.ListNodesByUser(0).Len(), "tagged nodes are owned by no user")

	for _, nv := range snap.ListNodes().All() {
		peers := snap.ListPeerIDs(nv.ID())
		assert.Len(t, peers, 3, "node %d sees every other node", nv.ID())
		assert.NotContains(t, peers, nv.ID(), "node %d listed among its own peers", nv.ID())
	}

	assert.Zero(t, newTestWorld(t).snapshot().ListNodes().Len())
}

func TestGetNodesByMachineKeyAllUsers(t *testing.T) {
	mk := key.NewMachine().Public()

	owned1 := createTestNode(1, 1, "user1", "node1")
	owned1.MachineKey = mk
	owned2 := createTestNode(2, 2, "user2", "node2")
	owned2.MachineKey = mk
	tagged := createTestNode(3, 3, "user3", "node3")
	tagged.MachineKey = mk
	tagged.UserID, tagged.User = nil, nil
	tagged.Tags = []string{"tag:foo"}

	require.Empty(t, newTestWorld(t).snapshot().GetNodesByMachineKeyAllUsers(mk))

	all := newTestWorld(t, owned1, owned2, tagged).snapshot().GetNodesByMachineKeyAllUsers(mk)
	require.Len(t, all, 3)
	require.Equal(t, types.NodeID(1), all[types.UserID(1)].ID())
	require.Equal(t, types.NodeID(2), all[types.UserID(2)].ID())
	require.True(t, all[types.UserID(0)].IsTagged(), "tagged node is indexed under UserID(0)")
	require.Equal(t, types.NodeID(3), all[types.UserID(0)].ID())
}

// nodeKeyIndexMismatch describes where snap's NodeKey index disagrees with
// its node list, or returns "" when every listed node, and nothing else, is
// indexed.
func nodeKeyIndexMismatch(snap *Snapshot) string {
	idx := snap.index()
	if len(idx.byNodeKey) != len(idx.all) {
		return fmt.Sprintf("index holds %d keys, list holds %d nodes", len(idx.byNodeKey), len(idx.all))
	}

	for _, nv := range idx.all {
		got, ok := idx.byNodeKey[nv.NodeKey()]
		if !ok {
			return fmt.Sprintf("node %d: key not indexed", nv.ID())
		}

		if got.ID() != nv.ID() {
			return fmt.Sprintf("node %d: key indexed to node %d", nv.ID(), got.ID())
		}
	}

	return ""
}

// TestWorldNodeKeyIndexMatchesNodes pins the index DERP admission reads:
// every published snapshot indexes exactly its nodes' keys, and a key
// rotated away or deleted stops resolving, also on writes the policy
// ignores.
func TestWorldNodeKeyIndexMatchesNodes(t *testing.T) {
	n1 := createTestNode(1, 1, "user1", "node1")
	n2 := createTestNode(2, 1, "user1", "node2")
	n3 := createTestNode(3, 2, "user2", "node3")
	w := newTestWorld(t, n1, n2, n3)

	// Readers load snapshots while the writes below publish them, so a torn
	// or stale index surfaces here and under -race.
	var (
		firstMismatch atomic.Pointer[string]
		stop          atomic.Bool
		readers       sync.WaitGroup
	)

	for range 4 {
		readers.Go(func() {
			for !stop.Load() {
				if msg := nodeKeyIndexMismatch(w.snapshot()); msg != "" {
					firstMismatch.CompareAndSwap(nil, &msg)
				}
			}
		})
	}

	stopReaders := func() {
		stop.Store(true)
		readers.Wait()
	}
	t.Cleanup(stopReaders)

	requireResolves := func(k key.NodePublic, want types.NodeID) {
		t.Helper()

		nv, ok := w.snapshot().GetNodeByNodeKey(k)
		require.True(t, ok, "key of node %d must resolve", want)
		require.Equal(t, want, nv.ID())
	}

	requireRefused := func(k key.NodePublic) {
		t.Helper()

		_, ok := w.snapshot().GetNodeByNodeKey(k)
		require.False(t, ok, "key must not resolve")
	}

	requireResolves(n1.NodeKey, 1)
	requireResolves(n2.NodeKey, 2)
	requireResolves(n3.NodeKey, 3)

	before := w.snapshot()

	// Repeat the rotation so the readers overlap many publishes.
	current := n1.NodeKey
	for range 50 {
		prev := current
		current = key.NewNode().Public()

		_, ok := w.UpdateNode(1, func(n *types.Node) { n.NodeKey = current })
		require.True(t, ok)

		requireRefused(prev)
		requireResolves(current, 1)
	}

	w.UpdateNode(2, func(n *types.Node) { n.Hostname = "node2-renamed" })

	nv, ok := w.snapshot().GetNodeByNodeKey(n2.NodeKey)
	require.True(t, ok)
	require.Equal(t, "node2-renamed", nv.Hostname(), "a payload write must republish the indexed view")

	require.Equal(t, before.PeersRev(), w.snapshot().PeersRev(),
		"rotation and payload writes must not rebuild the peer map")

	w.DeleteNode(3)
	requireRefused(n3.NodeKey)
	requireResolves(current, 1)
	requireResolves(n2.NodeKey, 2)

	stopReaders()

	if msg := firstMismatch.Load(); msg != nil {
		t.Fatalf("snapshot index disagreed with node list: %s", *msg)
	}

	require.Empty(t, nodeKeyIndexMismatch(w.snapshot()))
}

// TestWorldNonPolicyWritesKeepPolicy covers which node writes recompile the
// policy: only fields it reads, so routine map requests and sessions do not
// pay for a compile and a peer-map build.
func TestWorldNonPolicyWritesKeepPolicy(t *testing.T) {
	route := netip.MustParsePrefix("10.0.0.0/24")

	tests := []struct {
		name    string
		write   func(n *types.Node)
		compile bool
	}{
		{name: "last seen", write: func(n *types.Node) { n.LastSeen = new(time.Now()) }},
		{name: "node key", write: func(n *types.Node) { n.NodeKey = key.NewNode().Public() }},
		{name: "online", write: func(n *types.Node) { n.IsOnline = new(true) }},
		{name: "health", write: func(n *types.Node) { n.Unhealthy = true }},
		{name: "given name", write: func(n *types.Node) { n.GivenName = "renamed" }},
		{name: "announced only", write: func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		}},
		{name: "tags", compile: true, write: func(n *types.Node) {
			n.Tags = []string{"tag:srv"}
			n.UserID, n.User = nil, nil
		}},
		{name: "address", compile: true, write: func(n *types.Node) {
			n.IPv4 = new(netip.MustParseAddr("100.64.9.9"))
		}},
		{name: "announced and approved", compile: true, write: func(n *types.Node) {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
			n.ApprovedRoutes = []netip.Prefix{route}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := newTestWorld(t, createTestNode(1, 1, "user1", "node1"), createTestNode(2, 1, "user1", "node2"))
			before := w.snapshot()

			_, ok := w.UpdateNode(1, tt.write)
			require.True(t, ok)

			after := w.snapshot()
			require.Greater(t, after.Rev(), before.Rev())
			assert.Equal(t, tt.compile, after.PolicyRev() != before.PolicyRev(), "policy recompiled")

			if !tt.compile {
				assert.Same(t, before.Policy(), after.Policy())
			}
		})
	}
}

func TestUpdateNodeDiff(t *testing.T) {
	node := createTestNode(1, 1, "user1", "node1")
	w := newTestWorld(t, node)

	newKey := key.NewNode().Public()
	before, after, ok := w.UpdateNodeDiff(1, func(n *types.Node) { n.NodeKey = newKey })
	require.True(t, ok)
	assert.Equal(t, node.NodeKey, before.NodeKey())
	assert.Equal(t, newKey, after.NodeKey())

	rev := w.snapshot().Rev()
	called := false

	before, after, ok = w.UpdateNodeDiff(99, func(*types.Node) { called = true })
	assert.False(t, ok)
	assert.False(t, before.Valid())
	assert.False(t, after.Valid())
	assert.False(t, called, "an update of a missing node must not run")
	assert.Equal(t, rev, w.snapshot().Rev(), "an update of a missing node must not commit")
}

func TestPrimaryRoutesForNodeSorted(t *testing.T) {
	node := createTestNode(1, 1, "user1", "router")

	prefixes := make([]netip.Prefix, 0, 8)
	for i := range 8 {
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i), 0, 0}), 16))
	}

	node.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: prefixes}
	node.ApprovedRoutes = prefixes
	node.IsOnline = new(true)

	snap := newTestWorld(t, node).snapshot()

	// Map iteration order varies per call; repeat to catch an unsorted result.
	for range 20 {
		require.Equal(t, prefixes, snap.PrimaryRoutesForNode(1))
	}
}

// Policy shapes for TestWorldPeersMatchFullBuild: a global ACL,
// autogroup:self, and a via grant.
const (
	policyGlobal = `{
		"groups": {"group:a": ["u1@"]},
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [
			{"action": "accept", "src": ["group:a"], "dst": ["tag:srv:*"]},
			{"action": "accept", "src": ["u2@"], "dst": ["10.33.0.0/24:*"]}
		]}`

	policyAutogroupSelf = `{
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]}`

	policyVia = `{
		"tagOwners": {"tag:router": ["u1@"]},
		"grants": [{"src": ["u2@"], "dst": ["10.33.0.0/24"], "ip": ["*"], "via": ["tag:router"]}]}`
)

// TestWorldPeersMatchFullBuild drives random node writes through the world
// and checks after every step that the derived peer map, including one the
// policy-nodes cutoff kept from the previous commit, matches a policy
// compiled from scratch. Divergence means the cutoff skipped a field the
// policy reads.
func TestWorldPeersMatchFullBuild(t *testing.T) {
	subnet := netip.MustParsePrefix("10.33.0.0/24")

	for _, tc := range []struct {
		name string
		pol  string
	}{
		{name: "global", pol: policyGlobal},
		{name: "autogroup-self", pol: policyAutogroupSelf},
		{name: "via", pol: policyVia},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				users := []types.User{{Name: "u1"}, {Name: "u2"}}
				users[0].ID, users[1].ID = 1, 2

				nodes := make(types.Nodes, 0, 6)

				for i := 1; i <= 6; i++ {
					u := users[i%2]
					n := createTestNode(types.NodeID(i), u.ID, u.Name, fmt.Sprintf("n%d", i))
					nodes = append(nodes, &n)
				}

				w, err := newWorld(nodes, users, []byte(tc.pol))
				if err != nil {
					rt.Fatalf("world: %v", err)
				}

				steps := rapid.IntRange(1, 20).Draw(rt, "steps")
				for range steps {
					id := types.NodeID(rapid.IntRange(1, 6).Draw(rt, "id")) //nolint:gosec // small test ids
					switch rapid.IntRange(0, 5).Draw(rt, "op") {
					case 0: // payload only
						w.UpdateNode(id, func(n *types.Node) { n.LastSeen = new(time.Now()) })
					case 1: // tag
						tag := rapid.SampledFrom([]string{"tag:srv", "tag:router"}).Draw(rt, "tag")

						w.UpdateNode(id, func(n *types.Node) {
							n.Tags = []string{tag}
							n.UserID, n.User = nil, nil
						})
					case 2: // announce + approve subnet
						w.UpdateNode(id, func(n *types.Node) {
							n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
							n.ApprovedRoutes = []netip.Prefix{subnet}
						})
					case 3: // drop routes
						w.UpdateNode(id, func(n *types.Node) { n.ApprovedRoutes = nil })
					case 4: // online flip
						w.UpdateNode(id, func(n *types.Node) { n.IsOnline = new(!n.Online()) })
					case 5: // endpoint
						w.UpdateNode(id, func(n *types.Node) {
							n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
						})
					}

					checkPeersMatchFullBuild(rt, w.snapshot())
				}
			})
		})
	}
}

// TestListPeersExcludesSelf proves a node is never returned among its own
// peers, also when the caller names it explicitly. The mapper would
// otherwise emit the recipient in its own PeersChanged, and the Tailscale
// client would merge it into its peer map next to the self node.
func TestListPeersExcludesSelf(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("peer-user")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "peer-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	allIDs := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		allIDs = append(allIDs, n.ID)
	}

	for _, self := range allIDs {
		t.Run(self.String(), func(t *testing.T) {
			for _, peer := range s.ListPeers(self).All() {
				require.NotEqual(t, self, peer.ID(), "node listed in its own peers")
			}

			named := s.ListPeers(self, allIDs...)
			require.Equal(t, len(allIDs)-1, named.Len(), "self must be dropped, every other named node kept")

			for _, peer := range named.All() {
				require.NotEqual(t, self, peer.ID(), "node listed in its own named peers")
			}

			require.Zero(t, s.ListPeers(self, self).Len(), "naming only self must yield no peers")
		})
	}
}

// TestPolicyCachesSurviveStaleView asks the newly compiled policy about a
// node through a view taken before the write that compiled it, as a caller
// holding an older view does. That answer must not be cached under the
// node's ID, or the fresh view keeps getting it.
func TestPolicyCachesSurviveStaleView(t *testing.T) {
	subnet := netip.MustParsePrefix("10.33.0.0/24")

	pol := `{
		"tagOwners": {"tag:srv": ["u1@"]},
		"acls": [{"action": "accept", "src": ["u2@"], "dst": ["10.33.0.0/24:*"]}],
		"ssh": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self"], "users": ["root"]}]
	}`

	tests := []struct {
		name   string
		mutate func(n *types.Node)
		// probe reports a property of node 1's policy artefact that the
		// write flips from !want to want.
		probe func(pm policy.PolicyManager, view types.NodeView) (bool, error)
		want  bool
	}{
		{
			name: "filter after route approval",
			mutate: func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
				n.ApprovedRoutes = []netip.Prefix{subnet}
			},
			probe: func(pm policy.PolicyManager, view types.NodeView) (bool, error) {
				rules, err := pm.FilterForNode(view)
				if err != nil {
					return false, err
				}

				for _, r := range rules {
					for _, d := range r.DstPorts {
						if d.IP == subnet.String() {
							return true, nil
						}
					}
				}

				return false, nil
			},
			want: true,
		},
		{
			// A tagged node is outside autogroup:self, so tagging it must
			// drop its SSH rules.
			name: "ssh after tagging",
			mutate: func(n *types.Node) {
				n.Tags = []string{"tag:srv"}
				n.UserID, n.User = nil, nil
			},
			probe: func(pm policy.PolicyManager, view types.NodeView) (bool, error) {
				sshPol, err := pm.SSHPolicy("", view)
				if err != nil {
					return false, err
				}

				return sshPol != nil && len(sshPol.Rules) > 0, nil
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := []types.User{{Name: "u1"}, {Name: "u2"}}
			users[0].ID, users[1].ID = 1, 2

			// Node 3 shares node 1's user so autogroup:self has a source
			// for node 1 once node 1 itself is tagged away.
			owners := []int{0, 1, 0}
			nodes := make(types.Nodes, 0, len(owners))

			for i, o := range owners {
				n := createTestNode(types.NodeID(i+1), users[o].ID, users[o].Name, fmt.Sprintf("n%d", i+1)) //nolint:gosec // small test ids
				nodes = append(nodes, &n)
			}

			w, err := newWorld(nodes, users, []byte(pol))
			require.NoError(t, err)

			before, ok := w.snapshot().GetNode(1)
			require.True(t, ok)

			got, err := tt.probe(w.snapshot().Policy(), before)
			require.NoError(t, err)
			require.NotEqual(t, tt.want, got, "precondition: the write must flip the probed artefact")

			after, ok := w.UpdateNode(1, tt.mutate)
			require.True(t, ok)

			pm := w.snapshot().Policy()

			_, err = tt.probe(pm, before)
			require.NoError(t, err)

			got, err = tt.probe(pm, after)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got, "the policy must answer for the written node")
		})
	}
}

// TestWorldGroupCommitsQueuedWrites queues writes behind a stalled commit
// and checks they land together: one more commit, so one policy compile,
// for the whole burst.
func TestWorldGroupCommitsQueuedWrites(t *testing.T) {
	alice := &types.User{Name: "alice"}
	alice.ID = 1

	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"))
	before := w.snapshot().Rev()

	entered, release := make(chan struct{}), make(chan struct{})

	go w.UpdateNode(1, func(*types.Node) {
		close(entered)
		<-release
	})

	<-entered

	const burst = 10

	var wg sync.WaitGroup

	for i := range burst {
		wg.Go(func() {
			w.PutNode(*worldNode(types.NodeID(i+2), alice, fmt.Sprintf("100.64.0.%d", i+2)))
		})
	}

	require.Eventually(t, func() bool {
		w.writeMu.Lock()
		defer w.writeMu.Unlock()

		return len(w.writes) == burst
	}, 5*time.Second, time.Millisecond)

	close(release)
	wg.Wait()

	after := w.snapshot()
	assert.Equal(t, before+2, after.Rev(), "the stalled write and the burst commit once each")
	assert.Equal(t, burst+1, after.ListNodes().Len())
	assert.Len(t, after.ListPeerIDs(1), burst)
}
