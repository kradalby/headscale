package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
