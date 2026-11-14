package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestAutoApproveBatchApprovesRoutes preserves route approval and durability
// coverage at the announcement boundary; a policy reload approves nothing.
func TestAutoApproveBatchApprovesRoutes(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")

	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	})
	require.True(t, ok)

	pol := `{
		"autoApprovers": {"routes": {"10.0.0.0/24": ["persist-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err := s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	err = s.ReloadPolicy()
	require.NoError(t, err)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Empty(t, nv.ApprovedRoutes().AsSlice(), "a reload approves nothing")

	for _, routes := range [][]netip.Prefix{nil, {route}} {
		err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
			NodeKey: nv.NodeKey(), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes},
		})
		require.NoError(t, err)
	}

	nv, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, []netip.Prefix{route}, nv.ApprovedRoutes().AsSlice())
	assert.Equal(t, []netip.Prefix{route}, nv.AutoApprovedRoutes().AsSlice())

	durable, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{route}, []netip.Prefix(durable.ApprovedRoutes))
	assert.Equal(t, []netip.Prefix{route}, []netip.Prefix(durable.AutoApprovedRoutes))
}

// TestAutoApproveSurvivesVanishedRow verifies that a deleting node cannot block
// policy reload or the targeted, durable approval of a surviving node.
func TestAutoApproveSurvivesVanishedRow(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	routeA := netip.MustParsePrefix("10.0.0.0/24")
	routeB := netip.MustParsePrefix("10.1.0.0/24")

	_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{routeA}}
	})
	require.True(t, ok)

	survivor := registerPersistedNode(t, s, "autoapprove-survivor")

	_, ok = s.world.UpdateNode(survivor.ID(), func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{routeB}}
	})
	require.True(t, ok)

	pol := `{
		"autoApprovers": {"routes": {
			"10.0.0.0/24": ["persist-user@"],
			"10.1.0.0/24": ["persist-user@"]
		}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`
	_, err := s.SetPolicy([]byte(pol))
	require.NoError(t, err)

	// A lifetime delete's window: the victim's row is gone while the world
	// still knows it. Neither reload nor another node's approval may write it.
	victim, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.NoError(t, s.db.DeleteNode(victim.AsStruct()))

	err = s.ReloadPolicy()
	require.NoError(t, err, "a vanished node must not fail the reload")

	live, ok := s.GetNodeByID(survivor.ID())
	require.True(t, ok)
	require.Empty(t, live.ApprovedRoutes().AsSlice(), "a reload approves nothing")

	for _, routes := range [][]netip.Prefix{nil, {routeB}} {
		err = s.UpdateNodeFromMapRequest(survivor.ID(), tailcfg.MapRequest{
			NodeKey: live.NodeKey(), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: routes},
		})
		require.NoError(t, err)
	}

	live, ok = s.GetNodeByID(survivor.ID())
	require.True(t, ok)
	assert.Equal(t, []netip.Prefix{routeB}, live.ApprovedRoutes().AsSlice(),
		"the surviving node's approval must publish")
	assert.Equal(t, []netip.Prefix{routeB}, live.AutoApprovedRoutes().AsSlice())

	durable, err := s.db.GetNodeByID(survivor.ID())
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{routeB}, []netip.Prefix(durable.ApprovedRoutes),
		"the surviving node's approval must reach its row")
	assert.Equal(t, []netip.Prefix{routeB}, []netip.Prefix(durable.AutoApprovedRoutes))

	_, err = s.db.GetNodeByID(nodeID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound, "the deleted row must stay deleted")

	victim, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, victim.ApprovedRoutes().AsSlice(), "approval must leave the deleting node untouched")
}

func TestRouteApprovalWaitsForAnnouncement(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	added := netip.MustParsePrefix("10.0.1.0/24")

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	report := func(hostname string, routes ...netip.Prefix) {
		t.Helper()

		err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
			NodeKey:  nv.NodeKey(),
			DiscoKey: nv.DiscoKey(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname, RoutableIPs: routes},
		})
		require.NoError(t, err)
	}
	approved := func() []netip.Prefix {
		t.Helper()

		current, ok := s.GetNodeByID(nodeID)
		require.True(t, ok)

		return current.ApprovedRoutes().AsSlice()
	}

	report("router", route)
	require.Empty(t, approved())

	_, err := s.db.SetPolicy(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`)
	require.NoError(t, err)

	err = s.ReloadPolicy()
	require.NoError(t, err)
	assert.Empty(t, approved(), "a reload approves nothing")

	report("router-renamed", route)
	assert.Empty(t, approved(), "a report that keeps the routes approves nothing")

	report("router-renamed", route, added)
	assert.ElementsMatch(t, []netip.Prefix{route, added}, approved(),
		"a new announcement runs approvers over every announced route")
}

func TestAutoApproveKeepsCurrentManualRoutes(t *testing.T) {
	manual := netip.MustParsePrefix("10.0.0.0/24")
	automatic := netip.MustParsePrefix("10.1.0.0/24")
	addition := netip.MustParsePrefix("10.2.0.0/24")

	for _, tt := range []struct {
		name        string
		replacement []netip.Prefix
		want        []netip.Prefix
	}{
		{name: "revoke", want: []netip.Prefix{automatic}},
		{name: "add", replacement: []netip.Prefix{manual, addition}, want: []netip.Prefix{manual, automatic, addition}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			_, err := s.SetPolicy([]byte(`{
				"autoApprovers": {"routes": {"10.1.0.0/24": ["persist-user@"]}},
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`))
			require.NoError(t, err)

			_, ok := s.world.UpdateNode(nodeID, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{manual, automatic}}
			})
			require.True(t, ok)

			stale, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{manual})
			require.NoError(t, err)

			_, err = s.SetApprovedRoutes(nodeID, tt.replacement)
			require.NoError(t, err)

			err = s.AutoApproveRoutes(stale)
			require.NoError(t, err)

			current, ok := s.GetNodeByID(nodeID)
			require.True(t, ok)
			assert.ElementsMatch(t, tt.want, current.ApprovedRoutes().AsSlice())

			stored, err := s.db.GetNodeByID(nodeID)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, stored.ApprovedRoutes.List())
		})
	}
}

func TestRegistrationApprovesOnlyWithNewNodeKey(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("approve-user")

	_, err := s.SetPolicy([]byte(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["approve-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	route := netip.MustParsePrefix("10.0.1.0/24")
	machineKey := key.NewMachine().Public()
	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{route}},
	}

	node, err := s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{route}, approvedRoutes(t, s, node.ID()), "a new node")

	_, err = s.SetApprovedRoutes(node.ID(), nil)
	require.NoError(t, err)

	_, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Empty(t, approvedRoutes(t, s, node.ID()), "the same node key")

	added := netip.MustParsePrefix("10.0.2.0/24")
	req.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{route, added}}
	_, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{route, added}, approvedRoutes(t, s, node.ID()), "a new announced route")

	_, err = s.SetApprovedRoutes(node.ID(), nil)
	require.NoError(t, err)

	req.NodeKey = key.NewNode().Public()
	_, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{route, added}, approvedRoutes(t, s, node.ID()), "a new node key")
}

func TestRegistrationApprovalComparesReplacedNode(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("approve-user")

	_, err := s.SetPolicy([]byte(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["approve-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	c := registerForPAKRereg(t, s, pak)
	stale, stalePAK := c.lookup(t, pak.Key)

	route := netip.MustParsePrefix("10.0.1.0/24")
	hi := &tailcfg.Hostinfo{Hostname: "h0", RoutableIPs: []netip.Prefix{route}}

	err = s.UpdateNodeFromMapRequest(c.node.ID(), tailcfg.MapRequest{NodeKey: c.regReq.NodeKey, Hostinfo: hi})
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{route}, approvedRoutes(t, s, c.node.ID()), "the announcement approves")

	_, err = s.SetApprovedRoutes(c.node.ID(), nil)
	require.NoError(t, err)

	req := c.regReq
	req.Hostinfo = hi.Clone()
	node, replaced, err := s.reregisterNodeWithPAK(stale, stalePAK, nil, req, c.machineKey, hi.Hostname, req.Hostinfo)
	require.NoError(t, err)

	err = s.approveRoutesAfterRegistration(replaced, node)
	require.NoError(t, err)
	assert.Empty(t, approvedRoutes(t, s, c.node.ID()), "the admin revoke stands")
}

func approvedRoutes(t *testing.T, s *State, id types.NodeID) []netip.Prefix {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	return nv.ApprovedRoutes().AsSlice()
}

func TestWithdrawnRouteKeepsOnlyAdminApprovals(t *testing.T) {
	auto := netip.MustParsePrefix("10.0.1.0/24")
	admin := netip.MustParsePrefix("10.0.2.0/24")

	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, s *State, id types.NodeID) // after announcing both routes
		want  []netip.Prefix                                // approved after the withdrawal
	}{
		{name: "auto only", want: nil},
		{
			name: "admin overlap",
			setup: func(t *testing.T, s *State, id types.NodeID) {
				t.Helper()

				_, err := s.SetApprovedRoutes(id, []netip.Prefix{auto, admin})
				require.NoError(t, err)
			},
			want: []netip.Prefix{auto, admin},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath, s, id := persistTestSetup(t)

			// Stored, so the restart below keeps it.
			_, err := s.db.SetPolicy(`{
				"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`)
			require.NoError(t, err)
			err = s.ReloadPolicy()
			require.NoError(t, err)

			announce(t, s, id, auto, admin)
			require.ElementsMatch(t, []netip.Prefix{auto, admin}, approvedRoutes(t, s, id))

			if tt.setup != nil {
				tt.setup(t, s, id)
			}

			// The marks are stored, so a restart between keeps them.
			require.NoError(t, s.Close())
			s = persistTestReopen(t, dbPath)

			announce(t, s, id)
			assert.ElementsMatch(t, tt.want, approvedRoutes(t, s, id), "after the withdrawal")

			stored, err := s.db.GetNodeByID(id)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, stored.ApprovedRoutes.List())

			announce(t, s, id, auto, admin)
			assert.ElementsMatch(t, []netip.Prefix{auto, admin}, approvedRoutes(t, s, id), "announced again")
		})
	}

	t.Run("approved before the upgrade", func(t *testing.T) {
		dbPath, s, id := persistTestSetup(t)
		require.NoError(t, s.Close())

		// A row as the migration leaves it: approved, with no marks.
		database, err := db.NewHeadscaleDatabase(persistTestConfig(dbPath))
		require.NoError(t, err)
		require.NoError(t, database.DB.Exec(
			`UPDATE nodes SET approved_routes = ?, auto_approved_routes = NULL, host_info = ? WHERE id = ?`,
			`["10.0.1.0/24"]`, `{"RoutableIPs":["10.0.1.0/24"]}`, id).Error)
		require.NoError(t, database.Close())

		s = persistTestReopen(t, dbPath)

		_, err = s.SetPolicy([]byte(`{
			"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
		}`))
		require.NoError(t, err)

		announce(t, s, id)
		assert.Equal(t, []netip.Prefix{auto}, approvedRoutes(t, s, id))
	})
}

func announce(t *testing.T, s *State, id types.NodeID, routes ...netip.Prefix) {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	err := s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{
		NodeKey:  nv.NodeKey(),
		DiscoKey: nv.DiscoKey(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: nv.Hostname(), RoutableIPs: routes},
	})
	require.NoError(t, err)
}

func TestRegistrationDropsWithdrawnAutoApprovals(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("withdraw-user")

	_, err := s.SetPolicy([]byte(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["withdraw-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	kept := netip.MustParsePrefix("10.0.1.0/24")
	withdrawn := netip.MustParsePrefix("10.0.2.0/24")
	machineKey := key.NewMachine().Public()
	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{kept, withdrawn}},
	}

	node, err := s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{kept, withdrawn}, approvedRoutes(t, s, node.ID()))

	req.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{kept}}
	_, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{kept}, approvedRoutes(t, s, node.ID()))
}

func TestAdminTagChangeApprovesRoutes(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{
		"tagOwners": {"tag:router": ["persist-user@"]},
		"autoApprovers": {"routes": {"10.0.0.0/16": ["tag:router"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	route := netip.MustParsePrefix("10.0.1.0/24")

	announce(t, s, id, route)
	require.Empty(t, approvedRoutes(t, s, id), "the user may not approve it")

	node, err := s.SetNodeTags(id, []string{"tag:router"})
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{route}, node.ApprovedRoutes().AsSlice())
	assert.Equal(t, []netip.Prefix{route}, approvedRoutes(t, s, id))
}
