package mapper

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestStreamRouteOverlaySurvivesStaleCacheAndMembership is an intentionally
// failing diagnostic: rendering a retained snapshot must not make a later
// membership change discard an unrelated router's routes.
func TestStreamRouteOverlaySurvivesStaleCacheAndMembership(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	viewer, removed, routerID := ids[0], ids[1], ids[2]
	route := netip.MustParsePrefix("10.0.0.0/24")
	router := mustNode(t, s, routerID).AsStruct()
	router.Tags = []string{"tag:a"}
	router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	router.ApprovedRoutes = []netip.Prefix{route}
	s.PutNodeInStoreForTest(*router)
	s.Connect(routerID)

	hub := NewHub()
	t.Cleanup(hub.Close)
	stream := NewStream(cfg, hub, viewer, capVer)
	old := s.Snapshot()
	_, err := stream.Initial(old)
	require.NoError(t, err)
	stream.Delivered()

	checkRoute := func() {
		t.Helper()

		peer, ok := stream.sent.peer(routerID.NodeID())
		require.True(t, ok)
		require.Contains(t, peer.AllowedIPs, route)
		require.Contains(t, peer.PrimaryRoutes, route)
	}
	checkRoute()

	updateViewer := func(port uint16) {
		n := mustNode(t, s, viewer).AsStruct()
		n.Endpoints = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), port)}
		s.PutNodeInStoreForTest(*n)
		_, err := stream.Update(s.Snapshot())
		require.NoError(t, err)
		stream.Delivered()
	}
	updateViewer(1)
	checkRoute()

	// A delayed renderer can still render a snapshot captured before the
	// endpoint update, sharing the current session's peer-render cache.
	_, err = NewStream(cfg, hub, viewer, capVer).r.render(old)
	require.NoError(t, err)

	s.DeleteNodeFromStoreForTest(removed)
	_, err = stream.Update(s.Snapshot())
	require.NoError(t, err)
	stream.Delivered()
	checkRoute()

	updateViewer(2)

	freshHub := NewHub()
	t.Cleanup(freshHub.Close)
	fresh, err := NewStream(cfg, freshHub, viewer, capVer).Initial(s.Snapshot())
	require.NoError(t, err)
	require.Contains(t, peerSet(fresh[0]), routerID.NodeID())

	for _, peer := range fresh[0].Peers {
		if peer.ID == routerID.NodeID() {
			require.Contains(t, peer.AllowedIPs, route, "fresh renderer still serves the route")
		}
	}

	checkRoute()
}
