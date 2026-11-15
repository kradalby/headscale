package servertest_test

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestConnectDisconnectRace races a new [state.State.Connect] against a
// stale [state.State.Disconnect] of the same node. Disconnect releases a
// session and marks the node offline in one world write, and the primary
// route election derives from that write, so a Connect landing on either
// side must leave the node online and its route primary.
//
// The poll.go reconnect grace covers the common case. Connect/Disconnect
// on [state.State] directly bypass it and must still leave the state
// consistent — if they don't, that is the bug behind the original race
// issue.
//
// Run with -race to also catch any data race exposed.
func TestConnectDisconnectRace(t *testing.T) {
	srv := servertest.NewServer(t)
	user := srv.CreateUser(t, "race-user")

	route := netip.MustParsePrefix("10.0.0.0/24")

	// Use [servertest.NewClient] to get a node fully registered + Connected via the
	// real noise/poll path. After this the snapshot holds the node and its
	// route election, and [state.State.Connect] has been called once.
	//
	// Only c2 advertises the route. The election keeps a route on the
	// router with the oldest control session, so if both nodes were
	// advertising, c1 (connected first) would stay primary and the test
	// could never observe the route slipping out of c2's
	// [tailcfg.NodeView.PrimaryRoutes] — it would never have been there in the first place.
	c1 := servertest.NewClient(t, srv, "race-r1", servertest.WithUser(user))
	c2 := servertest.NewClient(t, srv, "race-r2", servertest.WithUser(user))

	c1.WaitForPeers(t, 1, 10*time.Second)

	c2.Direct().SetHostinfo(&tailcfg.Hostinfo{
		BackendLogID: "servertest-race-r2",
		Hostname:     "race-r2",
		RoutableIPs:  []netip.Prefix{route},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = c2.Direct().SendUpdate(ctx)

	cancel()

	r2ID := findNodeID(t, srv, "race-r2")

	_, err := srv.State().SetApprovedRoutes(r2ID, []netip.Prefix{route})
	require.NoError(t, err)

	// Wait for advertisement + approval to be reflected as a primary
	// route assignment in [tailcfg.NodeView.PrimaryRoutes]; otherwise we'd be racing the
	// initial steady-state setup, not the [state.State.Connect]/[state.State.Disconnect] window.
	require.Eventually(t, func() bool {
		return slices.Contains(srv.State().GetNodePrimaryRoutes(r2ID), route)
	}, 10*time.Second, 50*time.Millisecond,
		"primary route should be assigned to r2 before driving the race")

	// Drive the race repeatedly. Each iteration:
	//   1. Call [state.State.Connect](id) to obtain a fresh gen — this stands in for
	//      a session that "owns" the node.
	//   2. Spawn a goroutine that issues [state.State.Disconnect](id, gen) — the
	//      stale deferred disconnect.
	//   3. Concurrently spawn a goroutine that issues [state.State.Connect](id) —
	//      the new session arriving.
	//   4. After both finish, check the state is consistent: the node
	//      should be online and primaryRoutes should hold the approved
	//      route for it.
	//
	// The two goroutines synchronise on a barrier so they start
	// approximately simultaneously, maximising the chance of hitting the
	// TOCTOU window.
	const iterations = 100

	for i := range iterations {
		// Establish a "current session" with a known gen for r2.
		gen := srv.State().Connect(r2ID)

		var wg sync.WaitGroup

		start := make(chan struct{})

		wg.Go(func() {
			<-start

			_ = srv.State().Disconnect(r2ID, gen)
		})
		wg.Go(func() {
			<-start

			_ = srv.State().Connect(r2ID)
		})

		close(start)
		wg.Wait()

		// Post-condition: the node should be ONLINE (the new Connect's
		// effect must dominate, because the stale Disconnect ran with
		// an older gen and should have been a no-op — or its effects
		// must not have overtaken the new Connect's writes).
		nv, ok := srv.State().GetNodeByID(r2ID)
		if !assert.True(t, ok, "iteration %d: node should exist", i) {
			continue
		}

		online, known := nv.IsOnline().GetOk()
		if !assert.True(t, known, "iteration %d: online status should be known", i) {
			continue
		}

		assert.True(t, online,
			"iteration %d: node should be ONLINE after concurrent Connect+Disconnect (gen=%d)",
			i, gen)

		// The approved route must still be reflected as a primary for r2.
		primary := srv.State().GetNodePrimaryRoutes(r2ID)
		assert.True(t, slices.Contains(primary, route),
			"iteration %d: r2 should hold primary for %s after concurrent Connect+Disconnect, got %v",
			i, route, primary)

		if t.Failed() {
			t.Logf("primaryRoutes state at failure:\n%s",
				srv.State().PrimaryRoutesString())

			return
		}
	}
}
