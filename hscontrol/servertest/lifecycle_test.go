package servertest_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/control/controlclient"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestConnectionLifecycle exercises the core node lifecycle:
// connecting, seeing peers, joining mid-session, departing, and
// reconnecting.
func TestConnectionLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("single_node", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 1)
		nm := h.Client(0).Netmap()
		assert.NotNil(t, nm, "single node should receive a netmap")
		assert.Empty(t, nm.Peers, "single node should have no peers")
	})

	t.Run("new_node_joins_mesh", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		// Add a 4th client mid-test.
		h.AddClient(t)
		h.WaitForMeshComplete(t, 10*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
		servertest.AssertSymmetricVisibility(t, h.Clients())
	})

	t.Run("node_departs_peer_goes_offline", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 3)

		departingName := h.Client(2).Name

		// First verify the departing node is online (may need a moment
		// for Online status to propagate after mesh formation).
		h.Client(0).WaitForCondition(t, "peer initially online", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == departingName {
						isOnline, known := p.Online().GetOk()

						return known && isOnline
					}
				}

				return false
			})

		h.Client(2).Disconnect(t)

		// After the 10-second grace period, the remaining clients
		// should see the departed node as offline. The peer stays
		// in the peer list (non-ephemeral nodes are not removed).
		h.Client(0).WaitForCondition(t, "peer goes offline", 30*time.Second,
			func(nm *netmap.NetworkMap) bool {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == departingName {
						isOnline, known := p.Online().GetOk()

						return known && !isOnline
					}
				}

				return false
			})
	})

	t.Run("reconnect_restores_mesh", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Disconnect and reconnect.
		h.Client(0).Disconnect(t)
		h.Client(0).Reconnect(t)

		// Mesh should recover.
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("session_replacement", func(t *testing.T) {
		t.Parallel()
		h := servertest.NewHarness(t, 2)

		// Reconnect without explicitly waiting for the old session to
		// fully drain. This tests that Headscale correctly replaces
		// the old map session for the same node.
		h.Client(0).Reconnect(t)
		h.WaitForMeshComplete(t, 15*time.Second)
		servertest.AssertMeshComplete(t, h.Clients())
	})

	t.Run("multiple_nodes_join_sequentially", func(t *testing.T) {
		t.Parallel()

		sizes := []int{2, 5, 10}
		for _, n := range sizes {
			t.Run(fmt.Sprintf("%d_nodes", n), func(t *testing.T) {
				t.Parallel()
				h := servertest.NewHarness(t, n)
				servertest.AssertMeshComplete(t, h.Clients())
				servertest.AssertSymmetricVisibility(t, h.Clients())
			})
		}
	})
}

// TestNodeExpiryPreservesControlConnection exercises the same-key map repoll
// that controlclient.Auto performs while the backend is in NeedsLogin.
func TestNodeExpiryPreservesControlConnection(t *testing.T) {
	t.Parallel()

	for _, scheduled := range []bool{false, true} {
		t.Run(fmt.Sprintf("scheduled=%v", scheduled), func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 2,
				servertest.WithServerOptions(servertest.WithBatchDelay(10*time.Millisecond)),
			)
			client, observer := h.Client(0), h.Client(1)
			id := findNodeID(t, h.Server, client.Name)
			node, ok := h.Server.State().GetNodeByID(id)
			require.True(t, ok)

			epoch, nodeKey := node.SessionEpoch(), node.NodeKey()
			require.True(t, node.IsOnline().Get())

			lastCheck := time.Now()

			expiry := lastCheck
			if scheduled {
				expiry = lastCheck.Add(time.Second)
			}

			node, err := h.Server.State().SetNodeExpiry(id, &expiry)
			require.NoError(t, err)
			require.Equal(t, scheduled, node.IsOnline().Get())

			if scheduled {
				require.Eventually(t, func() bool { return time.Now().After(expiry) },
					3*time.Second, 10*time.Millisecond)

				_, changed := h.Server.State().ExpireExpiredNodes(lastCheck)
				require.True(t, changed)
			}

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				current, found := h.Server.State().GetNodeByID(id)
				if !assert.True(c, found) {
					return
				}

				assert.False(c, current.IsOnline().Get())
				assert.Equal(c, 1, current.ActiveSessions())
				assert.Equal(c, epoch, current.SessionEpoch())
				assert.True(c, h.Server.App.MapHub().IsConnected(id))
				assert.True(c, client.Netmap().SelfNode.Expired())
				assert.False(c, client.Netmap().SelfNode.Online().Get())

				peer, found := observer.PeerByName(client.Name)
				if assert.True(c, found) {
					assert.True(c, peer.Expired())
					assert.False(c, peer.Online().Get())
				}
			}, 5*time.Second, 10*time.Millisecond, "expiry must take the node offline without ending its control session")

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			require.NoError(t, client.RestartPoll(ctx))
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				current, found := h.Server.State().GetNodeByID(id)
				if !assert.True(c, found) {
					return
				}

				assert.Greater(c, current.SessionEpoch(), epoch)
				assert.Equal(c, 1, current.ActiveSessions())
				assert.Equal(c, nodeKey, current.NodeKey())
				assert.False(c, current.IsOnline().Get(), "an expired-key repoll cannot bring a node online")
				assert.True(c, h.Server.App.MapHub().IsConnected(id))
			}, 5*time.Second, 10*time.Millisecond, "expired-key repoll must preserve offline status")

			// Restoring expiry must reach the client through that same stream.
			current, _ := h.Server.State().GetNodeByID(id)
			epoch = current.SessionEpoch()
			_, err = h.Server.State().SetNodeExpiry(id, nil)
			require.NoError(t, err)
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				current, found := h.Server.State().GetNodeByID(id)
				if !assert.True(c, found) {
					return
				}

				assert.True(c, current.IsOnline().Get())
				assert.Equal(c, epoch, current.SessionEpoch())
				assert.Equal(c, nodeKey, current.NodeKey())
				assert.Equal(c, 1, current.ActiveSessions())
				assert.False(c, client.Netmap().SelfNode.Expired())
				assert.True(c, client.Netmap().SelfNode.Online().Get())

				peer, found := observer.PeerByName(client.Name)
				if assert.True(c, found) {
					assert.False(c, peer.Expired())
					assert.True(c, peer.Online().Get())
				}
			}, 5*time.Second, 10*time.Millisecond, "restoring expiry must recover both clients without another login or poll")
		})
	}
}

// TestRestoredExpirySurvivesBackToBackWrites expires a node and immediately
// restores its expiry, so its session may render either write or only the
// second. The node must end up with the restored expiry, online, on the
// session it already had.
func TestRestoredExpirySurvivesBackToBackWrites(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1,
		servertest.WithServerOptions(servertest.WithBatchDelay(10*time.Millisecond)),
	)
	client := h.Client(0)
	node := h.Server.State().ListNodes().At(0)
	past := time.Now()
	_, err := h.Server.State().SetNodeExpiry(node.ID(), &past)
	require.NoError(t, err)

	future := past.Add(time.Hour)
	_, err = h.Server.State().SetNodeExpiry(node.ID(), &future)
	require.NoError(t, err)

	client.WaitForCondition(t, "restored expiry delivered", 5*time.Second,
		func(nm *netmap.NetworkMap) bool { return nm.SelfKeyExpiry().Equal(future) })
	// Observe beyond delivery: a momentary expiry must not end the stream
	// that carries the restored one.
	require.Never(t, func() bool { return len(h.ConnectedClients()) == 0 },
		200*time.Millisecond, 10*time.Millisecond, "a momentary expiry must not close the restored stream")

	current, found := h.Server.State().GetNodeByID(node.ID())
	require.True(t, found)
	require.True(t, current.IsOnline().Get())
	require.Equal(t, node.SessionEpoch(), current.SessionEpoch())
}

// TestReloginOfExpiredNodeClearsPeerExpiry covers #3531. Peers hold an expired
// node with Expired=true, which only a whole node from control can clear:
// [tailcfg.PeerChange] has no Expired field. Hostinfo is identical across the
// relogin, so no Hostinfo-driven whole-node update can mask a missing one.
func TestReloginOfExpiredNodeClearsPeerExpiry(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 2,
		servertest.WithServerOptions(servertest.WithBatchDelay(10*time.Millisecond)),
	)
	client, observer := h.Client(0), h.Client(1)
	id := findNodeID(t, h.Server, client.Name)
	node, ok := h.Server.State().GetNodeByID(id)
	require.True(t, ok)

	oldKey := node.NodeKey()

	expiry := time.Now()
	_, err := h.Server.State().SetNodeExpiry(id, &expiry)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		peer, found := observer.PeerByName(client.Name)
		if assert.True(c, found) {
			assert.True(c, peer.Expired())
		}
	}, 5*time.Second, 10*time.Millisecond, "observer must see the node expired")

	// A client that has seen its own key expire generates a new key on
	// relogin, the way tailscaled re-authenticates. Its map is sent
	// independently of the observer's, so wait for it too.
	client.WaitForCondition(t, "own key expired", 5*time.Second,
		func(nm *netmap.NetworkMap) bool {
			exp := nm.SelfKeyExpiry()

			return !exp.IsZero() && !exp.After(time.Now())
		})

	client.Reconnect(t)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		current, found := h.Server.State().GetNodeByID(id)
		if !assert.True(c, found) {
			return
		}

		assert.NotEqual(c, oldKey, current.NodeKey())
		assert.False(c, current.IsExpired())

		peer, found := observer.PeerByName(client.Name)
		if assert.True(c, found) {
			assert.Equal(c, current.NodeKey(), peer.Key())
			assert.False(c, peer.Expired(), "relogin must clear the peer's expired flag")
		}
	}, 5*time.Second, 10*time.Millisecond, "observer must see the relogged node with its new key and not expired")
}

// TestReloginPeerVisibleHostinfoReachesPeers covers the rest of the #3531
// class: a relogin stores the RegisterRequest's Hostinfo, so the following
// MapRequest carries no Hostinfo delta, and a peer-visible change made at
// relogin reaches peers only if the relogin itself sends the whole node.
func TestReloginPeerVisibleHostinfoReachesPeers(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 2,
		servertest.WithServerOptions(servertest.WithBatchDelay(10*time.Millisecond)),
	)
	client, observer := h.Client(0), h.Client(1)

	svc := tailcfg.Service{Proto: tailcfg.PeerAPI4, Port: 4242}
	// Same Hostinfo as servertest.NewClient, plus a service.
	hi := &tailcfg.Hostinfo{
		BackendLogID: "servertest-" + client.Name,
		Hostname:     client.Name,
		Services:     []tailcfg.Service{svc},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// `tailscale up --force-reauth`: an interactive login rotates the key.
	client.Disconnect(t)
	client.Direct().SetHostinfo(hi)
	_, err := client.Direct().TryLogin(ctx, controlclient.LoginInteractive)
	require.NoError(t, err)
	require.NoError(t, client.RestartPoll(ctx))

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		peer, found := observer.PeerByName(client.Name)
		if assert.True(c, found) {
			assert.Equal(c, []tailcfg.Service{svc}, peer.Hostinfo().Services().AsSlice(),
				"peer must see the Hostinfo the node relogged in with")
		}
	}, 5*time.Second, 10*time.Millisecond, "observer must see the relogin's peer-visible Hostinfo")
}

func TestNodeExpiryRouteFailover(t *testing.T) {
	t.Parallel()

	for _, scheduled := range []bool{false, true} {
		t.Run(fmt.Sprintf("scheduled=%v", scheduled), func(t *testing.T) {
			t.Parallel()
			h := servertest.NewHarness(t, 3,
				servertest.WithServerOptions(servertest.WithBatchDelay(10*time.Millisecond)),
			)
			route := netip.MustParsePrefix("10.70.0.0/24")
			primary := advertiseAndApproveRoute(t, h.Server, h.Client(0), route)
			standby := advertiseAndApproveRoute(t, h.Server, h.Client(1), route)
			require.Contains(t, h.Server.State().GetNodePrimaryRoutes(primary), route)

			lastCheck := time.Now()

			expiry := lastCheck
			if scheduled {
				expiry = lastCheck.Add(time.Second)
			}

			_, err := h.Server.State().SetNodeExpiry(primary, &expiry)
			require.NoError(t, err)

			if scheduled {
				require.Eventually(t, func() bool { return time.Now().After(expiry) },
					3*time.Second, 10*time.Millisecond)

				h.Server.State().ExpireExpiredNodes(lastCheck)
			}

			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Empty(c, h.Server.State().GetNodePrimaryRoutes(primary))
				assert.Contains(c, h.Server.State().GetNodePrimaryRoutes(standby), route)
				assert.True(c, h.Server.App.MapHub().IsConnected(primary))

				peer, found := h.Client(2).PeerByName(h.Client(1).Name)
				if assert.True(c, found) {
					assert.Contains(c, peer.PrimaryRoutes().AsSlice(), route)
				}
			}, 5*time.Second, 10*time.Millisecond, "expiry must move the route to the standby while preserving control connectivity")

			_, err = h.Server.State().SetNodeExpiry(primary, nil)
			require.NoError(t, err)
			_, err = h.Server.State().SetNodeExpiry(standby, &expiry)
			require.NoError(t, err)
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Contains(c, h.Server.State().GetNodePrimaryRoutes(primary), route)

				peer, found := h.Client(2).PeerByName(h.Client(0).Name)
				if assert.True(c, found) {
					assert.Contains(c, peer.PrimaryRoutes().AsSlice(), route)
				}
			}, 5*time.Second, 10*time.Millisecond, "restored router must be eligible for failover without reconnecting")
		})
	}
}

// TestLogoutReloginAllClientsConverge is an in-process reproduction of the
// flaky integration tests TestAuthKeyLogoutAndReloginSameUser,
// TestAuthWebFlowLogoutAndReloginSameUser and
// TestAuthWebFlowLogoutAndReloginNewUser: a full mesh of clients logs out,
// the server marks every node expired and offline, then all clients log
// back in near-simultaneously with fresh NodeKeys. In the flake, a subset
// of clients never converges — their netmaps stay empty through the whole
// retry window even though the server believes everything is connected.
//
// Each client here is a real [controlclient.Direct], so the client-side
// netmap assembly semantics (full peer list vs. delta, patch handling for
// unknown peers) match the real Tailscale client.
func TestLogoutReloginAllClientsConverge(t *testing.T) {
	if testing.Short() {
		t.Skip("relogin convergence test includes 10s+ disconnect grace per iteration")
	}

	const (
		numClients = 12
		iterations = 4
		// Maximum random delay between the relogins of different
		// clients, so registrations and fresh map streams interleave
		// the way concurrent `tailscale up` invocations do.
		reloginStagger = 500 * time.Millisecond
	)

	// Production tuning: the integration flake happens with the default
	// 800ms batch delay (large coalescing windows), so reproduce with it.
	h := servertest.NewHarness(t, numClients,
		servertest.WithServerOptions(
			servertest.WithBatchDelay(800*time.Millisecond),
		),
		servertest.WithConvergenceTimeout(60*time.Second),
	)

	for iteration := range iterations {
		t.Logf("iteration %d: logging out all clients", iteration)
		logoutAllAndWaitOffline(t, h)

		t.Logf("iteration %d: relogging in all clients", iteration)

		clients := h.Clients()
		errs := make(chan error, len(clients))

		for _, c := range clients {
			go func() {
				time.Sleep(rand.N(reloginStagger)) //nolint:forbidigo,gosec // intentional jitter so relogins interleave; weak random is fine

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()

				errs <- c.ReloginAndPoll(ctx)
			}()
		}

		for range clients {
			require.NoError(t, <-errs)
		}

		// Every client must converge to the full mesh. A stuck client —
		// the flake — sits at zero peers and fails here.
		deadline := time.Now().Add(30 * time.Second)
		for _, c := range clients {
			waitForMeshOrDump(t, clients, c, numClients-1, time.Until(deadline))
		}
	}
}

// TestLogoutReloginWithPollChurn is the same logout/relogin storm as
// [TestLogoutReloginAllClientsConverge], but each client also restarts its
// map poll once or twice shortly after logging back in — without
// re-registering — the way newer tailscaled versions cycle their map
// session around login state transitions. The integration flake hits the
// head and unstable clients, which churn their sessions far more than
// older releases, so the rapid session replacement is the prime suspect.
func TestLogoutReloginWithPollChurn(t *testing.T) {
	if testing.Short() {
		t.Skip("relogin convergence test includes 10s+ disconnect grace per iteration")
	}

	const (
		numClients     = 12
		iterations     = 4
		reloginStagger = 500 * time.Millisecond
	)

	h := servertest.NewHarness(t, numClients,
		servertest.WithServerOptions(
			servertest.WithBatchDelay(800*time.Millisecond),
		),
		servertest.WithConvergenceTimeout(60*time.Second),
	)

	for iteration := range iterations {
		t.Logf("iteration %d: logging out all clients", iteration)
		logoutAllAndWaitOffline(t, h)

		t.Logf("iteration %d: relogging in all clients with poll churn", iteration)

		clients := h.Clients()
		errs := make(chan error, len(clients))

		for _, c := range clients {
			go func() {
				time.Sleep(rand.N(reloginStagger)) //nolint:forbidigo,gosec // intentional jitter so relogins interleave; weak random is fine

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				err := c.ReloginAndPoll(ctx)
				if err != nil {
					errs <- err
					return
				}

				// Churn the map session like a freshly logged-in
				// tailscaled: restart the poll once or twice with
				// small random gaps.
				for range 1 + rand.IntN(2) { //nolint:gosec // weak random is fine for test jitter
					time.Sleep(rand.N(400 * time.Millisecond)) //nolint:forbidigo,gosec // intentional jitter between poll restarts; weak random is fine

					err = c.RestartPoll(ctx)
					if err != nil {
						errs <- err
						return
					}
				}

				errs <- nil
			}()
		}

		for range clients {
			require.NoError(t, <-errs)
		}

		deadline := time.Now().Add(30 * time.Second)
		for _, c := range clients {
			waitForMeshOrDump(t, clients, c, numClients-1, time.Until(deadline))
		}
	}
}

// logoutAllAndWaitOffline logs every client out concurrently, then blocks
// until the server reports each node expired and offline — the integration
// tests' logout barrier, including the ~10s disconnect grace period.
func logoutAllAndWaitOffline(t *testing.T, h *servertest.TestHarness) {
	t.Helper()

	clients := h.Clients()
	errs := make(chan error, len(clients))

	for _, c := range clients {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			errs <- c.LogoutAndDisconnect(ctx)
		}()
	}

	for range clients {
		require.NoError(t, <-errs)
	}

	st := h.Server.State()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, node := range st.ListNodes().All() {
			assert.True(c, node.IsExpired(), "node %d should be expired after logout", node.ID())
			online := node.IsOnline()
			assert.True(c, online.Valid() && !online.Get(), "node %d should be offline after logout", node.ID())
		}
	}, 30*time.Second, 100*time.Millisecond, "all nodes expired and offline after logout")
}

// waitForMeshOrDump waits until client c reports at least wantPeers peers.
// On timeout it dumps every client's view of the mesh before failing, so a
// reproduced flake shows exactly which clients are stuck and what they see.
func waitForMeshOrDump(t *testing.T, all []*servertest.TestClient, c *servertest.TestClient, wantPeers int, timeout time.Duration) {
	t.Helper()

	deadline := time.After(timeout)
	ticker := time.NewTicker(100 * time.Millisecond)

	defer ticker.Stop()

	for {
		if nm := c.Netmap(); nm != nil && len(nm.Peers) >= wantPeers {
			return
		}

		select {
		case <-ticker.C:
		case <-deadline:
			for _, other := range all {
				t.Logf("client %s netmap: %s", other.Name, describeNetmap(other))
			}

			nm := c.Netmap()

			got := 0
			if nm != nil {
				got = len(nm.Peers)
			}

			t.Fatalf("client %s did not converge: want %d peers, got %d", c.Name, wantPeers, got)
		}
	}
}

// describeNetmap renders a client's current netmap as a compact string for
// failure dumps: peer names with their expiry/online flags.
func describeNetmap(c *servertest.TestClient) string {
	nm := c.Netmap()
	if nm == nil {
		return "<nil>"
	}

	var out strings.Builder

	fmt.Fprintf(&out, "%d peers:", len(nm.Peers))

	for _, p := range nm.Peers {
		hostname := "<no hostinfo>"
		if hi := p.Hostinfo(); hi.Valid() {
			hostname = hi.Hostname()
		}

		fmt.Fprintf(&out, " %s(id=%d expired=%t online=%v)", hostname, p.ID(), p.KeyExpiry().Before(time.Now()), p.Online())
	}

	return out.String()
}

func TestServerStateCleanup(t *testing.T) {
	var srv *servertest.TestServer

	t.Run("server", func(t *testing.T) { srv = servertest.NewServer(t) })

	database, err := srv.State().DB().DB.DB()
	require.NoError(t, err)
	require.ErrorContains(t, database.Ping(), "database is closed")
}
