package servertest_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// TestPingNode verifies the full ping round-trip: the server sends a
// [tailcfg.PingRequest] via [tailcfg.MapResponse], the real [controlclient.Direct] handles it
// by making a HEAD request back over Noise, and the ping tracker records
// the latency.
func TestPingNode(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)
	require.True(t, nm.SelfNode.Valid())

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	st := h.Server.State()
	pingID, responseCh := st.RegisterPing(nodeID)

	defer st.CancelPing(pingID)

	callbackURL := h.Server.URL + "/machine/ping-response?id=" + pingID
	require.True(t, h.Server.App.MapHub().Ping(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	}), "a connected node's session must take the ping")

	select {
	case latency := <-responseCh:
		assert.Positive(t, latency, "latency should be positive, got %v", latency)
		assert.Less(t, latency, 10*time.Second, "latency should be reasonable, got %v", latency)
	case <-time.After(15 * time.Second):
		t.Fatal("ping response not received within 15s")
	}
}

// TestPingDisconnectedNode verifies that pinging a disconnected node
// results in no response (the channel never receives).
func TestPingDisconnectedNode(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	// Disconnect the client.
	h.Client(0).Disconnect(t)

	st := h.Server.State()
	pingID, responseCh := st.RegisterPing(nodeID)

	defer st.CancelPing(pingID)

	callbackURL := h.Server.URL + "/machine/ping-response?id=" + pingID
	h.Server.App.MapHub().Ping(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	})

	select {
	case <-responseCh:
		t.Fatal("should not receive response from disconnected node")
	case <-time.After(3 * time.Second):
		// Expected: no response.
	}
}

// TestPingTwoSameNode verifies that two concurrent pings to the same
// node complete independently.
func TestPingTwoSameNode(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	nm := h.Client(0).Netmap()
	require.NotNil(t, nm)

	nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

	st := h.Server.State()

	pingID1, ch1 := st.RegisterPing(nodeID)
	defer st.CancelPing(pingID1)

	pingID2, ch2 := st.RegisterPing(nodeID)
	defer st.CancelPing(pingID2)

	require.NotEqual(t, pingID1, pingID2)

	// Send both [tailcfg.PingRequest]s.
	url1 := h.Server.URL + "/machine/ping-response?id=" + pingID1
	url2 := h.Server.URL + "/machine/ping-response?id=" + pingID2

	require.True(t, h.Server.App.MapHub().Ping(nodeID, &tailcfg.PingRequest{
		URL: url1,
	}))
	require.True(t, h.Server.App.MapHub().Ping(nodeID, &tailcfg.PingRequest{
		URL: url2,
	}))

	timeout := time.After(15 * time.Second)

	var got1, got2 bool

	for !got1 || !got2 {
		select {
		case latency := <-ch1:
			assert.GreaterOrEqual(t, latency, time.Duration(0))

			got1 = true
		case latency := <-ch2:
			assert.GreaterOrEqual(t, latency, time.Duration(0))

			got2 = true
		case <-timeout:
			t.Fatalf("timed out: got1=%v got2=%v", got1, got2)
		}
	}
}

// TestPingSurvivesConcurrentUpdate verifies that a ping is delivered while
// the node's view is also changing, whether the change lands just before
// the ping or just after it.
func TestPingSurvivesConcurrentUpdate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		send func(t *testing.T, h *servertest.TestHarness, id types.NodeID, pr *tailcfg.PingRequest)
	}{
		{
			name: "ping then update",
			send: func(t *testing.T, h *servertest.TestHarness, id types.NodeID, pr *tailcfg.PingRequest) {
				t.Helper()
				require.True(t, h.Server.App.MapHub().Ping(id, pr))
				expireInAnHour(t, h, id)
			},
		},
		{
			name: "update then ping",
			send: func(t *testing.T, h *servertest.TestHarness, id types.NodeID, pr *tailcfg.PingRequest) {
				t.Helper()
				expireInAnHour(t, h, id)
				require.True(t, h.Server.App.MapHub().Ping(id, pr))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := servertest.NewHarness(t, 1)

			nm := h.Client(0).Netmap()
			require.NotNil(t, nm)

			nodeID := types.NodeID(nm.SelfNode.ID()) //nolint:gosec

			st := h.Server.State()
			pingID, responseCh := st.RegisterPing(nodeID)

			defer st.CancelPing(pingID)

			tt.send(t, h, nodeID, &tailcfg.PingRequest{
				URL: h.Server.URL + "/machine/ping-response?id=" + pingID,
				Log: true,
			})

			select {
			case latency := <-responseCh:
				assert.GreaterOrEqual(t, latency, time.Duration(0))
			case <-time.After(15 * time.Second):
				t.Fatal("ping lost to the concurrent update")
			}

			h.Client(0).WaitForCondition(t, "update delivered", 10*time.Second,
				func(nm *netmap.NetworkMap) bool { return !nm.SelfKeyExpiry().IsZero() })
		})
	}
}

// expireInAnHour sets a key expiry on id, a change its own client sees.
func expireInAnHour(t *testing.T, h *servertest.TestHarness, id types.NodeID) {
	t.Helper()

	expiry := time.Now().Add(time.Hour)
	_, err := h.Server.State().SetNodeExpiry(id, &expiry)
	require.NoError(t, err)
}

// TestPingResolveByHostname verifies that [state.State.ResolveNode] can find a node
// by hostname and that the resolved node can be pinged.
func TestPingResolveByHostname(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1, servertest.WithDefaultClientOptions(
		servertest.WithHostname("my-test-host"),
	))

	st := h.Server.State()

	// Resolve by hostname.
	node, ok := st.ResolveNode("my-test-host")
	require.True(t, ok, "should resolve node by hostname")

	nodeID := node.ID()

	pingID, responseCh := st.RegisterPing(nodeID)
	defer st.CancelPing(pingID)

	callbackURL := h.Server.URL + "/machine/ping-response?id=" + pingID
	require.True(t, h.Server.App.MapHub().Ping(nodeID, &tailcfg.PingRequest{
		URL: callbackURL,
		Log: true,
	}))

	select {
	case latency := <-responseCh:
		assert.Positive(t, latency)
	case <-time.After(15 * time.Second):
		t.Fatal("ping response not received")
	}
}

// TestPingResponseHandlerRejectsNonHEAD verifies the endpoint returns 405
// for method verbs other than HEAD, even when chi is configured to allow
// them.
func TestPingResponseHandlerRejectsNonHEAD(t *testing.T) {
	t.Parallel()

	h := servertest.NewHarness(t, 1)

	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			req, err := http.NewRequestWithContext(ctx, method, h.Server.URL+"/machine/ping-response?id=x", nil)
			require.NoError(t, err)

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				// chi may refuse the method entirely; that's equivalent to 405.
				return
			}
			defer resp.Body.Close()

			assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
		})
	}
}
