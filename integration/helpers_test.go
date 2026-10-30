package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/stretchr/testify/require"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// These unit tests exercise the convergence oracle without Docker.
func TestOnlineOracleIgnoresFailedStaleInitial(t *testing.T) {
	prefix := netip.MustParsePrefix("100.64.0.0/10")
	cfg := &types.Config{
		Database:     types.DatabaseConfig{Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: t.TempDir() + "/h.db"}},
		PrefixV4:     &prefix,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		ServerURL:    "https://headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
	}
	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("oracle")
	viewer := database.CreateRegisteredNodeForTest(user, "viewer")
	peer := database.CreateRegisteredNodeForTest(user, "peer")
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	hub := mapper.NewHub()
	stale := mapper.NewStream(cfg, hub, viewer.ID, tailcfg.CurrentCapabilityVersion)
	// Every Connect needs its Disconnect; the state is discarded with the
	// test, but a lingering session would strand the node online if this
	// fixture were copied into a longer-lived harness.
	viewerEpoch := s.Connect(viewer.ID)

	t.Cleanup(func() { require.NoError(t, s.Disconnect(viewer.ID, viewerEpoch)) })

	before := s.Snapshot()

	peerEpoch := s.Connect(peer.ID)

	t.Cleanup(func() { require.NoError(t, s.Disconnect(peer.ID, peerEpoch)) })

	current := mapper.NewStream(cfg, hub, viewer.ID, tailcfg.CurrentCapabilityVersion)
	frames, err := current.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, frames, 1)

	var wire bytes.Buffer
	require.NoError(t, json.NewEncoder(&wire).Encode(frames[0]))

	var received tailcfg.MapResponse
	require.NoError(t, json.NewDecoder(&wire).Decode(&received))
	current.Delivered()

	// The abandoned stream renders last, but its initial frame never arrives.
	late, err := stale.Initial(before)
	require.NoError(t, err)
	require.Len(t, late, 1)

	reader, writer := io.Pipe()
	require.NoError(t, reader.Close())
	require.ErrorIs(t, json.NewEncoder(writer).Encode(late[0]), io.ErrClosedPipe)
	require.NoError(t, writer.Close())

	peerStream := mapper.NewStream(cfg, hub, peer.ID, tailcfg.CurrentCapabilityVersion)
	peerFrames, err := peerStream.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, peerFrames, 1)
	server := &onlineOracleServer{
		nodes: map[types.NodeID]types.Node{
			viewer.ID: {ID: viewer.ID, IsOnline: new(true)},
			peer.ID:   {ID: peer.ID, IsOnline: new(true)},
		},
		dumps: map[types.NodeID][]tailcfg.MapResponse{
			viewer.ID: {received, *late[0]},
			peer.ID:   {*peerFrames[0]},
		},
		clients: []TailscaleClient{&onlineOracleClient{response: received}, &onlineOracleClient{response: *peerFrames[0]}},
	}
	requireAllClientsOnline(t, server, server.clients, []types.NodeID{viewer.ID, peer.ID}, true, "a failed stale initial frame must not replace client-observed state", 3*time.Second)

	// The dump-derived oracle disagrees: the abandoned stream's late render
	// is the last word there and still shows the peer offline, while the
	// client observed it online. If a helper ever consults dumps again, this
	// contrast is what must fail it.
	dumpOnline := integrationutil.BuildExpectedOnlineMap(server.dumps)
	require.False(t, dumpOnline[viewer.ID][peer.ID], "the stale dump still shows the peer offline")

	observed, err := clientOnlineMap(server.clients)
	require.NoError(t, err)
	require.True(t, observed[viewer.ID][peer.ID], "the client observed the peer online")

	// Generated online output cannot hide a client that still has the old map.
	server.clients[0] = &onlineOracleClient{response: *late[0]}
	observed, err = clientOnlineMap(server.clients)
	require.NoError(t, err)
	require.Contains(t, observed[viewer.ID], peer.ID)
	require.False(t, observed[viewer.ID][peer.ID])

	late[0].Peers = nil
	server.clients[0] = &onlineOracleClient{response: *late[0]}
	observed, err = clientOnlineMap(server.clients)
	require.NoError(t, err)
	require.Contains(t, observed, viewer.ID)
	require.NotContains(t, observed[viewer.ID], peer.ID, "missing peers must not inherit generated online state")
}

type onlineOracleServer struct {
	ControlServer

	nodes   map[types.NodeID]types.Node
	dumps   map[types.NodeID][]tailcfg.MapResponse
	clients []TailscaleClient
}

func TestClientOnlineMapUnavailable(t *testing.T) {
	for _, tt := range []struct {
		name    string
		status  *ipnstate.Status
		err     error
		wantErr bool
	}{
		{name: "status query failed", err: io.ErrClosedPipe},
		{name: "nil status", wantErr: true},
		{name: "missing self", status: &ipnstate.Status{BackendState: "Running"}, wantErr: true},
		{name: "stopped client", status: &ipnstate.Status{BackendState: "Stopped"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			observed, err := clientOnlineMap([]TailscaleClient{&onlineStatusClient{status: tt.status, err: tt.err}})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			require.Empty(t, observed, "unavailable clients must not satisfy convergence")
		})
	}

	t.Run("unreadable client does not hide readable ones", func(t *testing.T) {
		healthy := &ipnstate.Status{
			BackendState: "Running",
			Self:         &ipnstate.PeerStatus{ID: "7"},
			Peer:         map[key.NodePublic]*ipnstate.PeerStatus{},
		}

		observed, err := clientOnlineMap([]TailscaleClient{
			&onlineStatusClient{err: io.ErrClosedPipe, hostname: "flaky"},
			&onlineStatusClient{status: healthy, hostname: "healthy"},
		})
		require.NoError(t, err)
		require.Contains(t, observed, types.NodeID(7), "a readable client must still be observed")
		require.Empty(t, observed[types.NodeID(7)])
	})

	t.Run("reads clients concurrently", func(t *testing.T) {
		const clients = 12

		// Each read announces itself and waits for the rest, so only
		// concurrent reads ever reach full overlap: serial reads time
		// out one by one and stay at a peak of one.
		var (
			arrived  atomic.Int64
			inflight atomic.Int64
			peak     atomic.Int64
			release  = make(chan struct{})
		)

		list := make([]TailscaleClient, clients)
		for i := range list {
			c := &onlineStatusClient{
				status: &ipnstate.Status{
					BackendState: "Running",
					Self:         &ipnstate.PeerStatus{ID: tailcfg.StableNodeID(strconv.Itoa(i + 1))},
					Peer:         map[key.NodePublic]*ipnstate.PeerStatus{},
				},
			}

			c.read = func() {
				// Count the read in flight before announcing arrival: the
				// barrier can then only close once every read is counted,
				// so no scheduling gap can shave the peak below clients.
				n := inflight.Add(1)

				for {
					p := peak.Load()
					if n <= p || peak.CompareAndSwap(p, n) {
						break
					}
				}

				defer inflight.Add(-1)

				if arrived.Add(1) == clients {
					close(release)
				}

				select {
				case <-release:
				case <-time.After(2 * time.Second):
				}
			}

			list[i] = c
		}

		observed, err := clientOnlineMap(list)

		require.NoError(t, err)
		require.Len(t, observed, clients)
		require.EqualValues(t, clients, peak.Load(), "all status reads must overlap; a serial loop peaks at one")
	})
}

type onlineStatusClient struct {
	TailscaleClient

	status   *ipnstate.Status
	err      error
	hostname string
	read     func()
}

func (c *onlineStatusClient) Status() (*ipnstate.Status, error) {
	if c.read != nil {
		c.read()
	}

	return c.status, c.err
}

func (c *onlineStatusClient) Hostname() string { return c.hostname }

type statusAssertionRecorder struct {
	messages []string
}

func (r *statusAssertionRecorder) Errorf(format string, args ...any) {
	r.messages = append(r.messages, fmt.Sprintf(format, args...))
}

func TestClientStatusAssertions(t *testing.T) {
	loggedIn := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{UserID: 1},
		User:         map[tailcfg.UserID]tailcfg.UserProfile{1: {LoginName: "user1@test.no"}},
	}
	for _, tt := range []struct {
		name              string
		status            *ipnstate.Status
		err               error
		wantStatusFailure bool
		wantLoginFailure  bool
	}{
		{name: "query error", err: io.ErrClosedPipe, wantStatusFailure: true, wantLoginFailure: true},
		{name: "query error with payload", status: loggedIn, err: io.ErrClosedPipe, wantStatusFailure: true, wantLoginFailure: true},
		{name: "nil status", wantStatusFailure: true, wantLoginFailure: true},
		{name: "missing self", status: &ipnstate.Status{BackendState: "Running"}, wantLoginFailure: true},
		{name: "stopped without self", status: &ipnstate.Status{BackendState: "Stopped"}, wantLoginFailure: true},
		{name: "logged out without self", status: &ipnstate.Status{BackendState: "NeedsLogin"}, wantLoginFailure: true},
		{
			name: "peers without self",
			status: &ipnstate.Status{
				Peer: map[key.NodePublic]*ipnstate.PeerStatus{{}: {ID: "2", Online: true}},
			},
			wantLoginFailure: true,
		},
		{
			name:             "missing user",
			status:           &ipnstate.Status{Self: &ipnstate.PeerStatus{UserID: 1}},
			wantLoginFailure: true,
		},
		{
			name: "wrong login",
			status: &ipnstate.Status{
				Self: &ipnstate.PeerStatus{UserID: 1},
				User: map[tailcfg.UserID]tailcfg.UserProfile{1: {LoginName: "user2@test.no"}},
			},
			wantLoginFailure: true,
		},
		{name: "expected login", status: loggedIn},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &onlineStatusClient{status: tt.status, err: tt.err, hostname: "callback-client"}

			t.Run("status", func(t *testing.T) {
				recorder := &statusAssertionRecorder{}

				var status *ipnstate.Status

				require.NotPanics(t, func() { status = assertClientStatus(recorder, client) })

				if tt.wantStatusFailure {
					require.Nil(t, status, "failed observations must not reach consumers")
					require.Len(t, recorder.messages, 1)
					require.Contains(t, recorder.messages[0], client.Hostname())

					if tt.err != nil {
						require.Contains(t, recorder.messages[0], tt.err.Error())
					}
				} else {
					require.Empty(t, recorder.messages)
					require.Same(t, tt.status, status, "valid observations must reach consumers unchanged")
				}
			})
			t.Run("login", func(t *testing.T) {
				recorder := &statusAssertionRecorder{}

				require.NotPanics(t, func() { assertClientLogin(recorder, client, "user1@test.no") })

				if tt.wantLoginFailure {
					require.Len(t, recorder.messages, 1, "unavailable or wrong identity must not satisfy login")
					require.Contains(t, recorder.messages[0], client.Hostname())

					if tt.err != nil {
						require.Contains(t, recorder.messages[0], tt.err.Error())
					}
				} else {
					require.Empty(t, recorder.messages)
				}
			})
		})
	}

	t.Run("another expected login", func(t *testing.T) {
		client := &onlineStatusClient{hostname: "another-client", status: &ipnstate.Status{
			Self: &ipnstate.PeerStatus{UserID: 2},
			User: map[tailcfg.UserID]tailcfg.UserProfile{2: {LoginName: "user2@test.no"}},
		}}
		recorder := &statusAssertionRecorder{}
		assertClientLogin(recorder, client, "user2@test.no")
		require.Empty(t, recorder.messages)
	})

	t.Run("login recovers after a failed observation", func(t *testing.T) {
		client := &onlineStatusClient{err: io.ErrClosedPipe, hostname: "callback-client"}
		failed := &statusAssertionRecorder{}

		require.NotPanics(t, func() { assertClientLogin(failed, client, "user1@test.no") })
		require.Len(t, failed.messages, 1)

		client.err, client.status = nil, loggedIn
		recovered := &statusAssertionRecorder{}
		assertClientLogin(recovered, client, "user1@test.no")
		require.Empty(t, recovered.messages)
	})

	t.Run("logout", func(t *testing.T) {
		for _, tt := range []struct {
			name        string
			status      *ipnstate.Status
			err         error
			wantFailure bool
		}{
			{name: "query error", err: io.ErrClosedPipe, wantFailure: true},
			{name: "query error with payload", status: &ipnstate.Status{BackendState: "NeedsLogin"}, err: io.ErrClosedPipe, wantFailure: true},
			{name: "nil status", wantFailure: true},
			{name: "logged out without self", status: &ipnstate.Status{BackendState: "NeedsLogin"}},
			{name: "still running", status: loggedIn, wantFailure: true},
		} {
			t.Run(tt.name, func(t *testing.T) {
				client := &onlineStatusClient{status: tt.status, err: tt.err, hostname: "logout-client"}
				recorder := &statusAssertionRecorder{}

				require.NotPanics(t, func() { assertTailscaleNodesLogout(recorder, []TailscaleClient{client}) })

				if tt.wantFailure {
					require.Len(t, recorder.messages, 1)
					require.Contains(t, recorder.messages[0], client.Hostname())

					if tt.err != nil {
						require.Contains(t, recorder.messages[0], tt.err.Error())
					}
				} else {
					require.Empty(t, recorder.messages)
				}
			})
		}
	})

	t.Run("logout checks clients after a failed observation", func(t *testing.T) {
		recorder := &statusAssertionRecorder{}
		clients := []TailscaleClient{
			&onlineStatusClient{err: io.ErrClosedPipe, hostname: "failed-client"},
			&onlineStatusClient{status: loggedIn, hostname: "still-logged-in"},
			&onlineStatusClient{status: &ipnstate.Status{BackendState: "NeedsLogin"}, hostname: "logged-out"},
		}

		require.NotPanics(t, func() { assertTailscaleNodesLogout(recorder, clients) })
		require.Len(t, recorder.messages, 2)
		require.Contains(t, recorder.messages[0], "failed-client")
		require.Contains(t, recorder.messages[0], io.ErrClosedPipe.Error())
		require.Contains(t, recorder.messages[1], "still-logged-in")
	})
}

func (s *onlineOracleServer) DebugBatcher() (*hscontrol.DebugBatcherInfo, error) {
	info := &hscontrol.DebugBatcherInfo{ConnectedNodes: make(map[string]hscontrol.DebugBatcherNodeInfo)}
	for id := range s.nodes {
		info.ConnectedNodes[id.String()] = hscontrol.DebugBatcherNodeInfo{Connected: true, ActiveConnections: 1}
	}

	return info, nil
}

func (s *onlineOracleServer) DebugNodeStore() (map[types.NodeID]types.Node, error) {
	return s.nodes, nil
}

type onlineOracleClient struct {
	TailscaleClient

	response tailcfg.MapResponse
}

func (c *onlineOracleClient) Status() (*ipnstate.Status, error) {
	status := &ipnstate.Status{
		BackendState: "Running",
		Self:         &ipnstate.PeerStatus{ID: c.response.Node.StableID},
		Peer:         make(map[key.NodePublic]*ipnstate.PeerStatus),
	}
	for _, peer := range c.response.Peers {
		status.Peer[peer.Key] = &ipnstate.PeerStatus{ID: peer.StableID, Online: peer.Online != nil && *peer.Online}
	}

	return status, nil
}
