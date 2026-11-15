package mapper

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

func TestMapSessionOverlapLimitConcurrent(t *testing.T) {
	h := NewHub()
	defer h.Close()

	const attempts = 64

	var (
		stops atomic.Int32
		wg    sync.WaitGroup
	)
	for range attempts {
		wg.Go(func() { require.NotNil(t, h.Join(1, func() { stops.Add(1) })) })
	}

	wg.Wait()
	require.Equal(t, maxConcurrentMapSessionsPerNode, h.Connected()[1])
	require.EqualValues(t, attempts-maxConcurrentMapSessionsPerNode, stops.Load())
}

func TestEvictedSessionLeavesPeerTrackingAlone(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)

	h := NewHub()
	defer h.Close()

	stopped := make(chan struct{})
	oldSession := h.Join(ids[0], func() { close(stopped) })
	old := NewStream(cfg, h, ids[0], capVer)
	old.Attach(oldSession)
	stale, err := old.Initial(s.Snapshot())
	require.NoError(t, err)
	require.False(t, mentions(stale, ids[2]))

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)

	for range maxConcurrentMapSessionsPerNode {
		sess := h.Join(ids[0], func() {})
		newer := NewStream(cfg, h, ids[0], capVer)
		newer.Attach(sess)
		full, err := newer.Initial(s.Snapshot())
		require.NoError(t, err)
		require.True(t, mentions(full, ids[2]))
		newer.Delivered()
	}

	select {
	case <-stopped:
	default:
		t.Fatal("oldest session was not stopped")
	}

	old.Delivered()
	require.Contains(t, h.lastPeers(ids[0]), ids[2])
	require.True(t, h.Leave(oldSession), "releasing an evicted session leaves surviving streams connected")
	require.Equal(t, maxConcurrentMapSessionsPerNode, h.Connected()[ids[0]])
}

func TestOlderInitialMapLeavesNewerStreamsPeers(t *testing.T) {
	for _, oldConstructedFirst := range []bool{true, false} {
		name := "old snapshot rendered after newer history"
		if oldConstructedFirst {
			name = "old initial write parked before newer delivery"
		}

		t.Run(name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, ownUserOnly)

			h := NewHub()
			defer h.Close()

			snap := s.Snapshot()
			old := NewStream(cfg, h, ids[0], capVer)
			old.Attach(h.Join(ids[0], func() {}))

			var (
				stale []*tailcfg.MapResponse
				err   error
			)

			written := make(chan []*tailcfg.MapResponse)
			finished := make(chan struct{})

			if oldConstructedFirst {
				stale, err = old.Initial(snap)
				require.NoError(t, err)

				go func() { written <- stale; old.Delivered(); close(finished) }()
			}

			_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
			require.NoError(t, err)

			newer := NewStream(cfg, h, ids[0], capVer)
			newer.Attach(h.Join(ids[0], func() {}))
			fresh, err := newer.Initial(s.Snapshot())
			require.NoError(t, err)
			require.True(t, mentions(fresh, ids[2]))
			newer.Delivered()

			if oldConstructedFirst {
				stale = <-written

				<-finished
			} else {
				stale, err = old.Initial(snap)
				require.NoError(t, err)
				old.Delivered()
			}

			if oldConstructedFirst {
				require.False(t, mentions(stale, ids[2]))
			} else {
				require.True(t, mentions(stale, ids[2]), "obsolete initial snapshot refreshes consistently with newer history")
			}

			for _, resp := range stale {
				require.NotContains(t, resp.PeersRemoved, ids[2].NodeID())
			}

			require.Contains(t, h.lastPeers(ids[0]), ids[2], "late old delivery must not roll shared history back")

			update, err := old.Update(s.Snapshot())
			require.NoError(t, err)

			if oldConstructedFirst {
				require.True(t, mentions(update, ids[2]), "older stream catches up to the newer peer set")
			} else {
				require.Empty(t, update)
			}

			old.Delivered()

			quiet, err := newer.Update(s.Snapshot())
			require.NoError(t, err)
			require.Empty(t, quiet, "old stream completion must not subtract newer stream peers")
		})
	}
}

func TestNodeDeletedWhileChangesPending(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	h.Watch(s)

	stopped := make(chan struct{})
	sess := h.Join(ids[0], func() { close(stopped) })
	st := NewStream(cfg, h, ids[0], capVer)
	st.Attach(sess)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	_, err = s.RenameNode(ids[1], "pending")
	require.NoError(t, err)
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[0])))

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("deleted node's parked stream was not stopped")
	}

	out, err := st.Update(s.Snapshot())
	require.ErrorIs(t, err, ErrNodeGone)
	require.Nil(t, out)
	st.Delivered()
	require.False(t, h.HasPeerHistoryForTest(ids[0]), "late completion cannot resurrect deleted peer history")
}

func TestDeleteWhileInitialMapInFlight(t *testing.T) {
	for _, policyChange := range []bool{true, false} {
		name := "removal_only"
		if policyChange {
			name = "with_policy_change"
		}

		t.Run(name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")

			h := NewHub()
			defer h.Close()

			st := NewStream(cfg, h, ids[0], capVer)
			st.Attach(h.Join(ids[0], func() {}))
			initial, err := st.Initial(s.Snapshot())
			require.NoError(t, err)
			require.Contains(t, peerSet(initial[0]), ids[2].NodeID())
			// The initial has rendered, but its delivery cannot finish until
			// the receiver below accepts it after the peer is deleted.
			written := make(chan []*tailcfg.MapResponse)
			finished := make(chan struct{})

			go func() {
				written <- initial

				st.Delivered()
				close(finished)
			}()

			require.NoError(t, s.DeleteNode(mustNode(t, s, ids[2])))

			if policyChange {
				before := s.Snapshot().PolicyRev()
				_, err = s.SetPolicy([]byte(ownUserOnly))
				require.NoError(t, err)
				require.NotEqual(t, before, s.Snapshot().PolicyRev())
			}

			old := <-written

			<-finished
			require.NotNil(t, old[0].Node, "first delivered frame is the old initial")
			require.Contains(t, peerSet(old[0]), ids[2].NodeID(), "old initial predates peer deletion")

			out, err := st.Update(s.Snapshot())
			require.NoError(t, err)
			require.NotEmpty(t, out)
			require.Equal(t, []tailcfg.NodeID{ids[2].NodeID()}, out[0].PeersRemoved, "same session must explicitly remove the peer exposed by the blocked initial")

			client := newModelClient(old[0])
			for _, response := range out {
				client.apply(response)
			}

			require.NotContains(t, client.peers, ids[2].NodeID())
		})
	}

	// Deleting self independently stops the stream and discards its history.
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	st := NewStream(cfg, h, ids[0], capVer)
	st.Attach(h.Join(ids[0], func() {}))
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[0])))
	h.forget(ids[0])
	st.Delivered()
	require.False(t, h.HasPeerHistoryForTest(ids[0]))

	out, err := st.Update(s.Snapshot())
	require.ErrorIs(t, err, ErrNodeGone)
	require.Empty(t, out)
}

func TestSelfSentOnlyWhenChanged(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	s.Connect(ids[1])
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, out)

	for _, resp := range out {
		require.Nil(t, resp.Node, "unchanged self is stripped from peer updates")
	}

	_, err = s.RenameNode(ids[0], "self-renamed")
	require.NoError(t, err)
	out, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.Equal(t, "self-renamed.headscale.test.", out[0].Node.Name)
	out, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, out)

	_, err = s.RenameNode(ids[0], "self-renamed-again")
	require.NoError(t, err)

	newer := NewStream(cfg, st.hub, ids[0], capVer)
	first, err := newer.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Equal(t, "self-renamed-again.headscale.test.", first[0].Node.Name)
	newer.Delivered()

	olderUpdate, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, olderUpdate, 1)
	require.NotNil(t, olderUpdate[0].Node, "older stream still holds the first rename")
	require.Equal(t, first[0].Node.Name, olderUpdate[0].Node.Name)

	newerUpdate, err := newer.Update(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, newerUpdate, "new stream already holds the second rename")
}

func TestSSHPolicyEmptyOnWire(t *testing.T) {
	const withSSH = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"ssh":[{"action":"accept","src":["u1@"],"dst":["autogroup:self"],"users":["root"]}]}`

	for _, revoke := range []bool{false, true} {
		name := "no ssh rules"

		policy := ""
		if revoke {
			name, policy = "rules revoked", withSSH
		}

		t.Run(name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, policy)
			st := NewStream(cfg, NewHub(), ids[0], capVer)
			out, err := st.Initial(s.Snapshot())
			require.NoError(t, err)

			if revoke {
				require.NotEmpty(t, out[0].SSHPolicy.Rules)
				st.Delivered()

				_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"ssh":[]}`))
				require.NoError(t, err)
				out, err = st.Update(s.Snapshot())
				require.NoError(t, err)
			}

			require.Len(t, out, 1)
			require.NotNil(t, out[0].SSHPolicy)
			require.NotNil(t, out[0].SSHPolicy.Rules)
			wire, err := Marshal(out[0])
			require.NoError(t, err)
			require.Contains(t, string(wire), `"SSHPolicy":{"rules":[]}`)

			fresh, err := NewStream(cfg, NewHub(), ids[0], capVer).Initial(s.Snapshot())
			require.NoError(t, err)
			wire, err = Marshal(fresh[0])
			require.NoError(t, err)
			require.Contains(t, string(wire), `"SSHPolicy":{"rules":[]}`)
		})
	}
}

func TestSSHPolicySentOnlyWhenChanged(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"ssh":[{"action":"accept","src":["u1@"],"dst":["autogroup:self"],"users":["root"]}]}`)
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	initial, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.NotNil(t, initial[0].SSHPolicy)
	s.Connect(ids[1])
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)

	for _, resp := range out {
		require.Nil(t, resp.SSHPolicy)
	}

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"ssh":[]}`))
	require.NoError(t, err)
	out, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, out, 1)
	require.NotNil(t, out[0].SSHPolicy, "revocation must clear the old SSH rules")
	require.Empty(t, out[0].SSHPolicy.Rules)
}

func TestInvisiblePeerChangeSendsNoFrame(t *testing.T) {
	cfg, s, ids := streamTestState(t, ownUserOnly)
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	s.Connect(ids[2])
	_, err = s.RenameNode(ids[2], "hidden-change")
	require.NoError(t, err)
	out, err := st.Update(s.Snapshot())
	require.NoError(t, err)
	require.Empty(t, out)
}

func TestConnectDisconnectOrdinaryNodeNoRuntimeRecompute(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	var gen uint64

	for _, online := range []bool{true, false} {
		before := s.Snapshot()
		if online {
			gen = s.Connect(ids[1])
			require.NotZero(t, gen)
		} else {
			require.NoError(t, s.Disconnect(ids[1], gen))
		}

		after := s.Snapshot()
		all, wake := Route(before, after, after.Since(before))
		require.False(t, all, "ordinary connectivity must not fan out to unrelated sessions")
		require.Contains(t, wake, ids[0])

		out, err := st.Update(after)
		require.NoError(t, err)
		require.Len(t, out, 1)
		require.Len(t, out[0].PeersChangedPatch, 1)
		patch := out[0].PeersChangedPatch[0]
		require.Equal(t, ids[1].NodeID(), patch.NodeID)
		require.Equal(t, online, *patch.Online)

		if !online {
			require.NotNil(t, patch.LastSeen)
		}

		require.Nil(t, out[0].Node)
		require.Nil(t, out[0].SSHPolicy)
		require.Nil(t, out[0].PacketFilters)
		require.Nil(t, out[0].DNSConfig)
		require.Empty(t, out[0].Peers)
		require.Empty(t, out[0].PeersChanged)
	}
}

func TestConnectDisconnectRelayTargetTriggersRecompute(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"grants":[{"src":["*"],"dst":["u1@"],"ip":["*"],"app":{"tailscale.com/cap/relay":[{}]}}]}`)
	st := NewStream(cfg, NewHub(), ids[2], capVer)
	_, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	var gen uint64

	for _, online := range []bool{true, false} {
		before := s.Snapshot()
		if online {
			gen = s.Connect(ids[0])
		} else {
			require.NoError(t, s.Disconnect(ids[0], gen))
		}

		after := s.Snapshot()
		all, wake := Route(before, after, after.Since(before))
		_, woke := wake[ids[2]]
		require.True(t, all || woke, "relay change must reach its viewer")

		out, err := st.Update(after)
		require.NoError(t, err)
		require.NotEmpty(t, out)

		peer, ok := st.sent.peer(ids[0].NodeID())
		require.True(t, ok)
		require.NotNil(t, peer.Online)
		require.Equal(t, online, *peer.Online, "clients revoke PeerRelay allocation when their relay goes offline")
		require.True(t, mentions(out, ids[0]), "the online/offline state must reach the client")
	}
}

func TestConnectDisconnectSubnetRouterForcesRecompute(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	route := netip.MustParsePrefix("10.0.0.0/24")
	require.NoError(t, s.UpdateNodeFromMapRequest(ids[1], tailcfg.MapRequest{NodeKey: mustNode(t, s, ids[1]).NodeKey(), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}}))
	_, err := s.SetApprovedRoutes(ids[1], []netip.Prefix{route})
	require.NoError(t, err)

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)

	var gen uint64

	for _, online := range []bool{true, false} {
		before := s.Snapshot()
		if online {
			gen = s.Connect(ids[1])
		} else {
			require.NoError(t, s.Disconnect(ids[1], gen))
		}

		after := s.Snapshot()
		all, wake := Route(before, after, after.Since(before))
		_, woke := wake[ids[0]]
		require.True(t, all || woke)

		out, err := st.Update(after)
		require.NoError(t, err)
		require.Len(t, out, 1, "one response carries route transition and online state")
		require.Nil(t, out[0].DNSConfig)
		require.Nil(t, out[0].DERPMap)
		require.Nil(t, out[0].Node)
		require.Nil(t, out[0].Debug)
		require.Empty(t, out[0].Peers)

		peer, ok := st.sent.peer(ids[1].NodeID())
		require.True(t, ok)
		require.Equal(t, online, *peer.Online)
		require.Contains(t, peer.AllowedIPs, route, "a sole offline approved router remains the fallback")
	}
}

func TestReconnectWhileOnlineAnnouncesNothing(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	route := netip.MustParsePrefix("10.0.0.0/24")
	require.NoError(t, s.UpdateNodeFromMapRequest(ids[1], tailcfg.MapRequest{NodeKey: mustNode(t, s, ids[1]).NodeKey(), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}}))
	_, err := s.SetApprovedRoutes(ids[1], []netip.Prefix{route})
	require.NoError(t, err)

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)

	check := func(online bool, changed bool) {
		t.Helper()

		out, err := st.Update(s.Snapshot())
		require.NoError(t, err)

		if !changed {
			require.Empty(t, out)
			return
		}

		require.Len(t, out, 1)

		peer, ok := st.sent.peer(ids[1].NodeID())
		require.True(t, ok)
		require.Equal(t, online, *peer.Online)
		require.Contains(t, peer.AllowedIPs, route, "a sole offline approved router remains the fallback")
		require.Nil(t, out[0].DNSConfig)
		require.Nil(t, out[0].Node)
		require.Nil(t, out[0].DERPMap)
	}
	first := s.Connect(ids[1])
	require.NotZero(t, first)
	check(true, true)

	second := s.Connect(ids[1])
	require.NotZero(t, second)
	check(true, false)
	require.NoError(t, s.Disconnect(ids[1], first))
	check(true, false)
	require.NoError(t, s.Disconnect(ids[1], second))
	check(false, true)
	s.Connect(ids[1])
	check(true, true)
}

// requirePeerWireShape is shared by the wire normalization regression cases.
func requirePeerWireShape(t *testing.T, p *tailcfg.Node) {
	t.Helper()
	require.True(t, p.Machine.IsZero())
	require.False(t, p.MachineAuthorized)

	if !p.Hostinfo.Valid() {
		return
	}

	require.Empty(t, p.Hostinfo.RoutableIPs().AsSlice())
	require.False(t, p.Hostinfo.NetInfo().Valid())
	require.False(t, p.Hostinfo.Location().Valid())
}

func TestStreamWireEntriesMatchMain(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	hi := &tailcfg.Hostinfo{Hostname: "node", OS: "linux", DeviceModel: "private", IPNVersion: "private", RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, RequestTags: []string{"tag:x"}, Services: []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 1}, {Proto: tailcfg.PeerAPIDNS, Port: 2}}, SSH_HostKeys: []string{"", "key"}, NetInfo: &tailcfg.NetInfo{PreferredDERP: 1}}
	require.NoError(t, s.UpdateNodeFromMapRequest(ids[1], tailcfg.MapRequest{NodeKey: mustNode(t, s, ids[1]).NodeKey(), Hostinfo: hi, Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:1234")}}))
	s.Connect(ids[1])
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	out, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	self := out[0].Node
	require.True(t, self.Machine.IsZero())
	require.True(t, self.MachineAuthorized)
	require.False(t, self.Expired)
	require.Zero(t, self.Cap)
	require.Nil(t, self.Online)
	require.Nil(t, self.LastSeen)

	for _, p := range out[0].Peers {
		requirePeerWireShape(t, p)
	}

	peer, _ := st.sent.peer(ids[1].NodeID())
	require.Len(t, peer.Hostinfo.Services().AsSlice(), 1)
	require.Equal(t, []string{"", "key"}, peer.Hostinfo.SSH_HostKeys().AsSlice())

	past := time.Now().Add(-time.Hour)
	_, err = s.SetNodeExpiry(ids[1], &past)
	require.NoError(t, err)
	out, err = st.Update(s.Snapshot())
	require.NoError(t, err)
	require.NotEmpty(t, out)

	peer, _ = st.sent.peer(ids[1].NodeID())
	require.True(t, peer.Expired)
	require.True(t, *peer.Online)
	require.Nil(t, peer.LastSeen)
	require.Empty(t, peer.Endpoints)
	require.Zero(t, peer.HomeDERP)
}

func TestTaggedSelfIdentityIsIsolated(t *testing.T) {
	cfg, s, ids := streamTestState(t, `{"tagOwners":{"tag:x":["u1@"]},"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)
	for _, id := range ids[:2] {
		_, err := s.SetNodeTags(id, []string{"tag:x"})
		require.NoError(t, err)
	}

	st := NewStream(cfg, NewHub(), ids[0], capVer)
	out, err := st.Initial(s.Snapshot())
	require.NoError(t, err)

	self := out[0].Node
	require.Equal(t, taggedSelfUserID(ids[0]), self.User)
	require.NotContains(t, self.CapMap, nodecap.Admin)

	for _, p := range out[0].Peers {
		require.NotEqual(t, self.User, p.User)
	}

	profile, ok := st.sent.profile(self.User)
	require.True(t, ok)
	require.Equal(t, "n1.headscale.test", profile.LoginName)
	require.Equal(t, "n1", profile.DisplayName)

	_, err = s.RenameNode(ids[0], "tagged-renamed")
	require.NoError(t, err)
	_, err = st.Update(s.Snapshot())
	require.NoError(t, err)

	profile, ok = st.sent.profile(self.User)
	require.True(t, ok)
	require.Equal(t, "tagged-renamed.headscale.test", profile.LoginName)
	require.Equal(t, "tagged-renamed", profile.DisplayName)
}

func TestStreamViewerDisableIPv4Toggle(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")
	route := netip.MustParsePrefix("10.0.0.0/24")
	require.NoError(t, s.UpdateNodeFromMapRequest(ids[1], tailcfg.MapRequest{NodeKey: mustNode(t, s, ids[1]).NodeKey(), Hostinfo: &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}}))
	_, err := s.SetApprovedRoutes(ids[1], []netip.Prefix{route})
	require.NoError(t, err)
	s.Connect(ids[1])

	h := NewHub()
	st := NewStream(cfg, h, ids[0], capVer)
	other := NewStream(cfg, h, ids[2], capVer)
	_, err = st.Initial(s.Snapshot())
	require.NoError(t, err)
	_, err = other.Initial(s.Snapshot())
	require.NoError(t, err)

	for _, disabled := range []bool{true, false} {
		policy := `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`
		if disabled {
			policy = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}],"nodeAttrs":[{"target":["100.64.0.1"],"attr":["disable-ipv4"]}]}`
		}

		_, err = s.SetPolicy([]byte(policy))
		require.NoError(t, err)
		out, err := st.Update(s.Snapshot())
		require.NoError(t, err)
		require.NotEmpty(t, out)

		_, err = other.Update(s.Snapshot())
		require.NoError(t, err)

		for _, id := range ids[1:] {
			peer, ok := st.sent.peer(id.NodeID())
			require.True(t, ok)

			has4 := slices.ContainsFunc(peer.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() })
			require.Equal(t, !disabled, has4)

			for _, p := range peer.Addresses {
				require.Contains(t, peer.AllowedIPs, p)
			}
		}

		router, _ := st.sent.peer(ids[1].NodeID())
		require.Contains(t, router.AllowedIPs, route)

		shared, _ := other.sent.peer(ids[1].NodeID())
		require.True(t, slices.ContainsFunc(shared.Addresses, func(p netip.Prefix) bool { return p.Addr().Is4() }), "viewer overlay must not mutate shared peer")
	}
}

func TestOlderInitialPreservesRemovalAfterNewerFailedAttempt(t *testing.T) {
	cfg, s, ids := streamTestState(t, "")

	h := NewHub()
	defer h.Close()

	original := NewStream(cfg, h, ids[0], preNetmapRemovalsVer)
	full, err := original.Initial(s.Snapshot())
	require.NoError(t, err)

	client := newModelClient(full[0])

	original.Delivered()
	require.Contains(t, client.deltaPeers, ids[1].NodeID())
	require.NoError(t, s.DeleteNode(mustNode(t, s, ids[1])))
	olderSnapshot := s.Snapshot()
	_, err = s.RenameNode(ids[2], "unrelated-newer-commit")
	require.NoError(t, err)

	newerSnapshot := s.Snapshot()
	require.Greater(t, newerSnapshot.Rev(), olderSnapshot.Rev())

	failed := NewStream(cfg, h, ids[0], preNetmapRemovalsVer)
	attempted, err := failed.Initial(newerSnapshot)
	require.NoError(t, err)
	require.Len(t, attempted, 2)
	require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, attempted[1].PeersRemoved)
	client.apply(attempted[0]) // The socket fails before the removal, without Delivered.
	require.Contains(t, client.deltaPeers, ids[1].NodeID())
	older := NewStream(cfg, h, ids[0], preNetmapRemovalsVer)
	retry, err := older.Initial(olderSnapshot)
	require.NoError(t, err)
	require.Len(t, retry, 2, "newer failed attempt cannot discard confirmed removal history")
	require.Equal(t, []tailcfg.NodeID{ids[1].NodeID()}, retry[1].PeersRemoved)

	for _, resp := range retry {
		client.apply(resp)
	}

	older.Delivered()
	require.NotContains(t, client.deltaPeers, ids[1].NodeID())

	update, err := older.Update(newerSnapshot)
	require.NoError(t, err)

	for _, resp := range update {
		client.apply(resp)
	}

	fresh, err := NewStream(cfg, NewHub(), ids[0], preNetmapRemovalsVer).Initial(newerSnapshot)
	require.NoError(t, err)
	require.Equal(t, peerSet(fresh[0]), client.deltaPeers)
	require.Empty(t, client.sameAs(newModelClient(fresh[0])))
}

func TestHubBelongsToOneWorldAcrossReconstruction(t *testing.T) {
	cfg, original, ids := streamTestState(t, "")

	oldHub := NewHub()
	defer oldHub.Close()

	for i := range 8 {
		_, err := original.RenameNode(ids[0], fmt.Sprintf("older-world-%d", i))
		require.NoError(t, err)
	}

	oldHub.Watch(original)
	oldHub.Watch(original) // Repeated attachment cannot start duplicate watchers.
	oldHub.mu.Lock()
	observed := oldHub.latest
	oldHub.mu.Unlock()
	require.True(t, observed.SameWorld(original.Snapshot()))
	require.Equal(t, original.Snapshot().Rev(), observed.Rev(), "Watch must observe its initial snapshot before any event")
	_, err := NewStream(cfg, oldHub, ids[0], capVer).Initial(original.Snapshot())
	require.NoError(t, err)
	reloadedCfg, reloaded, reloadedIDs := streamTestState(t, "")
	require.Greater(t, observed.Rev(), reloaded.Snapshot().Rev(), "reconstructed world's local revision starts lower")
	require.PanicsWithValue(t, hubWorldMismatch, func() { oldHub.Watch(reloaded) })
	require.PanicsWithValue(t, hubWorldMismatch, func() { _, _ = NewStream(reloadedCfg, oldHub, reloadedIDs[0], capVer).Initial(reloaded.Snapshot()) })
	require.PanicsWithValue(t, hubWorldMismatch, func() { oldHub.observe(reloaded.Snapshot()) })

	freshHub := NewHub()
	defer freshHub.Close()

	freshHub.Watch(reloaded)
	out, err := NewStream(reloadedCfg, freshHub, reloadedIDs[0], capVer).Initial(reloaded.Snapshot())
	require.NoError(t, err)
	require.Equal(t, "n1.headscale.test.", out[0].Node.Name)
	require.Equal(t, mustNode(t, reloaded, reloadedIDs[0]).NodeKey(), out[0].Node.Key)
}

func TestScale1000AllToAllGraphMaps(t *testing.T) {
	const count = 1000

	s, streams := scalingTailnet(t, count, "allow-all")
	for _, st := range streams {
		peers := 0

		for id := range st.sent.allPeers() {
			require.NotEqual(t, st.nodeID.NodeID(), id)

			peers++
		}

		require.Equal(t, count-1, peers, "every initial graph map contains every other node")
	}

	target := streams[count/2].nodeID
	before := s.Snapshot()
	require.NotZero(t, s.Connect(target))
	after := s.Snapshot()
	all, wake := Route(before, after, after.Since(before))
	require.True(t, all || len(wake) == count, "online update must reach every viewer in this class")

	for _, st := range streams {
		out, err := st.Update(after)
		require.NoError(t, err)

		if st.nodeID == target {
			require.Empty(t, out, "self online metadata is omitted")
			continue
		}

		require.Len(t, out, 1)
		require.Len(t, out[0].PeersChangedPatch, 1)
		require.Equal(t, target.NodeID(), out[0].PeersChangedPatch[0].NodeID)
		require.True(t, *out[0].PeersChangedPatch[0].Online)
		require.Nil(t, out[0].Node)
		require.Nil(t, out[0].DNSConfig)
	}
}
