package state

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
)

func TestMapRequestChecksNodeKeyInsideWriter(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	before := s.Snapshot()
	rowUpdates := countNodeRowUpdates(t, s)
	newKey := key.NewNode().Public()
	entered, release := make(chan struct{}), make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })

	var wg sync.WaitGroup

	t.Cleanup(func() { unblock(); wg.Wait() })
	wg.Go(func() {
		s.world.UpdateNode(id, func(n *types.Node) {
			close(entered)
			<-release

			n.NodeKey = newKey
		})
	})
	<-entered

	result := make(chan error, 1)

	wg.Go(func() {
		result <- s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{
			NodeKey: node.NodeKey(), DiscoKey: key.NewDisco().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: "stale"},
		})
	})
	require.Eventually(t, func() bool {
		s.world.writeMu.Lock()
		defer s.world.writeMu.Unlock()

		return len(s.world.writes) == 1
	}, 5*time.Second, time.Millisecond, "map request must queue before the key change commits")
	unblock()
	wg.Wait()
	require.ErrorIs(t, <-result, ErrNodeKeyChanged)

	expected := node.AsStruct()
	expected.NodeKey = newKey
	live, ok := s.GetNodeByID(id)
	require.True(t, ok)
	assert.Equal(t, expected, live.AsStruct())
	assert.Equal(t, before.Rev()+1, s.Snapshot().Rev(), "only the key change may publish")
	assert.Zero(t, rowUpdates.Load())

	// A zero key is not a trusted internal bypass.
	require.ErrorIs(t, s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{}), ErrNodeKeyChanged)
	assert.Equal(t, before.Rev()+1, s.Snapshot().Rev())
	assert.Zero(t, rowUpdates.Load())
}

func TestMapRequestDeletedInSameBatch(t *testing.T) {
	for _, substantive := range []bool{false, true} {
		t.Run(fmt.Sprintf("substantive=%v", substantive), func(t *testing.T) {
			_, s, id := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			node, ok := s.GetNodeByID(id)
			require.True(t, ok)

			req := tailcfg.MapRequest{NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey()}
			if substantive {
				req.Hostinfo = &tailcfg.Hostinfo{Hostname: "changed"}
			}

			rowUpdates := countNodeRowUpdates(t, s)
			entered, release := make(chan struct{}), make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })

			var wg sync.WaitGroup

			t.Cleanup(func() { unblock(); wg.Wait() })
			wg.Go(func() {
				s.world.update(func(*nodeEdit) { close(entered); <-release })
			})
			<-entered

			result := make(chan error, 1)

			wg.Go(func() { result <- s.UpdateNodeFromMapRequest(id, req) })

			queued := func(count int) bool {
				s.world.writeMu.Lock()
				defer s.world.writeMu.Unlock()

				return len(s.world.writes) == count
			}

			require.Eventually(t, func() bool { return queued(1) }, 5*time.Second, time.Millisecond)
			wg.Go(func() { s.world.DeleteNode(id) })
			require.Eventually(t, func() bool { return queued(2) }, 5*time.Second, time.Millisecond)
			unblock()
			wg.Wait()
			require.ErrorIs(t, <-result, ErrNodeNotInNodeStore)

			_, ok = s.GetNodeByID(id)
			require.False(t, ok)
			require.Zero(t, rowUpdates.Load())
		})
	}
}

// TestVanishedRowSurfacesInPersists pins that a persist against a deleted
// row reports the row gone instead of silent success. The lifetime deletes
// drop the row first and the world node a beat later; a map-request persist
// or an expiry landing in that window writes zero rows, and the database is
// the source of truth — callers must see ErrNodeNotInNodeStore, not a no-op
// reported as success.
func TestVanishedRowSurfacesInPersists(t *testing.T) {
	_, s, id := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(id)
	require.True(t, ok)

	// The window between the row delete and the world delete, as the
	// lifetime deletes leave it: row gone, memory still has the node.
	require.NoError(t, s.db.DeleteNode(node.AsStruct()))

	err := s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{
		NodeKey:  node.NodeKey(),
		DiscoKey: key.NewDisco().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "vanished"},
	})
	require.ErrorIs(t, err, ErrNodeNotInNodeStore, "a persist that wrote zero rows is not a success")

	_, err = s.SetNodeExpiry(id, new(time.Now().Add(time.Hour)))
	require.ErrorIs(t, err, ErrNodeNotInNodeStore, "an expiry that wrote zero rows is not a success")

	// Manual cleanup: the row is already gone, drop the world node too.
	s.world.DeleteNode(id)
}

func TestMapRequestOwnsRequestData(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	req := tailcfg.MapRequest{
		NodeKey:   node.NodeKey(),
		DiscoKey:  node.DiscoKey(),
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")},
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: "original",
			Services: []tailcfg.Service{{Proto: "tcp", Port: 80}},
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.1},
			},
		},
	}
	original := req.Hostinfo.Clone()
	err := s.UpdateNodeFromMapRequest(nodeID, req)
	require.NoError(t, err)
	require.Equal(t, original, req.Hostinfo, "map update must not modify its request")

	req.Hostinfo.Hostname = "changed"
	req.Hostinfo.Services[0].Port = 443
	req.Hostinfo.NetInfo.PreferredDERP = 2
	req.Hostinfo.NetInfo.DERPLatency["1-v4"] = 0.2
	req.Endpoints[0] = netip.MustParseAddrPort("192.0.2.2:41641")

	stored, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, original, stored.Hostinfo().AsStruct())
	require.Equal(t, netip.MustParseAddrPort("192.0.2.1:41641"), stored.Endpoints().At(0))
}

func TestNetInfoFromMapRequest(t *testing.T) {
	nodeID := types.NodeID(1)

	tests := []struct {
		name            string
		currentHostinfo *tailcfg.Hostinfo
		reqHostinfo     *tailcfg.Hostinfo
		expectNetInfo   *tailcfg.NetInfo
	}{
		{
			name:            "no current NetInfo - return nil",
			currentHostinfo: nil,
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
			},
			expectNetInfo: nil,
		},
		{
			name: "current has NetInfo, request has NetInfo - use request",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 1},
			},
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 2},
			},
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 2},
		},
		{
			name: "current has NetInfo, request has no NetInfo - use current",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 3},
			},
			reqHostinfo: &tailcfg.Hostinfo{
				Hostname: "test-node",
			},
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 3},
		},
		{
			name: "current has NetInfo, no request Hostinfo - use current",
			currentHostinfo: &tailcfg.Hostinfo{
				NetInfo: &tailcfg.NetInfo{PreferredDERP: 4},
			},
			reqHostinfo:   nil,
			expectNetInfo: &tailcfg.NetInfo{PreferredDERP: 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := netInfoFromMapRequest(nodeID, tt.currentHostinfo, tt.reqHostinfo)

			if tt.expectNetInfo == nil {
				assert.Nil(t, result, "expected nil NetInfo")
			} else {
				require.NotNil(t, result, "expected non-nil NetInfo")
				assert.Equal(t, tt.expectNetInfo.PreferredDERP, result.PreferredDERP, "DERP mismatch")
			}
		})
	}
}

func TestNetInfoPreservationInRegistrationFlow(t *testing.T) {
	nodeID := types.NodeID(1)

	// This test reproduces the bug in registration flows where NetInfo was lost
	// because we used the wrong hostinfo reference when calling [netInfoFromMapRequest]
	t.Run("registration_flow_bug_reproduction", func(t *testing.T) {
		// Simulate existing node with NetInfo (before re-registration)
		existingNodeHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 5},
		}

		// Simulate new registration request (no NetInfo)
		newRegistrationHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			OS:       "linux",
			// NetInfo is nil - this is what comes from the registration request
		}

		// Simulate what was happening in the bug: we passed the "current node being modified"
		// hostinfo (which has no NetInfo) instead of the existing node's hostinfo
		nodeBeingModifiedHostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			// NetInfo is nil because this node is being modified/reset
		}

		// BUG: Using the node being modified (no NetInfo) instead of existing node (has NetInfo)
		buggyResult := netInfoFromMapRequest(nodeID, nodeBeingModifiedHostinfo, newRegistrationHostinfo)
		assert.Nil(t, buggyResult, "Bug: Should return nil when using wrong hostinfo reference")

		// CORRECT: Using the existing node's hostinfo (has NetInfo)
		correctResult := netInfoFromMapRequest(nodeID, existingNodeHostinfo, newRegistrationHostinfo)
		assert.NotNil(t, correctResult, "Fix: Should preserve NetInfo when using correct hostinfo reference")
		assert.Equal(t, tailcfg.DERPRegionID(5), correctResult.PreferredDERP, "Should preserve the DERP region from existing node")
	})

	t.Run("new_node_creation_for_different_user_should_preserve_netinfo", func(t *testing.T) {
		// This test covers the scenario where:
		// 1. A node exists for user1 with NetInfo
		// 2. The same machine logs in as user2 (different user)
		// 3. A NEW node is created for user2 (pre-auth key flow)
		// 4. The new node should preserve NetInfo from the old node

		// Existing node for user1 with NetInfo
		existingNodeUser1Hostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 7},
		}

		// New registration request for user2 (no NetInfo yet)
		newNodeUser2Hostinfo := &tailcfg.Hostinfo{
			Hostname: "test-node",
			OS:       "linux",
			// NetInfo is nil - registration request doesn't include it
		}

		// When creating a new node for user2, we should preserve NetInfo from user1's node
		result := netInfoFromMapRequest(types.NodeID(2), existingNodeUser1Hostinfo, newNodeUser2Hostinfo)
		assert.NotNil(t, result, "New node for user2 should preserve NetInfo from user1's node")
		assert.Equal(t, tailcfg.DERPRegionID(7), result.PreferredDERP, "Should preserve DERP region from existing node")
	})
}

// TestNoOpMapRequestSkipsPersist ensures an identical, no-op MapRequest does
// not issue a database UPDATE. The node state is unchanged, so persisting is
// pure waste on the hot map-request path.
func TestNoOpMapRequestSkipsPersist(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "noop_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement == nil {
			return
		}

		if tx.Statement.Table == "nodes" ||
			strings.Contains(strings.ToLower(tx.Statement.SQL.String()), "update \"nodes\"") {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist")

	stored := nv.AsStruct()

	req := tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}

	// First request establishes the Hostinfo/DERP state (expected to persist).
	err = s.UpdateNodeFromMapRequest(nodeID, req)
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	// Second request is value-identical: a no-op.
	req2 := tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}

	err = s.UpdateNodeFromMapRequest(nodeID, req2)
	require.NoError(t, err)

	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"no-op MapRequest should not issue any nodes-table UPDATE, got %d",
		nodeUpdateCount.Load())
}

// TestNoOpMapRequestOnlyStampsLastSeen ensures an identical, no-op MapRequest
// changes nothing but LastSeen: it keeps the stored Hostinfo and neither
// recompiles the policy nor moves peers or primaries.
func TestNoOpMapRequestOnlyStampsLastSeen(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist")

	stored := nv.AsStruct()

	req := func() tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: stored.Hostname,
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
			},
		}
	}

	// First request establishes the Hostinfo/DERP state.
	err := s.UpdateNodeFromMapRequest(nodeID, req())
	require.NoError(t, err)

	beforeSeen := mustLastSeen(t, s, nodeID)
	before := s.Snapshot()
	beforeNode, _ := before.GetNode(nodeID)

	// Second request is value-identical: a no-op.
	err = s.UpdateNodeFromMapRequest(nodeID, req())
	require.NoError(t, err)

	after := s.Snapshot()
	afterNode, _ := after.GetNode(nodeID)
	require.True(t, beforeNode.Hostinfo().Equal(afterNode.Hostinfo()), "no-op request must keep the stored Hostinfo")
	require.Equal(t, before.PolicyRev(), after.PolicyRev(), "no-op request must not recompile the policy")
	require.Equal(t, before.PeersRev(), after.PeersRev(), "no-op request must not move peers")
	require.Equal(t, before.PrimariesRev(), after.PrimariesRev(), "no-op request must not move primaries")

	require.True(t, mustLastSeen(t, s, nodeID).After(beforeSeen),
		"no-op request must still stamp LastSeen in memory")
}

// TestFirstEndpointsReachPeersEvenWhenSTUNOnly pins that the first endpoint
// set a node announces is stored and persisted even when it is STUN-only.
// Peers render the node from memory, so an endpoint not stored leaves them
// with no direct path to it.
func TestFirstEndpointsReachPeersEvenWhenSTUNOnly(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist")
	require.Empty(t, nv.Endpoints().AsSlice(), "precondition: node starts with no endpoints")

	stored := nv.AsStruct()
	stun := netip.MustParseAddrPort("198.51.100.7:41641")

	err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:       stored.NodeKey,
		DiscoKey:      stored.DiscoKey,
		Endpoints:     []netip.AddrPort{stun},
		EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointSTUN},
	})
	require.NoError(t, err)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, []netip.AddrPort{stun}, after.Endpoints().AsSlice(),
		"a node's first endpoints must be stored")

	row, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []netip.AddrPort{stun}, row.Endpoints.List(),
		"a node's first endpoints must be persisted")
}

// TestMapRequestDERPLatencyJitterIsNoChange pins the wiring between
// [State.UpdateNodeFromMapRequest] and the Hostinfo comparison: DERP latency
// is transport diagnostics that no peer reads, so jitter must neither
// replace the stored Hostinfo, which every map stream would then re-render,
// nor be persisted. hostinfoEqual covers the comparison itself; this covers
// the path.
func TestMapRequestDERPLatencyJitterIsNoChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist")

	stored := nv.AsStruct()

	hi := func(latency float64) *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": latency},
			},
		}
	}

	// Establish the Hostinfo, DERP region and a first latency sample.
	err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: hi(0.010),
	})
	require.NoError(t, err)

	rowUpdates := countNodeRowUpdates(t, s)

	// Only the latency sample moves.
	err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: hi(0.025),
	})
	require.NoError(t, err)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, 1, int(after.Hostinfo().NetInfo().PreferredDERP()),
		"the DERP region must survive a latency-only request")

	latency, _ := after.Hostinfo().NetInfo().DERPLatency().GetOk("1-v4")
	require.InDelta(t, 0.010, latency, 1e-9, "latency jitter must not replace the stored Hostinfo")
	require.Zero(t, rowUpdates.Load(), "latency jitter must not be persisted")
}

// TestMapRequestOmittedNetInfoIsNoChange pins that a MapRequest carrying
// Hostinfo with NetInfo omitted is compared against the preserved NetInfo, not
// against the bare request. Tailscale clients send NetInfo only when it
// changed, so classifying the omission as a Hostinfo change turns
// every routine map request into a database write and a re-render of the
// node for every peer.
func TestMapRequestOmittedNetInfoIsNoChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "omitted_netinfo_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	// Establish Hostinfo with NetInfo.
	err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			OS:       "linux",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	})
	require.NoError(t, err)
	require.Positive(t, nodeUpdateCount.Load(), "first request must persist")

	nodeUpdateCount.Store(0)

	before, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	// Same Hostinfo, NetInfo omitted: the client is saying "unchanged".
	err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			OS:       "linux",
		},
	})
	require.NoError(t, err)

	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"omitted NetInfo must not persist, got %d updates", nodeUpdateCount.Load())

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, before.Hostinfo().Equal(after.Hostinfo()),
		"omitted NetInfo must not replace the stored Hostinfo")
	require.Equal(t, tailcfg.DERPRegionID(1), hostinfoDERP(after.AsStruct().Hostinfo),
		"stored NetInfo must survive a request that omits it")
}

// TestMapRequestDERPClearToZeroIsStoredAndPersisted pins that a node reporting
// PreferredDERP 0 has its home region cleared. tailcfg.PeerChange.DERPRegion
// zero means "unchanged" on the wire, so the clear is invisible to the peer
// change and has to be detected on its own.
func TestMapRequestDERPClearToZeroIsStoredAndPersisted(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "derp_clear_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	})
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 0},
		},
	})
	require.NoError(t, err)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(after.AsStruct().Hostinfo),
		"clearing PreferredDERP must be stored")
	require.Positive(t, nodeUpdateCount.Load(), "clearing PreferredDERP must be persisted")
}

// TestMapRequestDERPOnlyChangeKeepsGivenName pins that a request changing only
// PreferredDERP does not re-derive GivenName: only a real hostname change
// may.
func TestMapRequestDERPOnlyChangeKeepsGivenName(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	req := func(derp tailcfg.DERPRegionID) tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: stored.Hostname,
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: derp},
			},
		}
	}

	err := s.UpdateNodeFromMapRequest(nodeID, req(1))
	require.NoError(t, err)

	// A collision-bumped name whose base is free again is exactly what the
	// auto-derive path rewrites.
	bumped := stored.Hostname + "-1"
	_, ok = s.world.UpdateNode(nodeID, func(n *types.Node) { n.GivenName = bumped })
	require.True(t, ok)

	err = s.UpdateNodeFromMapRequest(nodeID, req(2))
	require.NoError(t, err)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, bumped, after.GivenName(), "DERP-only change must not touch GivenName")
}

func TestConcurrentMapRequestDERPUsesPersistedState(t *testing.T) {
	for _, rotateDiscoKey := range []bool{false, true} {
		for _, tt := range []struct {
			name                string
			firstDERP, lastDERP tailcfg.DERPRegionID
		}{
			{name: "newer region", firstDERP: 2, lastDERP: 3},
			{name: "newer clear", firstDERP: 2, lastDERP: 0},
			{name: "superseded clear", firstDERP: 0, lastDERP: 3},
		} {
			name := tt.name
			if rotateDiscoKey {
				name += " with disco key rotation"
			}

			t.Run(name, func(t *testing.T) {
				_, s, nodeID := persistTestSetup(t)
				t.Cleanup(func() { _ = s.Close() })

				nv, ok := s.GetNodeByID(nodeID)
				require.True(t, ok)

				req := tailcfg.MapRequest{
					NodeKey:  nv.NodeKey(),
					DiscoKey: nv.DiscoKey(),
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: nv.Hostname(),
						NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
					},
				}
				err := s.UpdateNodeFromMapRequest(nodeID, req)
				require.NoError(t, err)

				if rotateDiscoKey {
					req.DiscoKey = key.NewDisco().Public()
				}

				// Let both requests publish their memory writes before
				// either can persist. Both must then persist the last
				// region, whichever persists first.
				s.persistMu.Lock()
				unlockPersist := sync.OnceFunc(s.persistMu.Unlock)

				var wg sync.WaitGroup

				t.Cleanup(func() {
					unlockPersist()
					wg.Wait()
				})

				errs := make(chan error, 2)

				for _, derp := range []tailcfg.DERPRegionID{tt.firstDERP, tt.lastDERP} {
					request := req
					request.Hostinfo = req.Hostinfo.Clone()
					request.Hostinfo.NetInfo.PreferredDERP = derp

					wg.Go(func() {
						errs <- s.UpdateNodeFromMapRequest(nodeID, request)
					})

					require.EventuallyWithT(t, func(c *assert.CollectT) {
						stored, exists := s.GetNodeByID(nodeID)
						require.True(c, exists)
						require.Equal(c, derp, stored.Hostinfo().NetInfo().PreferredDERP())
					}, 5*time.Second, time.Millisecond, "request must update memory before persisting")
				}

				unlockPersist()
				wg.Wait()
				close(errs)

				for err := range errs {
					require.NoError(t, err)
				}

				stored, ok := s.GetNodeByID(nodeID)
				require.True(t, ok)
				require.Equal(t, tt.lastDERP, stored.Hostinfo().NetInfo().PreferredDERP(),
					"memory must not restore a superseded DERP region")

				persisted, err := s.DB().GetNodeByID(nodeID)
				require.NoError(t, err)
				require.Equal(t, tt.lastDERP, persisted.Hostinfo.NetInfo.PreferredDERP,
					"the database must not restore a superseded DERP region")

				// A resend is still a no-op; correct state cannot depend
				// on a future identical request repairing it.
				rowUpdates := countNodeRowUpdates(t, s)
				req.Hostinfo = req.Hostinfo.Clone()
				req.Hostinfo.NetInfo.PreferredDERP = tt.lastDERP
				err = s.UpdateNodeFromMapRequest(nodeID, req)
				require.NoError(t, err)
				require.Zero(t, rowUpdates.Load(), "a resend must not persist")
			})
		}
	}
}

// TestMapRequestPeerInvisibleHostinfoChangeIsStored pins that a Hostinfo
// field no peer reads is still stored and persisted: the node itself and the
// admin API read it.
func TestMapRequestPeerInvisibleHostinfoChangeIsStored(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	var nodeUpdateCount atomic.Int64

	gdb := s.DB().DB
	cbName := "peer_invisible_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(cbName, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			nodeUpdateCount.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(cbName) })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	req := func(model string) tailcfg.MapRequest {
		return tailcfg.MapRequest{
			NodeKey:  stored.NodeKey,
			DiscoKey: stored.DiscoKey,
			Hostinfo: &tailcfg.Hostinfo{
				Hostname:    stored.Hostname,
				OS:          "linux",
				DeviceModel: model,
				NetInfo:     &tailcfg.NetInfo{PreferredDERP: 1},
			},
		}
	}

	err = s.UpdateNodeFromMapRequest(nodeID, req("a"))
	require.NoError(t, err)

	nodeUpdateCount.Store(0)

	err = s.UpdateNodeFromMapRequest(nodeID, req("b"))
	require.NoError(t, err)
	require.Positive(t, nodeUpdateCount.Load(), "the new DeviceModel must be persisted")

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, "b", after.Hostinfo().DeviceModel(), "the new DeviceModel must be stored")
}

func mustLastSeen(t *testing.T, s *State, id types.NodeID) time.Time {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	seen, ok := nv.LastSeen().GetOk()
	require.True(t, ok, "LastSeen must be stamped")

	return seen
}

func TestHostinfoEqual(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		require.True(t, hostinfoEqual(nil, nil))
	})

	t.Run("one nil", func(t *testing.T) {
		require.False(t, hostinfoEqual(&tailcfg.Hostinfo{}, nil))
		require.False(t, hostinfoEqual(nil, &tailcfg.Hostinfo{}))
	})

	t.Run("identical", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1", OS: "linux"}
		b := &tailcfg.Hostinfo{Hostname: "node1", OS: "linux"}
		require.True(t, hostinfoEqual(a, b))
	})

	t.Run("DERPLatency jitter is not a change", func(t *testing.T) {
		a := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.010},
			},
		}
		b := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.025}, // jitter
			},
		}
		require.True(t, hostinfoEqual(a, b),
			"DERPLatency jitter must not count as a change")
	})

	t.Run("PreferredDERP change is not a change here", func(t *testing.T) {
		a := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		}
		b := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 2},
		}
		require.True(t, hostinfoEqual(a, b),
			"PreferredDERP change is tracked separately")
	})

	t.Run("hostname change", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1"}
		b := &tailcfg.Hostinfo{Hostname: "node2"}
		require.False(t, hostinfoEqual(a, b))
	})

	t.Run("route change", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1", RoutableIPs: nil}
		b := &tailcfg.Hostinfo{Hostname: "node1"}
		// RoutableIPs nil vs nil: equal
		require.True(t, hostinfoEqual(a, b))

		// Add a route.
		// (also tracked separately as routesChangedInput)
		b.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
		require.False(t, hostinfoEqual(a, b))
	})
}

func TestNetInfoEqualIgnoringDERP(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		require.True(t, netInfoEqualIgnoringDERP(nil, nil))
	})

	t.Run("ignores PreferredDERP", func(t *testing.T) {
		a := &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: opt.NewBool(true)}
		b := &tailcfg.NetInfo{PreferredDERP: 9, WorkingUDP: opt.NewBool(true)}
		require.True(t, netInfoEqualIgnoringDERP(a, b))
	})

	t.Run("ignores DERPLatency", func(t *testing.T) {
		a := &tailcfg.NetInfo{DERPLatency: map[string]float64{"1": 0.01}}
		b := &tailcfg.NetInfo{DERPLatency: map[string]float64{"1": 0.99}}
		require.True(t, netInfoEqualIgnoringDERP(a, b))
	})

	t.Run("catches WorkingUDP change", func(t *testing.T) {
		a := &tailcfg.NetInfo{WorkingUDP: opt.NewBool(true)}
		b := &tailcfg.NetInfo{WorkingUDP: opt.NewBool(false)}
		require.False(t, netInfoEqualIgnoringDERP(a, b))
	})
}

func TestHostinfoDERP(t *testing.T) {
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(nil))
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(&tailcfg.Hostinfo{}))
	require.Equal(t, tailcfg.DERPRegionID(0), hostinfoDERP(&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{}}))
	require.Equal(t, tailcfg.DERPRegionID(5), hostinfoDERP(&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 5}}))
}

// benchMapRequestSetup pre-creates a sqlite database with n registered
// nodes spread across 10 users (~10% tagged tag:srv, half of those also
// carrying an approved and announced 10.x.0.0/24 route), then constructs a State
// that loads them, at benchmark scale the same way persistTestSetup
// does for a single node. Returns the State and the ID of node 0, a
// plain node with neither tag nor route, to drive requests against.
func benchMapRequestSetup(b *testing.B, n int) (*State, types.NodeID) {
	b.Helper()

	dbPath := b.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(b, err)

	users := make([]*types.User, 10)
	for i := range users {
		users[i] = database.CreateUserForTest(fmt.Sprintf("u%d", i+1))
	}

	var targetID types.NodeID

	for i := range n {
		node := database.CreateRegisteredNodeForTest(users[i%len(users)], fmt.Sprintf("n%d", i))

		if i == 0 {
			targetID = node.ID

			continue
		}

		if i%10 != 0 {
			continue
		}

		node.Tags = []string{"tag:srv"}

		if i%20 == 0 {
			subnet := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte((i / 20) % 256), 0, 0}), 24) //nolint:gosec
			node.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnet}}
			node.ApprovedRoutes = []netip.Prefix{subnet}
		}

		require.NoError(b, database.DB.Save(node).Error)
	}

	require.NoError(b, database.Close())

	s, err := NewState(cfg)
	require.NoError(b, err)
	b.Cleanup(func() { _ = s.Close() })

	target, ok := s.GetNodeByID(targetID)
	require.True(b, ok)
	require.False(b, target.IsTagged(), "target must be plain")
	require.Empty(b, target.AnnouncedRoutes(), "target must be plain")

	routers := 0

	for _, nv := range s.ListNodes().All() {
		if len(nv.AnnouncedRoutes()) > 0 {
			routers++
		}
	}

	require.Positive(b, routers, "setup must create subnet routers")

	return s, targetID
}

// BenchmarkUpdateNodeFromMapRequest measures the no-op path
// TestNoOpMapRequestSkipsPersist and TestNoOpMapRequestOnlyStampsLastSeen
// pin the behaviour of: a MapRequest that is value-identical to the
// node's current state, against a realistic node count. The baseline
// later write-path changes are compared against.
func BenchmarkUpdateNodeFromMapRequest(b *testing.B) {
	b.Run("identical/n=617", func(b *testing.B) {
		s, nodeID := benchMapRequestSetup(b, 617)

		nv, ok := s.GetNodeByID(nodeID)
		require.True(b, ok, "target node should exist")

		req := tailcfg.MapRequest{
			NodeKey:  nv.NodeKey(),
			DiscoKey: nv.DiscoKey(),
			Hostinfo: &tailcfg.Hostinfo{
				Hostname: nv.Hostname(),
				NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
			},
		}

		// Establish the Hostinfo/DERP state once so every request timed
		// below is a genuine no-op.
		err := s.UpdateNodeFromMapRequest(nodeID, req)
		require.NoError(b, err)

		b.ReportAllocs()

		for b.Loop() {
			err := s.UpdateNodeFromMapRequest(nodeID, req)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}

// autoApproveTestPolicy lets aa-user's nodes see each other and
// auto-approve subnets under 10.55.0.0/16 and exit routes; aa-other's
// node only reaches the internet, so it sees an aa-user node only once
// that node is an approved exit node.
const autoApproveTestPolicy = `{
	"acls": [
		{"action": "accept", "src": ["aa-user@"], "dst": ["aa-user@:*", "10.55.0.0/16:*"]},
		{"action": "accept", "src": ["aa-other@"], "dst": ["autogroup:internet:*"]}
	],
	"autoApprovers": {
		"routes": {"10.55.0.0/16": ["aa-user@"]},
		"exitNode": ["aa-user@"]
	}}`

// newAutoApproveTestState returns a State under autoApproveTestPolicy with
// three aa-user nodes followed by one aa-other node. prepare edits the
// database rows before the State loads them.
func newAutoApproveTestState(
	t *testing.T,
	prepare func(nodes []*types.Node),
) (*State, []types.NodeID) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("aa-user")
	other := database.CreateUserForTest("aa-other")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "aa-node")
	nodes = append(nodes, database.CreateRegisteredNodeForTest(other, "aa-other-node"))

	if prepare != nil {
		prepare(nodes)

		for _, n := range nodes {
			require.NoError(t, database.DB.Save(n).Error)
		}
	}

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(autoApproveTestPolicy))
	require.NoError(t, err)

	ids := make([]types.NodeID, 0, len(nodes))
	for _, n := range nodes {
		ids = append(ids, n.ID)
	}

	return s, ids
}

func routeMapRequest(t *testing.T, s *State, id types.NodeID, routes ...netip.Prefix) tailcfg.MapRequest {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	return tailcfg.MapRequest{
		NodeKey:  nv.NodeKey(),
		DiscoKey: nv.DiscoKey(),
		Hostinfo: &tailcfg.Hostinfo{
			Hostname:    nv.Hostname(),
			RoutableIPs: routes,
			NetInfo:     &tailcfg.NetInfo{PreferredDERP: 1},
		},
	}
}

// countNodeRowUpdates counts UPDATEs of the nodes table from now on.
func countNodeRowUpdates(t *testing.T, s *State) *atomic.Int64 {
	t.Helper()

	var n atomic.Int64

	gdb := s.DB().DB
	name := t.Name() + "_count_node_updates"
	err := gdb.Callback().Update().After("gorm:update").Register(name, func(tx *gorm.DB) {
		if tx.Statement != nil && tx.Statement.Table == "nodes" {
			n.Add(1)
		}
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = gdb.Callback().Update().Remove(name) })

	return &n
}

// TestMapRequestAutoApprovalIsOneWrite pins that a map request whose
// announced route the policy auto-approves lands in one commit (so one
// policy compile and one peer build) and one row update, persists the
// approval, and recompiles the policy for the new route.
func TestMapRequestAutoApprovalIsOneWrite(t *testing.T) {
	s, ids := newAutoApproveTestState(t, nil)
	route := netip.MustParsePrefix("10.55.1.0/24")

	req := routeMapRequest(t, s, ids[0], route)
	rowUpdates := countNodeRowUpdates(t, s)
	before := s.Snapshot()

	err := s.UpdateNodeFromMapRequest(ids[0], req)
	require.NoError(t, err)

	after := s.Snapshot()
	assert.Equal(t, before.Rev()+1, after.Rev(), "commits for one map request")
	assert.Equal(t, after.Rev(), after.PolicyRev(), "the approved route must recompile the policy")
	assert.Equal(t, int64(1), rowUpdates.Load(), "node row updates for one map request")

	row, err := s.DB().GetNodeByID(ids[0])
	require.NoError(t, err)
	assert.Contains(t, row.ApprovedRoutes, route, "the approval must be persisted")

	nv, ok := s.GetNodeByID(ids[0])
	require.True(t, ok)
	assert.Contains(t, nv.SubnetRoutes(), route)

	checkPeersMatchFullBuild(t, after)
}

// TestMapRequestWithdrawingRoutesClearsUnhealthy pins that a node whose
// announced set shrinks to empty stops being an unhealthy HA candidate.
func TestMapRequestWithdrawingRoutesClearsUnhealthy(t *testing.T) {
	route := netip.MustParsePrefix("10.55.1.0/24")
	s, ids := newAutoApproveTestState(t, func(nodes []*types.Node) {
		nodes[0].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		nodes[0].ApprovedRoutes = []netip.Prefix{route}
	})

	_, ok := s.world.UpdateNode(ids[0], func(n *types.Node) { n.Unhealthy = true })
	require.True(t, ok)

	err := s.UpdateNodeFromMapRequest(ids[0], routeMapRequest(t, s, ids[0]))
	require.NoError(t, err)

	nv, ok := s.GetNodeByID(ids[0])
	require.True(t, ok)
	assert.Empty(t, nv.AllApprovedRoutes())
	assert.False(t, nv.Unhealthy(), "a node with no approved routes is no HA candidate")
}

// TestSetApprovedRoutesReportsVisibility pins what an admin route approval
// moves: nothing the policy reads when the route is not announced, a policy
// recompile otherwise, and the peers and primaries that follow from it.
func TestSetApprovedRoutesReportsVisibility(t *testing.T) {
	subnetA := netip.MustParsePrefix("10.55.1.0/24")
	subnetB := netip.MustParsePrefix("10.55.2.0/24")
	exit := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}

	tests := []struct {
		name    string
		prepare func(nodes []*types.Node)
		approve []netip.Prefix
		// wantCompile reports whether the approval recompiles the policy.
		wantCompile bool
		// wantNewPeer is the index of a node that must become a peer.
		wantNewPeer int
	}{
		{
			name: "unannounced route moves nothing peers see",
			prepare: func(nodes []*types.Node) {
				nodes[0].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnetA}}
				nodes[0].ApprovedRoutes = []netip.Prefix{subnetA}
			},
			approve:     []netip.Prefix{subnetA, netip.MustParsePrefix("10.99.0.0/24")},
			wantNewPeer: -1,
		},
		{
			// No primary moves and no peer is gained, but the node's
			// approved subnets are a policy input (wildcard sources, via
			// grants and its own reduced filter read them), so the
			// policy is recompiled.
			name: "second subnet as HA standby is a policy input",
			prepare: func(nodes []*types.Node) {
				nodes[1].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnetB}}
				nodes[1].ApprovedRoutes = []netip.Prefix{subnetB}
				nodes[0].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{subnetA, subnetB}}
				nodes[0].ApprovedRoutes = []netip.Prefix{subnetA}
			},
			approve:     []netip.Prefix{subnetA, subnetB},
			wantCompile: true,
			wantNewPeer: -1,
		},
		{
			name: "first exit approval makes the node visible to a new peer",
			prepare: func(nodes []*types.Node) {
				nodes[0].Hostinfo = &tailcfg.Hostinfo{RoutableIPs: exit}
			},
			approve:     exit,
			wantCompile: true,
			wantNewPeer: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, ids := newAutoApproveTestState(t, tt.prepare)

			before := s.Snapshot()

			_, err := s.SetApprovedRoutes(ids[0], tt.approve)
			require.NoError(t, err)

			after := s.Snapshot()
			assert.Equal(t, tt.wantCompile, after.PolicyRev() != before.PolicyRev(), "policy recompiled")

			peersBefore := before.ListPeerIDs(ids[0])
			peersAfter := after.ListPeerIDs(ids[0])

			if tt.wantNewPeer < 0 {
				assert.Equal(t, peersBefore, peersAfter, "scenario must keep the node's peers")
				assert.Equal(t, before.PrimaryRoutes(), after.PrimaryRoutes(), "scenario must keep every primary")
			} else {
				assert.NotContains(t, peersBefore, ids[tt.wantNewPeer])
				assert.Contains(t, peersAfter, ids[tt.wantNewPeer])
			}

			checkPeersMatchFullBuild(t, after)
		})
	}
}

// TestRoutesChanged compares announced routes order-insensitively, with no
// routes and an empty list the same, and leaves the stored node unsorted.
func TestRoutesChanged(t *testing.T) {
	a, b := netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.1.0.0/24")

	node := func(routes ...netip.Prefix) types.NodeView {
		n := &types.Node{}
		if routes != nil {
			n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: routes}
		}

		return n.View()
	}

	for name, tc := range map[string]struct {
		old     types.NodeView
		new     []netip.Prefix
		changed bool
	}{
		"no hostinfo, none": {node(), nil, false},
		"none, empty":       {node(), []netip.Prefix{}, false},
		"same, reordered":   {node(b, a), []netip.Prefix{a, b}, false},
		"added":             {node(a), []netip.Prefix{a, b}, true},
		"removed":           {node(a, b), []netip.Prefix{a}, true},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.changed, routesChanged(tc.old, &tailcfg.Hostinfo{RoutableIPs: tc.new}))
		})
	}

	stored := node(b, a)
	routesChanged(stored, &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{a, b}})
	assert.Equal(t, []netip.Prefix{b, a}, stored.Hostinfo().RoutableIPs().AsSlice(), "the stored node stays as it was")
}
