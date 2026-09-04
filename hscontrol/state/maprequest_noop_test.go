package state

import (
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// TestNoOpMapRequestSkipsPersist ensures an identical, no-op MapRequest does
// not issue a database UPDATE (nor the O(n) policy SetNodes scan that follows
// persistNodeToDB). The node state is unchanged, so persisting is pure waste on
// the hot map-request path.
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
	require.True(t, ok, "node should exist in NodeStore")

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
	_, err = s.UpdateNodeFromMapRequest(nodeID, req)
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

	_, err = s.UpdateNodeFromMapRequest(nodeID, req2)
	require.NoError(t, err)

	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"no-op MapRequest should not issue any nodes-table UPDATE, got %d",
		nodeUpdateCount.Load())
}

// TestNoOpMapRequestEmitsNoPeerChange ensures an identical, no-op MapRequest
// does not emit a peer-visible change.
//
// UpdateNodeFromMapRequest has no outcome for "nothing to announce": its
// classifier falls through to change.NodeAdded, a peers-changed fan-out
// delivered to every connected peer. The peerChangeEmpty guard that was
// supposed to catch this is unreachable, because PeerChangeFromMapRequest
// always stamps LastSeen and peerChangeEmpty requires LastSeen == nil.
//
// See https://github.com/juanfont/headscale/issues/3417.
func TestNoOpMapRequestEmitsNoPeerChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

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
	_, err := s.UpdateNodeFromMapRequest(nodeID, req())
	require.NoError(t, err)

	// Second request is value-identical: a no-op.
	c, err := s.UpdateNodeFromMapRequest(nodeID, req())
	require.NoError(t, err)

	require.Truef(t, c.IsEmpty(),
		"no-op MapRequest must not emit a change, got reason=%q type=%q peersChanged=%v",
		c.Reason, c.Type(), c.PeersChanged)
}

// TestSTUNOnlyEndpointUpdateEmitsNoPeerChange ensures endpoint churn that
// endpointBroadcastWorthy deliberately suppresses stays suppressed. The
// suppression sets endpointChanged=false, which drops through to the
// change.NodeAdded fall-through — escalating what used to be a cheap
// PeerChange patch into a full peer change delivered to every peer.
//
// See https://github.com/juanfont/headscale/issues/3417.
func TestSTUNOnlyEndpointUpdateEmitsNoPeerChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok, "node should exist in NodeStore")

	stored := nv.AsStruct()

	hi := func() *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		}
	}

	// First request establishes the Hostinfo/DERP state.
	_, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: hi(),
	})
	require.NoError(t, err)

	// Second request adds a single STUN-derived endpoint and nothing else.
	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:       stored.NodeKey,
		DiscoKey:      stored.DiscoKey,
		Hostinfo:      hi(),
		Endpoints:     []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")},
		EndpointTypes: []tailcfg.EndpointType{tailcfg.EndpointSTUN},
	})
	require.NoError(t, err)

	require.Truef(t, c.IsEmpty(),
		"suppressed STUN-only endpoint delta must not emit a change, got reason=%q type=%q peersChanged=%v",
		c.Reason, c.Type(), c.PeersChanged)
}

// TestMapRequestOmittedNetInfoIsNotStructural pins that a MapRequest carrying
// Hostinfo with NetInfo omitted is compared against the preserved NetInfo, not
// against the bare request. Tailscale clients send NetInfo only when it
// changed, so classifying the omission as a structural Hostinfo change turns
// every routine map request into a database write, an O(n) policy rescan and a
// whole-peer broadcast.
func TestMapRequestOmittedNetInfoIsNotStructural(t *testing.T) {
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
	_, err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
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

	// Same Hostinfo, NetInfo omitted: the client is saying "unchanged".
	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			OS:       "linux",
		},
	})
	require.NoError(t, err)

	require.True(t, c.IsEmpty(), "omitted NetInfo must not broadcast, got %+v", c)
	require.Equalf(t, int64(0), nodeUpdateCount.Load(),
		"omitted NetInfo must not persist, got %d updates", nodeUpdateCount.Load())

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Equal(t, 1, hostinfoDERP(after.AsStruct().Hostinfo),
		"stored NetInfo must survive a request that omits it")
}

// TestMapRequestDERPClearToZeroIsStoredAndBroadcast pins that a node reporting
// PreferredDERP 0 has its home region cleared. tailcfg.PeerChange.DERPRegion
// zero means "unchanged" on the wire, so the clear cannot ride a patch and has
// to escalate to a whole-peer update.
func TestMapRequestDERPClearToZeroIsStoredAndBroadcast(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	stored := nv.AsStruct()

	_, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  stored.NodeKey,
		DiscoKey: stored.DiscoKey,
		Hostinfo: &tailcfg.Hostinfo{
			Hostname: stored.Hostname,
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		},
	})
	require.NoError(t, err)

	c, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
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
	require.Equal(t, 0, hostinfoDERP(after.AsStruct().Hostinfo),
		"clearing PreferredDERP must be stored")

	require.Contains(t, c.PeersChanged, nodeID,
		"clearing PreferredDERP cannot be a patch, got %+v", c)
	require.Empty(t, c.PeerPatches,
		"clearing PreferredDERP must not emit a DERP patch, got %+v", c)
}
