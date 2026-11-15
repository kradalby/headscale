//go:build headscale_debug

package state

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestDebugGraphNetworkInventoryPagesAndOwnership(t *testing.T) {
	a := createTestNode(1, 1, "alice", "one")
	b := createTestNode(2, 1, "alice", "two")
	b.Tags = []string{"tag:web"}
	s := newTestWorld(t, a, b).snapshot()
	first := s.DebugNetworkInventory(NetworkQuery{Category: "nodes", Limit: 1})
	require.Equal(t, 2, first.Total)
	require.NotNil(t, first.NextOffset)
	second := s.DebugNetworkInventory(NetworkQuery{Category: "nodes", Offset: *first.NextOffset, Limit: 1})
	require.NotEqual(t, first.Items[0].ID, second.Items[0].ID)
	require.Empty(t, second.Items[0].OwnerID)
	require.Contains(t, second.Items[0].RelatedIDs, "tag:tag:web")
	require.Len(t, s.DebugNetworkInventory(NetworkQuery{Category: "tags", Limit: 50}).Items, 1)
	require.Len(t, s.DebugNetworkInventory(NetworkQuery{Category: "nodes", Search: "two", Limit: 50}).Items, 1)
}

func TestDebugGraphNetworkInventoryCategoriesAndBounds(t *testing.T) {
	n := createTestNode(1, 1, "alice", "router")
	n.Tags = []string{"tag:router"}
	n.Hostinfo.Services = []tailcfg.Service{{Proto: "tcp", Port: 80}}
	route := netip.MustParsePrefix("10.0.0.0/24")
	n.Hostinfo.RoutableIPs = []netip.Prefix{route}
	n.ApprovedRoutes = []netip.Prefix{route}
	w := newTestWorld(t, n)
	require.NoError(t, w.SetUsers([]types.User{{ID: 1, Name: "alice"}}))

	s := w.snapshot()
	for _, category := range []string{"nodes", "users", "tags", "routes", "services"} {
		p := s.DebugNetworkInventory(NetworkQuery{Category: category, Limit: 1})
		require.Positive(t, p.Total, category)
		require.Len(t, p.Items, 1, category)
	}

	services := s.DebugNetworkInventory(NetworkQuery{Category: "services", Limit: 100}).Items
	require.Equal(t, "host-reported", services[0].Provenance)

	topology := s.DebugNetworkTopology("node:1")
	require.LessOrEqual(t, len(topology.Objects), 200)
	require.LessOrEqual(t, len(topology.Relationships), 1000)
	require.GreaterOrEqual(t, len(topology.Objects), 4)
}

func TestDebugGraphNetworkLargeInventory(t *testing.T) {
	nodes := make([]types.Node, 250)
	for i := range nodes {
		nodes[i] = createTestNode(types.NodeID(i+1), 1, "alice", fmt.Sprintf("node-%03d", i))
	}

	s := newTestWorld(t, nodes...).snapshot()
	seen := map[string]bool{}

	offset := 0
	for {
		p := s.DebugNetworkInventory(NetworkQuery{Category: "nodes", Limit: 37, Offset: offset})
		for _, n := range p.Items {
			require.False(t, seen[n.ID])
			seen[n.ID] = true
		}

		if p.NextOffset == nil {
			break
		}

		offset = *p.NextOffset
	}

	require.Len(t, seen, 250)

	topology := s.DebugNetworkTopology("user:1")
	require.Len(t, topology.Objects, 200)
	require.Positive(t, topology.Omitted)
}

func TestDebugGraphNetworkSourceImmutable(t *testing.T) {
	n := createTestNode(1, 1, "alice", "tagged")
	n.Tags = []string{"tag:web"}
	w := newTestWorld(t, n)
	source := []byte("{ // original comment\n \"tagOwners\":{\"tag:web\":[\"alice@\"]},\"grants\":[]}")
	_, err := w.SetPolicy(source, (*Snapshot).PolicyErr)
	require.NoError(t, err)

	s := w.snapshot()
	before := string(s.PolicySource())
	s.DebugNetworkInventory(NetworkQuery{Category: "tags", Limit: 50})
	require.Equal(t, before, string(s.PolicySource()))
}

func BenchmarkDebugGraphNetworkInventory(b *testing.B) {
	w, err := newWorld(nil, nil, nil, types.DNSView{})
	if err != nil {
		b.Fatal(err)
	}

	w.update(func(e *nodeEdit) {
		for i := range 10000 {
			n := createTestNode(types.NodeID(i+1), 1, "alice", fmt.Sprintf("node-%d", i))
			e.Set(n.ID, &n)
		}
	})
	s := w.snapshot()

	b.ResetTimer()

	for b.Loop() {
		s.DebugNetworkInventory(NetworkQuery{Category: "nodes", Search: "node", Offset: 500, Limit: 50})
	}
}

func TestDebugGraphNetworkAccessAndExplain(t *testing.T) {
	a := createTestNode(1, 1, "alice", "source")
	b := createTestNode(2, 2, "bob", "dest")
	s := newTestWorld(t, a, b).snapshot()
	p, err := s.DebugNetworkAccess(t.Context(), NetworkQuery{ID: "node:1", Direction: "outgoing", Limit: 1})
	require.NoError(t, err)
	require.Len(t, p.Items, 1)
	require.NotNil(t, p.NextOffset)
	result, err := s.DebugNetworkExplain(t.Context(), NetworkExplainQuery{Source: "node:1", Destination: "node:2", Protocol: 6, Port: 80})
	require.NoError(t, err)
	require.NotEmpty(t, result.Results)

	for _, r := range result.Results {
		require.Equal(t, "allowed", r.Policy.Packet)
	}

	_, err = s.DebugNetworkExplain(t.Context(), NetworkExplainQuery{Source: "node:1", Destination: "node:2", SourceIP: "192.0.2.1", Protocol: 6, Port: 80})
	require.Error(t, err)
	_, err = s.DebugNetworkAccess(t.Context(), NetworkQuery{ID: "node:999", Direction: "incoming", Limit: 1})
	require.Error(t, err)
}

func BenchmarkDebugGraphNetworkAccess(b *testing.B) {
	w, err := newWorld(nil, nil, nil, types.DNSView{})
	if err != nil {
		b.Fatal(err)
	}

	w.update(func(e *nodeEdit) {
		for i := range 1000 {
			n := createTestNode(types.NodeID(i+1), 1, "alice", fmt.Sprintf("node-%d", i))
			e.Set(n.ID, &n)
		}
	})
	s := w.snapshot()

	b.ResetTimer()

	for b.Loop() {
		_, err := s.DebugNetworkAccess(context.Background(), NetworkQuery{ID: "node:1", Direction: "outgoing", Limit: 50})
		if err != nil {
			b.Fatal(err)
		}
	}
}

func TestDebugGraphNetworkCapabilityFilters(t *testing.T) {
	a := createTestNode(1, 1, "alice", "source")
	b := createTestNode(2, 2, "bob", "target")
	w := newTestWorld(t, a, b)
	_, err := w.SetPolicy([]byte(`{"grants":[{"src":["*"],"dst":["*"],"app":{"example.com/cap":[{}]}}]}`), (*Snapshot).PolicyErr)
	require.NoError(t, err)
	p, err := w.snapshot().DebugNetworkAccess(t.Context(), NetworkQuery{ID: "node:1", Direction: "outgoing", Limit: 100, Protocol: new(6), Port: new(uint16(443))})
	require.NoError(t, err)

	for _, item := range p.Items {
		if item.Node.ID == "node:2" {
			require.Contains(t, item.Capabilities, "example.com/cap")
			require.NotEmpty(t, item.Ranges)
		}
	}
}

func TestDebugGraphNetworkUnavailableDestinations(t *testing.T) {
	n := createTestNode(1, 1, "alice", "source")
	n.IPv6 = nil

	s := newTestWorld(t, n).snapshot()
	for _, destination := range []string{"192.0.2.55", "2001:db8::55"} {
		result, err := s.DebugNetworkExplain(t.Context(), NetworkExplainQuery{Source: "node:1", Destination: destination, Protocol: 6, Port: 443})
		require.NoError(t, err)
		require.Len(t, result.Results, 1)
		require.Equal(t, "unavailable", result.Results[0].Policy.Packet)
		require.NotEmpty(t, result.Results[0].Policy.Reason)
		require.Empty(t, result.Results[0].RouteEvidence)
	}
}
