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

func TestDebugGraphNetworkOverview(t *testing.T) {
	a := createTestNode(1, 1, "alice", "router")
	a.Hostinfo.Services = []tailcfg.Service{{Proto: "tcp", Port: 80}}
	a.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	b := createTestNode(2, 2, "bob", "tagged")
	b.Tags = []string{"tag:web"}
	w := newTestWorld(t, a, b)
	require.NoError(t, w.SetUsers([]types.User{{ID: 1, Name: "alice"}, {ID: 2, Name: "bob"}}))
	s := w.snapshot()
	overview := s.DebugNetworkTopology("")
	require.Equal(t, overview, s.DebugNetworkTopology(""))
	require.Zero(t, overview.Omitted)

	present := map[string]bool{}
	for _, o := range overview.Objects {
		present[o.ID] = true
		if o.ID == "user:1" || o.ID == "tag:tag:web" {
			require.Equal(t, 1, o.MemberCount)
		}

		if o.ID == "user:2" {
			require.Zero(t, o.MemberCount)
		}
	}

	for _, id := range []string{"user:1", "user:2", "tag:tag:web", "node:1", "node:2", "route:1:10.0.0.0/24", "service:1:host:tcp:80"} {
		require.True(t, present[id], id)
	}

	for _, edge := range overview.Relationships {
		require.True(t, present[edge.Source])
		require.True(t, present[edge.Target])
	}

	require.Contains(t, overview.Relationships, NetworkRelationship{"node:2", "tag:tag:web", "tag identity"})
	require.NotContains(t, overview.Relationships, NetworkRelationship{"node:2", "user:2", "owned by"})

	focused := s.DebugNetworkTopology("", NetworkQuery{Identity: "user:1"})
	for _, o := range focused.Objects {
		require.NotEqual(t, "node:2", o.ID)
	}

	searched := s.DebugNetworkTopology("", NetworkQuery{Search: "10.0.0.0"})
	require.Len(t, searched.Objects, 3)
	require.Len(t, searched.Relationships, 2)
	require.Empty(t, s.DebugNetworkTopology("", NetworkQuery{Search: "no-match"}).Objects)
	require.Equal(t, s.DebugNetworkTopology("node:1"), s.DebugNetworkTopology("node:1", NetworkQuery{}))
}

func TestDebugGraphNetworkOverviewBounds(t *testing.T) {
	nodes := make([]types.Node, 250)
	for i := range nodes {
		nodes[i] = createTestNode(types.NodeID(i+1), 1, "alice", fmt.Sprintf("node-%03d", i))
	}

	s := newTestWorld(t, nodes...).snapshot()
	overview := s.DebugNetworkTopology("")
	require.Len(t, overview.Objects, 200)

	total := 1 // Ownership context for the missing user record.
	for _, category := range []string{"users", "tags", "nodes", "routes", "services"} {
		total += len(s.networkObjects(category))
	}

	require.Equal(t, total-200, overview.Omitted)
	require.Equal(t, "user:1", overview.Objects[0].ID)
	require.Equal(t, 250, overview.Objects[0].MemberCount)
	require.Len(t, overview.Relationships, 199)
}

func TestDebugGraphNetworkPermittedAccessPages(t *testing.T) {
	source := createTestNode(1, 1, "alice", "source")
	blocked := createTestNode(2, 2, "bob", "blocked")
	allowed := createTestNode(3, 2, "bob", "allowed")
	capability := createTestNode(4, 2, "bob", "capability")
	w := newTestWorld(t, source, blocked, allowed, capability)
	policy := fmt.Sprintf(`{"grants":[{"src":[%q],"dst":[%q],"ip":["tcp:443"]},{"src":[%q],"dst":[%q],"app":{"example.com/cap":[{}]}}]}`, source.IPv4.String(), allowed.IPv4.String(), source.IPv4.String(), capability.IPv4.String())
	_, err := w.SetPolicy([]byte(policy), (*Snapshot).PolicyErr)
	require.NoError(t, err)

	s := w.snapshot()
	q := NetworkQuery{ID: "node:1", Direction: "outgoing", Limit: 1, OnlyPermitted: true}
	page, err := s.DebugNetworkAccess(t.Context(), q)
	require.NoError(t, err)
	require.Equal(t, 4, page.Total)
	require.Equal(t, 2, page.Matched)
	require.Len(t, page.Items, 1)
	require.Equal(t, "node:3", page.Items[0].Node.ID)
	require.True(t, page.Items[0].Visible)
	require.NotNil(t, page.NextOffset)
	q.Offset = *page.NextOffset
	page, err = s.DebugNetworkAccess(t.Context(), q)
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	require.Equal(t, "node:4", page.Items[0].Node.ID)
	require.Contains(t, page.Items[0].Capabilities, "example.com/cap")
	require.Nil(t, page.NextOffset)

	filtered, err := s.DebugNetworkAccess(t.Context(), NetworkQuery{ID: "node:1", Direction: "outgoing", Limit: 12, OnlyPermitted: true, Protocol: new(6), Port: new(uint16(80))})
	require.NoError(t, err)
	require.Equal(t, 1, filtered.Matched)
	require.Equal(t, "node:4", filtered.Items[0].Node.ID)

	incoming, err := s.DebugNetworkAccess(t.Context(), NetworkQuery{ID: "node:3", Direction: "incoming", Limit: 1, OnlyPermitted: true})
	require.NoError(t, err)
	require.Equal(t, 1, incoming.Matched)
	require.Equal(t, "node:1", incoming.Items[0].Node.ID)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = s.DebugNetworkAccess(ctx, q)
	require.ErrorIs(t, err, context.Canceled)
}

func TestDebugGraphNetworkPermittedAccessReportsPolicyFailure(t *testing.T) {
	w := newTestWorld(t, createTestNode(1, 1, "alice", "source"), createTestNode(2, 2, "bob", "destination"))
	_, err := w.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["nohost"],"dst":["*:*"]}]}`), func(*Snapshot) error { return nil })
	require.NoError(t, err)

	s := w.snapshot()
	require.Error(t, s.PolicyErr())
	_, err = s.DebugNetworkAccess(t.Context(), NetworkQuery{ID: "node:1", Direction: "outgoing", OnlyPermitted: true})
	require.ErrorIs(t, err, s.PolicyErr())
}
