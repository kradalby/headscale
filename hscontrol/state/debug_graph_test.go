//go:build headscale_debug

package state

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func graphVertices(scene DebugGraphScene) map[string]DebugGraphVertex {
	vertices := make(map[string]DebugGraphVertex)
	for _, v := range scene.Vertices {
		vertices[v.ID] = v
	}

	return vertices
}

func hasGraphEdge(scene DebugGraphScene, source, target, kind string) bool {
	for _, e := range scene.Edges {
		if e.Source == source && e.Target == target && e.Kind == kind {
			return true
		}
	}

	return false
}

func TestDebugGraphWorldRelationshipsAndDetails(t *testing.T) {
	owned := createTestNode(1, 1, "alice", "laptop")
	tagged := createTestNode(2, 1, "alice", "router")
	tagged.AuthKey = &types.Credential{Identifier: "private-credential-identifier", Hash: []byte("private-credential-hash")}
	tagged.Tags = []string{"tag:router"}
	tagged.IsOnline = new(true)
	route := netip.MustParsePrefix("10.0.0.0/24")
	tagged.Hostinfo.RoutableIPs = []netip.Prefix{route}
	tagged.ApprovedRoutes = []netip.Prefix{route}
	w := newTestWorld(t, owned, tagged)
	s := w.snapshot()
	scene := s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: "node:2"})

	vertices := graphVertices(scene)
	for _, id := range []string{"node:1", "node:2", "user:1", "tag:tag:router", "route:10.0.0.0/24", "filter:2", "cell:policy", "cell:policy-source"} {
		assert.Contains(t, vertices, id)
	}

	assert.True(t, hasGraphEdge(scene, "node:1", "user:1", "owned by"))
	assert.False(t, hasGraphEdge(scene, "node:2", "user:1", "owned by"))
	assert.True(t, hasGraphEdge(scene, "node:2", "tag:tag:router", "tagged with"))

	for _, kind := range []string{"advertises", "approved for", "primary for"} {
		assert.True(t, hasGraphEdge(scene, "node:2", "route:10.0.0.0/24", kind), kind)
	}

	assert.True(t, hasGraphEdge(scene, "node:1", "node:2", "visible to"))
	assert.True(t, hasGraphEdge(scene, "filter:2", "node:2", "effective filter for"))
	assert.True(t, hasGraphEdge(scene, "filter:2", "cell:policy", "compiled from"))
	assert.True(t, hasGraphEdge(scene, "cell:policy", "cell:policy-source", "compiled from"))

	detail, ok := s.DebugGraphDetail("node:2", "https://headscale.example")
	require.True(t, ok)
	d, ok := detail.(map[string]any)
	require.True(t, ok)

	n, _ := s.GetNode(2)
	filter, err := s.Policy().FilterForNode(n)
	require.NoError(t, err)
	ssh, err := s.Policy().SSHPolicy("https://headscale.example", n)
	require.NoError(t, err)
	assert.Equal(t, filter, d["packetFilter"])
	assert.Equal(t, ssh, d["sshPolicy"])

	b, err := json.Marshal(detail)
	require.NoError(t, err)

	for _, secret := range []string{"AuthKey", "MachineKey", "NodeKey", "DiscoKey", "Credential", "ProviderIdentifier", "private-credential", tagged.MachineKey.String(), tagged.NodeKey.String()} {
		assert.NotContains(t, string(b), secret)
	}

	for _, v := range scene.Vertices {
		data, ok := s.DebugGraphDetail(v.ID, "")
		require.True(t, ok, v.ID)

		encoded, err := json.Marshal(data)
		require.NoError(t, err)
		assert.NotContains(t, string(encoded), "private-credential")
	}

	for _, id := range []string{"", "node:nope", "node:999", "cell:missing", "filter:999", "tag:missing", "user:999", "route:invalid"} {
		_, ok := s.DebugGraphDetail(id, "")
		assert.False(t, ok, id)
	}

	before, err := json.Marshal(scene)
	require.NoError(t, err)
	w.DeleteNode(2)

	after, err := json.Marshal(s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: "node:2"}))
	require.NoError(t, err)
	assert.Equal(t, string(before), string(after), "old snapshots must stay consistent")

	_, ok = w.snapshot().DebugGraphDetail("node:2", "")
	assert.False(t, ok)
}

func TestDebugGraphBoundsAndSearch(t *testing.T) {
	const count = 1000

	nodes := make(types.Nodes, count)
	for i := range nodes {
		n := createTestNode(types.NodeID(i+1), 1, "alice", fmt.Sprintf("device-%04d", i+1))
		nodes[i] = &n
	}

	w, err := newWorld(nodes, nil, nil, types.DNSView{})
	require.NoError(t, err)

	s := w.snapshot()
	for _, query := range []DebugGraphQuery{{Perspective: "world"}, {Perspective: "world", Focus: "node:1000"}} {
		scene := s.DebugGraph(query)
		assert.LessOrEqual(t, len(scene.Vertices), 200)
		assert.LessOrEqual(t, len(scene.Edges), 1000)
		assert.Equal(t, count, scene.TotalNodes)
		assert.Equal(t, count, scene.MatchedNodes)
		assert.True(t, scene.Truncated)
		assert.Equal(t, 200, scene.Limit)
		assert.Equal(t, scene, s.DebugGraph(query))
		vertices := graphVertices(scene)
		shown := 0

		for _, v := range vertices {
			if v.Kind == "node" {
				shown++
			}
		}

		assert.Equal(t, shown, scene.ShownNodes)

		for _, e := range scene.Edges {
			assert.Contains(t, vertices, e.Source)
			assert.Contains(t, vertices, e.Target)

			if query.Focus == "" {
				assert.NotEqual(t, "visible to", e.Kind)
			}
		}

		if query.Focus != "" {
			assert.Contains(t, vertices, query.Focus)
		}
	}

	for _, search := range []string{"DEVICE-1000", "100.64.3.232", "node:1000"} {
		scene := s.DebugGraph(DebugGraphQuery{Perspective: "world", Search: search})
		assert.Equal(t, 1, scene.MatchedNodes)
		assert.Equal(t, 1, scene.ShownNodes)
		assert.Contains(t, graphVertices(scene), "node:1000")
		assert.False(t, scene.Truncated)
	}
}

func TestDebugGraphCanonicalUserSearch(t *testing.T) {
	for _, tc := range []struct{ name, username, email, provider, search string }{
		{"email", "alice", "alice@example.com", "", "ALICE@EXAMPLE.COM"},
		{"provider", "", "", "https://idp.example/alice", "HTTPS://IDP.EXAMPLE/ALICE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			owned := createTestNode(1, 1, tc.username, "laptop")
			owned.User.DisplayName = "Alice Example"
			owned.User.Email = tc.email
			owned.User.ProviderIdentifier.String = tc.provider
			owned.User.ProviderIdentifier.Valid = tc.provider != ""
			tagged := createTestNode(2, 1, tc.username, "service")
			tagged.User = owned.User
			tagged.Tags = []string{"tag:service"}
			w := newTestWorld(t, owned, tagged)
			require.NoError(t, w.SetUsers([]types.User{*owned.User}))

			query := DebugGraphQuery{Perspective: "world", Search: tc.search}
			scene := w.snapshot().DebugGraph(query)
			vertices := graphVertices(scene)
			assert.Equal(t, 1, scene.MatchedNodes)
			assert.Equal(t, 1, scene.ShownNodes)
			assert.Contains(t, vertices, "node:1")
			assert.Contains(t, vertices, "user:1")
			assert.NotContains(t, vertices, "node:2", "a tagged device's creator is not its owner")
			assert.True(t, hasGraphEdge(scene, "node:1", "user:1", "owned by"))

			w.DeleteNode(1)
			scene = w.snapshot().DebugGraph(query)
			assert.Zero(t, scene.MatchedNodes)
			assert.Zero(t, scene.ShownNodes)
			assert.Contains(t, graphVertices(scene), "user:1", "users remain searchable without owned devices")
		})
	}
}

func TestDebugGraphRouteSearchSurvivesLimit(t *testing.T) {
	routes := make([]netip.Prefix, 300)
	for i := range routes {
		routes[i] = netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256))
	}

	for _, tc := range []struct {
		name                string
		announced, approved []netip.Prefix
		online              bool
		kinds               []string
	}{
		{"advertised", routes, nil, false, []string{"advertises"}},
		{"approved", nil, routes, false, []string{"approved for"}},
		{"approved-after-advertised", routes[:299], routes[299:], false, []string{"approved for"}},
		{"primary", routes, routes, true, []string{"advertises", "approved for", "primary for"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := createTestNode(1, 1, "alice", "router")
			n.Hostinfo.RoutableIPs = tc.announced
			n.ApprovedRoutes = tc.approved
			n.IsOnline = new(tc.online)
			s := newTestWorld(t, n).snapshot()
			id := "route:10.1.43.0/24"
			assert.NotContains(t, graphVertices(s.DebugGraph(DebugGraphQuery{Perspective: "world"})), id)

			query := DebugGraphQuery{Perspective: "world", Search: "10.1.43.0/24"}
			scene := s.DebugGraph(query)
			vertices := graphVertices(scene)
			assert.Equal(t, 1, scene.MatchedNodes)
			assert.Equal(t, 1, scene.ShownNodes)
			assert.Contains(t, vertices, "node:1")
			assert.Contains(t, vertices, id)
			assert.True(t, scene.Truncated)
			assert.LessOrEqual(t, len(scene.Vertices), 200)
			assert.LessOrEqual(t, len(scene.Edges), 1000)
			assert.Equal(t, scene, s.DebugGraph(query))

			for _, kind := range []string{"advertises", "approved for", "primary for"} {
				assert.Equal(t, slices.Contains(tc.kinds, kind), hasGraphEdge(scene, "node:1", id, kind), kind)
			}

			scene = s.DebugGraph(DebugGraphQuery{Perspective: "world", Search: "10."})
			assert.Contains(t, graphVertices(scene), "node:1", "matching routes must not displace device identity")
			assert.True(t, scene.Truncated)
			assert.LessOrEqual(t, len(scene.Vertices), 200)
			assert.LessOrEqual(t, len(scene.Edges), 1000)
		})
	}
}

func TestDebugGraphDenseRelationsRespectEdgeLimit(t *testing.T) {
	tags := make([]string, 100)
	for i := range tags {
		tags[i] = fmt.Sprintf("tag:service-%d", i)
	}

	nodes := make(types.Nodes, 50)
	for i := range nodes {
		n := createTestNode(types.NodeID(i+1), 1, "alice", fmt.Sprintf("device-%d", i))
		n.Tags = tags
		nodes[i] = &n
	}

	w, err := newWorld(nodes, nil, nil, types.DNSView{})
	require.NoError(t, err)

	scene := w.snapshot().DebugGraph(DebugGraphQuery{Perspective: "world"})
	assert.Len(t, scene.Edges, 1000)
	assert.LessOrEqual(t, len(scene.Vertices), 200)
	assert.True(t, scene.Truncated)
}

func TestDebugGraphCoreAndValues(t *testing.T) {
	w := newTestWorld(t)
	w.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: {RegionID: 7, RegionName: "test relay", Nodes: []*tailcfg.DERPNode{{Name: "relay", HostName: "relay.example"}}}}})
	w.SetExtraRecords([]tailcfg.DNSRecord{{Name: "host.example", Type: "A", Value: "192.0.2.1"}})
	s := w.snapshot()
	core := s.DebugGraph(DebugGraphQuery{Perspective: "core"})
	assert.Equal(t, strconv.FormatUint(s.Rev(), 10), core.Revision)
	assert.True(t, hasGraphEdge(core, "cell:policy", "cell:policy-source", "depends on"))

	for _, v := range core.Vertices {
		assert.Contains(t, []string{"input", "derived"}, v.Kind)
		assert.NotEmpty(t, v.ChangedAt)
		assert.NotNil(t, v.Properties)
		_, ok := s.DebugGraphDetail(v.ID, "")
		assert.True(t, ok, v.ID)
	}

	for _, tc := range []struct{ focus, kind, label string }{{"cell:derp-map", "derp", "test relay"}, {"cell:dns", "dns", "host.example"}} {
		scene := s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: tc.focus})
		found := false

		for _, v := range scene.Vertices {
			if v.Kind == tc.kind {
				found = true

				assert.Equal(t, tc.label, v.Label)
				assert.True(t, hasGraphEdge(scene, tc.focus, v.ID, "contains"))
				_, ok := s.DebugGraphDetail(v.ID, "")
				assert.True(t, ok)
			}
		}

		assert.True(t, found)
	}

	empty := s.DebugGraph(DebugGraphQuery{Perspective: "world", Search: "missing"})
	b, err := json.Marshal(empty)
	require.NoError(t, err)
	assert.NotContains(t, string(b), ":null")
}

func TestDebugGraphEntityChangesStayLocal(t *testing.T) {
	w := newTestWorld(t, createTestNode(1, 1, "alice", "one"), createTestNode(2, 1, "alice", "two"))
	query := DebugGraphQuery{Perspective: "world"}
	before := graphVertices(w.snapshot().DebugGraph(query))
	w.UpdateNode(1, func(n *types.Node) { n.Hostname = "renamed" })
	after := graphVertices(w.snapshot().DebugGraph(query))
	assert.NotEqual(t, before["node:1"], after["node:1"])
	assert.Equal(t, before["node:2"], after["node:2"])
	assert.Equal(t, before["user:1"], after["user:1"])

	for _, v := range after {
		if v.Kind != "input" && v.Kind != "derived" {
			assert.Empty(t, v.ChangedAt, v.ID)
		}
	}
}

func TestDebugGraphFocusedRouteSurvivesLimit(t *testing.T) {
	n := createTestNode(1, 1, "alice", "router")
	for i := range 300 {
		n.Hostinfo.RoutableIPs = append(n.Hostinfo.RoutableIPs, netip.MustParsePrefix(fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)))
	}

	w := newTestWorld(t, n)
	s := w.snapshot()
	id := "route:10.1.43.0/24"
	scene := s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: id})
	assert.Contains(t, graphVertices(scene), id)
	assert.True(t, scene.Truncated)
	assert.LessOrEqual(t, len(scene.Vertices), 200)
	assert.True(t, hasGraphEdge(scene, "node:1", id, "advertises"))
	_, ok := s.DebugGraphDetail(id, "")
	assert.True(t, ok)
}

func TestDebugGraphDERPDetail(t *testing.T) {
	w := newTestWorld(t)

	region := &tailcfg.DERPRegion{RegionID: 7, RegionName: "relay"}
	for i := range 205 {
		region.Nodes = append(region.Nodes, &tailcfg.DERPNode{Name: fmt.Sprintf("relay-%d", i), HostName: "relay.example", DERPPort: 443})
	}

	w.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{7: region}})
	detail, ok := w.snapshot().DebugGraphDetail("derp:7", "")
	require.True(t, ok)
	d, ok := detail.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, 205, d["totalNodes"])
	assert.Equal(t, true, d["truncated"])
	nodes, ok := d["nodes"].([]map[string]string)
	require.True(t, ok)
	require.Len(t, nodes, 200)
	assert.Equal(t, "relay.example", nodes[0]["hostname"])
}

func TestDebugGraphSafeDeviceMetadata(t *testing.T) {
	n := createTestNode(1, 1, "alice", "router")
	n.Hostinfo.OS = "linux"
	n.Expiry = new(time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC))
	n.LastSeen = new(time.Date(2020, 1, 1, 3, 4, 5, 0, time.UTC))
	n.AuthKey = &types.Credential{Ephemeral: true, Identifier: "private-credential"}
	prefix := netip.MustParsePrefix("10.1.0.0/16")
	n.Hostinfo.RoutableIPs = []netip.Prefix{prefix}
	n.ApprovedRoutes = []netip.Prefix{prefix}
	w := newTestWorld(t, n)
	s := w.snapshot()
	detail, ok := s.DebugGraphDetail("node:1", "")
	require.True(t, ok)
	d, ok := detail.(map[string]any)
	require.True(t, ok)
	props, ok := d["properties"].(map[string]string)
	require.True(t, ok)

	for key, expected := range map[string]string{
		"os": "linux", "expiry": "2020-01-02T03:04:05Z", "expired": "true", "ephemeral": "true",
		"lastSeen": "2020-01-01T03:04:05Z", "announcedRoutes": "10.1.0.0/16", "approvedRoutes": "10.1.0.0/16", "primaryRoutes": "",
	} {
		value, exists := props[key]
		assert.True(t, exists, key)
		assert.Equal(t, expected, value, key)
	}

	w.UpdateNode(1, func(n *types.Node) { n.Hostinfo.OS = "windows"; n.Expiry = nil })

	old, ok := s.DebugGraphDetail("node:1", "")
	require.True(t, ok)
	assert.Equal(t, detail, old)
}

func TestDebugGraphPolicyFailureAndDistinctFilters(t *testing.T) {
	alice, bob := &types.User{Name: "alice"}, &types.User{Name: "bob"}
	alice.ID, bob.ID = 1, 2
	w, _ := testWorld(t, worldNode(1, alice, "100.64.0.1"), worldNode(2, bob, "100.64.0.2"))
	s := w.snapshot()
	first, ok := s.DebugGraphDetail("node:1", "")
	require.True(t, ok)
	second, ok := s.DebugGraphDetail("node:2", "")
	require.True(t, ok)
	firstDetail, ok := first.(map[string]any)
	require.True(t, ok)
	secondDetail, ok := second.(map[string]any)
	require.True(t, ok)
	assert.NotEqual(t, firstDetail["packetFilter"], secondDetail["packetFilter"])

	scene := s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: "node:1"})
	assert.NotContains(t, graphVertices(scene), "node:2", "visibility comes from the real policy")

	// State.SetPolicy refuses a document that cannot compile; accept it here
	// to reach the failed-compile cell the scene reports.
	_, err := w.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["nohost"],"dst":["*:*"]}]}`),
		func(*Snapshot) error { return nil })
	require.NoError(t, err)

	failed := w.snapshot()
	require.Error(t, failed.PolicyErr())
	assert.Equal(t, failed.PolicyErr().Error(), failed.DebugGraph(DebugGraphQuery{Perspective: "core"}).PolicyError)
	assert.Empty(t, s.DebugGraph(DebugGraphQuery{Perspective: "core"}).PolicyError)
}
