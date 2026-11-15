package mapper

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/internal/propcheck"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/mem"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// These policies have deliberately different visibility, route and capability
// effects. The first three also have a small, independent visibility oracle.
var streamPropertyPolicies = []string{
	`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	`{"acls":[]}`,
	`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
	`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u2@"]},
	  "acls":[{"action":"accept","src":["u1@"],"dst":["tag:a:*","10.0.0.0/24:*"]}],
	  "ssh":[{"action":"accept","src":["u2@"],"dst":["tag:b"],"users":["root"]}]}`,
	`{"tagOwners":{"tag:a":["u1@"],"tag:b":["u2@"]},
	  "grants":[{"src":["u1@","u2@"],"dst":["10.0.0.0/24"],"ip":["*"],"via":["tag:a"]},
	            {"src":["*"],"dst":["*"],"ip":["*"]}]}`,
	`{"nodeAttrs":[{"target":["u1@"],"attr":["disable-ipv4"]}],
	  "acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	`{"acls":[{"action":"accept","src":["u2@"],"dst":["autogroup:internet:*"]}]}`,
}

var streamPropertyVersions = []tailcfg.CapabilityVersion{
	capver.MinSupportedCapabilityVersion,
	capver.FullNetmapRemovalsCapVer - 1,
	capver.FullNetmapRemovalsCapVer,
	tailcfg.CurrentCapabilityVersion,
}

type streamPropertySession struct {
	stream     *Stream
	client     *propertyClient
	capVer     tailcfg.CapabilityVersion
	down       bool
	token      uint64
	ids        []types.NodeID
	pendingRev uint64
	pending    bool
}

type streamPropertySystem struct {
	dnsRecords []tailcfg.DNSRecord
	viaOnly    bool
	cfg        *types.Config
	state      *state.State
	hub        *Hub
	sessions   map[types.NodeID]*streamPropertySession
	policy     int
	policyDoc  []byte
	policies   [][]byte
	world      propcheck.World
	probes     propcheck.WorldProbes
	routes     propcheck.RouteResult
	history    *peerHistoryModel
	token      uint64
	reportSeq  uint64
}

// newStreamPropertySystem owns resources per Rapid case, including shrink
// attempts. No assertion or Cleanup escapes to the outer testing.T.
func newStreamPropertySystem(t *rapid.T) *streamPropertySystem {
	dir, err := os.MkdirTemp("", "mapper-property-")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, os.RemoveAll(dir)) })

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database:  types.DatabaseConfig{Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: dir + "/h.db"}},
		ServerURL: "https://headscale.test",
		Policy:    types.PolicyConfig{Mode: types.PolicyModeDB},
		Prefixes:  types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential},
		DNSConfig: types.DNSConfig{BaseDomain: "headscale.test", MagicDNS: true},
	}
	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })

	s.DB().DB.NowFunc = func() time.Time { return propertyEpoch }
	hub := NewHub()
	hub.now = func() time.Time { return propertyEpoch }
	t.Cleanup(hub.Close)

	p := &streamPropertySystem{
		cfg: cfg, state: s, hub: hub, sessions: make(map[types.NodeID]*streamPropertySession),
		world:   propcheck.World{Nodes: map[types.NodeID]*types.Node{}},
		history: newPeerHistoryModel(maxConcurrentMapSessionsPerNode, peerHistoryTTL),
		probes:  propcheck.WorldProbes{IDs: []types.NodeID{1, 2, 3, 4, 5, 6, 7, 8}, UserIDs: []types.UserID{0, 1, 2, 3}},
	}

	for i := range 3 {
		u := types.User{ID: uint(i + 1), Name: fmt.Sprintf("u%d", i+1), CreatedAt: propertyEpoch, UpdatedAt: propertyEpoch}
		got, err := s.CreateUser(u)
		require.NoError(t, err)
		require.Equal(t, u, *got)
		p.world.Users = append(p.world.Users, u)
	}

	s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}})

	count := rapid.IntRange(3, 8).Draw(t, "nodes")
	for i := range count {
		p.insert(t, types.NodeID(i+1))
	}

	p.setPolicy(t, rapid.IntRange(0, len(streamPropertyPolicies)-1).Draw(t, "initial-policy"))

	for _, node := range s.ListNodes().All() {
		p.open(t, node.ID(), s.Snapshot(), false)
	}

	return p
}

var propertyEpoch = time.Unix(1_700_000_000, 0).UTC()

func (p *streamPropertySystem) drawNode(t *rapid.T, id types.NodeID) *types.Node {
	user := p.world.Users[(id-1)%3].Clone()

	name := fmt.Sprintf("node-%d", id)

	var raw [32]byte

	raw[0], raw[31] = byte(id), rapid.Byte().Draw(t, "key-byte") //nolint:gosec // IDs are in [1, 8].
	n := types.Node{
		ID: id, UserID: &user.ID, User: user, GivenName: name, Hostname: name,
		MachineKey: key.MachinePublicFromRaw32(mem.B(raw[:])),
		NodeKey:    key.NodePublicFromRaw32(mem.B(raw[:])), DiscoKey: key.DiscoPublicFromRaw32(mem.B(raw[:])),
		IPv4:      new(netip.AddrFrom4([4]byte{100, 64, 0, byte(id)})), //nolint:gosec // IDs are in [1, 8].
		IPv6:      new(netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%x", id.Uint64()))),
		Hostinfo:  &tailcfg.Hostinfo{Hostname: name, OS: "linux"},
		CreatedAt: propertyEpoch, UpdatedAt: propertyEpoch, IsOnline: new(false),
	}
	// Start with both user-owned classes and a router whose creator is set.
	if id == 3 {
		n.Tags = []string{"tag:a", "tag:srv", "tag:router"}
		n.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
		n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
		n.ActiveSessions, n.IsOnline = 1, new(true)
		n.SessionStart = time.Unix(1_700_000_000, 0).UTC()
	}

	return &n
}

func (p *streamPropertySystem) insert(t *rapid.T, id types.NodeID) {
	n := p.drawNode(t, id)
	p.create(t, n)
}

func (p *streamPropertySystem) create(t *rapid.T, n *types.Node) {
	require.NoError(t, p.state.DB().DB.Save(n.Clone()).Error)
	p.put(t, n)
}

func (p *streamPropertySystem) put(t *rapid.T, n *types.Node) {
	p.world.Put(n)
	p.state.PutNodeInStoreForTest(*n.Clone())
	p.checkWorld(t)
}

func (p *streamPropertySystem) setPolicy(t *rapid.T, index int) {
	_, err := p.state.SetPolicy([]byte(streamPropertyPolicies[index]))
	require.NoError(t, err)

	p.policy = index
	p.policyDoc = []byte(streamPropertyPolicies[index])
	p.policies = append(p.policies, slices.Clone(p.policyDoc))
	p.checkWorld(t)
}

// applyStreamPropertyWire crosses the real encoder boundary. Removal frames
// must stand alone, so even old delta-only consumers receive revocations.
func applyStreamPropertyWire(t *rapid.T, client *propertyClient, responses []*tailcfg.MapResponse) {
	for _, response := range responses {
		data, err := Marshal(response)
		require.NoError(t, err)
		standard, err := json.Marshal(response)
		require.NoError(t, err)
		require.JSONEq(t, string(standard), string(data), "cached encoding changed the response")

		var wire tailcfg.MapResponse
		require.NoError(t, json.Unmarshal(data, &wire))

		if len(wire.PeersRemoved) != 0 {
			without := wire
			without.PeersRemoved, without.ControlTime = nil, nil
			require.Equal(t, tailcfg.MapResponse{}, without, "removals must be delta-only")
			require.True(t, slices.IsSorted(wire.PeersRemoved))
		}

		for _, peers := range [][]*tailcfg.Node{wire.Peers, wire.PeersChanged} {
			for i, peer := range peers {
				if client.self != nil {
					require.NotEqual(t, client.self.ID, peer.ID, "self leaked into peers")
				}

				if i > 0 {
					require.Less(t, peers[i-1].ID, peer.ID, "peers must be sorted and unique")
				}
			}
		}

		client.apply(&wire)

		if client.self != nil {
			require.NotContains(t, client.peers, client.self.ID, "self leaked into the initial peer list")

			for _, patch := range wire.PeersChangedPatch {
				require.NotEqual(t, client.self.ID, patch.NodeID, "self leaked into peer patches")
			}
		}

		require.Zero(t, client.unseenProfile(), "profile of an owner never visible to the client")
	}
}

func (p *streamPropertySystem) open(t *rapid.T, id types.NodeID, snap *state.Snapshot, partial bool) {
	previous := p.sessions[id]
	cv := rapid.SampledFrom(streamPropertyVersions).Draw(t, "cap-version")

	client := newPropertyClient(&tailcfg.MapResponse{})
	if previous != nil {
		client = previous.client
		if !previous.down {
			p.hub.Leave(previous.stream.sess)
			p.history.Leave(previous.token, propertyEpoch)
		}
	}

	p.token++
	token := p.token
	require.Empty(t, p.history.Join(token, id, propertyEpoch))
	session := p.hub.Join(id, func() {})
	require.NotNil(t, session)

	st := NewStream(p.cfg, p.hub, id, cv)
	st.Attach(session)
	responses, err := st.Initial(snap)
	require.NoError(t, err)

	ids := p.expectedPeers(t, id, snap, cv)
	p.history.Attempt(token, snap.Rev(), ids)

	if partial {
		applyStreamPropertyWire(t, client, responses[:rapid.IntRange(0, len(responses)).Draw(t, "initial-prefix")])
		p.hub.Leave(session)
		p.history.Leave(token, propertyEpoch)
	} else {
		applyStreamPropertyWire(t, client, responses)
		st.Delivered()
		p.history.Delivered(token, snap.Rev(), ids)
	}

	p.sessions[id] = &streamPropertySession{stream: st, client: client, capVer: cv, down: partial, token: token, ids: ids}
	p.checkHistory(t)
}

func (p *streamPropertySystem) update(t *rapid.T, id types.NodeID, snap *state.Snapshot, mode int) {
	session := p.sessions[id]
	responses, err := session.stream.Update(snap)
	require.NoError(t, err)

	ids := p.expectedPeers(t, id, snap, session.capVer)
	if len(responses) > 0 && !slices.Equal(session.ids, ids) {
		session.pending, session.pendingRev = true, snap.Rev()
		p.history.Attempt(session.token, snap.Rev(), ids)
	}

	session.ids = ids

	switch mode {
	case 1: // An unconfirmed prefix may have reached the client.
		applyStreamPropertyWire(t, session.client, responses[:rapid.IntRange(0, len(responses)).Draw(t, "update-prefix")])
		p.hub.Leave(session.stream.sess)
		p.history.Leave(session.token, propertyEpoch)
		session.down = true
	case 2: // An obsolete write confirmation must not replace new history.
		stale := session.stream

		p.open(t, id, snap, false)
		stale.Delivered()

		if session.pending {
			p.history.Delivered(session.token, session.pendingRev, session.ids)
		}
	default:
		applyStreamPropertyWire(t, session.client, responses)
		session.stream.Delivered()

		if session.pending {
			p.history.Delivered(session.token, session.pendingRev, session.ids)
			session.pending = false
		}

		quiet, err := session.stream.Update(snap)
		require.NoError(t, err)
		require.Empty(t, quiet, "same snapshot must be quiet")
	}

	p.checkHistory(t)
}

func (p *streamPropertySystem) check(t *rapid.T, snap *state.Snapshot) {
	for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
		session := p.sessions[id]
		if session.down {
			continue
		}

		freshHub := NewHub()
		responses, err := NewStream(p.cfg, freshHub, id, session.capVer).Initial(snap)
		freshHub.Close()
		require.NoError(t, err)

		fresh := newPropertyClient(&tailcfg.MapResponse{})
		applyStreamPropertyWire(t, fresh, responses)
		session.client.check(t, fresh)
		require.Len(t, session.client.deltaPeers, len(fresh.peers), "delta-only observer retained a removed peer")

		for peer := range fresh.peers {
			require.True(t, session.client.deltaPeers[peer], "delta-only observer missed peer %d", peer)
		}

		self := p.world.Nodes[id]
		require.NotNil(t, self)

		for _, peerID := range slices.Sorted(maps.Keys(p.world.Nodes)) {
			peer := p.world.Nodes[peerID]
			if peer.ID == id {
				continue
			}

			wire, visible := session.client.peers[peer.ID.NodeID()]
			// Same-user visibility is unconditional; tags never confer a
			// creator's ownership, including when UserID remains populated.
			if p.policy >= 0 && p.policy <= 2 {
				want := p.policy == 0 || (len(self.Tags) == 0 && len(peer.Tags) == 0 && self.UserID != nil && peer.UserID != nil && *self.UserID == *peer.UserID)
				require.Equal(t, want, visible, "policy %d: viewer %d peer %d", p.policy, id, peer.ID)
			}

			if visible {
				require.Equal(t, peer.NodeKey, wire.Key, "peer identity")
				require.Equal(t, peer.DiscoKey, wire.DiscoKey, "peer discovery key")
				require.True(t, slices.Equal([]string(peer.Tags), wire.Tags), "peer tags")

				owner := tailcfg.UserID(types.TaggedDevicesUserID)
				if len(peer.Tags) == 0 && peer.UserID != nil {
					owner = tailcfg.UserID(*peer.UserID) //nolint:gosec // Fixture user IDs are 1..3.
				}

				require.Equal(t, owner, wire.User, "peer ownership")

				if p.policy == 0 {
					var primaries []netip.Prefix

					for prefix, winner := range p.routes.Global {
						if winner == uint64(peer.ID) {
							primaries = append(primaries, prefix)
						}
					}

					require.ElementsMatch(t, primaries, wire.PrimaryRoutes, "independent primary routes")

					allowed := []netip.Prefix{netip.PrefixFrom(*peer.IPv4, 32), netip.PrefixFrom(*peer.IPv6, 128)}
					allowed = append(allowed, primaries...)

					for _, prefix := range propertyApproved(peer) {
						if prefix.Bits() == 0 {
							allowed = append(allowed, prefix)
						}
					}

					require.ElementsMatch(t, allowed, wire.AllowedIPs, "independent allowed routes")
				}
			}
		}
	}
}

// checkWorld reuses the exact scan assertions used by the focused state property.
// Probes retain old keys as well as current ones to catch stale index entries.
func (p *streamPropertySystem) checkWorld(t *rapid.T) {
	for _, id := range slices.Sorted(maps.Keys(p.world.Nodes)) {
		n := p.world.Nodes[id]
		if !slices.Contains(p.probes.NodeKeys, n.NodeKey) {
			p.probes.NodeKeys = append(p.probes.NodeKeys, n.NodeKey)
		}

		if !slices.Contains(p.probes.MachineKeys, n.MachineKey) {
			p.probes.MachineKeys = append(p.probes.MachineKeys, n.MachineKey)
		}
	}

	snap := p.state.Snapshot()
	propcheck.CheckWorld(t, p.world, snap, p.probes)
	require.True(t, slices.Equal(p.dnsRecords, snap.DNS().ExtraRecords().AsSlice()), "DNS reference")
	require.Equal(t, string(p.policyDoc), string(snap.PolicySource()), "published policy input")

	nodes := make([]propcheck.RouteNode, 0, len(p.world.Nodes))
	for _, n := range p.world.Nodes {
		nodes = append(nodes, propcheck.RouteNode{
			ID: uint64(n.ID), Online: n.ActiveSessions > 0,
			Expired: propertyExpired(n), Unhealthy: n.Unhealthy, SessionStart: n.SessionStart,
			Announced: n.Hostinfo.RoutableIPs, Approved: n.ApprovedRoutes, Tags: n.Tags,
		})
	}

	var scopes []propcheck.ViaScope

	if p.policy == 4 || p.viaOnly {
		var candidates []uint64

		for _, n := range p.world.Nodes {
			if slices.Contains(n.Tags, "tag:a") {
				candidates = append(candidates, uint64(n.ID))
			}
		}

		scopes = []propcheck.ViaScope{{Key: "tag:a", Prefix: netip.MustParsePrefix("10.0.0.0/24"), Candidates: candidates}}
	}

	p.routes = propcheck.ElectRoutes(nodes, p.routes.Global, scopes)

	want := map[netip.Prefix]types.NodeID{}
	for prefix, id := range p.routes.Global {
		want[prefix] = types.NodeID(id)
	}

	require.Equal(t, want, snap.PrimaryRoutes(), "independent election after each write")
}

// Generated expiry dates are deliberately outside the campaign's time range.
func propertyExpired(n *types.Node) bool {
	return n.Expiry != nil && !n.Expiry.IsZero() && n.Expiry.Year() < 2020
}

func propertyPeerIDs(peers []*tailcfg.Node) []types.NodeID {
	ids := make([]types.NodeID, 0, len(peers))
	for _, peer := range peers {
		ids = append(ids, types.NodeID(peer.ID)) //nolint:gosec // Fixture node IDs are 1..8.
	}

	slices.Sort(ids)

	return ids
}

func (p *streamPropertySystem) checkHistory(t *rapid.T) {
	for _, id := range p.probes.IDs {
		want := p.history.Possible(id)
		p.hub.mu.Lock()
		actual, exists := p.hub.sentPeers[id]

		got := slices.Clone(actual.ids)
		for _, attempted := range actual.attempts {
			got = append(got, attempted...)
		}
		p.hub.mu.Unlock()
		slices.Sort(got)
		got = slices.Compact(got)
		// Shared class views may contain self; it is never a possible wire peer.
		got = slices.DeleteFunc(got, func(peer types.NodeID) bool { return peer == id })

		require.Equal(t, p.history.HasHistory(id), exists, "history existence for %d", id)
		require.True(t, slices.Equal(want, got), "history for %d: want %v got %v", id, want, got)
	}

	for _, session := range p.sessions {
		require.Equal(t, !session.down, p.history.Live(session.token))
	}
}

// expectedPeers uses input intent for the three simple policies. Rich policies
// use a separate fresh renderer as a secondary oracle, never the live stream's
// sent state. The ledger itself only sees intended write events and peer sets.
func (p *streamPropertySystem) expectedPeers(t *rapid.T, viewer types.NodeID, snap *state.Snapshot, version tailcfg.CapabilityVersion) []types.NodeID {
	if p.policy >= 0 && p.policy <= 2 {
		var peers []types.NodeID

		self := p.world.Nodes[viewer]
		for _, id := range slices.Sorted(maps.Keys(p.world.Nodes)) {
			peer := p.world.Nodes[id]
			if id != viewer && (p.policy == 0 || len(self.Tags) == 0 && len(peer.Tags) == 0 && self.UserID != nil && peer.UserID != nil && *self.UserID == *peer.UserID) {
				peers = append(peers, id)
			}
		}

		return peers
	}

	hub := NewHub()
	responses, err := NewStream(p.cfg, hub, viewer, version).Initial(snap)
	hub.Close()
	require.NoError(t, err)

	return propertyPeerIDs(responses[0].Peers)
}
