package mapper

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/mem"
	"pgregory.net/rapid"
	"tailscale.com/envknob"
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
	stream *Stream
	client *modelClient
	capVer tailcfg.CapabilityVersion
	down   bool
}

type streamPropertySystem struct {
	cfg      *types.Config
	state    *state.State
	hub      *Hub
	sessions map[types.NodeID]*streamPropertySession
	policy   int
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

	hub := NewHub()
	t.Cleanup(hub.Close)

	for i := range 3 {
		_, err := s.CreateUser(types.User{Name: fmt.Sprintf("u%d", i+1)})
		require.NoError(t, err)
	}

	s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}})

	p := &streamPropertySystem{cfg: cfg, state: s, hub: hub, sessions: make(map[types.NodeID]*streamPropertySession)}

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

func (p *streamPropertySystem) insert(t *rapid.T, id types.NodeID) {
	user, err := p.state.GetUserByID(types.UserID(1 + (id-1)%3))
	require.NoError(t, err)

	name := fmt.Sprintf("node-%d", id)

	var raw [32]byte

	raw[0], raw[31] = byte(id), rapid.Byte().Draw(t, "key-byte") //nolint:gosec // IDs are in [1, 8].
	n := types.Node{
		ID: id, UserID: &user.ID, User: user, GivenName: name, Hostname: name,
		NodeKey: key.NodePublicFromRaw32(mem.B(raw[:])), DiscoKey: key.DiscoPublicFromRaw32(mem.B(raw[:])),
		IPv4:      new(netip.AddrFrom4([4]byte{100, 64, 0, byte(id)})), //nolint:gosec // IDs are in [1, 8].
		IPv6:      new(netip.MustParseAddr(fmt.Sprintf("fd7a:115c:a1e0::%x", id.Uint64()))),
		Hostinfo:  &tailcfg.Hostinfo{Hostname: name, OS: "linux"},
		CreatedAt: time.Unix(1_700_000_000, 0).UTC(), IsOnline: new(false),
	}
	// Start with both user-owned classes and a router whose creator is set.
	if id == 3 {
		n.Tags = []string{"tag:a"}
		n.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
		n.ApprovedRoutes = slices.Clone(n.Hostinfo.RoutableIPs)
		n.ActiveSessions, n.IsOnline = 1, new(true)
		n.SessionStart = time.Unix(1_700_000_000, 0).UTC()
	}

	p.state.PutNodeInStoreForTest(n)
}

func (p *streamPropertySystem) setPolicy(t *rapid.T, index int) {
	_, err := p.state.SetPolicy([]byte(streamPropertyPolicies[index]))
	require.NoError(t, err)

	p.policy = index
}

// applyStreamPropertyWire crosses the real encoder boundary. Removal frames
// must stand alone, so even old delta-only consumers receive revocations.
func applyStreamPropertyWire(t *rapid.T, client *modelClient, responses []*tailcfg.MapResponse) {
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

	client := newModelClient(&tailcfg.MapResponse{})
	if previous != nil {
		client = previous.client
		if !previous.down {
			p.hub.Leave(previous.stream.sess)
		}
	}

	session := p.hub.Join(id, func() {})
	require.NotNil(t, session)

	st := NewStream(p.cfg, p.hub, id, cv)
	st.Attach(session)
	responses, err := st.Initial(snap)
	require.NoError(t, err)

	if partial {
		applyStreamPropertyWire(t, client, responses[:rapid.IntRange(0, len(responses)).Draw(t, "initial-prefix")])
		p.hub.Leave(session)
	} else {
		applyStreamPropertyWire(t, client, responses)
		st.Delivered()
	}

	p.sessions[id] = &streamPropertySession{stream: st, client: client, capVer: cv, down: partial}
}

func (p *streamPropertySystem) update(t *rapid.T, id types.NodeID, snap *state.Snapshot, mode int) {
	session := p.sessions[id]
	responses, err := session.stream.Update(snap)
	require.NoError(t, err)

	switch mode {
	case 1: // An unconfirmed prefix may have reached the client.
		applyStreamPropertyWire(t, session.client, responses[:rapid.IntRange(0, len(responses)).Draw(t, "update-prefix")])
		p.hub.Leave(session.stream.sess)
		session.down = true
	case 2: // An obsolete write confirmation must not replace new history.
		stale := session.stream

		p.open(t, id, snap, false)
		stale.Delivered()
	default:
		applyStreamPropertyWire(t, session.client, responses)
		session.stream.Delivered()
		quiet, err := session.stream.Update(snap)
		require.NoError(t, err)
		require.Empty(t, quiet, "same snapshot must be quiet")
	}
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

		fresh := newModelClient(&tailcfg.MapResponse{})
		applyStreamPropertyWire(t, fresh, responses)
		require.Empty(t, session.client.sameAs(fresh), "viewer %d revision %d", id, snap.Rev())
		require.Len(t, session.client.deltaPeers, len(fresh.peers), "delta-only observer retained a removed peer")

		for peer := range fresh.peers {
			require.True(t, session.client.deltaPeers[peer], "delta-only observer missed peer %d", peer)
		}

		self, ok := snap.GetNode(id)
		require.True(t, ok)

		for _, peer := range snap.ListNodes().All() {
			if peer.ID() == id {
				continue
			}

			wire, visible := fresh.peers[peer.ID().NodeID()]
			// Same-user visibility is unconditional; tags never confer a
			// creator's ownership, including when UserID remains populated.
			if p.policy <= 2 {
				want := p.policy == 0 || (!self.IsTagged() && !peer.IsTagged() && self.TypedUserID() == peer.TypedUserID())
				require.Equal(t, want, visible, "policy %d: viewer %d peer %d", p.policy, id, peer.ID())
			}

			if visible && peer.IsTagged() {
				require.Equal(t, tailcfg.UserID(types.TaggedDevicesUserID), wire.User)
			}
		}
	}
}

// write draws real operations and their values, rather than a seed for another
// PRNG. Every target is live; add/delete are enabled only when they can act.
//
//nolint:gocyclo // Each switch case is one independently generated world operation.
func (p *streamPropertySystem) write(t *rapid.T) {
	nodes := p.state.ListNodes()
	nv := nodes.At(rapid.IntRange(0, nodes.Len()-1).Draw(t, "node"))
	n := nv.AsStruct()

	operations := []string{"endpoints", "hostinfo", "keys", "expiry", "online", "identity", "routes", "health", "policy", "user", "dns", "derp", "noop", "revert"}
	if nodes.Len() > 3 {
		operations = append(operations, "delete")
	}

	if nodes.Len() < 8 {
		operations = append(operations, "add")
	}

	op := rapid.SampledFrom(operations).Draw(t, "operation")
	switch op {
	case "endpoints", "revert":
		n.Endpoints = nil
		for range rapid.IntRange(0, 3).Draw(t, "endpoint-count") {
			n.Endpoints = append(n.Endpoints, netip.AddrPortFrom(
				netip.AddrFrom4([4]byte{192, 0, 2, rapid.ByteRange(1, 254).Draw(t, "endpoint-ip")}),
				rapid.Uint16().Draw(t, "endpoint-port")))
		}

		p.state.PutNodeInStoreForTest(*n)

		if op == "revert" {
			p.state.PutNodeInStoreForTest(*nv.AsStruct())
		}
	case "hostinfo":
		n.Hostinfo.OS = rapid.SampledFrom([]string{"linux", "windows", "android", ""}).Draw(t, "os")
		n.Hostinfo.Hostname = fmt.Sprintf("reported-%d", rapid.IntRange(0, 10).Draw(t, "hostname"))
		n.Hostinfo.NetInfo = &tailcfg.NetInfo{PreferredDERP: tailcfg.DERPRegionID(rapid.IntRange(0, 3).Draw(t, "home-derp"))}

		n.Hostinfo.Services = nil
		if rapid.Bool().Draw(t, "service") {
			n.Hostinfo.Services = []tailcfg.Service{{Proto: "tcp", Port: rapid.Uint16().Draw(t, "service-port")}}
		}

		p.state.PutNodeInStoreForTest(*n)
	case "keys":
		var raw [32]byte
		copy(raw[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "node-key"))
		raw[0] |= 1 // Registered nodes cannot have a zero node key.
		n.NodeKey = key.NodePublicFromRaw32(mem.B(raw[:]))

		var disco [32]byte
		if !rapid.Bool().Draw(t, "zero-disco") {
			copy(disco[:], rapid.SliceOfN(rapid.Byte(), 32, 32).Draw(t, "disco-key"))
		}

		n.DiscoKey = key.DiscoPublicFromRaw32(mem.B(disco[:]))
		p.state.PutNodeInStoreForTest(*n)
	case "expiry":
		// Fixed distant dates make shrinking independent of wall time.
		n.Expiry = rapid.SampledFrom([]*time.Time{nil, new(time.Time{}), new(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)), new(time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC))}).Draw(t, "expiry")
		n.IsOnline = new(n.ShouldBeOnline())
		p.state.PutNodeInStoreForTest(*n)
	case "online":
		n.ActiveSessions = 1 - n.ActiveSessions
		n.IsOnline = new(n.ShouldBeOnline())
		n.LastSeen = new(time.Unix(1_700_000_000+rapid.Int64Range(0, 1000).Draw(t, "last-seen"), 0).UTC())
		n.SessionStart = time.Unix(1_700_000_000+int64(n.ID), 0).UTC() //nolint:gosec // IDs are in [1, 8].
		p.state.PutNodeInStoreForTest(*n)
	case "identity":
		user, err := p.state.GetUserByID(types.UserID(rapid.Uint64Range(1, 3).Draw(t, "owner")))
		require.NoError(t, err)

		n.UserID, n.User = &user.ID, user

		n.Tags = rapid.SampledFrom([]types.Strings{nil, {"tag:a"}, {"tag:b"}, {"tag:a", "tag:b"}}).Draw(t, "tags")
		if len(n.Tags) > 0 && rapid.Bool().Draw(t, "clear-creator") {
			n.UserID, n.User = nil, nil
		}

		p.state.PutNodeInStoreForTest(*n)
	case "routes":
		routes := rapid.SampledFrom([][]netip.Prefix{
			nil,
			{netip.MustParsePrefix("10.0.0.0/24")},
			{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")},
			{netip.MustParsePrefix("10.0.0.0/24"), netip.MustParsePrefix("10.1.0.0/24")},
		}).Draw(t, "routes")
		n.Hostinfo.RoutableIPs = slices.Clone(routes)

		n.ApprovedRoutes = nil
		if rapid.Bool().Draw(t, "approve") {
			n.ApprovedRoutes = slices.Clone(routes)
		}

		p.state.PutNodeInStoreForTest(*n)
	case "health":
		n.Unhealthy = !n.Unhealthy
		p.state.PutNodeInStoreForTest(*n)
	case "policy":
		// Always change the policy, including reversions to earlier ones.
		next := (p.policy + rapid.IntRange(1, len(streamPropertyPolicies)-1).Draw(t, "policy-offset")) % len(streamPropertyPolicies)
		p.setPolicy(t, next)
	case "user":
		id := types.UserID(rapid.Uint64Range(1, 3).Draw(t, "user"))
		name := rapid.SampledFrom([]string{"", "Renamed", "Display ☃"}).Draw(t, "display-name")
		_, err := p.state.UpdateUser(id, func(user *types.User) error {
			user.DisplayName = name
			if user.Name == fmt.Sprintf("u%d", id) {
				user.Name += "-renamed"
			} else {
				user.Name = fmt.Sprintf("u%d", id)
			}

			return nil
		})
		require.NoError(t, err)
	case "dns":
		var records []tailcfg.DNSRecord
		if rapid.Bool().Draw(t, "dns-record") {
			records = []tailcfg.DNSRecord{{Name: fmt.Sprintf("extra-%d.headscale.test", rapid.IntRange(0, 3).Draw(t, "dns-name")), Type: "A", Value: "192.0.2.1"}}
		}

		p.state.SetExtraRecords(records)
	case "derp":
		regions := make(map[tailcfg.DERPRegionID]*tailcfg.DERPRegion)

		for i := range rapid.IntRange(0, 3).Draw(t, "derp-count") {
			id := tailcfg.DERPRegionID(i + 1)
			regions[id] = &tailcfg.DERPRegion{RegionID: id, RegionName: fmt.Sprintf("region-%d", rapid.IntRange(0, 3).Draw(t, "derp-name"))}
		}

		p.state.SetDERPMap(&tailcfg.DERPMap{Regions: regions})
	case "delete":
		p.state.DeleteNodeFromStoreForTest(n.ID)
		p.hub.forget(n.ID)

		if session := p.sessions[n.ID]; session != nil {
			_, err := session.stream.Update(p.state.Snapshot())
			require.ErrorIs(t, err, ErrNodeGone)
		}

		delete(p.sessions, n.ID)
	case "add":
		var absent []types.NodeID

		for id := types.NodeID(1); id <= 8; id++ {
			if _, ok := p.state.GetNodeByID(id); !ok {
				absent = append(absent, id)
			}
		}

		id := rapid.SampledFrom(absent).Draw(t, "insert-id")
		p.insert(t, id)
		p.open(t, id, p.state.Snapshot(), false)
	case "noop":
		p.state.PutNodeInStoreForTest(*n)
	}
}

// TestRapidStreamSystem checks the entire world/policy/Route/render/diff/wire
// path. Only Route's viewers receive updates; every other active viewer must
// already equal an independent fresh stream. Rapid's default case and step
// budgets bound CI work; -rapid.checks, -rapid.steps and -rapid.seed drive campaigns.
func TestRapidStreamSystem(t *testing.T) {
	envknob.SetenvForTest(t, "HEADSCALE_DEBUG_POLICY_AUDIT", "true")
	rapid.Check(t, func(t *rapid.T) {
		audits := state.PolicyAuditFailures()
		p := newStreamPropertySystem(t)
		last := p.state.Snapshot()
		p.check(t, last)
		t.Repeat(map[string]func(*rapid.T){"commit": func(t *rapid.T) {
			// Keep an old snapshot and its wire model across writes and
			// cache advancement; a late renderer must still read it correctly.
			old := p.state.Snapshot()
			oldNode := old.ListNodes().At(0).ID()
			oldHub := NewHub()
			oldMap, err := NewStream(p.cfg, oldHub, oldNode, capVer).r.render(old)
			oldHub.Close()
			require.NoError(t, err)

			oldClient := newModelClient(&tailcfg.MapResponse{})
			applyStreamPropertyWire(t, oldClient, []*tailcfg.MapResponse{fullResponse(p.cfg, oldMap)})

			for range rapid.IntRange(1, 3).Draw(t, "coalesced-writes") {
				p.write(t)

				if rapid.Bool().Draw(t, "intermediate-render") {
					id := rapid.SampledFrom(slices.Sorted(maps.Keys(p.sessions))).Draw(t, "intermediate-viewer")

					session := p.sessions[id]
					if session.down {
						p.open(t, id, p.state.Snapshot(), rapid.Bool().Draw(t, "partial-reconnect"))
					} else {
						p.update(t, id, p.state.Snapshot(), 0)
					}
				}
			}

			snap := p.state.Snapshot()
			all, wake := Route(last, snap, snap.Since(last))
			p.hub.advance(snap)

			for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
				session := p.sessions[id]
				if session.down {
					if rapid.Bool().Draw(t, "reconnect") {
						p.open(t, id, snap, rapid.Bool().Draw(t, "partial-reconnect"))
					}
				} else if _, named := wake[id]; all || named {
					p.update(t, id, snap, rapid.IntRange(0, 5).Draw(t, "delivery"))
				}
			}

			p.check(t, snap)
			lateMap, err := NewStream(p.cfg, p.hub, oldNode, capVer).r.render(old)
			require.NoError(t, err)

			lateClient := newModelClient(&tailcfg.MapResponse{})
			applyStreamPropertyWire(t, lateClient, []*tailcfg.MapResponse{fullResponse(p.cfg, lateMap)})
			require.Empty(t, lateClient.sameAs(oldClient), "retained snapshot changed after writes/cache advancement")

			last = snap
		}})

		for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
			if p.sessions[id].down {
				p.open(t, id, p.state.Snapshot(), false)
			}
		}

		p.check(t, p.state.Snapshot())
		require.Equal(t, audits, state.PolicyAuditFailures(), "incremental policy disagreed with full compile")
	})
}

// Guard the reusable replay model's two less common patch fields without
// claiming the system generator can create a node's KeySignature in State.
func TestRapidStreamModelPatchFields(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		capability := tailcfg.CapabilityVersion(rapid.IntRange(1, 200).Draw(t, "cap"))
		signature := rapid.SliceOfN(rapid.Byte(), 1, 64).Draw(t, "signature")
		client := newModelClient(&tailcfg.MapResponse{Peers: []*tailcfg.Node{{ID: 2}}})
		applyStreamPropertyWire(t, client, []*tailcfg.MapResponse{{PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 2, Cap: capability, KeySignature: signature}}}})
		require.Equal(t, capability, client.peers[2].Cap)
		require.True(t, slices.Equal(signature, client.peers[2].KeySignature))
	})
}

// The route oracle needs no policy compiler: with two approved routers and
// exactly one healthy online router, that router must carry the subnet. Run
// both ordinary grants and via grants, then withdraw and restore approvals.
func TestRapidStreamRouteFailover(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := newStreamPropertySystem(t)
		last := p.state.Snapshot()
		route := netip.MustParsePrefix("10.0.0.0/24")

		via := ""
		if rapid.Bool().Draw(t, "via") {
			via = `,"via":["tag:a"]`
		}

		_, err := p.state.SetPolicy([]byte(`{"tagOwners":{"tag:a":["u1@"]},"grants":[{"src":["u1@"],"dst":["10.0.0.0/24"],"ip":["*"]` + via + `}]}`))
		require.NoError(t, err)

		p.policy = 3 // This property's route oracle replaces the simple-policy oracle.
		winner := rapid.SampledFrom([]types.NodeID{2, 3}).Draw(t, "healthy-router")

		for _, id := range []types.NodeID{2, 3} {
			n, ok := p.state.GetNodeByID(id)
			require.True(t, ok)

			router := n.AsStruct()
			router.Tags = []string{"tag:a"}
			router.Hostinfo.RoutableIPs = []netip.Prefix{route}
			router.ApprovedRoutes = []netip.Prefix{route}
			router.ActiveSessions, router.IsOnline = 1, new(true)
			router.Unhealthy = id != winner
			router.SessionStart = time.Unix(1_700_000_000+int64(id), 0).UTC() //nolint:gosec // Router IDs are 2 and 3.
			p.state.PutNodeInStoreForTest(*router)
		}

		for phase := range 4 {
			if phase == 1 {
				winner = 5 - winner
			}

			if phase > 0 {
				for _, id := range []types.NodeID{2, 3} {
					n, ok := p.state.GetNodeByID(id)
					require.True(t, ok)

					router := n.AsStruct()
					router.Unhealthy = id != winner

					router.ApprovedRoutes = []netip.Prefix{route}
					if phase == 2 {
						router.ApprovedRoutes = nil
					}

					p.state.PutNodeInStoreForTest(*router)
				}
			}

			snap := p.state.Snapshot()
			all, wake := Route(last, snap, snap.Since(last))
			p.hub.advance(snap)

			for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
				if _, named := wake[id]; all || named {
					p.update(t, id, snap, 0)
				}
			}

			p.check(t, snap)

			for _, id := range []types.NodeID{2, 3} {
				peer := p.sessions[1].client.peers[id.NodeID()]

				want := phase != 2 && id == winner
				if want {
					require.NotNil(t, peer, "healthy router must be visible")
				}

				if peer != nil {
					require.Equal(t, want, slices.Contains(peer.AllowedIPs, route), "phase %d router %d", phase, id)
					require.Equal(t, want, slices.Contains(peer.PrimaryRoutes, route), "phase %d router %d", phase, id)
				}
			}

			last = snap
		}
	})
}

// Visibility changes must revoke peers through deltas as well as full maps;
// reconnecting clients retain profiles, but never learn a hidden owner.
func TestRapidStreamVisibilityTransitions(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := newStreamPropertySystem(t)

		last := p.state.Snapshot()
		for _, policy := range []int{0, 1, 0, 2} {
			p.setPolicy(t, policy)
			snap := p.state.Snapshot()
			all, wake := Route(last, snap, snap.Since(last))
			p.hub.advance(snap)

			for _, id := range slices.Sorted(maps.Keys(p.sessions)) {
				if _, named := wake[id]; all || named {
					p.update(t, id, snap, 0)
				}
			}

			p.check(t, snap)
			id := rapid.SampledFrom(slices.Sorted(maps.Keys(p.sessions))).Draw(t, "reconnecting-viewer")
			p.open(t, id, snap, false)
			p.check(t, snap)
			last = snap
		}
	})
}
