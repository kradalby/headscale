package mapper

import (
	"encoding/json"
	"maps"
	"reflect"
	"slices"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/util/zstdframe"
)

// wirePeers models the peer state in Tailscale f7c1b8e52600's
// control/controlclient/map.go: upgradeNode, peerChangeDiff and
// updatePeersStateFromResponse. In particular, PeersChanged is NOT always
// replacement: the client first converts eligible entries to in-memory patches.
// Keep this independent of peerPatch, needsPeerListRefresh and modelClient.
type wirePeers map[tailcfg.NodeID]*tailcfg.Node

func (peers wirePeers) apply(resp *tailcfg.MapResponse) {
	if len(resp.Peers) > 0 {
		clear(peers)

		for _, n := range resp.Peers {
			peers[n.ID] = wireUpgrade(n)
		}

		return
	}

	// Patchification happens before removal in the client.
	patches := slices.Clone(resp.PeersChangedPatch)

	var replacements []*tailcfg.Node

	for _, n := range resp.PeersChanged {
		n = wireUpgrade(n)
		if before := peers[n.ID]; before != nil && wirePatchable(before, n) {
			p := &tailcfg.PeerChange{
				NodeID: n.ID, DERPRegion: n.HomeDERP, Cap: n.Cap,
				Endpoints: n.Endpoints, Key: &n.Key, DiscoKey: &n.DiscoKey,
				KeyExpiry: &n.KeyExpiry, KeySignature: n.KeySignature,
				CapMap: n.CapMap,
			}
			// An internal patch can clear a map or a zero expiry: it never
			// passes through JSON's omitempty/omitzero a second time.
			if p.CapMap == nil {
				p.CapMap = tailcfg.NodeCapMap{}
			}

			if before.Online != nil && n.Online != nil {
				p.Online = n.Online
			}

			if before.LastSeen != nil && n.LastSeen != nil {
				p.LastSeen = n.LastSeen
			}

			patches = append(patches, p)
		} else {
			replacements = append(replacements, n)
		}
	}

	for _, id := range resp.PeersRemoved {
		delete(peers, id)
	}

	for _, n := range replacements {
		peers[n.ID] = n
	}

	for _, p := range patches {
		n := peers[p.NodeID]
		if n == nil {
			continue
		}

		if p.DERPRegion != 0 {
			n.HomeDERP = p.DERPRegion
		}

		if p.Cap != 0 {
			n.Cap = p.Cap
		}

		if p.Endpoints != nil {
			n.Endpoints = p.Endpoints
		}

		if p.Key != nil {
			n.Key = *p.Key
		}

		if p.DiscoKey != nil {
			n.DiscoKey = *p.DiscoKey
		}

		if p.Online != nil {
			n.Online = p.Online
		}

		if p.LastSeen != nil {
			n.LastSeen = p.LastSeen
		}

		if p.KeyExpiry != nil {
			n.KeyExpiry = *p.KeyExpiry
		}

		if p.KeySignature != nil {
			n.KeySignature = p.KeySignature
		}

		if p.CapMap != nil {
			n.CapMap = p.CapMap
		}
	}
}

func wireUpgrade(n *tailcfg.Node) *tailcfg.Node {
	n = n.Clone()
	if n.AllowedIPs == nil {
		n.AllowedIPs = slices.Clone(n.Addresses)
	}

	return n
}

// All fields outside upstream's patch/ignored sets must compare equal.
// Reflection makes a future Node field conservative instead of dropping it.
// Generated nodes use modern HomeDERP and no legacy DERP string.
func wirePatchable(before, after *tailcfg.Node) bool {
	a, b := reflect.ValueOf(*before), reflect.ValueOf(*after)
	for field := range a.Type().Fields() {
		switch field.Name {
		case "Key", "DiscoKey", "KeyExpiry", "KeySignature", "HomeDERP", "Endpoints", "Cap", "CapMap", "Online", "LastSeen",
			"ComputedName", "ComputedNameWithHost", "computedHostIfDifferent", "DataPlaneAuditLogID", "StableTailnetID", "Capabilities":
			continue
		case "Hostinfo":
			if !before.Hostinfo.Equal(after.Hostinfo) {
				return false
			}
		case "Created":
			if !before.Created.Equal(after.Created) {
				return false
			}
		default:
			x, y := a.FieldByIndex(field.Index), b.FieldByIndex(field.Index)
			if x.Kind() == reflect.Slice && x.Len() == 0 && y.Len() == 0 {
				continue
			}

			if !reflect.DeepEqual(x.Interface(), y.Interface()) {
				return false
			}
		}
	}

	return true
}

func wireDecode(t require.TestingT, resp *tailcfg.MapResponse) *tailcfg.MapResponse {
	return wireRoundTrip(t, nil, resp, false)
}

// wireRoundTrip shares the real session Hub's encoded-frame cache when supplied.
// Standalone model inputs use the same encoder without a Hub cache.
func wireRoundTrip(t require.TestingT, hub *Hub, resp *tailcfg.MapResponse, compress bool) *tailcfg.MapResponse {
	var (
		data []byte
		err  error
	)
	if hub == nil {
		data, err = benchEncode(resp, compress)
	} else {
		data, err = hub.Encode(resp, compress, benchEncode)
	}

	require.NoError(t, err)

	if compress {
		data, err = zstdframe.AppendDecode(nil, data)
		require.NoError(t, err)
	}

	standard, err := json.Marshal(resp)
	require.NoError(t, err)
	require.JSONEq(t, string(standard), string(data), "Hub encoding changed response content")

	var decoded tailcfg.MapResponse
	require.NoError(t, json.Unmarshal(data, &decoded))

	return &decoded
}

func wireJSON(t require.TestingT, v any) any {
	data, err := json.Marshal(v)
	require.NoError(t, err)

	var decoded any
	require.NoError(t, json.Unmarshal(data, &decoded))

	return decoded
}

func wireSemantic(t require.TestingT, peers wirePeers) any {
	cloned := make(wirePeers, len(peers))
	for id, n := range peers {
		n = n.Clone()
		// tailcfg.Node documents LastSeen as stale while Online is true.
		if n.Online != nil && *n.Online {
			n.LastSeen = nil
		}

		cloned[id] = n
	}

	return wireJSON(t, cloned)
}

// propertyClient composes pinned peer replay with the sticky global fields and
// an observer that only learns removals through explicit delta frames.
type propertyClient struct {
	domain          string
	collectServices bool
	filters         map[string][]tailcfg.FilterRule
	self            *tailcfg.Node
	peers           wirePeers
	filter          []tailcfg.FilterRule
	ssh             *tailcfg.SSHPolicy
	dns             *tailcfg.DNSConfig
	derp            *tailcfg.DERPMap
	profiles        map[tailcfg.UserID]tailcfg.UserProfile
	seen            map[tailcfg.UserID]bool
	deltaPeers      map[tailcfg.NodeID]bool
}

func newPropertyClient(full *tailcfg.MapResponse) *propertyClient {
	c := &propertyClient{peers: wirePeers{}, filters: map[string][]tailcfg.FilterRule{}, profiles: map[tailcfg.UserID]tailcfg.UserProfile{}, seen: map[tailcfg.UserID]bool{}, deltaPeers: map[tailcfg.NodeID]bool{}}
	c.apply(full)

	return c
}

func (c *propertyClient) apply(r *tailcfg.MapResponse) {
	if r.Node != nil {
		c.self = wireUpgrade(r.Node)

		c.seen[c.self.User] = true
		if len(c.self.Tags) > 0 {
			c.seen[tailcfg.UserID(types.TaggedDevicesUserID)] = true
		}
	}

	if r.SSHPolicy != nil {
		c.ssh = r.SSHPolicy
	}

	if r.DNSConfig != nil {
		c.dns = r.DNSConfig
	}

	if r.DERPMap != nil {
		dm := r.DERPMap.Clone()
		// The pinned client treats omitted DERP fields as unchanged.
		if previous := c.derp; previous != nil {
			if dm.Regions == nil {
				dm.Regions, dm.OmitDefaultRegions = previous.Regions, previous.OmitDefaultRegions
			}

			if dm.HomeParams == nil {
				dm.HomeParams = previous.HomeParams
			} else if previous.HomeParams != nil && dm.HomeParams.RegionScore == nil {
				dm.HomeParams.RegionScore = previous.HomeParams.RegionScore
			}
		}

		c.derp = dm
	}

	if r.Domain != "" {
		c.domain = r.Domain
	}

	if value, ok := r.CollectServices.Get(); ok {
		c.collectServices = value
	}

	if r.PacketFilter != nil {
		c.filters["base"] = r.PacketFilter
	}

	if value, reset := r.PacketFilters["*"]; reset && value == nil {
		clear(c.filters)
	}

	for name, rules := range r.PacketFilters {
		if name == "*" {
			continue
		}

		if rules == nil {
			delete(c.filters, name)
		} else {
			c.filters[name] = rules
		}
	}

	c.filter = nil
	for _, name := range slices.Sorted(maps.Keys(c.filters)) {
		c.filter = append(c.filter, c.filters[name]...)
	}

	for _, p := range r.UserProfiles {
		c.profiles[p.ID] = p
	}

	for _, p := range slices.Concat(r.Peers, r.PeersChanged) {
		c.deltaPeers[p.ID] = true
	}

	for _, id := range r.PeersRemoved {
		delete(c.deltaPeers, id)
	}

	c.peers.apply(r)

	for _, p := range c.peers {
		c.seen[p.User] = true
	}
}

func (c *propertyClient) unseenProfile() tailcfg.UserID {
	for id := range c.profiles {
		if !c.seen[id] {
			return id
		}
	}

	return 0
}

func (c *propertyClient) check(t require.TestingT, fresh *propertyClient) {
	require.Equal(t, fresh.domain, c.domain, "domain")
	require.Equal(t, fresh.collectServices, c.collectServices, "service collection")
	require.Equal(t, wireSemantic(t, wirePeers{0: fresh.self}), wireSemantic(t, wirePeers{0: c.self}), "self")
	require.Equal(t, wireSemantic(t, fresh.peers), wireSemantic(t, c.peers), "peers")
	require.Equal(t, wireJSON(t, fresh.filter), wireJSON(t, c.filter), "filter")
	require.Equal(t, wireJSON(t, fresh.ssh), wireJSON(t, c.ssh), "SSH")
	require.Equal(t, wireJSON(t, fresh.dns), wireJSON(t, c.dns), "DNS")
	require.Equal(t, wireJSON(t, fresh.derp), wireJSON(t, c.derp), "DERP")

	for id, p := range fresh.profiles {
		require.Equal(t, p, c.profiles[id], "profile %d", id)
	}

	require.Zero(t, c.unseenProfile(), "hidden owner profile")
	require.Len(t, c.deltaPeers, len(fresh.peers), "delta-only observer retained a removed peer")

	for id := range fresh.peers {
		require.True(t, c.deltaPeers[id], "delta-only observer missed peer %d", id)
	}
}

func TestPropertyClientContracts(t *testing.T) {
	before := wirePeer(2)
	client := newPropertyClient(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{before, wirePeer(3)}}))
	// An empty full-list field is a delta, not a reset, in the pinned client.
	client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{}}))
	require.Len(t, client.peers, 2)
	client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{before}}))
	require.Len(t, client.peers, 1)
	require.True(t, client.deltaPeers[3], "full replacement cannot notify delta-only observer")
	client.apply(&tailcfg.MapResponse{PeersRemoved: []tailcfg.NodeID{3}})
	require.NotContains(t, client.deltaPeers, tailcfg.NodeID(3))

	after := before.Clone()
	after.Online, after.LastSeen = new(false), new(propertyEpoch)
	client.apply(wireDecode(t, &tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{after}}))
	require.Nil(t, client.peers[2].LastSeen, "upstream patchification cannot introduce absent LastSeen")
	require.NotEqual(t, wireSemantic(t, wirePeers{2: after}), wireSemantic(t, client.peers), "offline lost fields must remain observable")
	after = after.Clone()
	after.Hostinfo = (&tailcfg.Hostinfo{Hostname: "changed"}).View()
	client.apply(wireDecode(t, &tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{after}}))
	require.Equal(t, after.LastSeen, client.peers[2].LastSeen, "nonpatchable replacement keeps LastSeen")

	client.apply(&tailcfg.MapResponse{PacketFilters: map[string][]tailcfg.FilterRule{"a": {{SrcIPs: []string{"a"}}}, "b": {{SrcIPs: []string{"b"}}}}})
	require.Len(t, client.filter, 2)
	client.apply(&tailcfg.MapResponse{PacketFilters: map[string][]tailcfg.FilterRule{"a": nil}})
	require.Equal(t, "b", client.filter[0].SrcIPs[0])
	client.apply(&tailcfg.MapResponse{PacketFilters: map[string][]tailcfg.FilterRule{"*": nil}})
	require.Empty(t, client.filter)
}

func TestPropertyClientDERPStickyFields(t *testing.T) {
	initial := &tailcfg.DERPMap{
		Regions:            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}},
		OmitDefaultRegions: true,
		HomeParams:         &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{1: 0.5}},
	}
	client := newPropertyClient(&tailcfg.MapResponse{DERPMap: initial})

	for _, update := range []*tailcfg.DERPMap{{}, {HomeParams: &tailcfg.DERPHomeParams{}}} {
		frozen := update.Clone()
		client.apply(&tailcfg.MapResponse{DERPMap: update})
		require.Equal(t, initial, client.derp, "nil fields retain previous values")
		require.Equal(t, frozen, update, "replay owns the received map")
	}

	client.apply(&tailcfg.MapResponse{DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}})
	require.Empty(t, client.derp.Regions)
	require.False(t, client.derp.OmitDefaultRegions, "non-nil Regions replaces the associated flag")
	require.Equal(t, initial.HomeParams, client.derp.HomeParams)

	scores := map[tailcfg.DERPRegionID]float64{2: 2}
	client.apply(&tailcfg.MapResponse{DERPMap: &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{RegionScore: scores}}})
	require.Equal(t, scores, client.derp.HomeParams.RegionScore)
	require.Empty(t, client.derp.Regions)
	require.False(t, client.derp.OmitDefaultRegions)
}

func TestPropertyWireEncodingSlots(t *testing.T) {
	hub := NewHub()
	defer hub.Close()

	response := hub.frames.share(&tailcfg.MapResponse{ControlTime: new(propertyEpoch), DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}}})
	require.Contains(t, hub.frames.byResp, response)

	for range 2 {
		for _, compress := range []bool{false, true} {
			wireRoundTrip(t, hub, response, compress)
		}
	}
}
