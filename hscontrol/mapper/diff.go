package mapper

import (
	"bytes"
	"maps"
	"reflect"
	"slices"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// fullResponse is the map that opens a stream: everything the node needs,
// with the whole peer list.
func fullResponse(cfg *types.Config, nm *netMap) *tailcfg.MapResponse {
	now := time.Now()

	resp := &tailcfg.MapResponse{
		ControlTime:   &now,
		Node:          nm.self,
		DERPMap:       nm.derpMap,
		Domain:        cfg.Domain(),
		Debug:         cfg.TailcfgDebug(),
		SSHPolicy:     nm.ssh,
		DNSConfig:     nm.dns,
		UserProfiles:  sortedProfiles(nm.profiles),
		PacketFilters: map[string][]tailcfg.FilterRule{"base": nm.filter},
		Peers:         sortedPeers(nm.peers),
	}
	resp.CollectServices.Set(false)

	return resp
}

// diff returns the responses that take a client holding sent to next, or
// nil when there is nothing to tell it. Removed peers go first, in a
// response of their own: clients before capability version 148 report
// removals to delta-only IPN watchers (the Android app) only from
// responses they apply as deltas, and the second response can carry fields
// that force a full rebuild.
func diff(sent, next *netMap) []*tailcfg.MapResponse {
	resp := &tailcfg.MapResponse{}
	changed := false

	if !reflect.DeepEqual(sent.self, next.self) {
		resp.Node = next.self
		changed = true
	}

	var removed []tailcfg.NodeID

	for id := range sent.peers {
		if _, ok := next.peers[id]; !ok {
			removed = append(removed, id)
		}
	}

	slices.Sort(removed)

	refresh := false

	for _, after := range sortedPeers(next.peers) {
		before, ok := sent.peers[after.ID]

		switch {
		case !ok:
			resp.PeersChanged = append(resp.PeersChanged, after)
		case before == after:
			continue
		default:
			patch, patchable := peerPatch(before, after)

			switch {
			case patchable && patch == nil:
				continue
			case patchable:
				resp.PeersChangedPatch = append(resp.PeersChangedPatch, patch)
			case needsPeerListRefresh(before, after):
				refresh = true
			default:
				resp.PeersChanged = append(resp.PeersChanged, after)
			}
		}
	}

	if refresh {
		// The client turns a PeersChanged entry back into a patch, which
		// cannot express this clear; only a whole peer list applies it.
		resp.Peers = sortedPeers(next.peers)
		resp.PeersChanged, resp.PeersChangedPatch = nil, nil
	}

	if len(resp.Peers)+len(resp.PeersChanged)+len(resp.PeersChangedPatch) > 0 {
		changed = true
	}

	if !reflect.DeepEqual(sent.filter, next.filter) {
		resp.PacketFilters = map[string][]tailcfg.FilterRule{"base": next.filter}
		changed = true
	}

	if !reflect.DeepEqual(sent.ssh, next.ssh) {
		resp.SSHPolicy = next.ssh
		changed = true
	}

	if !reflect.DeepEqual(sent.dns, next.dns) {
		resp.DNSConfig = next.dns
		changed = true
	}

	if sent.derpMap != next.derpMap && !reflect.DeepEqual(sent.derpMap, next.derpMap) {
		resp.DERPMap = next.derpMap
		changed = true
	}

	for _, p := range sortedProfiles(next.profiles) {
		if old, ok := sent.profiles[p.ID]; !ok || !reflect.DeepEqual(old, p) {
			resp.UserProfiles = append(resp.UserProfiles, p)
			changed = true
		}
	}

	var out []*tailcfg.MapResponse

	if len(removed) > 0 {
		out = append(out, &tailcfg.MapResponse{PeersRemoved: removed})
	}

	if changed {
		now := time.Now()
		resp.ControlTime = &now
		out = append(out, resp)
	}

	return out
}

// peerPatch returns the patch taking a client from before to after, nil
// when they are wire-equal, and false when a changed field cannot be
// patched. It masks the patchable fields and compares the rest, so a new
// [tailcfg.Node] field is never silently dropped.
func peerPatch(before, after *tailcfg.Node) (*tailcfg.PeerChange, bool) {
	var patch *tailcfg.PeerChange

	p := func() *tailcfg.PeerChange {
		if patch == nil {
			patch = &tailcfg.PeerChange{NodeID: after.ID}
		}

		return patch
	}

	if before.HomeDERP != after.HomeDERP {
		if after.HomeDERP == 0 {
			return nil, false
		}

		p().DERPRegion = after.HomeDERP
	}

	if !slices.Equal(before.Endpoints, after.Endpoints) {
		p().Endpoints = slices.Clone(after.Endpoints)
	}

	if before.Key != after.Key {
		p().Key = new(after.Key)
	}

	if before.DiscoKey != after.DiscoKey {
		p().DiscoKey = new(after.DiscoKey)
	}

	if !before.KeyExpiry.Equal(after.KeyExpiry) {
		p().KeyExpiry = new(after.KeyExpiry)
	}

	if !equalPtr(before.Online, after.Online) {
		if after.Online == nil {
			return nil, false
		}

		p().Online = new(*after.Online)
	}

	// LastSeen is only rendered for offline peers. A peer coming online
	// clears it, which a patch cannot say; the Online patch is what the
	// client acts on, so the stale LastSeen it keeps is harmless.
	if !equalTimePtr(before.LastSeen, after.LastSeen) && after.LastSeen != nil {
		p().LastSeen = new(*after.LastSeen)
	}

	if !bytes.Equal(before.KeySignature, after.KeySignature) {
		p().KeySignature = slices.Clone(after.KeySignature)
	}

	if before.Cap != after.Cap {
		if after.Cap == 0 {
			return nil, false
		}

		p().Cap = after.Cap
	}

	if !before.CapMap.Equal(after.CapMap) {
		m := maps.Clone(after.CapMap)
		if m == nil {
			m = make(tailcfg.NodeCapMap)
		}

		p().CapMap = m
	}

	rest := *before
	rest.HomeDERP = after.HomeDERP
	rest.Endpoints = after.Endpoints
	rest.Key = after.Key
	rest.DiscoKey = after.DiscoKey
	rest.KeyExpiry = after.KeyExpiry
	rest.Online = after.Online
	rest.LastSeen = after.LastSeen
	rest.KeySignature = after.KeySignature
	rest.Cap = after.Cap
	rest.CapMap = after.CapMap

	if !reflect.DeepEqual(&rest, after) {
		return nil, false
	}

	return patch, true
}

// needsPeerListRefresh reports a change only a whole peer list can apply:
// clients drop a HomeDERP, Cap or Online clear from both a patch and a
// PeersChanged entry they turn into one.
func needsPeerListRefresh(before, after *tailcfg.Node) bool {
	return before.HomeDERP != 0 && after.HomeDERP == 0 ||
		before.Cap != 0 && after.Cap == 0 ||
		before.Online != nil && after.Online == nil
}

func equalPtr[T comparable](a, b *T) bool {
	return a == b || a != nil && b != nil && *a == *b
}

func equalTimePtr(a, b *time.Time) bool {
	return a == b || a != nil && b != nil && a.Equal(*b)
}

// peerIDs returns the IDs of the peers in nm.
func peerIDs(nm *netMap) []tailcfg.NodeID {
	ids := make([]tailcfg.NodeID, 0, len(nm.peers))
	for id := range nm.peers {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
}
