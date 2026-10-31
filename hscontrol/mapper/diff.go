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
	// A full map can follow a quiet spell; it is per session anyway, so
	// it carries the current time, not the snapshot's.
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
		Peers:         sortedPeers(nm),
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
func diff(sent, next *netMap, frames *frameCache) []*tailcfg.MapResponse {
	resp := &tailcfg.MapResponse{}
	changed := false

	if sent.self != next.self && !reflect.DeepEqual(sent.self, next.self) {
		resp.Node = next.self
		changed = true
	}

	changedIDs, removed := peerChanges(sent, next)

	refresh := false

	for _, id := range changedIDs {
		after, _ := next.peer(id)
		before, ok := sent.peer(id)

		switch {
		case !ok:
			resp.PeersChanged = append(resp.PeersChanged, after)
		case before == after:
			continue
		default:
			patch, patchable := frames.patch(before, after)

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
		resp.Peers = sortedPeers(next)
		resp.PeersChanged, resp.PeersChangedPatch = nil, nil
	}

	if len(resp.Peers)+len(resp.PeersChanged)+len(resp.PeersChangedPatch) > 0 {
		changed = true
	}

	if !sameRules(sent.filter, next.filter) && !reflect.DeepEqual(sent.filter, next.filter) {
		resp.PacketFilters = map[string][]tailcfg.FilterRule{"base": next.filter}
		changed = true
	}

	if sent.ssh != next.ssh && !reflect.DeepEqual(sent.ssh, next.ssh) {
		resp.SSHPolicy = next.ssh
		changed = true
	}

	if sent.dns != next.dns && !reflect.DeepEqual(sent.dns, next.dns) {
		resp.DNSConfig = next.dns
		changed = true
	}

	if sent.derpMap != next.derpMap && !reflect.DeepEqual(sent.derpMap, next.derpMap) {
		resp.DERPMap = next.derpMap
		changed = true
	}

	if next.base != sent || !next.sameProfiles {
		for _, p := range sortedProfiles(next.profiles) {
			if old, ok := sent.profiles[p.ID]; !ok || !sameProfile(old, p) {
				resp.UserProfiles = append(resp.UserProfiles, p)
				changed = true
			}
		}
	}

	var out []*tailcfg.MapResponse

	// Every response carries the time of the state it shows.
	at := next.at

	if len(removed) > 0 {
		out = append(out, &tailcfg.MapResponse{PeersRemoved: removed, ControlTime: &at})
	}

	if changed {
		resp.ControlTime = &at
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
		if len(after.Endpoints) == 0 {
			return nil, false
		}

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
		// JSON omits an empty patch map; a complete changed peer clears it.
		if len(after.CapMap) == 0 {
			return nil, false
		}

		p().CapMap = maps.Clone(after.CapMap)
	}

	if !peerRestEqual(before, after) {
		return nil, false
	}

	return patch, true
}

// peerRestEqual reports whether a and b agree on every field a patch cannot
// carry. TestPeerRestEqualCoversEveryField fails when [tailcfg.Node] gains
// a field this does not compare, so an unknown change is never patched
// away.
func peerRestEqual(a, b *tailcfg.Node) bool {
	return a.ID == b.ID &&
		a.StableID == b.StableID &&
		a.Name == b.Name &&
		a.User == b.User &&
		a.Sharer == b.Sharer &&
		a.Machine == b.Machine &&
		slices.Equal(a.Addresses, b.Addresses) &&
		slices.Equal(a.AllowedIPs, b.AllowedIPs) &&
		a.LegacyDERPString == b.LegacyDERPString && //nolint:staticcheck // deprecated fields are still on the wire
		(a.Hostinfo == b.Hostinfo || a.Hostinfo.Equal(b.Hostinfo)) &&
		a.Created.Equal(b.Created) &&
		slices.Equal(a.Tags, b.Tags) &&
		slices.Equal(a.PrimaryRoutes, b.PrimaryRoutes) &&
		a.MachineAuthorized == b.MachineAuthorized &&
		slices.Equal(a.Capabilities, b.Capabilities) && //nolint:staticcheck // deprecated fields are still on the wire
		a.UnsignedPeerAPIOnly == b.UnsignedPeerAPIOnly &&
		a.ComputedName == b.ComputedName &&
		a.ComputedNameWithHost == b.ComputedNameWithHost &&
		a.DataPlaneAuditLogID == b.DataPlaneAuditLogID &&
		a.Expired == b.Expired &&
		equalPtr(a.SelfNodeV4MasqAddrForThisPeer, b.SelfNodeV4MasqAddrForThisPeer) &&
		equalPtr(a.SelfNodeV6MasqAddrForThisPeer, b.SelfNodeV6MasqAddrForThisPeer) &&
		a.IsWireGuardOnly == b.IsWireGuardOnly &&
		a.IsJailed == b.IsJailed &&
		reflect.DeepEqual(a.ExitNodeDNSResolvers, b.ExitNodeDNSResolvers) &&
		a.StableTailnetID == b.StableTailnetID
}

// peerChanges returns the peers to compare and the peers gone between sent
// and next. When next was rendered right after sent its render already
// knows; otherwise every peer is compared.
func peerChanges(sent, next *netMap) ([]tailcfg.NodeID, []tailcfg.NodeID) {
	if next.base == sent {
		return next.changed, next.removed
	}

	var removed []tailcfg.NodeID

	for id := range sent.allPeers() {
		if _, ok := next.peer(id); !ok {
			removed = append(removed, id)
		}
	}

	slices.Sort(removed)

	return peerIDs(next), removed
}

// needsPeerListRefresh reports a change only a whole peer list can apply:
// clients drop an Endpoints, HomeDERP, Cap or Online clear from both a patch and a
// PeersChanged entry they turn into one.
func needsPeerListRefresh(before, after *tailcfg.Node) bool {
	return before.HomeDERP != 0 && after.HomeDERP == 0 ||
		len(before.Endpoints) > 0 && len(after.Endpoints) == 0 ||
		before.Cap != 0 && after.Cap == 0 ||
		before.Online != nil && after.Online == nil
}

// sameRules reports whether a and b are the same slice, as the policy's
// cached filters are from one render to the next.
func sameRules(a, b []tailcfg.FilterRule) bool {
	return len(a) > 0 && len(a) == len(b) && &a[0] == &b[0]
}

func equalPtr[T comparable](a, b *T) bool {
	return a == b || a != nil && b != nil && *a == *b
}

func equalTimePtr(a, b *time.Time) bool {
	return a == b || a != nil && b != nil && a.Equal(*b)
}

// peerIDs returns the IDs of the peers in nm.
func peerIDs(nm *netMap) []tailcfg.NodeID {
	ids := make([]tailcfg.NodeID, 0, nm.peers.Len())
	for id := range nm.allPeers() {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	return ids
}
