// Package state provides pure functions for processing [tailcfg.MapRequest] data.
// These functions are extracted from [State.UpdateNodeFromMapRequest] to improve
// testability and maintainability.

package state

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// mapRequestDelta carries the classified facts extracted from one MapRequest
// against the currently-stored node. It separates the raw wire-level peer
// change (what the client actually sent) from the broadcast/persist/policy
// decisions made from it, so that each downstream decision (broadcast, persist,
// policy refresh, relation rebuild) sees only its own input.
//
// Construction happens once per MapRequest inside the NodeStore write callback
// (so comparisons run against serialized current state); classification happens
// after the write succeeds. Splitting these avoids redoing comparisons and
// avoids having the broadcast classifier depend on incidental branch order.
type mapRequestDelta struct {
	// peerChange is the wire-level delta produced by
	// [Node.PeerChangeFromMapRequest] - LastSeen is always stamped.
	peerChange tailcfg.PeerChange

	// structuralHostinfo reports whether Hostinfo fields visible to peers
	// (OS, services, SSH host keys, routes, etc.) changed. DERPLatency jitter
	// and PreferredDERP are excluded; those are tracked separately.
	structuralHostinfo bool

	// routesChangedInput reports whether announced routes (RoutableIPs)
	// changed. Routes are policy/election inputs, so they are tracked
	// separately from generic structural Hostinfo.
	routesChangedInput bool

	// derpChanged reports whether PreferredDERP changed. oldDERP/newDERP
	// carry the values; DERP zero means "unchanged" on the wire, so
	// clearing DERP to zero cannot be sent as a patch and forces a
	// whole-peer update.
	derpChanged      bool
	oldDERP, newDERP int

	// endpointBroadcast reports whether the endpoint delta is worth fanning
	// out (i.e., a newly-added useful non-STUN endpoint). Storage still
	// happens regardless; this gates only broadcast.
	endpointBroadcast bool

	// keyChanged and discoKeyChanged report whether the node's wire keys
	// changed. Key patches already carry the resulting endpoints/expiry,
	// so a key change subsumes endpoint/DERP patches.
	keyChanged      bool
	discoKeyChanged bool

	// persistWorthy reports whether the request carries data that should
	// hit the database. LastSeen-only updates are not persist-worthy.
	persistWorthy bool
}

// netInfoFromMapRequest determines the correct [tailcfg.NetInfo] to use.
// Returns the [tailcfg.NetInfo] that should be used for this request.
func netInfoFromMapRequest(
	nodeID types.NodeID,
	currentHostinfo *tailcfg.Hostinfo,
	reqHostinfo *tailcfg.Hostinfo,
) *tailcfg.NetInfo {
	// If request has [tailcfg.NetInfo], use it
	if reqHostinfo != nil && reqHostinfo.NetInfo != nil {
		return reqHostinfo.NetInfo
	}

	// Otherwise, use current [tailcfg.NetInfo] if available
	if currentHostinfo != nil && currentHostinfo.NetInfo != nil {
		log.Debug().
			Caller().
			Uint64("node.id", nodeID.Uint64()).
			Int64("preferredDERP", currentHostinfo.NetInfo.PreferredDERP.Int64()).
			Msg("using NetInfo from previous Hostinfo in MapRequest")

		return currentHostinfo.NetInfo
	}

	// No [tailcfg.NetInfo] available anywhere - log for debugging
	var hostname string
	if reqHostinfo != nil {
		hostname = reqHostinfo.Hostname
	} else if currentHostinfo != nil {
		hostname = currentHostinfo.Hostname
	}

	log.Debug().
		Caller().
		Uint64("node.id", nodeID.Uint64()).
		Str("node.hostname", hostname).
		Msg("node sent update but has no NetInfo in request or database")

	return nil
}

// hostinfoDERP returns the PreferredDERP value from a Hostinfo, or 0 when
// either pointer is nil. 0 is the wire "unchanged" sentinel.
func hostinfoDERP(hi *tailcfg.Hostinfo) int {
	if hi == nil || hi.NetInfo == nil {
		return 0
	}

	return int(hi.NetInfo.PreferredDERP)
}

// hostinfoStructuralEqual compares two Hostinfo values ignoring fields that
// should not trigger a structural (whole-peer) broadcast:
//
//   - NetInfo is compared via [tailcfg.NetInfo.BasicallyEqual], which skips
//     DERPLatency/RegionLatency jitter. PreferredDERP changes are tracked
//     separately by the caller, so they are zeroed out here.
//
// RoutableIPs is *not* ignored: route advertisements are policy inputs and
// must remain visible here. They are additionally tracked as a separate
// delta output.
//
// This function is intentionally Hostinfo-scoped; it is not a generic
// node-equality helper.
func hostinfoStructuralEqual(oldHI, newHI *tailcfg.Hostinfo) bool {
	if oldHI == nil && newHI == nil {
		return true
	}

	if (oldHI == nil) != (newHI == nil) {
		return false
	}

	// Compare NetInfo via BasicallyEqual, with PreferredDERP zeroed out so
	// that DERP changes do not masquerade as structural. DERPLatency maps
	// are skipped by BasicallyEqual itself.
	if !netInfoEqualIgnoringDERP(oldHI.NetInfo, newHI.NetInfo) {
		return false
	}

	// Compare the rest of Hostinfo structurally, with NetInfo removed so
	// the nil-vs-empty distinctions inside NetInfo do not leak through
	// reflect.DeepEqual.
	oldCopy := *oldHI
	oldCopy.NetInfo = nil
	newCopy := *newHI
	newCopy.NetInfo = nil

	return oldCopy.Equal(&newCopy)
}

// netInfoEqualIgnoringDERP compares two NetInfo values via
// [tailcfg.NetInfo.BasicallyEqual] after zeroing PreferredDERP on both, so
// that DERP-only changes do not appear here (they are tracked separately).
func netInfoEqualIgnoringDERP(old, current *tailcfg.NetInfo) bool {
	if old == nil && current == nil {
		return true
	}

	if (old == nil) != (current == nil) {
		return false
	}

	oldCopy := *old
	oldCopy.PreferredDERP = 0
	currentCopy := *current
	currentCopy.PreferredDERP = 0

	return oldCopy.BasicallyEqual(&currentCopy)
}
