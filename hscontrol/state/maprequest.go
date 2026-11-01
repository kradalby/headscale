// Pure functions for processing [tailcfg.MapRequest] data, extracted from
// [State.UpdateNodeFromMapRequest] so they can be tested alone.

package state

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// mapRequestDelta carries the facts compared from one MapRequest against the
// currently-stored node. It separates the raw wire-level peer change (what
// the client actually sent) from the store, persist and route-approval
// decisions made from it.
//
// It is built inside the writer closure, so comparisons run against the node
// the write replaces.
type mapRequestDelta struct {
	// peerChange is the wire-level delta produced by
	// [types.Node.PeerChangeFromMapRequest] - LastSeen is always stamped.
	peerChange tailcfg.PeerChange

	// hostinfoChanged reports whether anything in Hostinfo changed apart
	// from PreferredDERP (tracked by derpChanged) and DERP latency jitter.
	// It gates storing and persisting the new Hostinfo.
	hostinfoChanged bool

	// routesChanged reports whether announced routes (RoutableIPs)
	// changed. Routes are policy and election inputs, so they are tracked
	// on their own.
	routesChanged bool

	// derpChanged reports whether PreferredDERP changed. oldDERP/newDERP
	// carry the values; DERP zero means "unchanged" on the wire, so a
	// clear-to-zero is invisible to the peer change.
	derpChanged      bool
	oldDERP, newDERP tailcfg.DERPRegionID

	// persistWorthy reports whether the request carries data that should
	// hit the database. LastSeen-only updates are not persist-worthy.
	persistWorthy bool
}

// MarshalZerologObject implements [zerolog.LogObjectMarshaler].
func (d mapRequestDelta) MarshalZerologObject(e *zerolog.Event) {
	e.Bool("hostinfo.changed", d.hostinfoChanged).
		Bool("routes.changed", d.routesChanged).
		Bool("derp.changed", d.derpChanged).
		Int("derp.old", int(d.oldDERP)).
		Int("derp.new", int(d.newDERP)).
		Bool("persist", d.persistWorthy)
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
			Uint64(zf.NodeID, nodeID.Uint64()).
			Int64(zf.DERP, currentHostinfo.NetInfo.PreferredDERP.Int64()).
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
		Uint64(zf.NodeID, nodeID.Uint64()).
		Str(zf.Hostname, hostname).
		Msg("node sent update but has no NetInfo in request or database")

	return nil
}

// hostinfoDERP returns the PreferredDERP value from a Hostinfo, or 0 when
// either pointer is nil. 0 is the wire "unchanged" sentinel.
func hostinfoDERP(hi *tailcfg.Hostinfo) tailcfg.DERPRegionID {
	if hi == nil || hi.NetInfo == nil {
		return 0
	}

	return hi.NetInfo.PreferredDERP
}

// hostinfoEqual reports whether two Hostinfo values are the same apart from
// PreferredDERP, which the caller tracks on its own, and DERP latency
// jitter, which [tailcfg.NetInfo.BasicallyEqual] skips.
func hostinfoEqual(oldHI, newHI *tailcfg.Hostinfo) bool {
	if oldHI == nil || newHI == nil {
		return oldHI == newHI
	}

	if !netInfoEqualIgnoringDERP(oldHI.NetInfo, newHI.NetInfo) {
		return false
	}

	// NetInfo is compared above; drop it so nil-vs-empty inside it does
	// not leak through reflect.DeepEqual.
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
