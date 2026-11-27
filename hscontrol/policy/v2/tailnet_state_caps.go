package v2

// This file enumerates [tailcfg.NodeCapability] values that the
// Tailscale-hosted control plane emits where headscale has no
// equivalent concept yet. The compat test in
// tailscale_nodeattrs_compat_test.go builds the self-view CapMap via
// [types.Node.TailNode] -- the same call the mapper makes -- and
// strips these from BOTH sides before [cmp.Diff]; every other cap is
// compared in full as it lands on the wire.
//
// Each entry documents its purpose (cross-referenced to Tailscale
// source), why headscale does not emit it, and a tracking issue where
// one exists.

import (
	"maps"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/util/mak"
)

// PeerCapMap returns, when stamped, the source capabilities the peer is
// stamped with and, for an approved exit node, [nodecap.SuggestExitNode], preserving its
// policy value from peerSelfCaps. A peer with neither returns nil, matching
// the wire shape where [tailcfg.Node.CapMap] is omitted.
//
// Mapper peer rendering and compatibility tests share this emission rule.
func PeerCapMap(peer types.NodeView, peerSelfCaps tailcfg.NodeCapMap, stamped bool) tailcfg.NodeCapMap {
	var out tailcfg.NodeCapMap

	// The source capabilities the peer is stamped with, in capability mode:
	// a viewer's filter names them, and the viewer looks them up on the peer.
	//
	// TODO(capsrc/trim): lift when per-viewer trimming is worth giving up renders shared across viewers; every viewer sees every selector a peer is in
	// TODO(kradalby): capsrc/trim, overwake/stamp-viewers: so a stamp that
	// comes or goes wakes every viewer of the restamped node and sends each
	// the node's whole CapMap, whether or not any of the viewer's rules
	// names the stamp (a group edit restamps its users' nodes for the whole
	// tailnet); the client applies a CapMap patch by rebuilding its netmap,
	// a CapMap change being no NodeMutation (NodeMutationsFromPatch,
	// https://github.com/tailscale/tailscale/blob/f7c1b8e52600c1926623b29c91972a5ea1364d2f/types/netmap/nodemut.go;
	// the delta work under https://github.com/tailscale/tailscale/issues/12542). Mapper.Route
	// wakes them through Change.Caps. Fixing it takes rendering each peer
	// per viewer with the stamps the viewer's own rules name, giving up the
	// renders shared across viewers. No test tolerates it: the stamps are
	// what TestStampsFollowReference and TestWorldMatchesScratchWorld hold.
	for c := range peerSelfCaps {
		if stamped && IsSourceCap(string(c)) {
			mak.Set(&out, c, nil)
		}
	}

	// suggest-exit-node — surfaced on Peer.CapMap when the peer
	// advertises exit routes AND those routes are approved, with or
	// without a nodeAttrs grant: SaaS stamps it by default, and Apple
	// clients hide the exit-node list without a suggestion. A policy
	// value, if any, wins. Approval gating prevents the suggestion from
	// following an advertised-but-not-yet-trusted node, or one approved for
	// one family alone, which SaaS offers nobody.
	if len(peer.OfferedExitRoutes()) > 0 {
		mak.Set(&out, nodecap.SuggestExitNode, peerSelfCaps[nodecap.SuggestExitNode])
	}

	return out
}

// unmodelledTailnetStateCaps lists [tailcfg.NodeCapability] values
// stripped on both sides of the compat diff. Order:
//
//  1. Caps gated on a user-role concept headscale does not model.
//  2. Caps gated on a tailnet feature headscale does not implement.
//  3. Caps that are tailnet-state metadata (display name, key
//     duration, etc.) where the values are not derivable from
//     headscale config in a way that round-trips through the
//     anonymized capture.
//  4. Caps that are internal magicsock or embedded-SSH tuning with no
//     headscale-side equivalent.
var unmodelledTailnetStateCaps = []nodecap.Cap{
	// --- 1. User-role gated ---

	// [tailcfg.CapabilityOwner]: conditional on the "owner" role, which
	// headscale does not model, so it does not emit this cap at all.
	// autogroup:owner support is tracked under NO_USER_ROLES — see the
	// compat skip list.
	nodecap.Owner,

	// --- 2. Feature not implemented ---

	// [tailcfg.CapabilityTailnetLock]: tailnet-lock signs node keys
	// with a tailnet-wide signing key so peers can detect silent
	// re-keying by the control plane. Client gates
	// [tailscale.com/ipn/ipnlocal.LocalBackend.NetworkLockStatus] on it.
	// Headscale has no tailnet-lock implementation.
	nodecap.TailnetLock,

	// [tailcfg.NodeAttrServiceHost]: marks a node as approved to host
	// VIP services (Tailscale Services). Client decodes it via
	// [tailcfg.UnmarshalNodeCapViewJSON] into [tailcfg.ServiceIPMappings].
	// Headscale does not implement Tailscale Services.
	nodecap.ServiceHost,

	// [tailcfg.NodeAttrStoreAppCRoutes]: tells an app-connector node
	// to persist learned routes across restarts. Client reads via
	// [tailscale.com/control/controlknobs.Knobs.UpdateFromNodeAttributes]. Headscale does not implement app
	// connectors.
	nodecap.StoreAppCRoutes,

	// [tailcfg.CapabilityWarnFunnelNoHTTPS]: deprecated in Tailscale
	// 2023-08-09. Should not appear in fresh captures — listed
	// defensively in case a stale tailnet still emits it.
	nodecap.WarnFunnelNoHTTPS,

	// --- 3. Tailnet-state metadata not derivable from headscale config ---

	// [tailcfg.NodeAttrTailnetDisplayName]: tailnet display name
	// surfaced in the client UI. The hosted control plane emits the
	// tailnet admin's email; headscale would have to invent a value
	// from cfg.Domain() that does not round-trip through the
	// anonymized capture string. Skip rather than diverge on a value
	// with no real-world equivalent.
	nodecap.TailnetDisplayName,

	// [tailcfg.NodeAttrMaxKeyDuration]: tailnet-wide max key duration
	// value. Headscale has cfg.Node.Expiry but does not surface it
	// as a cap today; the hosted control plane emits this only when
	// a non-default value is configured.
	nodecap.MaxKeyDuration,

	// [tailcfg.NodeAttrNativeIPV4]: peer-consumed cap conditional on
	// tailnet ipv4 reachability state. Out of scope for the current
	// peer-cap adoption (only suggest-exit-node is wired in this
	// PR).
	nodecap.NativeIPV4,

	// --- 4. Internal tuning, no headscale equivalent ---

	// [tailcfg.NodeAttrProbeUDPLifetime]: tunes magicsock's UDP
	// path-lifetime probe behavior. Internal performance knob; not
	// policy-driven. Client reads via
	// [tailscale.com/control/controlknobs.Knobs.UpdateFromNodeAttributes].
	nodecap.ProbeUDPLifetime,

	// [tailcfg.NodeAttrSSHBehaviorV1]: picks the embedded SSH server's
	// older path on a root-run Linux daemon: no su, in-process SFTP, no
	// PAM session or login environment. SaaS stamps it on every node;
	// headscale leaves it to a nodeAttr on purpose, as switching changes
	// existing users' login environment. It is more than tuning, so
	// TestSSHBehaviorIsAnAdminChoice pins it apart from this strip.
	nodecap.SSHBehaviorV1,
}

// strippedCapPrefixes lists URL/string prefixes for parameterized or
// pattern-named caps that should be stripped alongside
// [unmodelledTailnetStateCaps].
var strippedCapPrefixes = []string{
	// "https://tailscale.com/cap/funnel-ports?…": parameterized cap
	// (e.g. "?ports=80,443") issued when funnel is configured.
	// Funnel is not supported.
	"https://tailscale.com/cap/funnel-ports?",
}

// stripUnmodelledTailnetStateCaps returns a copy of cm with
// [unmodelledTailnetStateCaps] and [strippedCapPrefixes] removed. Used
// by the compat test on both sides before [cmp.Diff].
func stripUnmodelledTailnetStateCaps(cm tailcfg.NodeCapMap) tailcfg.NodeCapMap {
	if len(cm) == 0 {
		return nil
	}

	out := maps.Clone(cm)
	maps.DeleteFunc(out, func(k nodecap.Cap, _ []tailcfg.RawMessage) bool {
		return isUnmodelledTailnetStateCap(k)
	})

	if len(out) == 0 {
		return nil
	}

	return out
}

func isUnmodelledTailnetStateCap(k nodecap.Cap) bool {
	if slices.Contains(unmodelledTailnetStateCaps, k) {
		return true
	}

	s := string(k)
	for _, p := range strippedCapPrefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}

	return false
}
