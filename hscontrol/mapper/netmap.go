package mapper

import (
	"cmp"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"slices"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// ErrNodeGone is returned when the node a map is rendered for is no
// longer in the world.
var ErrNodeGone = errors.New("node no longer exists")

// netMap is everything a node is told about its tailnet, rendered from one
// [state.Snapshot]. A client holds exactly the last netMap it was sent;
// what to send next is the difference to a fresh one, see [diff].
type netMap struct {
	self     *tailcfg.Node
	peers    map[tailcfg.NodeID]*tailcfg.Node
	profiles map[tailcfg.UserID]tailcfg.UserProfile
	filter   []tailcfg.FilterRule
	ssh      *tailcfg.SSHPolicy
	dns      *tailcfg.DNSConfig
	derpMap  *tailcfg.DERPMap

	// base is the render this one follows. changed lists the peers added or
	// rendered again since base and removed the peers gone, so a diff
	// against base touches only them. sameProfiles reports profiles shared
	// with base.
	base         *netMap
	changed      []tailcfg.NodeID
	removed      []tailcfg.NodeID
	sameProfiles bool
}

// renderer renders one node's netMap. It keeps every peer it rendered and
// renders a peer again only when the peer or what its rendering reads
// (policy, policy-relevant node facts, primary routes) changed; other
// writes, the common endpoint and online updates, cost one peer each.
type renderer struct {
	cfg    *types.Config
	nodeID types.NodeID
	capVer tailcfg.CapabilityVersion

	peers map[types.NodeID]renderedPeer
	last  *netMap

	// dns is reused while its inputs, the node and the policy's capability
	// map and the extra records, are unchanged.
	dns    *tailcfg.DNSConfig
	dnsKey dnsKey
}

type renderedPeer struct {
	node types.NodeView // the stored node; stored nodes are immutable
	key  renderKey
	tn   *tailcfg.Node
}

// renderKey is what a peer's rendering reads besides the peer itself.
type renderKey struct {
	policy, policyNodes, primaries uint64
}

type dnsKey struct {
	self        types.NodeView
	policy, dns uint64
}

func newRenderer(cfg *types.Config, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *renderer {
	return &renderer{
		cfg:    cfg,
		nodeID: nodeID,
		capVer: capVer,
		peers:  make(map[types.NodeID]renderedPeer),
	}
}

// render renders the node's netMap from snap.
func (r *renderer) render(snap *state.Snapshot) (*netMap, error) {
	self, ok := snap.GetNode(r.nodeID)
	if !ok {
		return nil, ErrNodeGone
	}

	pm := snap.Policy()
	capMaps := pm.NodeCapMaps()

	tn, err := self.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
		return snap.SelfRoutes(self)
	}, r.cfg, capMaps[self.ID()])
	if err != nil {
		return nil, err
	}

	filter, err := pm.FilterForNode(self)
	if err != nil {
		return nil, err
	}

	ssh, err := pm.SSHPolicy(r.cfg.ServerURL, self)
	if err != nil {
		// Fail closed: a nil SSHPolicy would leave the client's previous
		// rules in force.
		log.Error().Caller().Err(err).EmbedObject(self).
			Msg("compiling SSH policy failed; sending empty SSH policy")

		ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}
	}

	if k := (dnsKey{self: self, policy: snap.PolicyRev(), dns: snap.DNSRev()}); r.dns == nil || k != r.dnsKey {
		r.dns, r.dnsKey = generateDNSConfig(r.cfg, self, capMaps[self.ID()]), k
	}

	nm := &netMap{
		self:    tn,
		filter:  filter,
		ssh:     ssh,
		dns:     r.dns,
		derpMap: snap.DERPMap(),
		base:    r.last,
	}

	err = r.renderPeers(snap, self, capMaps, nm)
	if err != nil {
		return nil, err
	}

	r.renderProfiles(snap, self, nm)
	r.last = nm

	return nm, nil
}

// renderPeers fills nm.peers, rendering only the peers whose inputs moved
// since the previous render and recording which they are.
func (r *renderer) renderPeers(
	snap *state.Snapshot,
	self types.NodeView,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
	nm *netMap,
) error {
	ids := snap.PeerIDs(r.nodeID)
	key := renderKey{
		policy:      snap.PolicyRev(),
		policyNodes: snap.PolicyNodesRev(),
		primaries:   snap.PrimariesRev(),
	}

	if nm.base != nil {
		nm.peers = maps.Clone(nm.base.peers)
	} else {
		nm.peers = make(map[tailcfg.NodeID]*tailcfg.Node, len(ids))
	}

	var (
		matchers       []matcher.Match
		matchersLoaded bool
		current        = make(map[types.NodeID]struct{}, len(ids))
	)

	for _, id := range ids {
		peer, ok := snap.GetNode(id)
		if !ok {
			continue
		}

		current[id] = struct{}{}

		prev, cached := r.peers[id]
		if cached && prev.node == peer && prev.key == key {
			if _, ok := nm.peers[prev.tn.ID]; !ok {
				nm.peers[prev.tn.ID] = prev.tn
				nm.changed = append(nm.changed, prev.tn.ID)
			}

			continue
		}

		// RoutesForPeer needs the unreduced matchers: every rule where
		// the node is source or destination.
		if !matchersLoaded {
			var err error

			matchers, err = snap.Policy().MatchersForNode(self)
			if err != nil {
				return err
			}

			matchersLoaded = true
		}

		ptn, err := peer.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
			return snap.RoutesForPeer(self, peer, matchers)
		}, r.cfg, capMaps[peer.ID()])
		if err != nil {
			// One peer with invalid data must not blank out the map for
			// every node that can see it.
			log.Warn().Caller().Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Uint64("map.viewer.node.id", r.nodeID.Uint64()).
				Msgf("dropping peer %d from map response: invalid node data; fix with `headscale nodes rename %d <name>`", peer.ID(), peer.ID())
			delete(current, id)

			continue
		}

		// A peer's CapMap carries only the caps clients read from the
		// peer view; see [policyv2.PeerCapMap].
		ptn.CapMap = policyv2.PeerCapMap(peer, capMaps[peer.ID()])

		// Clients never read a peer's NetInfo, and its home DERP reaches
		// them as HomeDERP; leaving it in would turn every DERP move into
		// a whole-peer update.
		if ptn.Hostinfo.Valid() && ptn.Hostinfo.NetInfo().Valid() {
			hi := ptn.Hostinfo.AsStruct()
			hi.NetInfo = nil
			ptn.Hostinfo = hi.View()
		}

		// Hostinfo is not patchable, so any change resends the whole peer.
		// Keep what the client holds while the fields it reads are equal.
		if cached && peerHostinfoEqual(prev.tn.Hostinfo, ptn.Hostinfo) {
			ptn.Hostinfo = prev.tn.Hostinfo
		}

		r.peers[id] = renderedPeer{node: peer, key: key, tn: ptn}
		nm.peers[ptn.ID] = ptn
		nm.changed = append(nm.changed, ptn.ID)
	}

	for id := range r.peers {
		if _, ok := current[id]; !ok {
			delete(r.peers, id)
		}
	}

	for id := range nm.peers {
		if _, ok := current[types.NodeID(id)]; !ok { //nolint:gosec // NodeID types are the same value
			delete(nm.peers, id)
			nm.removed = append(nm.removed, id)
		}
	}

	slices.Sort(nm.changed)
	slices.Sort(nm.removed)

	return nil
}

// renderProfiles fills nm.profiles. They only move when a peer joins or
// leaves or the owner of a shown node changes, so a render that changed
// neither shares the previous profiles.
func (r *renderer) renderProfiles(snap *state.Snapshot, self types.NodeView, nm *netMap) {
	if base := nm.base; base != nil && len(nm.removed) == 0 && ownerProfileUnchanged(base, self) {
		same := true

		for _, id := range nm.changed {
			peer, ok := snap.GetNode(types.NodeID(id)) //nolint:gosec // NodeID types are the same value
			if _, existed := base.peers[id]; !existed || !ok || !ownerProfileUnchanged(base, peer) {
				same = false

				break
			}
		}

		if same {
			nm.profiles, nm.sameProfiles = base.profiles, true

			return
		}
	}

	nm.profiles = make(map[tailcfg.UserID]tailcfg.UserProfile)
	for _, p := range generateUserProfiles(self, snap.ListPeers(r.nodeID)) {
		nm.profiles[p.ID] = p
	}
}

// ownerProfileUnchanged reports whether base already shows the profile of
// node's owner as it is now.
func ownerProfileUnchanged(base *netMap, node types.NodeView) bool {
	owner := node.Owner()
	if !owner.Valid() {
		return true
	}

	p := owner.TailscaleUserProfile()
	old, ok := base.profiles[p.ID]

	return ok && reflect.DeepEqual(old, p)
}

func sortedPeers(peers map[tailcfg.NodeID]*tailcfg.Node) []*tailcfg.Node {
	out := slices.Collect(maps.Values(peers))
	slices.SortFunc(out, func(a, b *tailcfg.Node) int { return cmp.Compare(a.ID, b.ID) })

	return out
}

func sortedProfiles(profiles map[tailcfg.UserID]tailcfg.UserProfile) []tailcfg.UserProfile {
	out := slices.Collect(maps.Values(profiles))
	slices.SortFunc(out, func(a, b tailcfg.UserProfile) int { return cmp.Compare(a.ID, b.ID) })

	return out
}

// peerHostinfoEqual reports whether a and b agree on the Hostinfo fields a
// client reads from a peer: what tailscale status shows, PeerAPI services,
// SSH known hosts, exit-node location, app-connector eligibility and the
// announced routes.
func peerHostinfoEqual(a, b tailcfg.HostinfoView) bool {
	if !a.Valid() || !b.Valid() {
		return a.Valid() == b.Valid()
	}

	return a.Hostname() == b.Hostname() &&
		a.OS() == b.OS() &&
		servicesEqual(a.Services(), b.Services()) &&
		views.SliceEqual(a.SSH_HostKeys(), b.SSH_HostKeys()) &&
		locationEqual(a.Location(), b.Location()) &&
		a.AppConnector() == b.AppConnector() &&
		views.SliceEqual(a.RoutableIPs(), b.RoutableIPs())
}

// servicesEqual compares field by field, as [tailcfg.Service] is
// incomparable.
func servicesEqual(a, b views.Slice[tailcfg.Service]) bool {
	if a.Len() != b.Len() {
		return false
	}

	for i := range a.Len() {
		x, y := a.At(i), b.At(i)
		if x.Proto != y.Proto || x.Port != y.Port || x.Description != y.Description {
			return false
		}
	}

	return true
}

// locationEqual compares field by field, as [tailcfg.LocationView] has no
// Equal.
func locationEqual(a, b tailcfg.LocationView) bool {
	if !a.Valid() || !b.Valid() {
		return a.Valid() == b.Valid()
	}

	return a.Country() == b.Country() &&
		a.CountryCode() == b.CountryCode() &&
		a.City() == b.City() &&
		a.CityCode() == b.CityCode() &&
		a.Latitude() == b.Latitude() &&
		a.Longitude() == b.Longitude() &&
		a.Priority() == b.Priority()
}
