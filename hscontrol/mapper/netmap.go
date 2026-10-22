package mapper

import (
	"cmp"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
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

	peers  map[types.NodeID]renderedPeer
	last   *netMap
	shared *peerRenders

	// The revision, peer inputs and peer set of the previous render, for
	// telling which peers a later snapshot can have changed.
	lastRev      uint64
	lastKey      renderKey
	lastPeersRev uint64

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

func newRenderer(cfg *types.Config, shared *peerRenders, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *renderer {
	return &renderer{
		cfg:    cfg,
		nodeID: nodeID,
		capVer: capVer,
		peers:  make(map[types.NodeID]renderedPeer),
		shared: shared,
	}
}

// peerRenders shares, across sessions, the part of a peer's rendering that
// does not depend on who views it: everything but its routes. Each stored
// node is rendered once per capability version and policy, not once per
// viewer.
//
// ponytail: one entry per node ID and capability version ever rendered;
// bounded by nodes.
type peerRenders struct {
	m sync.Map // peerRenderID -> *peerRender
}

type peerRenderID struct {
	node   types.NodeID
	capVer tailcfg.CapabilityVersion
}

type peerRender struct {
	node   types.NodeView
	policy uint64
	tn     *tailcfg.Node
}

// render returns peer rendered without routes. The result is shared and
// must not be modified; see [withRoutes].
func (pr *peerRenders) render(
	cfg *types.Config,
	capVer tailcfg.CapabilityVersion,
	policy uint64,
	peer types.NodeView,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
) (*tailcfg.Node, error) {
	id := peerRenderID{node: peer.ID(), capVer: capVer}

	if v, ok := pr.m.Load(id); ok {
		if e := v.(*peerRender); e.node == peer && e.policy == policy { //nolint:forcetypeassert // only peerRender is stored
			return e.tn, nil
		}
	}

	tn, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return nil }, cfg, capMaps[peer.ID()])
	if err != nil {
		return nil, err
	}

	// A peer's CapMap carries only the caps clients read from the peer
	// view; see [policyv2.PeerCapMap].
	tn.CapMap = policyv2.PeerCapMap(peer, capMaps[peer.ID()])

	// Clients never read a peer's NetInfo, and its home DERP reaches them
	// as HomeDERP; leaving it in would turn every DERP move into a
	// whole-peer update.
	if tn.Hostinfo.Valid() && tn.Hostinfo.NetInfo().Valid() {
		hi := tn.Hostinfo.AsStruct()
		hi.NetInfo = nil
		tn.Hostinfo = hi.View()
	}

	pr.m.Store(id, &peerRender{node: peer, policy: policy, tn: tn})

	return tn, nil
}

// withRoutes returns a copy of the shared render base carrying the routes
// one viewer sees, as [types.NodeView.TailNode] would have rendered them.
func withRoutes(base *tailcfg.Node, routes []netip.Prefix) *tailcfg.Node {
	tn := *base
	tn.AllowedIPs = slices.Concat(base.Addresses, routes)
	slices.SortFunc(tn.AllowedIPs, netip.Prefix.Compare)

	tn.PrimaryRoutes = nil

	for _, r := range routes {
		if !tsaddr.IsExitRoute(r) {
			tn.PrimaryRoutes = append(tn.PrimaryRoutes, r)
		}
	}

	return &tn
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
	key := renderKey{
		policy:      snap.PolicyRev(),
		policyNodes: snap.PolicyNodesRev(),
		primaries:   snap.PrimariesRev(),
	}

	pr := &peerRendering{r: r, snap: snap, self: self, capMaps: capMaps, key: key}

	done, err := r.renderChangedPeers(pr, nm)
	if err != nil || done {
		return err
	}

	return r.renderAllPeers(pr, nm)
}

// peerRendering holds what rendering one render's peers needs.
type peerRendering struct {
	r       *renderer
	snap    *state.Snapshot
	self    types.NodeView
	capMaps map[types.NodeID]tailcfg.NodeCapMap
	key     renderKey

	matchers       []matcher.Match
	matchersLoaded bool
}

// renderChangedPeers is the fast path for a write that moved no policy,
// route or visibility input: only the nodes the snapshot's change log
// names since the previous render can differ, so only they are looked at.
// It reports false when that does not hold and every peer must be checked.
func (r *renderer) renderChangedPeers(pr *peerRendering, nm *netMap) (bool, error) {
	base := nm.base
	if base == nil || pr.key != r.lastKey || pr.snap.PeersRev() != r.lastPeersRev {
		return false, nil
	}

	ids, ok := pr.snap.NodesChangedSince(r.lastRev)
	if !ok {
		return false, nil
	}

	nm.peers = maps.Clone(base.peers)

	for _, id := range ids {
		prev, isPeer := r.peers[id]
		if !isPeer {
			continue
		}

		peer, exists := pr.snap.GetNode(id)
		if !exists {
			// A peer left; the slow path also drops it from the peer set.
			return false, nil
		}

		if prev.node == peer {
			continue
		}

		ptn, err := pr.render(peer, prev, true)
		if err != nil {
			return false, err
		}

		if ptn == nil {
			return false, nil
		}

		nm.peers[ptn.ID] = ptn
		nm.changed = append(nm.changed, ptn.ID)
	}

	slices.Sort(nm.changed)
	nm.changed = slices.Compact(nm.changed)

	r.markRendered(pr)

	return true, nil
}

// renderAllPeers checks every peer, rendering those whose inputs moved.
func (r *renderer) renderAllPeers(pr *peerRendering, nm *netMap) error {
	ids := pr.snap.PeerIDs(r.nodeID)

	// A fast path that gave up may have rendered some peers already; they
	// are in r.peers and are compared like any other below.
	nm.changed = nil

	if nm.base != nil {
		nm.peers = maps.Clone(nm.base.peers)
	} else {
		nm.peers = make(map[tailcfg.NodeID]*tailcfg.Node, len(ids))
	}

	current := make(map[types.NodeID]struct{}, len(ids))

	for _, id := range ids {
		peer, ok := pr.snap.GetNode(id)
		if !ok {
			continue
		}

		current[id] = struct{}{}

		prev, cached := r.peers[id]
		if cached && prev.node == peer && prev.key == pr.key {
			if nm.peers[prev.tn.ID] != prev.tn {
				nm.peers[prev.tn.ID] = prev.tn
				nm.changed = append(nm.changed, prev.tn.ID)
			}

			continue
		}

		ptn, err := pr.render(peer, prev, cached)
		if err != nil {
			return err
		}

		if ptn == nil {
			delete(current, id)

			continue
		}

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
	r.markRendered(pr)

	return nil
}

func (r *renderer) markRendered(pr *peerRendering) {
	r.lastRev, r.lastKey, r.lastPeersRev = pr.snap.Rev(), pr.key, pr.snap.PeersRev()
}

// render renders peer for this viewer and records it. It returns nil, with
// a warning logged, for a peer whose data cannot be rendered.
func (pr *peerRendering) render(peer types.NodeView, prev renderedPeer, cached bool) (*tailcfg.Node, error) {
	r := pr.r

	// RoutesForPeer needs the unreduced matchers: every rule where the node
	// is source or destination.
	if !pr.matchersLoaded {
		var err error

		pr.matchers, err = pr.snap.Policy().MatchersForNode(pr.self)
		if err != nil {
			return nil, err
		}

		pr.matchersLoaded = true
	}

	base, err := r.shared.render(r.cfg, r.capVer, pr.key.policy, peer, pr.capMaps)
	if err != nil {
		// One peer with invalid data must not blank out the map for every
		// node that can see it.
		log.Warn().Caller().Err(err).
			Uint64(zf.NodeID, peer.ID().Uint64()).
			Str(zf.NodeHostname, peer.Hostname()).
			Uint64("map.viewer.node.id", r.nodeID.Uint64()).
			Msgf("dropping peer %d from map response: invalid node data; fix with `headscale nodes rename %d <name>`", peer.ID(), peer.ID())

		return nil, nil //nolint:nilnil // a dropped peer is not an error for the map
	}

	ptn := withRoutes(base, pr.snap.RoutesForPeer(pr.self, peer, pr.matchers))

	// Hostinfo is not patchable, so any change resends the whole peer.
	// Keep what the client holds while the fields it reads are equal.
	if cached && peerHostinfoEqual(prev.tn.Hostinfo, ptn.Hostinfo) {
		ptn.Hostinfo = prev.tn.Hostinfo
	}

	r.peers[peer.ID()] = renderedPeer{node: peer, key: pr.key, tn: ptn}

	return ptn, nil
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
