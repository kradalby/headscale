package mapper

import (
	"cmp"
	"errors"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sync"

	"github.com/juanfont/headscale/hscontrol/graph"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// peerMap holds the rendered peers of a netMap by ID.
type peerMap = graph.Map[tailcfg.NodeID, *tailcfg.Node]

func newPeerMap() *peerMap {
	return graph.NewMap[tailcfg.NodeID, *tailcfg.Node](graph.Same[*tailcfg.Node], nil)
}

// ErrNodeGone is returned when the node a map is rendered for is no
// longer in the world.
var ErrNodeGone = errors.New("node no longer exists")

// netMap is everything a node is told about its tailnet, rendered from one
// [state.Snapshot]. A client holds exactly the last netMap it was sent;
// what to send next is the difference to a fresh one, see [diff].
type netMap struct {
	self *tailcfg.Node
	// peers shares structure with the base's, so a render that changed k
	// peers costs k entries, not a copy of them all.
	peers    *peerMap
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

// renderer renders one node's netMap. After the first render it renders a
// peer again only when the peer or what its rendering reads (its policy
// caps, its routes) changed; the common endpoint and online updates cost
// one peer each.
type renderer struct {
	cfg    *types.Config
	nodeID types.NodeID
	capVer tailcfg.CapabilityVersion

	last *netMap
	hub  *Hub

	// The nodes, peer inputs and peer set of the previous render, for
	// telling which peers a later snapshot can have changed.
	lastNodes   state.NodesVersion
	lastCaps    state.CapsVersion
	lastKey     renderKey
	lastPeerIDs []types.NodeID // the snapshot's shared view, see [state.Snapshot.PeerView]
	lastSelf    types.NodeView

	// dns is reused while its inputs, the node and the policy's capability
	// map and the extra records, are unchanged.
	dns    *tailcfg.DNSConfig
	dnsKey dnsKey

	// self is reused while the node, the policy and the primary routes,
	// which its own routes come from, are unchanged.
	self    *tailcfg.Node
	selfKey selfKey

	// rendered counts peer renders, for tests that bound per-write work.
	rendered int
}

// renderKey is what a peer's rendering reads besides the peer and the
// viewer: how the policy renders peers, and the primary routes.
type renderKey struct {
	policy, primaries uint64
}

type dnsKey struct {
	self        types.NodeView
	policy, dns uint64
}

type selfKey struct {
	self              types.NodeView
	policy, primaries uint64
}

func newRenderer(cfg *types.Config, hub *Hub, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *renderer {
	return &renderer{
		cfg:    cfg,
		nodeID: nodeID,
		capVer: capVer,
		hub:    hub,
	}
}

// peerRenders shares, across sessions, the part of a peer's rendering that
// does not depend on who views it: everything but its routes. Each stored
// node is rendered once per capability version and policy, not once per
// viewer.
type peerRenders struct {
	m sync.Map // peerRenderID -> *peerRender
}

// forget drops the renders of a deleted node.
func (pr *peerRenders) forget(id types.NodeID) {
	pr.m.Range(func(k, _ any) bool {
		if k.(peerRenderID).node == id { //nolint:forcetypeassert // only peerRenderID is stored
			pr.m.Delete(k)
		}

		return true
	})
}

type peerRenderID struct {
	node   types.NodeID
	capVer tailcfg.CapabilityVersion
}

type peerRender struct {
	node   types.NodeView
	policy uint64
	caps   tailcfg.NodeCapMap // the policy's caps for node, all it reads of the policy
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

	var prev *peerRender

	caps := capMaps[peer.ID()]

	if v, ok := pr.m.Load(id); ok {
		prev = v.(*peerRender) //nolint:forcetypeassert // only peerRender is stored
		if prev.node == peer && prev.policy == policy {
			return prev.tn, nil
		}

		// A new policy that gives the peer the same caps renders it the
		// same: keep the render, so sessions see nothing to send.
		if prev.node == peer && reflect.DeepEqual(prev.caps, caps) {
			pr.m.Store(id, &peerRender{node: peer, policy: policy, caps: caps, tn: prev.tn})

			return prev.tn, nil
		}
	}

	tn, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return nil }, cfg, caps)
	if err != nil {
		return nil, err
	}

	// A peer's CapMap carries only the caps clients read from the peer
	// view; see [policyv2.PeerCapMap].
	tn.CapMap = policyv2.PeerCapMap(peer, caps)

	// Clients never read a peer's NetInfo, and its home DERP reaches them
	// as HomeDERP; leaving it in would turn every DERP move into a
	// whole-peer update.
	if tn.Hostinfo.Valid() && tn.Hostinfo.NetInfo().Valid() {
		hi := tn.Hostinfo.AsStruct()
		hi.NetInfo = nil
		tn.Hostinfo = hi.View()
	}

	// Hostinfo is not patchable, so any change resends the whole peer.
	// Keep the Hostinfo clients hold while the fields they read are equal;
	// doing it here, once, keeps the render shared.
	if prev != nil && peerHostinfoEqual(prev.tn.Hostinfo, tn.Hostinfo) {
		tn.Hostinfo = prev.tn.Hostinfo
	}

	pr.m.Store(id, &peerRender{node: peer, policy: policy, caps: caps, tn: tn})

	return tn, nil
}

// withRoutes returns the shared render base carrying the routes one viewer
// sees, as [types.NodeView.TailNode] would have rendered them. A peer with
// no routes for the viewer, most of them, is the shared base itself, so a
// viewer holds a copy only of the peers that route for it.
func withRoutes(base *tailcfg.Node, routes []netip.Prefix) *tailcfg.Node {
	if len(routes) == 0 {
		return base
	}

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

	if k := (selfKey{self: self, policy: snap.PolicyRev(), primaries: snap.PrimariesRev()}); r.self == nil || k != r.selfKey {
		tn, err := self.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
			return snap.SelfRoutes(self)
		}, r.cfg, capMaps[self.ID()])
		if err != nil {
			return nil, err
		}

		r.self, r.selfKey = tn, k
	}

	tn := r.self

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

// renderPeers fills nm.peers: the shared peer map of the node's class (see
// [classMaps]) without the node itself and with its own routes on the
// routed peers. After the first render it records in nm.changed and
// nm.removed the peers that can differ from the base, so a diff looks at
// only them: those added to or gone from the view, those whose node
// changed, and those whose render reads something that moved without
// their node changing (their policy caps, or their routes, which come from
// the policy, the primary routes and the node's own routes).
func (r *renderer) renderPeers(
	snap *state.Snapshot,
	self types.NodeView,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
	nm *netMap,
) error {
	key := renderKey{
		policy:    snap.PeerPolicyRev(),
		primaries: snap.PrimariesRev(),
	}

	view := snap.PeerView(r.nodeID)
	inView := func(id types.NodeID) bool {
		_, found := slices.BinarySearch(view, id)

		return found
	}

	class := r.hub.classes.get(r.cfg, r.hub.renders, snap, view, r.capVer, key.policy, capMaps)
	peers := class.Edit()
	peers.Delete(r.nodeID.NodeID())

	var routed []types.NodeID

	for _, id := range snap.RoutedNodes() {
		if id != r.nodeID && inView(id) {
			routed = append(routed, id)
		}
	}

	if len(routed) > 0 {
		// RoutesForPeer needs the unreduced matchers: every rule where
		// the node is source or destination.
		matchers, err := snap.Policy().MatchersForNode(self)
		if err != nil {
			return err
		}

		for _, id := range routed {
			base, ok := class.Get(id.NodeID())
			peer, _ := snap.GetNode(id)

			if ok {
				peers.Set(id.NodeID(), withRoutes(base, snap.RoutesForPeer(self, peer, matchers)))
			}
		}
	}

	nm.peers = peers.Done()

	defer r.markRendered(snap, key, self)

	base := nm.base
	if base == nil {
		for id := range nm.peers.All() {
			nm.changed = append(nm.changed, id)
		}

		slices.Sort(nm.changed)
		r.rendered += len(nm.changed)

		return nil
	}

	var added, gone []types.NodeID
	if len(view) != len(r.lastPeerIDs) || len(view) > 0 && &view[0] != &r.lastPeerIDs[0] {
		added, gone = mergeDiff(r.lastPeerIDs, view)
	}

	candidates := slices.Concat(added, gone, snap.NodesChangedSince(r.lastNodes))

	if key.policy != r.lastKey.policy {
		candidates = append(candidates, snap.CapsChangedSince(r.lastCaps)...)
	}

	if key != r.lastKey || !sameRouteFacts(r.lastSelf, self) {
		candidates = append(candidates, snap.RoutedNodes()...)
	}

	slices.Sort(candidates)

	for _, id := range slices.Compact(candidates) {
		if id == r.nodeID {
			continue
		}

		was, sent := base.peers.Get(id.NodeID())
		is, ok := nm.peers.Get(id.NodeID())

		switch {
		case ok && (!sent || was != is):
			nm.changed = append(nm.changed, id.NodeID())
		case sent && !ok:
			nm.removed = append(nm.removed, id.NodeID())
		}
	}

	r.rendered += len(nm.changed)

	return nil
}

// sameRouteFacts reports whether a and b are the same viewer to the routes
// its peers are rendered with: its addresses and the routes it serves.
func sameRouteFacts(a, b types.NodeView) bool {
	return a == b || a.Valid() && b.Valid() &&
		slices.Equal(a.IPs(), b.IPs()) &&
		slices.Equal(a.AllApprovedRoutes(), b.AllApprovedRoutes())
}

// mergeDiff returns the IDs in b but not a, and in a but not b; both are
// sorted.
func mergeDiff(a, b []types.NodeID) ([]types.NodeID, []types.NodeID) {
	var added, gone []types.NodeID

	i, j := 0, 0
	for i < len(a) || j < len(b) {
		switch {
		case j == len(b) || i < len(a) && a[i] < b[j]:
			gone = append(gone, a[i])
			i++
		case i == len(a) || b[j] < a[i]:
			added = append(added, b[j])
			j++
		default:
			i++
			j++
		}
	}

	return added, gone
}

func (r *renderer) markRendered(snap *state.Snapshot, key renderKey, self types.NodeView) {
	r.lastNodes, r.lastKey, r.lastCaps = snap.NodesVersion(), key, snap.CapsVersion()
	r.lastPeerIDs, r.lastSelf = snap.PeerView(r.nodeID), self
}

// classMaps holds the peer maps shared by the sessions of a class: nodes
// that see the same nodes are sent the same peers but for themselves and
// their own routes, so the class's view is rendered once, without routes,
// and each session edits in only what is its own. A session's map then
// costs its own edits, not a copy of every peer.
type classMaps struct {
	mu sync.Mutex
	m  map[classKey]*classPeers
}

// classKey names a class by its view, which the snapshot shares and never
// changes, and the capability version the peers are rendered for.
type classKey struct {
	view   *types.NodeID
	n      int
	capVer tailcfg.CapabilityVersion
}

// classPeers is the peer map of a class's view at one snapshot.
type classPeers struct {
	rev   uint64
	nodes state.NodesVersion
	caps  state.CapsVersion
	peers *peerMap
}

// get returns the peer map of view at snap: every node of view rendered
// for capVer without routes, but those that cannot be rendered. It updates
// the class's latest map by the nodes and caps changed since.
func (cm *classMaps) get(
	cfg *types.Config,
	renders *peerRenders,
	snap *state.Snapshot,
	view []types.NodeID,
	capVer tailcfg.CapabilityVersion,
	policy uint64,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
) *peerMap {
	if len(view) == 0 {
		return newPeerMap()
	}

	key := classKey{view: &view[0], n: len(view), capVer: capVer}

	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.m == nil {
		cm.m = make(map[classKey]*classPeers)
	}

	cur := cm.m[key]
	if cur != nil && cur.rev == snap.Rev() {
		return cur.peers
	}

	inView := func(id types.NodeID) bool {
		_, found := slices.BinarySearch(view, id)

		return found
	}

	var (
		e       *graph.MapEdit[tailcfg.NodeID, *tailcfg.Node]
		changed []types.NodeID
	)

	if cur == nil {
		e, changed = newPeerMap().Edit(), view
	} else {
		e = cur.peers.Edit()
		changed = slices.Concat(snap.NodesChangedSince(cur.nodes), snap.CapsChangedSince(cur.caps))
	}

	for _, id := range changed {
		peer, ok := snap.GetNode(id)
		if !ok || !inView(id) {
			e.Delete(id.NodeID())

			continue
		}

		tn, err := renders.render(cfg, capVer, policy, peer, capMaps)
		if err != nil {
			// One peer with invalid data must not blank out the map for
			// every node that can see it.
			log.Warn().Caller().Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Msgf("dropping peer %d from map responses: invalid node data; fix with `headscale nodes rename %d <name>`", peer.ID(), peer.ID())
			e.Delete(id.NodeID())

			continue
		}

		e.Set(id.NodeID(), tn)
	}

	next := &classPeers{rev: snap.Rev(), nodes: snap.NodesVersion(), caps: snap.CapsVersion(), peers: e.Done()}

	// A session rendering an older snapshot than the class's latest keeps
	// its map to itself.
	if cur == nil || cur.rev < snap.Rev() {
		if cur == nil {
			cm.prune(snap)
		}

		cm.m[key] = next
	}

	return next.peers
}

// prune drops the maps of views snap no longer holds.
func (cm *classMaps) prune(snap *state.Snapshot) {
	current := map[*types.NodeID]struct{}{}

	for _, v := range snap.PeerViews() {
		if len(v) > 0 {
			current[&v[0]] = struct{}{}
		}
	}

	for k := range cm.m {
		if _, ok := current[k.view]; !ok {
			delete(cm.m, k)
		}
	}
}

// renderProfiles fills nm.profiles. A client keeps every profile it was
// sent, so after the first render only the owners of the node and of the
// peers rendered again can need one: they start from the base's profiles,
// shared until one changes.
func (r *renderer) renderProfiles(snap *state.Snapshot, self types.NodeView, nm *netMap) {
	base := nm.base
	if base == nil || !self.Owner().Valid() {
		nm.profiles = make(map[tailcfg.UserID]tailcfg.UserProfile)
		for _, p := range generateUserProfiles(self, snap.ListPeers(r.nodeID)) {
			nm.profiles[p.ID] = p
		}

		return
	}

	profiles, cloned := base.profiles, false
	show := func(n types.NodeView) {
		owner := n.Owner()
		if !owner.Valid() {
			return
		}

		p := owner.TailscaleUserProfile()
		if old, ok := profiles[p.ID]; ok && reflect.DeepEqual(old, p) {
			return
		}

		if !cloned {
			profiles, cloned = maps.Clone(profiles), true
		}

		profiles[p.ID] = p
	}

	show(self)

	for _, id := range nm.changed {
		if peer, ok := snap.GetNode(types.NodeID(id)); ok { //nolint:gosec // NodeID types are the same value
			show(peer)
		}
	}

	nm.profiles, nm.sameProfiles = profiles, !cloned
}

func sortedPeers(peers *peerMap) []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, peers.Len())
	for _, p := range peers.All() {
		out = append(out, p)
	}

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
