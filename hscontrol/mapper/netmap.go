package mapper

import (
	"cmp"
	"errors"
	"iter"
	"maps"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
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

// peer returns the peer with id; the node itself is not its own peer.
func (nm *netMap) peer(id tailcfg.NodeID) (*tailcfg.Node, bool) {
	if nm.self != nil && id == nm.self.ID {
		return nil, false
	}

	return nm.peers.Get(id)
}

// allPeers returns the peers, the node itself left out.
func (nm *netMap) allPeers() iter.Seq2[tailcfg.NodeID, *tailcfg.Node] {
	return func(yield func(tailcfg.NodeID, *tailcfg.Node) bool) {
		for id, p := range nm.peers.All() {
			if nm.self != nil && id == nm.self.ID {
				continue
			}

			if !yield(id, p) {
				return
			}
		}
	}
}

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
	// at is when the snapshot rendered was committed: the ControlTime of
	// the updates it is diffed into, the same for every session rendering
	// it, so their identical updates encode to identical bytes. Sessions
	// render on commits, so it is recent.
	at   time.Time
	self *tailcfg.Node
	// peers is usually the map its class shares (see [classMaps]), which
	// holds the node itself when it sees its own class; read it through
	// [netMap.peer] and [netMap.allPeers], which leave the node out.
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
	// ownerless is set when self had no owner, so no profiles were sent
	// though peers were.
	ownerless bool
}

// renderer renders one node's netMap. After the first render it renders a
// peer again only when the peer or what its rendering reads (its policy
// caps, its routes) changed; the common endpoint and online updates cost
// one peer each.
type renderer struct {
	cfg    *types.Config
	nodeID types.NodeID
	capVer tailcfg.CapabilityVersion

	last    *netMap
	renders *peerRenders
	classes *classMaps

	// The shared peers, peer inputs and peer set of the previous render, for
	// telling which peers a later snapshot can have changed.
	lastClass   *peerMap
	lastKey     renderKey
	lastPeerIDs []types.NodeID // the snapshot's shared view, see [state.Snapshot.PeerView]
	lastSelf    types.NodeView
	// overlays counts peers with viewer-specific routes, so losing the
	// last overlay restores the shared class map.
	overlays int

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

// selfKey holds what the node's own entry renders from. dns is there for
// the HTTPS capability: an extra record at the node's name takes it away.
type selfKey struct {
	self                   types.NodeView
	policy, primaries, dns uint64
}

func newRenderer(cfg *types.Config, hub *Hub, nodeID types.NodeID, capVer tailcfg.CapabilityVersion) *renderer {
	renders, classes := hub.renders, &hub.classes
	if capVer < capver.MinSupportedCapabilityVersion || capVer > tailcfg.CurrentCapabilityVersion {
		// Unknown versions remain compatible, but must not retain shared
		// caches for arbitrarily many client-supplied versions after Leave.
		classes = &classMaps{}
	}

	return &renderer{
		cfg:     cfg,
		nodeID:  nodeID,
		capVer:  capVer,
		renders: renders,
		classes: classes,
	}
}

// peerRenders shares, across sessions, the part of a peer's rendering that
// does not depend on who views it: everything but its routes. Each stored
// node is rendered once per capability version and policy, not once per
// viewer.
type peerRenders struct {
	m sync.Map // types.NodeID -> *sync.Map of tailcfg.CapabilityVersion -> *peerRender
	// mu serialises admission with deletion; floor rejects misses from
	// older snapshots without keeping a tombstone for every deleted node.
	mu    sync.Mutex
	floor uint64
}

// advance publishes the newest snapshot observed. The watcher must call
// it before deletion cleanup, even when a resync finds no retained IDs.
func (pr *peerRenders) advance(rev uint64) {
	pr.mu.Lock()
	pr.floor = max(pr.floor, rev)
	pr.mu.Unlock()
}

// forget drops the renders of a deleted node after advance publishes the
// deleting snapshot. Stores through an already admitted map remain safe:
// they write the detached map, never reinsert it.
func (pr *peerRenders) forget(id types.NodeID) {
	pr.mu.Lock()
	pr.m.Delete(id)
	pr.mu.Unlock()
}

// of returns node's renders, one per capability version.
func (pr *peerRenders) of(node types.NodeID, rev uint64) *sync.Map {
	if v, ok := pr.m.Load(node); ok {
		return v.(*sync.Map) //nolint:forcetypeassert // only *sync.Map is stored
	}

	pr.mu.Lock()
	defer pr.mu.Unlock()

	if rev < pr.floor {
		return &sync.Map{}
	}

	v, _ := pr.m.LoadOrStore(node, &sync.Map{})

	return v.(*sync.Map) //nolint:forcetypeassert // only *sync.Map is stored
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
	dns types.DNSView,
	capVer tailcfg.CapabilityVersion,
	rev, policy uint64,
	peer types.NodeView,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
) (*tailcfg.Node, error) {
	renders := &sync.Map{}
	if capVer >= capver.MinSupportedCapabilityVersion && capVer <= tailcfg.CurrentCapabilityVersion {
		renders = pr.of(peer.ID(), rev)
	}

	var prev *peerRender

	caps := capMaps[peer.ID()]

	if v, ok := renders.Load(capVer); ok {
		prev = v.(*peerRender) //nolint:forcetypeassert // only peerRender is stored
		if prev.node == peer && prev.policy == policy {
			return prev.tn, nil
		}

		// A new policy that gives the peer the same caps renders it the
		// same: keep the render, so sessions see nothing to send.
		if prev.node == peer && reflect.DeepEqual(prev.caps, caps) {
			renders.Store(capVer, &peerRender{node: peer, policy: policy, caps: caps, tn: prev.tn})

			return prev.tn, nil
		}
	}

	// Peers must not read DNS records: the class cache reuses peer renders
	// across DNS revisions, and the peer CapMap is replaced below. Names come
	// from the frozen base domain, so a records-free view keeps peer renders
	// independent of record changes by construction.
	tn, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return nil }, cfg, dns.WithExtraRecords(nil), caps)
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

	renders.Store(capVer, &peerRender{node: peer, policy: policy, caps: caps, tn: tn})

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

	dns := snap.DNS()

	if k := (selfKey{self: self, policy: snap.PolicyRev(), primaries: snap.PrimariesRev(), dns: snap.DNSRev()}); r.self == nil || k != r.selfKey {
		tn, err := self.TailNode(r.capVer, func(types.NodeID) []netip.Prefix {
			return snap.SelfRoutes(self)
		}, r.cfg, dns, capMaps[self.ID()])
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
		r.dns, r.dnsKey = generateDNSConfig(dns, self, capMaps[self.ID()]), k
	}

	nm := &netMap{
		at:      snap.Time(),
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
	class := r.classes.get(r.cfg, r.renders, snap, view, r.capVer, key.policy, capMaps)
	nm.peers = class

	base := nm.base

	var candidates []tailcfg.NodeID

	if base != nil {
		// The class map remembers changed renders, including view changes;
		// falling beyond its edit log compares only this class's peers.
		candidates = graph.Changes(r.lastClass, class)
		if base.peers != r.lastClass {
			// Keep this viewer's route overlays while applying class edits.
			nm.peers = base.peers
		}
	}

	if base == nil || key != r.lastKey || !sameRouteFacts(r.lastSelf, self) {
		for _, id := range snap.RoutedNodes() {
			candidates = append(candidates, id.NodeID())
		}
	}

	slices.Sort(candidates)
	candidates = slices.Compact(candidates)
	peers := nm.peers.Edit()
	overlays := r.overlays

	var routed []types.NodeID

	for _, id := range candidates {
		if base != nil {
			was, _ := base.peers.Get(id)

			plain, _ := r.lastClass.Get(id)
			if was != plain {
				overlays--
			}
		}

		tn, ok := class.Get(id)
		if !ok {
			peers.Delete(id)

			continue
		}

		peer, _ := snap.GetNode(types.NodeID(id)) //nolint:gosec // NodeID types are the same value
		if id != r.nodeID.NodeID() && peer.ApprovedRoutes().Len() > 0 {
			routed = append(routed, peer.ID())
		} else if old, _ := peers.Get(id); old != tn {
			peers.Set(id, tn)
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
			base, _ := class.Get(id.NodeID())
			peer, _ := snap.GetNode(id)

			tn := withRoutes(base, snap.RoutesForPeer(self, peer, matchers))
			if tn != base {
				overlays++
			}

			if old, _ := peers.Get(id.NodeID()); old != tn {
				peers.Set(id.NodeID(), tn)
			}
		}
	}

	// Only routed peers differ per viewer; a session without them
	// shares its class's map outright.
	nm.peers = peers.Done()
	if overlays == 0 {
		nm.peers = class
	}

	r.overlays = overlays

	if base == nil {
		for id := range nm.allPeers() {
			nm.changed = append(nm.changed, id)
		}

		slices.Sort(nm.changed)
		r.rendered += len(nm.changed)
		r.markRendered(snap, key, self, class)

		return nil
	}

	for _, id := range candidates {
		if id == r.nodeID.NodeID() {
			continue
		}

		was, sent := base.peer(id)
		is, ok := nm.peer(id)

		switch {
		case ok && (!sent || was != is):
			nm.changed = append(nm.changed, id)
		case sent && !ok:
			nm.removed = append(nm.removed, id)
		}
	}

	r.rendered += len(nm.changed)

	// Only a render that completed moves the cursor; a failed one is
	// retried from the same place.
	r.markRendered(snap, key, self, class)

	return nil
}

// sameRouteFacts reports whether a and b are the same viewer to the routes
// its peers are rendered with: its addresses and the routes it serves.
func sameRouteFacts(a, b types.NodeView) bool {
	return a == b || a.Valid() && b.Valid() &&
		slices.Equal(a.IPs(), b.IPs()) &&
		slices.Equal(a.AllApprovedRoutes(), b.AllApprovedRoutes())
}

func (r *renderer) markRendered(snap *state.Snapshot, key renderKey, self types.NodeView, class *peerMap) {
	r.lastClass, r.lastKey = class, key
	r.lastPeerIDs, r.lastSelf = snap.PeerView(r.nodeID), self
}

// classMaps holds the peer maps shared by the sessions of a class: nodes
// that see the same nodes are sent the same peers but for themselves and
// their own routes, so the class's view is rendered once, without routes,
// and each session edits in only what is its own. A session's map then
// costs its own edits, not a copy of every peer.
type classMaps struct {
	mu sync.Mutex
	m  map[classKey]*classEntry
	// pruned is the peer-classes revision maps were last pruned against.
	pruned uint64
}

// classEntry is one class's latest map; mu serialises its update, so
// classes update in parallel.
type classEntry struct {
	mu  sync.Mutex
	cur *classPeers
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
// the class's latest map by the nodes and caps changed since, or rebuilds
// it from the view when that is too far back to tell.
func (cm *classMaps) get(
	cfg *types.Config,
	renders *peerRenders,
	snap *state.Snapshot,
	view []types.NodeID,
	capVer tailcfg.CapabilityVersion,
	policy uint64,
	capMaps map[types.NodeID]tailcfg.NodeCapMap,
) *peerMap {
	renders.advance(snap.Rev())

	cm.mu.Lock()
	if cm.m == nil {
		cm.m = make(map[classKey]*classEntry)
	}

	cm.prune(snap)

	if len(view) == 0 {
		cm.mu.Unlock()
		return newPeerMap()
	}

	key := classKey{view: &view[0], n: len(view), capVer: capVer}

	entry, ok := cm.m[key]
	if !ok {
		entry = &classEntry{}
		// A render overtaken by pruning keeps a vanished class local.
		if snap.PeersRev() >= cm.pruned {
			cm.m[key] = entry
		}
	}
	cm.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	cur := entry.cur
	if cur != nil && cur.rev == snap.Rev() {
		return cur.peers
	}

	e, changed := newPeerMap().Edit(), view

	dns := snap.DNS()

	if cur != nil {
		if touched, ok := snap.NodesTouchedSince(cur.nodes); ok {
			e, changed = cur.peers.Edit(), slices.Concat(touched, snap.CapsChangedSince(cur.caps))
		}
	}

	for _, id := range changed {
		peer, ok := snap.GetNode(id)
		if !ok || !inView(view, id) {
			e.Delete(id.NodeID())

			continue
		}

		tn, err := renders.render(cfg, dns, capVer, snap.Rev(), policy, peer, capMaps)
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
		entry.cur = next
	}

	return next.peers
}

// advance drops obsolete classes even when no session renders the new
// snapshot. The watcher calls it before deletion cleanup.
func (cm *classMaps) advance(snap *state.Snapshot) {
	cm.mu.Lock()
	cm.prune(snap)
	cm.mu.Unlock()
}

// prune drops the maps of views snap no longer holds. The caller holds mu.
func (cm *classMaps) prune(snap *state.Snapshot) {
	// Views vanish only when the peer classes change; prune then, so a
	// class gone for good does not pin its map until a new one appears.
	if rev := snap.PeersRev(); rev > cm.pruned {
		cm.pruned = rev
	} else {
		return
	}

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
	nm.ownerless = !self.Owner().Valid()

	// Without an owner no profiles go out; gaining one sends every peer's.
	if base == nil || nm.ownerless || base.ownerless {
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
		if old, ok := profiles[p.ID]; ok && sameProfile(old, p) {
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

func sortedPeers(nm *netMap) []*tailcfg.Node {
	out := make([]*tailcfg.Node, 0, nm.peers.Len())
	for _, p := range nm.allPeers() {
		out = append(out, p)
	}

	slices.SortFunc(out, func(a, b *tailcfg.Node) int { return cmp.Compare(a.ID, b.ID) })

	return out
}

// sameProfile compares field by field; [tailcfg.UserProfile] holds a
// slice, and this runs for every update.
func sameProfile(a, b tailcfg.UserProfile) bool {
	return a.ID == b.ID && a.LoginName == b.LoginName && a.DisplayName == b.DisplayName &&
		a.ProfilePicURL == b.ProfilePicURL && slices.Equal(a.Groups, b.Groups)
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

// inView reports whether the sorted view holds id.
func inView(view []types.NodeID, id types.NodeID) bool {
	_, found := slices.BinarySearch(view, id)

	return found
}
